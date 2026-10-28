// Package planner 实现 ARGUS 的 LLM 规划器（OpenAI 兼容接口）。
//
// 契约要点（与 engine.Planner 对齐）：
//   - 只负责"产出下一批意图"，不直接执行任何工具；
//   - 产出的意图仍要过三层闸门、预算、指纹去重 —— 模型不能绕过任何一道；
//   - 未配置模型时返回空（任务收敛），而不是崩溃或无限空转；
//   - 每次调用的 token 用量通过 LastUsage 暴露给调度器记账。
package planner

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/argus/argus/internal/settings"
	"github.com/argus/argus/internal/store"
)

// LLMPlanner 是基于 chat/completions 的规划器。
type LLMPlanner struct {
	stg    *settings.Store
	client *http.Client

	mu         sync.Mutex
	lastTokens int64
	lastCost   int64
	lastErr    string
	calls      int64
}

// New 构造规划器。配置每次调用时读取，因此改配置无需重启。
func New(stg *settings.Store) *LLMPlanner {
	return &LLMPlanner{
		stg:    stg,
		client: &http.Client{Timeout: 150 * time.Second},
	}
}

// LastUsage 返回上一次调用的 token/成本（供 engine 记账）。
func (p *LLMPlanner) LastUsage() (int64, int64) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.lastTokens, p.lastCost
}

// Stats 返回调用统计（观测用）。
func (p *LLMPlanner) Stats() map[string]any {
	p.mu.Lock()
	defer p.mu.Unlock()
	return map[string]any{"calls": p.calls, "last_error": p.lastErr}
}

// Next 实现 engine.Planner。
func (p *LLMPlanner) Next(ctx context.Context, t store.Task, st store.Store) ([]store.Intent, error) {
	cfg := p.stg.LLM()
	if !cfg.Configured() {
		// 未配置：不产出新意图，让任务自然收敛（前端会显示"未配置模型"）。
		return nil, nil
	}
	sys, user := buildPrompt(t, st)
	out, tokens, err := p.chat(ctx, cfg, sys, user)
	p.mu.Lock()
	p.lastTokens = tokens
	p.calls++
	if err != nil {
		p.lastErr = err.Error()
	} else {
		p.lastErr = ""
	}
	p.mu.Unlock()
	if err != nil {
		return nil, err
	}
	intents := parseIntents(out)
	for i := range intents {
		intents[i].TaskID = t.ID
	}
	return intents, nil
}

// ---- 提示词 ----

const systemPrompt = `你是授权渗透测试任务的规划器（Planner）。你只输出 JSON，不输出任何解释。

规则（不可违反）：
1. 只能针对任务声明的授权范围内的目标规划动作；范围外的目标一律不要提出。
2. 不要重复已经做过的意图（用户消息里会给出已有意图清单）。
3. 一次最多提出 5 条新意图；没有值得做的新动作时返回空数组。
4. 每条意图必须是一个可执行的原子动作（一个工具调用），不要写"继续测试"这类空话。
5. vuln_class 只在你有明确证据表明存在该漏洞时填写，否则留空。

输出格式：
{"intents":[{"action":"Bash|WebFetch|Read|Write","summary":"工具输入的 JSON 字符串","param_key":"用于去重的简短参数签名","asset_id":数字,"target":"目标主机或URL","vuln_class":"可选","severity":"info|low|medium|high|critical"}]}`

func buildPrompt(t store.Task, st store.Store) (string, string) {
	var b strings.Builder
	fmt.Fprintf(&b, "任务目标：%s\n\n", t.Goal)

	b.WriteString("已授权范围：\n")
	b.WriteString("- 只允许测试任务声明范围内的目标（范围校验在系统内核层强制执行，你无法绕过）\n\n")

	intents := st.Intents(t.ID)
	if len(intents) == 0 {
		b.WriteString("已有意图：无（这是第一轮，请先做只读侦察）\n\n")
	} else {
		b.WriteString("已有意图（不要重复）：\n")
		start := 0
		if len(intents) > 30 {
			start = len(intents) - 30
		}
		for _, it := range intents[start:] {
			fmt.Fprintf(&b, "- [%s] %s\n", it.State, truncate(it.Summary, 160))
		}
		b.WriteString("\n")
	}

	assets, _ := st.Assets(t.ID, "", 20, 0)
	if len(assets) > 0 {
		b.WriteString("已确认接触过的资产：\n")
		for _, a := range assets {
			fmt.Fprintf(&b, "- %s (%s, %d 次)\n", a.Value, a.Type, a.Hits)
		}
		b.WriteString("\n")
	}

	findings := st.Findings(t.ID)
	if len(findings) > 0 {
		b.WriteString("已确认漏洞：\n")
		for _, f := range findings {
			fmt.Fprintf(&b, "- [%s] %s @ %s\n", f.Severity, f.VulnClass, f.Target)
		}
		b.WriteString("\n")
	}

	blocked := st.Violations(t.ID)
	if len(blocked) > 0 {
		b.WriteString("被闸门拦截的目标（不要再尝试，这些在授权范围外）：\n")
		seen := map[string]bool{}
		for _, v := range blocked {
			if seen[v.Target] {
				continue
			}
			seen[v.Target] = true
			fmt.Fprintf(&b, "- %s（%s）\n", v.Target, v.Reason)
		}
		b.WriteString("\n")
	}

	b.WriteString("请给出下一批意图（不超过 5 条）。")
	return systemPrompt, b.String()
}

// ---- HTTP ----

type chatReq struct {
	Model          string        `json:"model"`
	Messages       []chatMessage `json:"messages"`
	Temperature    float64       `json:"temperature,omitempty"`
	MaxTokens      int           `json:"max_tokens,omitempty"`
	ResponseFormat *respFormat   `json:"response_format,omitempty"`
}

type chatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type respFormat struct {
	Type string `json:"type"`
}

type chatResp struct {
	Choices []struct {
		Message chatMessage `json:"message"`
	} `json:"choices"`
	Usage struct {
		TotalTokens int64 `json:"total_tokens"`
	} `json:"usage"`
	Error *struct {
		Message string `json:"message"`
	} `json:"error"`
}

func (p *LLMPlanner) chat(ctx context.Context, cfg settings.LLM, sys, user string) (string, int64, error) {
	url := strings.TrimRight(cfg.BaseURL, "/") + "/chat/completions"
	req := chatReq{
		Model:       cfg.Model,
		Temperature: cfg.Temperature,
		MaxTokens:   cfg.MaxTokens,
		Messages: []chatMessage{
			{Role: "system", Content: sys},
			{Role: "user", Content: user},
		},
		ResponseFormat: &respFormat{Type: "json_object"},
	}
	body, err := json.Marshal(req)
	if err != nil {
		return "", 0, err
	}
	cctx := ctx
	if cfg.TimeoutSeconds > 0 {
		var cancel context.CancelFunc
		cctx, cancel = context.WithTimeout(ctx, time.Duration(cfg.TimeoutSeconds)*time.Second)
		defer cancel()
	}
	httpReq, err := http.NewRequestWithContext(cctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return "", 0, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+cfg.APIKey)
	resp, err := p.client.Do(httpReq)
	if err != nil {
		return "", 0, fmt.Errorf("调用模型失败: %w", err)
	}
	defer resp.Body.Close()
	var cr chatResp
	if err := json.NewDecoder(resp.Body).Decode(&cr); err != nil {
		return "", 0, fmt.Errorf("模型响应不是合法 JSON: %w", err)
	}
	if cr.Error != nil && cr.Error.Message != "" {
		return "", cr.Usage.TotalTokens, fmt.Errorf("模型返回错误: %s", cr.Error.Message)
	}
	if resp.StatusCode != http.StatusOK {
		return "", cr.Usage.TotalTokens, fmt.Errorf("模型 HTTP %d", resp.StatusCode)
	}
	if len(cr.Choices) == 0 {
		return "", cr.Usage.TotalTokens, fmt.Errorf("模型未返回任何内容")
	}
	return cr.Choices[0].Message.Content, cr.Usage.TotalTokens, nil
}

// ---- 解析 ----

type rawIntent struct {
	Action    string `json:"action"`
	Summary   string `json:"summary"`
	ParamKey  string `json:"param_key"`
	AssetID   int64  `json:"asset_id"`
	Target    string `json:"target"`
	VulnClass string `json:"vuln_class"`
	Severity  string `json:"severity"`
}

// parseIntents 对模型输出做"防御性解析"：模型可能包 ```json 代码块、可能多写字段。
func parseIntents(raw string) []store.Intent {
	s := strings.TrimSpace(raw)
	if i := strings.Index(s, "{"); i > 0 {
		s = s[i:]
	}
	if j := strings.LastIndex(s, "}"); j >= 0 && j < len(s)-1 {
		s = s[:j+1]
	}
	var payload struct {
		Intents []rawIntent `json:"intents"`
	}
	if err := json.Unmarshal([]byte(s), &payload); err != nil {
		return nil
	}
	out := make([]store.Intent, 0, len(payload.Intents))
	for _, r := range payload.Intents {
		action := strings.TrimSpace(r.Action)
		if action == "" {
			action = "Bash"
		}
		if strings.TrimSpace(r.Summary) == "" {
			continue
		}
		out = append(out, store.Intent{
			Action: action, Summary: r.Summary, ParamKey: r.ParamKey,
			AssetID: r.AssetID, Target: r.Target,
			VulnClass: r.VulnClass, Severity: r.Severity,
		})
		if len(out) >= 5 {
			break
		}
	}
	return out
}

// TestConnection 用给定配置做一次最小调用，返回模型回复与 token 用量。
// 用于 /api/llm/test，让用户配置完立刻验证"通不通"。
func TestConnection(ctx context.Context, cfg settings.LLM) (string, int64, error) {
	stg := settings.Open("")
	_ = stg.Update(func(s *settings.Settings) { s.LLM = cfg })
	p := New(stg)
	return p.chat(ctx, cfg, "你是连通性测试助手。", "只回复两个字：正常")
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
