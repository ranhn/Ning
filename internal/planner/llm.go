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

// Env 描述执行环境，注入提示词。
//
// 为什么需要：模型默认按 Linux 习惯生成命令（getent、ss、管道串联），
// 这些在本机要么不存在、要么会被沙箱拒绝，白白浪费预算和时间。
// 把"真实可用命令"写进提示词，比事后拦截有效得多。
type Env struct {
	OS      string   // runtime.GOOS
	Arch    string   // runtime.GOARCH
	Tools   []string // 已确认可用的工具名
	Missing []string // 白名单里但本机没有的工具
}

// EnvProvider 每次规划时调用，允许后台探测完成后动态更新。
type EnvProvider func() Env

// LLMPlanner 是基于 chat/completions 的规划器。
type LLMPlanner struct {
	stg    *settings.Store
	client *http.Client
	env    EnvProvider

	mu         sync.Mutex
	lastTokens int64
	lastCost   int64
	lastErr    string
	calls      int64
	goalMet    bool // 上一轮模型是否显式声明目标达成
	stagnant   int  // 连续无产出轮次（由调度器注入）
	stagnantAt int  // 触发"换方向"提示的阈值
}

// SetStagnation 实现 engine.StagnationAware：调度器把停滞轮次告诉规划器。
func (p *LLMPlanner) SetStagnation(rounds, threshold int) {
	p.mu.Lock()
	p.stagnant, p.stagnantAt = rounds, threshold
	p.mu.Unlock()
}

// GoalMet 实现 engine.GoalMet：模型显式声明目标已达成时，任务才正常结束。
func (p *LLMPlanner) GoalMet() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.goalMet
}

// New 构造规划器。配置每次调用时读取，因此改配置无需重启。
func New(stg *settings.Store) *LLMPlanner {
	return &LLMPlanner{
		stg:    stg,
		client: &http.Client{Timeout: 150 * time.Second},
	}
}

// NewWithEnv 构造带执行环境信息的规划器。
func NewWithEnv(stg *settings.Store, env EnvProvider) *LLMPlanner {
	p := New(stg)
	p.env = env
	return p
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
	sys, user := p.PromptFor(t, st)
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
	intents, goalMet := parseIntents(out)
	p.mu.Lock()
	p.goalMet = goalMet
	p.mu.Unlock()

	// 丢掉占位目标：它们必然被闸门拦下（example.invalid 之类），
	// 与其浪费一轮执行与越界台账，不如在生成时就过滤掉。
	clean := intents[:0]
	for _, it := range intents {
		if IsPlaceholderTarget(it.Summary) || IsPlaceholderTarget(it.Target) {
			continue
		}
		it.TaskID = t.ID
		clean = append(clean, it)
	}
	return clean, nil
}

// ---- 提示词 ----

const systemPrompt = `你是授权渗透测试任务的规划器（Planner）。你只输出 JSON，不输出任何解释。

规则（不可违反）：
1. 只能针对任务声明的授权范围内的目标规划动作；范围外的目标一律不要提出。
2. 不要重复已经做过的意图（用户消息里会给出已有意图清单）。
3. 一次最多提出 5 条新意图；没有值得做的新动作时返回空数组。
4. 每条意图必须是一个可执行的原子动作（一个工具调用），不要写"继续测试"这类空话。
5. vuln_class 只在你有明确证据表明存在该漏洞时填写，否则留空。
6. 只能使用用户消息里「执行环境」列出的命令；不要凭平台习惯臆造命令。
7. **只要目标尚未被证据证明达成，且没有待执行意图，你必须至少提出 1 条新意图。返回空数组是不允许的。**
8. 只有当你已用确凿证据（已确认漏洞、或覆盖度已达标）证明目标达成时，才返回 goal_met=true 与空意图。

输出格式：
{"goal_met":false,"intents":[{"action":"Bash|WebFetch|Read|Write","summary":"工具输入的 JSON 字符串","param_key":"用于去重的简短参数签名","asset_id":数字,"target":"目标主机或URL","vuln_class":"可选","severity":"info|low|medium|high|critical"}]}`

func buildPrompt(t store.Task, st store.Store, env *Env, stagnant, threshold int) (string, string) {
	var b strings.Builder

	// 执行环境放在最前面：模型最容易犯的错是"按 Linux 习惯生成命令"，
	// 而本机可能根本没有 getent / ss / awk，这类意图会全部撞在"工具未安装"上。
	if env != nil {
		b.WriteString("## 执行环境（硬约束，必须遵守）\n")
		if env.OS != "" {
			fmt.Fprintf(&b, "- 操作系统：%s/%s\n", env.OS, env.Arch)
		}
		if len(env.Tools) > 0 {
			fmt.Fprintf(&b, "- 真实可用的命令：%s\n", strings.Join(env.Tools, ", "))
			b.WriteString("- 只能使用上面列出的命令；其他命令在本机不存在，用了会直接失败\n")
		}
		if len(env.Missing) > 0 {
			fmt.Fprintf(&b, "- 不可用（不要使用）：%s\n", strings.Join(env.Missing, ", "))
		}
		if env.OS == "windows" {
			b.WriteString("- 不要生成 Linux 专有命令：getent、ss、netstat、lsof、awk、sed、grep、/dev/tcp 等\n")
			b.WriteString("- 命令必须是单条可执行命令，不要使用管道、重定向或 && 串联（会被沙箱直接拒绝）\n")
		}
		b.WriteString("\n")
	}

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

	// 停滞提示（不结束任务，只纠偏）：对齐 ARTEX 的 detectStagnation——
	// 同一方向重复多次且没有新发现时，要求换一个实质不同的方向。
	if threshold > 0 && stagnant >= threshold {
		fmt.Fprintf(&b, "## 停滞警告（连续 %d 轮没有新增完成意图或漏洞）\n", stagnant)
		b.WriteString("- 不要重复同一方向：同一子域的同类端口扫描、同一路径的重复探测都要避免。\n")
		b.WriteString("- 必须换一个实质不同的方向：未测子域、未测端口、未测路径、参数变体、已验证漏洞的深入验证。\n")
		b.WriteString("- 理解：任务不会因为停滞而结束，但你需要给出真正有信息增益的下一步。\n\n")
	}

	// 失败清单：明确告诉模型"这些做过且失败了，别原样重试"。
	// 448 条意图里 99 条被拦，很大一部分是反复重试同一类失败动作。
	if failed := recentBlocked(intents); len(failed) > 0 {
		b.WriteString("最近失败或被拦的动作（不要原样重试；换目标或换方法）：\n")
		for _, it := range failed {
			fmt.Fprintf(&b, "- %s\n", truncate(it.Summary, 130))
		}
		b.WriteString("\n")
	}

	// 工具用法：模型经常只会 nmap/curl，不知道"怎么才能发现漏洞"。
	// 顺序刻意按"扩面 → 确认存活 → 抽端点 → 验证"排列，因为这就是真实挖洞的链路。
	b.WriteString("## 可用动作与典型用法（按「扩面 → 探活 → 抽端点 → 验证」的顺序推进）\n")
	b.WriteString("- **子域枚举**：subfinder -d <domain> -silent\n")
	b.WriteString("- **HTTP 探活**：httpx -u https://<host> -status-code -title -tech-detect -silent\n")
	b.WriteString("- **爬端点**：katana -u https://<host> -d 2 -silent   ← 从页面和 JS 里抽接口，是发现漏洞的关键\n")
	b.WriteString("- 端口/服务识别：nmap -sV -Pn -p 80,443,8080,8443 <host>\n")
	b.WriteString("- 路径存活探测：curl -sS -I https://<host>/admin  （一次一条路径，不要用管道）\n")
	b.WriteString("- **已知漏洞模板验证**：nuclei -u https://<host> -severity critical,high,medium -silent\n")
	b.WriteString("- **XSS 验证**：dalfox url \"https://<host>/?q=test\" --silence\n")
	b.WriteString("- 页面抓取与差异比对：WebFetch {\"url\":\"https://<host>/path\"}\n")
	b.WriteString("- 只使用已授权范围里的真实主机名；禁止使用 example.com、*.invalid、<domain> 这类占位符\n")
	b.WriteString("- 挖不到洞通常不是扫描器不行，而是**没找到对的 URL**：优先把端点抽全，再对可疑端点做模板验证\n\n")

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

// recentBlocked 取最近失败/被拦的意图摘要（最多 8 条），用于提示词里"别再重复"。
func recentBlocked(intents []store.Intent) []store.Intent {
	out := make([]store.Intent, 0, 8)
	for i := len(intents) - 1; i >= 0 && len(out) < 8; i-- {
		switch intents[i].State {
		case store.IntentBlocked, store.IntentExhausted:
			out = append(out, intents[i])
		}
	}
	return out
}

// IsPlaceholderTarget 识别模型编造的占位目标（example.com / *.invalid / <domain>）。
//
// 这类意图一定会被闸门拦下（域名不在授权范围或无法解析），
// 白白消耗一轮预算和规划成本，因此在生成时直接丢弃。
func IsPlaceholderTarget(s string) bool {
	l := strings.ToLower(s)
	for _, bad := range []string{
		"example.com", "example.org", "example.net", "example.invalid",
		".invalid", "dns-brute.domain", "<domain>", "{domain}", "your-domain",
		"target.example", "localhost.localdomain",
	} {
		if strings.Contains(l, bad) {
			return true
		}
	}
	return false
}

// PromptFor 暴露提示词构造，便于自检断言"环境信息确实进到了提示里"。
func (p *LLMPlanner) PromptFor(t store.Task, st store.Store) (string, string) {
	var env *Env
	if p.env != nil {
		e := p.env()
		env = &e
	}
	p.mu.Lock()
	stagnant, threshold := p.stagnant, p.stagnantAt
	p.mu.Unlock()
	return buildPrompt(t, st, env, stagnant, threshold)
}

// ---- HTTP ----

type chatReq struct {
	Model    string        `json:"model"`
	Messages []chatMessage `json:"messages"`
	// 指针：推理模型不接受自定义 temperature，必须能整字段省略
	Temperature *float64 `json:"temperature,omitempty"`
	// 经典模型用 max_tokens，推理模型（gpt-5 / o 系列）只认 max_completion_tokens
	MaxTokens           int         `json:"max_tokens,omitempty"`
	MaxCompletionTokens int         `json:"max_completion_tokens,omitempty"`
	ResponseFormat      *respFormat `json:"response_format,omitempty"`
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

// chat 调用一次 chat/completions，并对"推理模型参数差异"做自适应：
//
//	经典模型：max_tokens + temperature
//	推理模型：只认 max_completion_tokens，且通常不接受自定义 temperature
//
// 与其让用户去猜该填哪个字段，不如先按通用参数请求，命中这两类错误时自动重试一次。
func (p *LLMPlanner) chat(ctx context.Context, cfg settings.LLM, sys, user string) (string, int64, error) {
	url := strings.TrimRight(cfg.BaseURL, "/") + "/chat/completions"
	msgs := []chatMessage{
		{Role: "system", Content: sys},
		{Role: "user", Content: user},
	}
	temp := cfg.Temperature
	req := chatReq{
		Model: cfg.Model, Messages: msgs, MaxTokens: cfg.MaxTokens,
		ResponseFormat: &respFormat{Type: "json_object"},
	}
	if temp > 0 {
		req.Temperature = &temp
	}
	out, tok, err := p.post(ctx, cfg, url, req)
	if err == nil {
		return out, tok, nil
	}

	msg := err.Error()
	if !strings.Contains(msg, "max_completion_tokens") && !strings.Contains(msg, "temperature") {
		return out, tok, err
	}
	// 退化为推理模型参数：不带 temperature，改用 max_completion_tokens
	req2 := chatReq{
		Model: cfg.Model, Messages: msgs, MaxCompletionTokens: cfg.MaxTokens,
		ResponseFormat: &respFormat{Type: "json_object"},
	}
	return p.post(ctx, cfg, url, req2)
}

// post 是单次 HTTP 调用（含超时、错误解析）。
func (p *LLMPlanner) post(ctx context.Context, cfg settings.LLM, url string, req chatReq) (string, int64, error) {
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
// 第二个返回值是模型是否声明"目标已达成"。
func parseIntents(raw string) ([]store.Intent, bool) {
	s := strings.TrimSpace(raw)
	if i := strings.Index(s, "{"); i > 0 {
		s = s[i:]
	}
	if j := strings.LastIndex(s, "}"); j >= 0 && j < len(s)-1 {
		s = s[:j+1]
	}
	var payload struct {
		GoalMet bool        `json:"goal_met"`
		Intents []rawIntent `json:"intents"`
	}
	if err := json.Unmarshal([]byte(s), &payload); err != nil {
		return nil, false
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
	return out, payload.GoalMet
}

// TestConnection 用给定配置做一次最小调用，返回模型回复与 token 用量。
// 用于 /api/llm/test，让用户配置完立刻验证"通不通"。
func TestConnection(ctx context.Context, cfg settings.LLM) (string, int64, error) {
	stg := settings.Open("")
	_ = stg.Update(func(s *settings.Settings) { s.LLM = cfg })
	p := New(stg)
	// response_format=json_object 要求 messages 里出现 "json" 字样，否则 OpenAI 直接报错。
	// 测试提示词也必须满足这一点，否则会把"配置正确"误判成"连接失败"。
	return p.chat(ctx, cfg,
		"你是连通性测试助手。只输出一个 JSON 对象，不要任何解释。",
		`只回复这个 JSON：{"ok":true}`)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
