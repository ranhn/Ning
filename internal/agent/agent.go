// Package agent 提供可运行的执行器与规划器实现。
//
// 执行器完整链路（顺序固定，任何一步都不能跳）：
//
//	规则层（用户可配 deny/ask）
//	  → 第 2 层闸门（范围校验）
//	  → 资产记账
//	  → 真实执行（HTTP 经 netguard.HTTPClient，出站再被第 3 层闸门校验）
//	  → 流量录制 + 证据落库
//	  → 知识层 fact
//	  → 漏洞登记（必须带证据）
//
// 注意：规则层是**闸门之上的附加层**，规则全删掉三层闸门依然生效。
package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/argus/argus/internal/attack"
	"github.com/argus/argus/internal/engine"
	"github.com/argus/argus/internal/evidence"
	"github.com/argus/argus/internal/gate"
	"github.com/argus/argus/internal/store"
)

// Runner 执行本地命令（不经 shell，避免命令注入），带超时与输出截断。
type Runner struct {
	Timeout   time.Duration
	MaxOutput int
}

// Command 运行命令并返回合并输出与退出码。
func (r Runner) Command(ctx context.Context, name string, args ...string) (string, int, error) {
	to := r.Timeout
	if to <= 0 {
		to = 10 * time.Second
	}
	max := r.MaxOutput
	if max <= 0 {
		max = 30000
	}
	cctx, cancel := context.WithTimeout(ctx, to)
	defer cancel()
	cmd := exec.CommandContext(cctx, name, args...)
	out, err := cmd.CombinedOutput()
	code := 0
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			code = ee.ExitCode()
		} else {
			code = -1
		}
	}
	s := string(out)
	if len(s) > max {
		s = s[:max] + fmt.Sprintf("\n…[输出已截断，原始 %d 字节]", len(out))
	}
	return strings.TrimRight(s, "\n"), code, err
}

// SimPlanner 按预置脚本逐轮下发意图（无模型时的兜底）。
type SimPlanner struct {
	mu     sync.Mutex
	script [][]store.Intent
	round  int
}

// NewSimPlanner 构造脚本化规划器。
func NewSimPlanner(script [][]store.Intent) *SimPlanner { return &SimPlanner{script: script} }

// Next 实现 engine.Planner。
func (p *SimPlanner) Next(_ context.Context, _ store.Task, _ store.Store) ([]store.Intent, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.round >= len(p.script) {
		return nil, nil
	}
	batch := p.script[p.round]
	p.round++
	return batch, nil
}

// SimExecutor 是执行器实现。HTTP 为 nil 时退化"只跑本地 echo"（演示/自测）。
type SimExecutor struct {
	Gate    *gate.Gate
	Ev      *evidence.Store
	St      store.Store
	Runner  Runner
	HTTP    *http.Client
	MaxBody int
}

func matchRule(r store.Rule, tool, input string) bool {
	if !r.Enabled || r.Pattern == "" {
		return false
	}
	target := input
	if r.MatchTarget == "tool_name" {
		target = tool
	}
	if strings.EqualFold(r.MatchType, "string") {
		return strings.Contains(target, r.Pattern)
	}
	re, err := regexp.Compile(r.Pattern)
	if err != nil {
		return false
	}
	return re.MatchString(target)
}

// Run 实现 engine.Executor。
func (e *SimExecutor) Run(ctx context.Context, t store.Task, it store.Intent) (engine.Result, error) {
	res := engine.Result{Steps: 1}
	input := json.RawMessage(it.Summary)
	if !json.Valid(input) {
		raw, _ := json.Marshal(map[string]string{"command": it.Summary})
		input = raw
	}

	// 规则层 → 第 2 层闸门 → 资产记账：与真实执行器共用同一份前置校验
	res0, pf, blocked := preflight(ctx, e.Gate, e.St, e.Ev, t, it, input)
	if blocked {
		return res0, nil
	}
	res = res0
	firstHost, firstURL := pf.firstHost, pf.firstURL

	// 4) 真实执行：有 URL 且注入了 HTTP 客户端时走真实请求（出站再被第 3 层闸门校验）
	var out string
	var code int
	if e.HTTP != nil && firstURL != "" {
		status, respLen, ctype, body, err := e.fetch(ctx, firstURL)
		traffic := store.Traffic{
			TaskID: t.ID, IntentID: it.ID, Method: http.MethodGet, URL: firstURL,
			Host: firstHost, Status: status, ContentType: ctype,
			ReqBody: it.Summary, RespBody: body, RespLen: respLen,
		}
		if err != nil {
			traffic.Err = err.Error()
		}
		rec, _ := e.St.AddTraffic(traffic)
		e.evidence(t, it, "traffic", map[string]any{
			"traffic_id": rec.ID, "url": firstURL, "status": status, "resp_len": respLen, "err": traffic.Err,
		})
		if err != nil {
			if ctx.Err() != nil {
				res.State = store.IntentOpen
				res.Note = "任务已停止，该动作未完成（续跑会重试）"
			} else {
				res.State = store.IntentBlocked
				res.Note = "请求失败: " + err.Error()
			}
			out = err.Error()
			code = -1
		} else {
			out = fmt.Sprintf("%s %s → %d, %d bytes", http.MethodGet, firstURL, status, respLen)
			code = 0
		}
	} else {
		var runErr error
		out, code, runErr = e.Runner.Command(ctx, "echo", "argus:"+it.Action)
		if runErr != nil {
			return res, runErr
		}
		if code != 0 {
			res.State = store.IntentBlocked
			res.Note = "工具执行失败"
		}
	}

	ev, err := e.Ev.Append(t.ID, it.ID, "command", store.Command{
		Tool: it.Action, Input: it.Summary, Output: out, ExitCode: code,
	})
	if err != nil {
		return res, err
	}

	// 5) 知识层：把结果沉淀成 fact（规划器下一轮会读到）
	if firstHost != "" {
		factKind := "reachable"
		factText := fmt.Sprintf("%s 经 %s 访问成功：%s", firstHost, it.Action, truncate(out, 160))
		if res.State == store.IntentBlocked {
			factKind = "note"
			factText = fmt.Sprintf("%s 访问失败：%s", firstHost, truncate(out, 160))
		}
		_, _ = e.St.AddFact(store.Fact{
			TaskID: t.ID, IntentID: it.ID, Kind: factKind, Text: factText,
		})
	}

	if res.State == "" {
		res.State = store.IntentDone
	}

	// 6) 漏洞登记（必须绑定证据）
	if it.VulnClass != "" && res.State == store.IntentDone {
		tech, _ := attack.Map(it.VulnClass)
		title := it.VulnClass
		if it.Target != "" {
			title += " @ " + it.Target
		}
		sev := it.Severity
		if sev == "" {
			sev = "medium"
		}
		if _, err := e.St.AddFinding(store.Finding{
			TaskID: t.ID, IntentID: it.ID, VulnClass: it.VulnClass, Severity: sev,
			Title: title, Target: it.Target, EvidenceID: ev.ID,
			Technique: tech.ID, Tactic: tech.Tactic,
		}); err != nil {
			return res, err
		}
		res.Findings = 1
	}
	return res, nil
}

func (e *SimExecutor) fetch(ctx context.Context, url string) (int, int, string, string, error) {
	cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(cctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, 0, "", "", err
	}
	resp, err := e.HTTP.Do(req)
	if err != nil {
		return 0, 0, "", "", err
	}
	defer resp.Body.Close()
	max := e.MaxBody
	if max <= 0 {
		max = 4096
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, int64(max)))
	return resp.StatusCode, len(body), resp.Header.Get("Content-Type"), string(body), nil
}

func (e *SimExecutor) evidence(t store.Task, it store.Intent, kind string, payload any) {
	if e.Ev == nil {
		return
	}
	_, _ = e.Ev.Append(t.ID, it.ID, kind, payload)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
