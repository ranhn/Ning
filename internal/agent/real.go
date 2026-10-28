package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"github.com/argus/argus/internal/attack"
	"github.com/argus/argus/internal/dedupe"
	"github.com/argus/argus/internal/discover"
	"github.com/argus/argus/internal/engine"
	"github.com/argus/argus/internal/evidence"
	"github.com/argus/argus/internal/gate"
	"github.com/argus/argus/internal/scope"
	"github.com/argus/argus/internal/store"
	"github.com/argus/argus/internal/toolbox"
)

// RealExecutor 用**真实工具**执行意图（nmap / nuclei / curl / httpx ...）。
//
// 与 SimExecutor 的关系：前置校验完全共用（preflight），差别只在"执行"那一步。
// 也就是说：换成真实执行器不会削弱任何一道闸门，也不会改变证据格式。
//
// 关键安全设计：外部二进制自己建 socket，我们无法挂 Dial.Control，
// 所以在**启动前**对目标做第 3 层预校验（assertDialable）：
// 把目标解析出的每个 IP 都过一遍 gate.CheckDial，任一越界即拒绝启动。
type RealExecutor struct {
	Gate    *gate.Gate
	Ev      *evidence.Store
	St      store.Store
	Tools   *toolbox.Executor
	HTTP    *http.Client
	MaxBody int
}

// commandOf 从意图输入里取出要执行的命令行。
func commandOf(input json.RawMessage) string {
	var m map[string]any
	if err := json.Unmarshal(input, &m); err != nil {
		return strings.TrimSpace(string(input))
	}
	for _, k := range []string{"command", "cmd", "cmdline"} {
		if v, ok := m[k]; ok {
			if s, ok := v.(string); ok && strings.TrimSpace(s) != "" {
				return strings.TrimSpace(s)
			}
		}
	}
	// WebFetch 之类的输入只有 url：交给 HTTP 分支处理
	return ""
}

// Run 实现 engine.Executor。
func (e *RealExecutor) Run(ctx context.Context, t store.Task, it store.Intent) (engine.Result, error) {
	input := json.RawMessage(it.Summary)
	if !json.Valid(input) {
		raw, _ := json.Marshal(map[string]string{"command": it.Summary})
		input = raw
	}

	res, pf, blocked := preflight(ctx, e.Gate, e.St, e.Ev, t, it, input)
	if blocked {
		return res, nil
	}

	// 内建动作：子域枚举（不走外部工具，由 discover 包直接完成并派生后续意图）
	if strings.EqualFold(it.Action, "Discover") {
		return e.runDiscover(ctx, t, it, input, res), nil
	}

	cmdline := commandOf(input)
	var out string
	var code int

	switch {
	case cmdline == "" && pf.firstURL != "" && e.HTTP != nil:
		// WebFetch：走受控 HTTP 客户端，能录制流量（出站同样被第 3 层校验）
		status, respLen, ctype, body, err := e.fetch(ctx, pf.firstURL)
		rec, _ := e.St.AddTraffic(store.Traffic{
			TaskID: t.ID, IntentID: it.ID, Method: http.MethodGet, URL: pf.firstURL,
			Host: pf.firstHost, Status: status, ContentType: ctype,
			ReqBody: it.Summary, RespBody: body, RespLen: respLen,
		})
		appendEvidence(e.Ev, t, it, "traffic", map[string]any{
			"traffic_id": rec.ID, "url": pf.firstURL, "status": status, "resp_len": respLen,
		})
		if err != nil {
			res.State = store.IntentBlocked
			res.Note = "请求失败: " + err.Error()
			out, code = err.Error(), -1
		} else {
			out = fmt.Sprintf("%s %s → %d, %d bytes", http.MethodGet, pf.firstURL, status, respLen)
		}

	case cmdline != "":
		plan, perr := e.Tools.Plan(cmdline)
		if perr != nil {
			// 沙箱拒绝：不是"执行失败"，而是"这条命令不允许存在"
			appendEvidence(e.Ev, t, it, "sandbox_denied", map[string]any{
				"reason": perr.Error(), "command": cmdline, "tool": it.Action,
			})
			res.State = store.IntentBlocked
			res.Note = "沙箱拒绝执行：" + perr.Error()
			return res, nil
		}

		// 第 3 层预校验：目标解析出的每个 IP 都必须可拨
		pins, derr := assertDialable(ctx, e.Gate, pf.targets)
		if derr != nil {
			appendEvidence(e.Ev, t, it, "scope_blocked", map[string]any{
				"layer": string(gate.LayerNetwork), "reason": derr.Error(),
				"tool": plan.Tool, "command": cmdline,
			})
			res.State = store.IntentBlocked
			res.Note = "网络层预校验未通过：" + derr.Error()
			return res, nil
		}

		// 每任务独立工作目录；容器模式下这个目录是容器内唯一的可写挂载
		workdir := filepath.Join(e.Tools.WorkDir, fmt.Sprintf("task-%d", t.ID))
		rr, runErr := e.Tools.RunIn(ctx, plan, workdir, toolbox.ContainerName(it.ID, ""), pins)
		out, code = rr.Output, rr.Exit
		appendEvidence(e.Ev, t, it, "command", store.Command{
			Tool: plan.Tool, Input: rr.Cmdline, Output: rr.Output, ExitCode: rr.Exit,
		})
		switch {
		case runErr != nil:
			// 任务被"停止"打断时，命令是被 kill 的，这不是失败而是中断：
			// 退回 open，续跑时会重试，否则这条动作就永久丢失了。
			if ctx.Err() != nil {
				res.State = store.IntentOpen
				res.Note = "任务已停止，该动作未完成（续跑会重试）"
				break
			}
			res.State = store.IntentBlocked
			res.Note = runErr.Error()
		case rr.Exit != 0:
			res.State = store.IntentBlocked
			res.Note = fmt.Sprintf("%s 退出码 %d", plan.Tool, rr.Exit)
		default:
			res.State = store.IntentDone
		}

	default:
		// 既没有命令也没有 URL：不假装执行成功
		appendEvidence(e.Ev, t, it, "noop", map[string]any{"input": it.Summary, "action": it.Action})
		res.State = store.IntentExhausted
		res.Note = "意图里没有可执行的命令或 URL"
		return res, nil
	}

	ev, err := e.Ev.Append(t.ID, it.ID, "result", map[string]any{
		"exit": code, "output": truncate(out, 2000),
	})
	if err != nil {
		return res, err
	}

	// 知识层
	if pf.firstHost != "" {
		kind := "reachable"
		text := fmt.Sprintf("%s 经 %s 访问成功：%s", pf.firstHost, it.Action, truncate(out, 160))
		if res.State != store.IntentDone {
			kind = "note"
			text = fmt.Sprintf("%s 访问异常：%s", pf.firstHost, truncate(out, 160))
		}
		_, _ = e.St.AddFact(store.Fact{TaskID: t.ID, IntentID: it.ID, Kind: kind, Text: text})
	}

	// 漏洞登记（必须绑定证据）
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

// runDiscover 执行子域枚举，并把发现的资产翻译成后续意图：
//
//	解析成功的主机 → 端口扫描（nmap）
//	HTTP 可达的主机 → 路径探测（robots.txt）
//
// 这样上层只需要给出一个根域，"扩面 → 确认可用 → 端口/路径"就串起来了。
func (e *RealExecutor) runDiscover(ctx context.Context, t store.Task, it store.Intent, input json.RawMessage, res engine.Result) engine.Result {
	var in struct {
		Domain string   `json:"domain"`
		Words  []string `json:"words"`
	}
	_ = json.Unmarshal(input, &in)

	domain := strings.TrimSpace(in.Domain)
	if domain == "" && e.Gate != nil && e.Gate.Scope() != nil {
		for _, r := range e.Gate.Scope().Rules() {
			if r.Kind == scope.KindDomainSuffix || r.Kind == scope.KindExactDomain {
				domain = strings.TrimPrefix(strings.TrimPrefix(r.Value, "*."), ".")
				break
			}
		}
	}
	if domain == "" {
		res.State = store.IntentBlocked
		res.Note = "Discover 需要 domain（范围里没有可用的域名规则）"
		return res
	}

	opts := discover.Options{
		TaskID: t.ID, IntentID: it.ID, Domain: domain, Words: in.Words,
		Gate: e.Gate, HTTP: e.HTTP, St: e.St, Ev: e.Ev,
	}

	// 主路径：subfinder 多源枚举 → httpx 批量探活 → 派生 katana / nuclei。
	// 这是"一个根域 → 一批可打 URL"的正确顺序：
	// 先扩大攻击面，再用模板验证，而不是在根域上直接反复 curl。
	// 工具不可用时自动回退到下面内置字典的旧路径。
	if e.Tools != nil {
		if pr, perr := discover.RunPipeline(ctx, opts, e.Tools); perr == nil && len(pr.Alive) > 0 {
			derived := 0
			for _, h := range pr.Alive {
				// 抽端点：从页面与 JS 里找出真实接口路径
				e.derive(t, it, "katana -u "+h.URL+" -d 2 -silent", "katana:"+h.URL)
				// 模板验证：已知 CVE / 配置缺陷 / 暴露面板
				e.derive(t, it, "nuclei -u "+h.URL+" -severity critical,high,medium -silent", "nuclei:"+h.URL)
				derived += 2
			}
			res.State = store.IntentDone
			res.Note = fmt.Sprintf("subfinder 枚举 %d 个子域，httpx 探活 %d 个站点，派生 %d 条意图（katana 抽端点 + nuclei 验证）",
				len(pr.Subs), len(pr.Alive), derived)
			return res
		}
	}

	dr, err := discover.Run(ctx, opts)
	if err != nil {
		// 被"停止"打断不是失败：退回 open，续跑时重做这次枚举
		if ctx.Err() != nil {
			res.State = store.IntentOpen
			res.Note = "任务已停止，子域枚举未完成（续跑会重试）"
			return res
		}
		res.State = store.IntentBlocked
		res.Note = "子域枚举失败: " + err.Error()
		return res
	}

	derived := 0
	for _, h := range dr.Hosts {
		if h.Skipped || len(h.IPs) == 0 {
			continue
		}
		// 端口：对解析成功的主机都扫（活着不代表端口开放）
		e.derive(t, it, "nmap -sV -Pn -p 22,80,443,3306,6379,8080,8443,9200 "+h.FQDN, "nmap:"+h.FQDN)
		derived++
		if h.Live {
			scheme := h.Scheme
			if scheme == "" {
				scheme = "http"
			}
			e.derive(t, it, "curl -sS --max-time 8 "+scheme+"://"+h.FQDN+"/robots.txt", "robots:"+h.FQDN)
			derived++
		}
	}

	res.State = store.IntentDone
	res.Note = fmt.Sprintf("枚举 %d 个候选，解析成功 %d，HTTP 可用 %d，派生 %d 条意图",
		dr.Tried, dr.Resolved, dr.Live, derived)
	if res.Findings == 0 {
		res.Findings = 0
	}
	return res
}

// derive 写入一条派生意图（带指纹，交给引擎做去重）。
func (e *RealExecutor) derive(t store.Task, parent store.Intent, cmd, key string) {
	summary, _ := json.Marshal(map[string]string{"command": cmd})
	fp := dedupe.Fingerprint(0, "Bash", key)
	for _, existing := range e.St.Intents(t.ID) {
		if existing.FP == fp {
			return
		}
	}
	_, _ = e.St.AddIntent(store.Intent{
		TaskID: t.ID, Action: "Bash", Summary: string(summary), ParamKey: key, FP: fp,
	})
}

func (e *RealExecutor) fetch(ctx context.Context, url string) (int, int, string, string, error) {
	cctx, cancel := context.WithTimeout(ctx, 20*time.Second)
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
		max = 8192
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, int64(max)))
	return resp.StatusCode, len(body), resp.Header.Get("Content-Type"), string(body), nil
}
