package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"strings"

	"github.com/argus/argus/internal/engine"
	"github.com/argus/argus/internal/evidence"
	"github.com/argus/argus/internal/gate"
	"github.com/argus/argus/internal/scope"
	"github.com/argus/argus/internal/store"
)

// preflightResult 是放行后得到的目标信息，供执行阶段使用。
type preflightResult struct {
	targets   []string
	firstHost string
	firstURL  string
}

// preflight 执行"规则层 → 第 2 层闸门 → 资产记账"这三步。
// 所有执行器（模拟/真实）都必须先过这里，保证两条路径的安全语义完全一致。
//
// 返回 blocked=true 时第一个返回值是应当直接返回的结果（已被拦下）。
func preflight(
	ctx context.Context,
	g *gate.Gate,
	st store.Store,
	ev *evidence.Store,
	t store.Task,
	it store.Intent,
	input json.RawMessage,
) (engine.Result, preflightResult, bool) {
	res := engine.Result{Steps: 1}

	// 1) 规则层（用户可配）：deny 直接拦；ask 入审批队列后拦下（等人工裁决）
	for _, r := range st.Rules() {
		if !matchRule(r, it.Action, it.Summary) {
			continue
		}
		switch strings.ToLower(r.Action) {
		case "deny":
			appendEvidence(ev, t, it, "rule_blocked", map[string]any{
				"rule": r.Name, "pattern": r.Pattern, "action": "deny",
			})
			res.State = store.IntentBlocked
			res.Note = "被拦截规则拦下：" + r.Name + "（" + r.Message + "）"
			return res, preflightResult{}, true
		case "ask":
			ap := st.AddApproval(store.Approval{
				TaskID: t.ID, IntentID: it.ID, RuleID: r.ID,
				Tool: it.Action, Input: it.Summary,
			})
			appendEvidence(ev, t, it, "rule_ask", map[string]any{"rule": r.Name, "approval_id": ap.ID})
			res.State = store.IntentBlocked
			res.Note = fmt.Sprintf("等待人工审批 #%d（规则：%s）", ap.ID, r.Name)
			return res, preflightResult{}, true
		}
	}

	// 2) 第 2 层闸门（执行期范围校验）
	//
	// Discover 是"扩面"动作：它要枚举的大多数子域本来就不存在，
	// 因此不能走「解析失败即拒绝」。改为只校验根域是否在授权范围内；
	// 它真正连的每一个 IP 仍会在 discover 内部逐个 CheckDial。
	if strings.EqualFold(it.Action, "Discover") {
		root := discoverDomain(g, input)
		if root == "" {
			appendEvidence(ev, t, it, "scope_blocked", map[string]any{
				"layer": string(gate.LayerExec), "reason": "Discover 缺少根域", "input": it.Summary,
			})
			res.State = store.IntentBlocked
			res.Note = "Discover 缺少根域（输入里没有 domain，范围里也没有域名规则）"
			return res, preflightResult{}, true
		}
		if sc := g.Scope(); sc == nil || !sc.AllowsHost(root) {
			appendEvidence(ev, t, it, "scope_blocked", map[string]any{
				"layer": string(gate.LayerExec), "target": root, "reason": "根域不在授权范围",
			})
			res.State = store.IntentBlocked
			res.Note = "根域不在授权范围：" + root
			return res, preflightResult{}, true
		}
	} else {
		dec := g.CheckTool(ctx, t.ID, it.ID, it.Action, input)
		if !dec.Allowed {
			appendEvidence(ev, t, it, "scope_blocked", map[string]any{
				"layer": string(dec.Layer), "target": dec.Target, "reason": dec.Reason,
				"tool": it.Action, "input": it.Summary,
			})
			res.State = store.IntentBlocked
			res.Note = dec.Reason
			return res, preflightResult{}, true
		}
	}

	// 3) 资产记账（只有放行过的目标才会入图）
	pf := preflightResult{targets: scope.Targets(it.Action, input)}
	for _, tgt := range pf.targets {
		host, raw := scope.SplitTarget(tgt)
		if host == "" {
			continue
		}
		if pf.firstHost == "" {
			pf.firstHost, pf.firstURL = host, raw
		}
		if ip, err := netip.ParseAddr(host); err == nil {
			st.UpsertAsset(t.ID, "ip", ip.Unmap().String())
			continue
		}
		st.UpsertAsset(t.ID, "subdomain", host)
	}
	return res, pf, false
}

// assertDialable 对"要交给外部二进制"的目标做第 3 层**预校验**：
// 二进制自己建 socket，我们无法在 Dial 时拦截，所以必须在启动前把解析出的每个 IP 都过一遍
// gate.CheckDial。这样"闸门放行的域名"与"实际会连的 IP"仍然是同一份解析结果。
//
// 返回的 pins（host → 已批准的 IP）在容器模式下会变成 --add-host，
// 让容器内的 DNS 答案与闸门判定完全一致。
func assertDialable(ctx context.Context, g *gate.Gate, targets []string) (map[string][]netip.Addr, error) {
	pins := map[string][]netip.Addr{}
	for _, tgt := range targets {
		host, _ := scope.SplitTarget(tgt)
		if host == "" {
			continue
		}
		if ip, err := netip.ParseAddr(host); err == nil {
			if err := g.CheckDial(ip.Unmap()); err != nil {
				return nil, err
			}
			continue
		}
		ips, err := g.Lookup(ctx, host)
		if err != nil {
			return nil, fmt.Errorf("解析 %s 失败: %w", host, err)
		}
		if len(ips) == 0 {
			return nil, fmt.Errorf("%s 未解析到任何地址", host)
		}
		// 顺序很重要：先做**授权判定**（域名在范围内 → 这批 IP 放行），再逐个校验。
		// 反过来写就会出现"CDN 换了批 IP → 校验失败 → 直接返回"，永远来不及放行。
		if err := g.AdmitHost(host, ips); err != nil {
			return nil, err
		}
		ok := make([]netip.Addr, 0, len(ips))
		for _, ip := range ips {
			if err := g.CheckDial(ip.Unmap()); err != nil {
				return nil, fmt.Errorf("%s 解析到 %s：%w", host, ip, err)
			}
			ok = append(ok, ip.Unmap())
		}
		pins[host] = ok
	}
	return pins, nil
}

// discoverDomain 取枚举根域：优先用输入里的 domain，其次用范围里的第一条域名规则。
func discoverDomain(g *gate.Gate, input json.RawMessage) string {
	var in struct {
		Domain string `json:"domain"`
	}
	_ = json.Unmarshal(input, &in)
	root := strings.TrimPrefix(strings.TrimPrefix(strings.TrimSpace(in.Domain), "*."), ".")
	if root != "" {
		return root
	}
	if g != nil && g.Scope() != nil {
		for _, r := range g.Scope().Rules() {
			switch r.Kind {
			case scope.KindDomainSuffix, scope.KindExactDomain:
				return strings.TrimPrefix(strings.TrimPrefix(r.Value, "*."), ".")
			}
		}
	}
	return ""
}

// appendEvidence 是证据直写的薄封装（ev 为空时安全跳过）。
func appendEvidence(ev *evidence.Store, t store.Task, it store.Intent, kind string, payload any) {
	if ev == nil {
		return
	}
	_, _ = ev.Append(t.ID, it.ID, kind, payload)
}
