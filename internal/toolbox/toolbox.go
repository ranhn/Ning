// Package toolbox 是真实工具执行的**唯一入口**。
//
// 设计约束（每一条都是为了"模型说啥都不能直接变成 shell"）：
//  1. 永远不经过 shell：cmdline 先被我们自己的分词器切成 argv，再 exec.CommandContext(bin, args...)。
//     因此 ; | & $ ` > < \n 这些字符一律视为非法，直接拒绝（不是转义，是拒绝）。
//  2. 只允许白名单里的二进制：nmap / nuclei / curl / httpx / dig / whois / nikto / sqlmap / ffuf / whatweb。
//  3. 每个工具都有**禁用参数**清单（写文件、读配置、调 NSE 脚本、反弹 shell 之类）。
//  4. 参数里不允许出现绝对路径与 `..`，避免读宿主机文件或逃逸工作目录。
//  5. 环境变量白名单：只留 PATH/HOME/TMPDIR/LANG，显式清掉所有 *_proxy，
//     防止子进程用环境变量里的代理绕过第 3 层闸门。
//  6. 超时 + 输出截断 + 独立工作目录。
//
// 这一层不做"目标是否合规"的判断——那是 gate 的职责，在调用本包之前已经判完；
// 本包只保证"就算给了越权命令，也不可能变成任意代码执行"。
package toolbox

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// Policy 是单个工具的执行策略。
type Policy struct {
	Bin      string   // 实际二进制名（可被测试注入为绝对路径）
	BadFlags []string // 出现即拒绝的参数前缀
	Timeout  time.Duration
	MaxArgs  int
	// AllowAbs 是**允许出现的绝对路径前缀**（只读资源，例如 nuclei 的离线模板目录）。
	// 绝对路径默认一律拒绝，只有这里列出的目录可以出现，且仅限作为参数值。
	AllowAbs []string
	// VersionArgs + Fingerprint 用于识别"同名不同工具"：
	// 例如 Python 的 httpx 库也叫 httpx，但完全没有 -u/-l 这些参数，
	// 直接调用会得到莫名其妙的结果。版本输出里必须出现任一关键字，否则该工具被禁用。
	VersionArgs []string
	Fingerprint []string
	// Strict 为 true 时，版本输出为空也视为指纹不匹配（禁用该工具）。
	// 用于同名冲突风险极高的名字（例如 httpx：Python 库与 ProjectDiscovery 扫描器同名）。
	Strict bool
}

// DefaultPolicies 返回内置白名单。刻意保守：写文件/读配置/调脚本的参数全部禁掉。
func DefaultPolicies() map[string]Policy {
	return map[string]Policy{
		"nmap": {
			Bin:     "nmap",
			Timeout: 5 * time.Minute,
			MaxArgs: 40,
			// -iL 读文件、-o* 写文件、--script 任意 NSE（可反弹 shell）
			BadFlags:    []string{"-il", "-on", "-ox", "-og", "-os", "-oa", "--script", "--datadir", "--servicedb", "--versiondb"},
			VersionArgs: []string{"--version"},
			Fingerprint: []string{"nmap"},
		},
		"nuclei": {
			Bin:      "nuclei",
			Timeout:  5 * time.Minute,
			MaxArgs:  40,
			BadFlags: []string{"-o", "-store-resp", "-config", "-sr", "-workflow", "-w"},
			// 离线模板目录（镜像内预置，只读）
			AllowAbs:    []string{"/opt/pd-templates", "/root/nuclei-templates"},
			VersionArgs: []string{"-version"},
			Fingerprint: []string{"projectdiscovery", "nuclei"},
		},
		"curl": {
			Bin:         "curl",
			Timeout:     60 * time.Second,
			MaxArgs:     30,
			BadFlags:    []string{"-o", "--output", "-O", "-K", "--config", "-T", "--upload-file", "-D", "--dump-header", "--trace", "--trace-ascii"},
			VersionArgs: []string{"-V"},
			Fingerprint: []string{"curl"},
		},
		"httpx": {
			Bin:         "httpx",
			Timeout:     2 * time.Minute,
			MaxArgs:     30,
			BadFlags:    []string{"-o", "-json", "-config"},
			AllowAbs:    []string{"/opt/pd-templates"},
			VersionArgs: []string{"-version"},
			// Python 的 httpx 库也是这个名字，但它不认 -u/-l，必须靠指纹排除；
			// 严格模式：它的 -version 输出为空，所以空输出也判为不匹配。
			Fingerprint: []string{"projectdiscovery"},
			Strict:      true,
		},
		"dig": {
			Bin:         "dig",
			Timeout:     30 * time.Second,
			MaxArgs:     20,
			BadFlags:    []string{"-f"},
			VersionArgs: []string{"-v"},
			Fingerprint: []string{"dig"},
		},
		"whois": {
			Bin:         "whois",
			Timeout:     30 * time.Second,
			MaxArgs:     5,
			VersionArgs: []string{"--version"},
			Fingerprint: []string{"whois"},
		},
		"nikto": {
			Bin:         "nikto",
			Timeout:     4 * time.Minute,
			MaxArgs:     30,
			BadFlags:    []string{"-o", "-output", "-update", "-configfile"},
			VersionArgs: []string{"-Version"},
			Fingerprint: []string{"nikto"},
		},
		"sqlmap": {
			Bin:      "sqlmap",
			Timeout:  8 * time.Minute,
			MaxArgs:  40,
			// 直接读写文件/拿 os-shell 的参数一律禁止：ARGUS 只做"验证存在"，不做"接管"
			BadFlags:    []string{"--file-write", "--file-read", "--file-dest", "--os-shell", "--os-pwn", "--os-smbrelay", "--os-bof", "--sql-shell", "--output-dir", "-o", "--config", "--batch-file"},
			VersionArgs: []string{"--version"},
			Fingerprint: []string{"sqlmap"},
		},
		"ffuf": {
			Bin:         "ffuf",
			Timeout:     3 * time.Minute,
			MaxArgs:     30,
			BadFlags:    []string{"-o", "-config", "-request", "-input-cmd"},
			VersionArgs: []string{"-V"},
			Fingerprint: []string{"ffuf"},
		},
		// 子域枚举：只读 DNS 查询，输出给后续意图消费。
		// -all 会把最慢的源全打开（单次可能跑几十分钟），禁掉。
		"subfinder": {
			Bin:         "subfinder",
			Timeout:     3 * time.Minute,
			MaxArgs:     25,
			BadFlags:    []string{"-o", "-oI", "-dL", "-config", "-all", "-resume"},
			VersionArgs: []string{"-version"},
			Fingerprint: []string{"subfinder"},
		},
		// 爬虫：从页面与 JS 里抽端点，是"发现攻击面"的关键一环。
		"katana": {
			Bin:      "katana",
			Timeout:  5 * time.Minute,
			MaxArgs:  30,
			BadFlags: []string{"-o", "-jsonl", "-config", "-resume"},
			// katana 的 -version 只往 stderr 打 banner（没有版本号），
			// 所以用项目域名做指纹：同系列工具都带这一行。
			VersionArgs: []string{"-version"},
			Fingerprint: []string{"projectdiscovery"},
		},
		// XSS 验证：反射/存储型探测，命中即产出证据。
		"dalfox": {
			Bin:         "dalfox",
			Timeout:     3 * time.Minute,
			MaxArgs:     30,
			BadFlags:    []string{"-o", "--output", "--config", "--custom-payload", "--remote-payloads"},
			VersionArgs: []string{"--version"},
			Fingerprint: []string{"dalfox"},
		},
		"whatweb": {
			Bin:         "whatweb",
			Timeout:     2 * time.Minute,
			MaxArgs:     25,
			BadFlags:    []string{"--log-brief", "--log-verbose", "--log-errors", "--log-xml", "--log-json", "--log-magictree", "--log-object"},
			VersionArgs: []string{"--version"},
			Fingerprint: []string{"whatweb"},
		},
	}
}

// ErrNotAllowed 表示命令被沙箱拒绝（不是执行失败）。
type ErrNotAllowed struct{ Reason string }

func (e *ErrNotAllowed) Error() string { return e.Reason }

// Plan 是一条通过校验、可以直接执行的命令。
type Plan struct {
	Tool    string
	Bin     string
	Args    []string
	Timeout time.Duration
}

// Cmdline 还原成可审计的字符串（写证据用）。
func (p *Plan) Cmdline() string {
	parts := append([]string{p.Bin}, p.Args...)
	for i, s := range parts {
		if strings.ContainsAny(s, " \t\"'") {
			parts[i] = "'" + s + "'"
		}
	}
	return strings.Join(parts, " ")
}

// forbiddenChars 是"能改变控制流"的字符集合。出现即拒绝，不做转义。
const forbiddenChars = "\n\r;|&$`><\\"

// tokenize 把一行命令切成 argv：支持单双引号，但拒绝任何控制字符。
func tokenize(cmdline string) ([]string, error) {
	var out []string
	var cur strings.Builder
	var quote rune
	started := false

	for _, r := range cmdline {
		if strings.ContainsRune(forbiddenChars, r) {
			return nil, &ErrNotAllowed{Reason: fmt.Sprintf("命令包含被禁止的控制字符 %q（不经过 shell，禁止改变控制流）", string(r))}
		}
		switch {
		case quote != 0:
			if r == quote {
				quote = 0
				continue
			}
			cur.WriteRune(r)
		case r == '\'' || r == '"':
			quote = r
			started = true
		case r == ' ' || r == '\t':
			if started {
				out = append(out, cur.String())
				cur.Reset()
				started = false
			}
		default:
			cur.WriteRune(r)
			started = true
		}
	}
	if quote != 0 {
		return nil, &ErrNotAllowed{Reason: "命令里的引号没有闭合"}
	}
	if started {
		out = append(out, cur.String())
	}
	if len(out) == 0 {
		return nil, &ErrNotAllowed{Reason: "命令为空"}
	}
	return out, nil
}

// Plan 校验并构造执行计划。
func (e *Executor) Plan(cmdline string) (*Plan, error) {
	argv, err := tokenize(strings.TrimSpace(cmdline))
	if err != nil {
		return nil, err
	}
	tool := strings.ToLower(filepath.Base(argv[0]))
	pol, ok := e.policies[tool]
	if !ok {
		return nil, &ErrNotAllowed{Reason: fmt.Sprintf("工具 %q 不在白名单内（可用：%s）", argv[0], e.allowedNames())}
	}
	if reason, bad := e.disabledReason(tool); bad {
		return nil, &ErrNotAllowed{Reason: fmt.Sprintf("工具 %q 不可用：%s", tool, reason)}
	}
	if pol.MaxArgs > 0 && len(argv)-1 > pol.MaxArgs {
		return nil, &ErrNotAllowed{Reason: fmt.Sprintf("参数过多（%d > %d）", len(argv)-1, pol.MaxArgs)}
	}
	for _, a := range argv[1:] {
		low := strings.ToLower(a)
		for _, bad := range pol.BadFlags {
			if low == bad || strings.HasPrefix(low, bad+"=") {
				return nil, &ErrNotAllowed{Reason: fmt.Sprintf("参数 %q 被禁止（%s 策略）", a, tool)}
			}
		}
		// 绝对路径与上跳：防止读宿主机文件或逃出工作目录；
		// 只读资源目录（如 nuclei 离线模板）在 AllowAbs 里显式放行。
		if strings.Contains(a, "..") {
			return nil, &ErrNotAllowed{Reason: fmt.Sprintf("参数 %q 含上跳，禁止", a)}
		}
		if strings.HasPrefix(a, "/") || strings.HasPrefix(a, "\\") || (len(a) > 1 && a[1] == ':') {
			permitted := false
			for _, prefix := range pol.AllowAbs {
				if strings.HasPrefix(a, prefix) {
					permitted = true
					break
				}
			}
			if !permitted {
				return nil, &ErrNotAllowed{Reason: fmt.Sprintf("参数 %q 含绝对路径或上跳，禁止", a)}
			}
		}
	}

	bin := pol.Bin
	if bin == "" {
		bin = tool
	}
	// 允许测试注入绝对路径的 Bin
	if !filepath.IsAbs(bin) {
		if _, err := exec.LookPath(bin); err != nil {
			return nil, &ErrNotAllowed{Reason: fmt.Sprintf("工具未安装：%s（请先安装或改用其他工具）", bin)}
		}
	}
	to := pol.Timeout
	if to <= 0 {
		to = 2 * time.Minute
	}
	return &Plan{Tool: tool, Bin: bin, Args: argv[1:], Timeout: to}, nil
}

func (e *Executor) allowedNames() string {
	names := make([]string, 0, len(e.policies))
	for k := range e.policies {
		names = append(names, k)
	}
	return strings.Join(names, ", ")
}

// ToolStatus 是工具自检结果。
type ToolStatus struct {
	Name   string `json:"name"`
	State  string `json:"state"` // ok | missing | mismatch
	Bin    string `json:"bin,omitempty"`
	Detail string `json:"detail,omitempty"`
}

// Executor 持有策略、工作目录与资源上限。
type Executor struct {
	policies  map[string]Policy
	WorkDir   string
	MaxOutput int
	Env       []string
	// Container 非 nil 时，所有命令都在"每意图一次性容器"里执行（真隔离）。
	Container *ContainerConfig

	// disabled 记录 VerifyTools 判定为不可用的工具（name → 原因）。
	// Plan 会拒绝这些工具，避免"同名不同工具"被误用。
	// 探测在后台异步进行，因此读写都要加锁。
	mu       sync.RWMutex
	disabled map[string]string
}

// setDisabled 线程安全地记录/清除某个工具的禁用原因（reason 为空表示可用）。
func (e *Executor) setDisabled(name, reason string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if reason == "" {
		delete(e.disabled, name)
		return
	}
	e.disabled[name] = reason
}

// disabledReason 返回工具被禁用的原因。
func (e *Executor) disabledReason(name string) (string, bool) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	r, ok := e.disabled[name]
	return r, ok
}

// New 构造执行器。WorkDir 为空表示用系统临时目录下固定子目录。
func New(policies map[string]Policy) *Executor {
	if policies == nil {
		policies = DefaultPolicies()
	}
	return &Executor{policies: policies, MaxOutput: 64 << 10, disabled: map[string]string{}}
}

// VerifyTools 检测白名单工具是否真的可用：存在 + 版本指纹匹配。
//
// 为什么要指纹：`httpx` 在 Python 生态里是 HTTP 客户端库，和 ProjectDiscovery 的扫描器同名，
// 参数完全不同。只看"命令存在"会把它们搞混，跑出莫名其妙的结果。
func (e *Executor) VerifyTools(ctx context.Context) []ToolStatus {
	names := make([]string, 0, len(e.policies))
	for k := range e.policies {
		names = append(names, k)
	}
	sort.Strings(names)

	out := make([]ToolStatus, 0, len(names))
	for _, name := range names {
		pol := e.policies[name]
		bin := pol.Bin
		if bin == "" {
			bin = name
		}
		st := ToolStatus{Name: name}
		path, err := exec.LookPath(bin)
		if err != nil {
			st.State = "missing"
			st.Detail = "未安装（" + bin + "）"
			e.setDisabled(name, st.Detail)
			out = append(out, st)
			continue
		}
		st.Bin = path
		if len(pol.Fingerprint) > 0 && len(pol.VersionArgs) > 0 {
			outv, verr := runVersion(ctx, path, pol.VersionArgs)
			low := strings.ToLower(outv)
			matched := false
			for _, fp := range pol.Fingerprint {
				if strings.Contains(low, strings.ToLower(fp)) {
					matched = true
					break
				}
			}
			switch {
			case matched:
				// 正常
			case verr != nil && strings.TrimSpace(outv) == "" && !pol.Strict:
				// 探测阶段跑不起来（EDR 拦截 / 依赖缺失等）不代表工具身份有问题，
				// 不能据此禁用；真正执行时若失败会有明确错误，比"指纹不匹配"更好排查。
				// 严格模式（Strict）不适用此豁免——那类工具必须自证身份。
				st.Detail = "版本探测未返回内容，跳过指纹校验"
			default:
				st.State = "mismatch"
				st.Detail = fmt.Sprintf("版本指纹不匹配（%s 输出里没有 %s）：%s",
					strings.Join(pol.VersionArgs, " "), strings.Join(pol.Fingerprint, "/"), firstLine(outv))
				e.setDisabled(name, st.Detail)
				out = append(out, st)
				continue
			}
		}
		st.State = "ok"
		e.setDisabled(name, "")
		out = append(out, st)
	}
	return out
}

// runVersion 跑一次 `-version` 类参数，8s 超时，输出截断。
func runVersion(ctx context.Context, bin string, args []string) (string, error) {
	cctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	out, err := exec.CommandContext(cctx, bin, args...).CombinedOutput()
	s := string(out)
	if len(s) > 600 {
		s = s[:600]
	}
	return s, err
}

// firstLine 取首行摘要，用于诊断日志。
func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexAny(s, "\r\n"); i >= 0 {
		s = s[:i]
	}
	if len(s) > 120 {
		s = s[:120] + "…"
	}
	return s
}

// SetPolicy 覆盖某个工具的策略（换自定义二进制等场景）。
//
// 安全语义：**禁用参数清单不可被静默清空**。如果新策略没写 BadFlags，就继承原策略的，
// 否则"为了换 binary 路径"的一次覆盖会顺手打开 --script / -o 这些后门。
func (e *Executor) SetPolicy(name string, p Policy) {
	key := strings.ToLower(name)
	if old, ok := e.policies[key]; ok {
		if len(p.BadFlags) == 0 {
			p.BadFlags = old.BadFlags
		}
		if p.Timeout <= 0 {
			p.Timeout = old.Timeout
		}
		if p.MaxArgs <= 0 {
			p.MaxArgs = old.MaxArgs
		}
	}
	e.policies[key] = p
}

// PolicyOf 查询策略（不存在返回 false）。
func (e *Executor) PolicyOf(name string) (Policy, bool) {
	p, ok := e.policies[strings.ToLower(name)]
	return p, ok
}

// Result 是一次真实执行的结果。
type Result struct {
	Cmdline  string
	Output   string
	Exit     int
	Dur      time.Duration
	TimedOut bool
}

// Run 在本机沙箱执行（同机，非容器）。
func (e *Executor) Run(ctx context.Context, p *Plan) (Result, error) {
	return e.RunIn(ctx, p, "", "", nil)
}

// RunIn 执行计划：无 shell、受限环境、超时、输出截断。
// workdir 为空时用 Executor.WorkDir；pins 只在容器模式下用于 --add-host。
func (e *Executor) RunIn(ctx context.Context, p *Plan, workdir, name string, pins map[string][]netip.Addr) (Result, error) {
	dir := workdir
	if dir == "" {
		dir = e.WorkDir
	}
	if dir == "" {
		dir = filepath.Join(os.TempDir(), "argus-work")
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return Result{}, fmt.Errorf("创建工作目录失败: %w", err)
	}

	cctx, cancel := context.WithTimeout(ctx, p.Timeout)
	defer cancel()

	var cmd *exec.Cmd
	if e.Container != nil {
		cfg := *e.Container
		if name == "" {
			name = ContainerName(0, "")
		}
		argv := cfg.BuildArgv(p, dir, name, pins)
		cmd = exec.CommandContext(cctx, cfg.Runtime, argv...)
		// 运行时进程需要宿主的 DOCKER_HOST 等变量；容器内的环境不继承这里
		cmd.Env = os.Environ()
	} else {
		cmd = exec.CommandContext(cctx, p.Bin, p.Args...)
		cmd.Dir = dir
		cmd.Env = e.env(dir)
	}

	start := time.Now()
	out, err := cmd.CombinedOutput()
	dur := time.Since(start)

	code := 0
	timedOut := false
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			code = ee.ExitCode()
		} else if cctx.Err() != nil {
			timedOut = true
			code = -1
		} else {
			code = -1
		}
	}
	text := string(out)
	if e.MaxOutput > 0 && len(text) > e.MaxOutput {
		text = text[:e.MaxOutput] + fmt.Sprintf("\n…[输出已截断，原始 %d 字节]", len(out))
	}
	audit := p.Cmdline()
	if e.Container != nil {
		audit = "container(" + e.Container.Image + ") " + p.Cmdline()
	}
	res := Result{Cmdline: audit, Output: text, Exit: code, Dur: dur, TimedOut: timedOut}
	if timedOut {
		return res, fmt.Errorf("执行超时（%s）", p.Timeout)
	}
	return res, nil
}

// env 只放行必要变量，并清掉所有代理设置。
func (e *Executor) env(dir string) []string {
	if e.Env != nil {
		return e.Env
	}
	keep := map[string]bool{"PATH": true, "PATHEXT": true, "SYSTEMROOT": true, "WINDIR": true}
	out := make([]string, 0, 8)
	for _, kv := range os.Environ() {
		i := strings.Index(kv, "=")
		if i <= 0 {
			continue
		}
		k := strings.ToUpper(kv[:i])
		if strings.Contains(k, "PROXY") {
			continue // 代理会绕过网络层闸门
		}
		if keep[k] {
			out = append(out, kv)
		}
	}
	out = append(out, "HOME="+dir, "TMPDIR="+dir, "TMP="+dir, "TEMP="+dir, "LANG=C.UTF-8")
	return out
}
