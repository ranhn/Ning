package gate

import "strings"

// Capability 是任务的能力档位：决定 agent 能用哪些工具。
//
// 来自 10 家 fork 里最一致的一条教训：**工具面越窄，越不容易出事**。
// Ernket 的代码审计模式把 Bash / WebFetch / MCP / 自定义工具全部剥离，
// 只留 7 个本地文件工具 —— 这让"代码审计任务"在物理上不可能发起网络请求，
// 而不是靠提示词劝阻。
//
// 我们把它做成通用档位，而不是写死一个模式：
//
//	full      全部工具（默认：渗透测试）
//	recon     只做探测，禁主动攻击工具（sqlmap/hydra/msf/nikto）
//	codeaudit 只读本地，禁一切出网与执行工具（代码审计 / 源码审计）
//
// 判定发生在工具调用前（guard.preToolUse → ArgusAdapter.CheckToolRaw），
// 因此与"模型是否听话"无关。
type Capability string

const (
	CapFull      Capability = "full"
	CapRecon     Capability = "recon"
	CapCodeAudit Capability = "codeaudit"
)

// deniedByCapability 返回该档位下禁止的工具名**前缀**。
//
// 用前缀匹配而不是精确匹配：同名工具常有变体（shell / shell_open / shell_send、
// browser / browser_open、mcp__xxx 等），逐个列举既容易漏，也会随插件新增而失效。
func deniedByCapability(c Capability) []string {
	switch c {
	case CapCodeAudit:
		// 代码审计只需要读本地源码：任何能出网、能执行任意命令、能拉起外部进程的
		// 工具都必须消失，否则"只读"就是一句空话。
		return []string{
			// 执行与出网
			"bash", "shell", "sleep", "monitor",
			"webfetch", "websearch", "web_search", "fetch", "curl", "wget", "http",
			// 自定义工具（用户可写入任意命令/脚本/HTTP）
			"command", "script", "custom_tool", "create_custom_tool", "update_custom_tool",
			// 子代理（会把上述能力递归带进子代理）
			"task",
			// MCP（用户可配置任意外部进程）
			"mcp__", "create_mcp", "update_mcp",
			// 流量录制回放
			"traffic_",
			// 浏览器 / 扫描器
			"browser", "playwright", "selenium",
			"nmap", "nuclei", "sqlmap", "ffuf", "dirsearch", "hydra", "metasploit", "nikto", "dalfox",
		}
	case CapRecon:
		// 探测档：允许 curl/nmap/nuclei 等信息收集，禁"会真正打进去"的工具。
		return []string{"sqlmap", "hydra", "metasploit", "msfconsole", "nikto", "dalfox", "intercept_execute"}
	}
	return nil
}

// AllowTool 判断该档位下是否允许调用某工具。
func AllowTool(c Capability, tool string) bool {
	n := strings.ToLower(strings.TrimSpace(tool))
	if n == "" {
		return true
	}
	for _, prefix := range deniedByCapability(c) {
		if strings.HasPrefix(n, prefix) {
			return false
		}
	}
	return true
}

// CapabilityFrom 把外部字符串归一化成已知档位（未知一律回落到 full，
// 避免拼错一个配置项就把所有工具禁掉）。
func CapabilityFrom(s string) Capability {
	switch Capability(strings.ToLower(strings.TrimSpace(s))) {
	case CapRecon:
		return CapRecon
	case CapCodeAudit:
		return CapCodeAudit
	case CapFull:
		return CapFull
	}
	return CapFull
}
