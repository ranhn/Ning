package gate

import "testing"

// TestCapabilityFull：默认档位不限制任何工具。
func TestCapabilityFull(t *testing.T) {
	for _, tool := range []string{"Bash", "WebFetch", "nmap", "sqlmap", "mcp__browser"} {
		if !AllowTool(CapFull, tool) {
			t.Errorf("full 档不应限制 %s", tool)
		}
	}
}

// TestCapabilityCodeAudit：代码审计档必须把"能出网/能执行"的工具全部摘掉，
// 只留本地文件工具。这是"只读审计"能成立的前提。
func TestCapabilityCodeAudit(t *testing.T) {
	denied := []string{
		"Bash", "shell_open", "shell_send", "Sleep", "Monitor",
		"WebFetch", "WebSearch", "fetch_url", "curl", "wget", "http_request",
		"command", "script", "create_custom_tool",
		"Task", "mcp__browser", "mcp__anything",
		"traffic_search", "traffic_get",
		"Browser_open", "playwright_run", "nmap", "nuclei", "sqlmap", "ffuf",
	}
	for _, tool := range denied {
		if AllowTool(CapCodeAudit, tool) {
			t.Errorf("codeaudit 档不应允许 %s", tool)
		}
	}
	allowed := []string{"Read", "Write", "Edit", "MultiEdit", "LS", "Glob", "Grep", "report_finding", "record_fact"}
	for _, tool := range allowed {
		if !AllowTool(CapCodeAudit, tool) {
			t.Errorf("codeaudit 档应允许本地工具 %s", tool)
		}
	}
}

// TestCapabilityRecon：探测档保留信息收集，禁"真正打进去"的工具。
func TestCapabilityRecon(t *testing.T) {
	for _, tool := range []string{"Bash", "curl", "nmap", "nuclei", "WebFetch"} {
		if !AllowTool(CapRecon, tool) {
			t.Errorf("recon 档应允许 %s", tool)
		}
	}
	for _, tool := range []string{"sqlmap", "hydra", "metasploit", "nikto"} {
		if AllowTool(CapRecon, tool) {
			t.Errorf("recon 档不应允许 %s", tool)
		}
	}
}

// TestCapabilityFrom：拼错配置不能把系统变成"全禁"。
func TestCapabilityFrom(t *testing.T) {
	cases := map[string]Capability{
		"codeaudit": CapCodeAudit,
		"CodeAudit": CapCodeAudit,
		"recon":     CapRecon,
		"full":      CapFull,
		"":          CapFull,
		"typo":      CapFull,
	}
	for in, want := range cases {
		if got := CapabilityFrom(in); got != want {
			t.Errorf("CapabilityFrom(%q)=%q want %q", in, got, want)
		}
	}
}
