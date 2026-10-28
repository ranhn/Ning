// Package attack 把漏洞结论映射到 MITRE ATT&CK，并生成检测规则草稿。
//
// 这是 ARTEX 生态最大的空白：十家 fork 里只有两家各做了一半
// （bdg9412 有流程、jiwoochris 有静态规则集），没人把"每次攻击自动产出
// 可用的检测规则"做成产品能力。ARGUS 把它做成 finding 的默认产物。
package attack

import (
	"fmt"
	"strings"
)

// Technique 是一条 ATT&CK 技术。
type Technique struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Tactic string `json:"tactic"`
}

type rule struct {
	keys []string
	t    Technique
}

// table 是关键词 → ATT&CK 的映射表。关键词同时覆盖中英文写法。
var table = []rule{
	{[]string{"sql injection", "sqli", "sql注入"}, Technique{"T1190", "Exploit Public-Facing Application", "Initial Access"}},
	{[]string{"command injection", "命令注入", "rce", "remote code", "代码执行"}, Technique{"T1059", "Command and Scripting Interpreter", "Execution"}},
	{[]string{"xss", "cross-site scripting", "跨站脚本"}, Technique{"T1059.007", "JavaScript", "Execution"}},
	{[]string{"ssrf", "服务端请求伪造"}, Technique{"T1190", "Exploit Public-Facing Application", "Initial Access"}},
	{[]string{"idor", "越权", "broken access control", "水平越权", "垂直越权"}, Technique{"T1078", "Valid Accounts", "Persistence"}},
	{[]string{"lfi", "path traversal", "目录穿越", "文件包含", "任意文件读取"}, Technique{"T1005", "Data from Local System", "Collection"}},
	{[]string{"file upload", "任意文件上传", "webshell"}, Technique{"T1105", "Ingress Tool Transfer", "Command and Control"}},
	{[]string{"xxe", "xml external"}, Technique{"T1190", "Exploit Public-Facing Application", "Initial Access"}},
	{[]string{"deserial", "反序列化"}, Technique{"T1059", "Command and Scripting Interpreter", "Execution"}},
	{[]string{"weak password", "default credential", "弱口令", "默认口令"}, Technique{"T1078.001", "Default Accounts", "Persistence"}},
	{[]string{"brute force", "暴力破解", "撞库"}, Technique{"T1110", "Brute Force", "Credential Access"}},
	{[]string{"exposed panel", "admin panel", "管理后台暴露", "未授权后台"}, Technique{"T1133", "External Remote Services", "Initial Access"}},
	{[]string{"vpn", "rdp", "ssh exposure", "远程服务暴露"}, Technique{"T1133", "External Remote Services", "Initial Access"}},
	{[]string{"subdomain takeover", "子域接管"}, Technique{"T1584.001", "Compromise Infrastructure: Domains", "Resource Development"}},
	{[]string{"public bucket", "oss 未授权", "s3 public", "对象存储"}, Technique{"T1530", "Data from Cloud Storage", "Collection"}},
	{[]string{"metadata", "元数据", "imds"}, Technique{"T1552.005", "Cloud Instance Metadata API", "Credential Access"}},
	{[]string{"jwt", "token 伪造", "alg none"}, Technique{"T1550.001", "Use Alternate Authentication Material: Application Access Token", "Defense Evasion"}},
	{[]string{"csrf", "跨站请求伪造"}, Technique{"T1190", "Exploit Public-Facing Application", "Initial Access"}},
	{[]string{"open redirect", "开放重定向"}, Technique{"T1190", "Exploit Public-Facing Application", "Initial Access"}},
	{[]string{"dir listing", "directory listing", "目录遍历", "信息泄露", "info leak"}, Technique{"T1592", "Gather Victim Host Information", "Reconnaissance"}},
	{[]string{"cve-", "known vuln", "已知漏洞", "n-day"}, Technique{"T1190", "Exploit Public-Facing Application", "Initial Access"}},
	{[]string{"reverse shell", "反弹 shell", "c2", "beacon"}, Technique{"T1071", "Application Layer Protocol", "Command and Control"}},
	{[]string{"credential dump", "mimikatz", "凭据导出"}, Technique{"T1003", "OS Credential Dumping", "Credential Access"}},
	{[]string{"tls", "证书", "certificate"}, Technique{"T1595", "Active Scanning", "Reconnaissance"}},
	{[]string{"port scan", "端口扫描", "指纹识别"}, Technique{"T1595.001", "Scanning IP Blocks", "Reconnaissance"}},
}

// Map 返回漏洞类别对应的 ATT&CK 技术。未命中时返回一条通用技术（T1190），
// 并返回 false 表示"这是兜底映射"。
func Map(vulnClass string) (Technique, bool) {
	// 中英文写法的空格差异极大（"sql injection" / "sql注入" / "SQL 注入"），
	// 因此去掉所有空白后再比对。
	s := stripSpaces(strings.ToLower(vulnClass))
	for _, r := range table {
		for _, k := range r.keys {
			if strings.Contains(s, stripSpaces(k)) {
				return r.t, true
			}
		}
	}
	return Technique{"T1190", "Exploit Public-Facing Application", "Initial Access"}, false
}

func stripSpaces(s string) string {
	return strings.Join(strings.Fields(s), "")
}

// SigmaDraft 生成一条 Sigma 规则草稿。
//
// 刻意只做"草稿"：真实环境必须按自己的日志字段（Web 访问日志 / WAF / EDR）
// 调整 logsource 与 selection，这里给出可直接粘进编辑器的骨架与判断依据。
func SigmaDraft(t Technique, vulnClass, target, evidenceID string) string {
	title := fmt.Sprintf("%s 检测草稿：%s", t.ID, vulnClass)
	var b strings.Builder
	b.WriteString("title: " + title + "\n")
	b.WriteString("id: argus-" + strings.ToLower(strings.ReplaceAll(t.ID, ".", "-")) + "-draft\n")
	b.WriteString("status: experimental\n")
	b.WriteString("description: 由 ARGUS 在授权测试中确认的漏洞自动生成；需按本地日志字段调整\n")
	b.WriteString("references:\n")
	b.WriteString("  - https://attack.mitre.org/techniques/" + strings.ReplaceAll(t.ID, ".", "/") + "/\n")
	b.WriteString("tags:\n")
	b.WriteString("  - attack." + strings.ToLower(strings.ReplaceAll(t.Tactic, " ", "_")) + "\n")
	b.WriteString("  - attack." + strings.ToLower(strings.ReplaceAll(t.ID, ".", "_")) + "\n")
	b.WriteString("logsource:\n")
	b.WriteString("  category: web\n")
	b.WriteString("  product: generic\n")
	b.WriteString("detection:\n")
	b.WriteString("  selection_target:\n")
	if target != "" {
		b.WriteString("    url|contains: '" + strings.ReplaceAll(target, "'", "''") + "'\n")
	} else {
		b.WriteString("    url|contains: '<按资产填写>'\n")
	}
	b.WriteString("  selection_evidence:\n")
	b.WriteString("    evidence_id: '" + evidenceID + "'\n")
	b.WriteString("  condition: selection_target and selection_evidence\n")
	b.WriteString("falsepositives:\n")
	b.WriteString("  - 授权测试期间的本系统流量（按源 IP 排除）\n")
	b.WriteString("level: medium\n")
	return b.String()
}
