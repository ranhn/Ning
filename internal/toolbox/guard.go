package toolbox

import (
	"fmt"
	"path"
	"regexp"
	"strings"
)

// CheckCommand 对"直通 shell 的命令"做宽松但有效的安全校验。
//
// 为什么不用 Plan 的严格白名单：ARTEX 的 worker 用的是完整 shell
// （管道、&&、python3、grep、cat 全都在用）。用白名单卡会把它的日常作业
// 全部打死，agent 会陷入"每条命令都被拒"的死循环。
//
// 所以这里只做两件真正有价值的事：
//  1. 拒绝破坏性 / 提权 / 持久化的二进制（rm、mkfs、dd、useradd、crontab…）
//  2. 拒绝已知的危险参数组合（nmap --script、sqlmap --os-shell、curl 上传、反弹 shell）
//
// 其余放行 —— 安全边界靠"范围闸门 + 网络层"兜底，命令层只拦真正的自杀动作。
func CheckCommand(cmdline string) error {
	cmdline = strings.TrimSpace(cmdline)
	if cmdline == "" {
		return &ErrNotAllowed{Reason: "空命令"}
	}

	for _, p := range deniedPatterns {
		if p.re.MatchString(cmdline) {
			return &ErrNotAllowed{Reason: "危险模式：" + p.why}
		}
	}

	for _, seg := range splitSegments(cmdline) {
		bin := firstToken(seg)
		if bin == "" {
			continue
		}
		name := binName(bin)
		if why, bad := deniedBins[name]; bad {
			return &ErrNotAllowed{Reason: fmt.Sprintf("禁止执行 %s（%s）", name, why)}
		}
	}
	return nil
}

// deniedBins 是"任何情况下都不该由 agent 直接执行"的二进制。
// 键是 basename（已去 .exe、已小写）。
var deniedBins = map[string]string{
	// 破坏性
	"rm": "删除文件", "del": "删除文件", "erase": "删除文件", "rd": "删除目录", "rmdir": "删除目录",
	"mkfs": "格式化", "dd": "裸写设备", "shred": "擦除数据", "srm": "擦除数据",
	"fdisk": "改分区", "parted": "改分区", "diskpart": "改分区", "format": "格式化",
	// 影响主机
	"shutdown": "关机", "reboot": "重启", "poweroff": "关机", "halt": "关机", "init": "切换运行级别",
	"killall": "结束进程", "taskkill": "结束进程", "pkill": "结束进程",
	// 账户与提权
	"useradd": "新增账户", "userdel": "删除账户", "usermod": "修改账户",
	"passwd": "修改密码", "chpasswd": "批量改密码", "net": "改账户/服务",
	"sudo": "提权", "su": "切换用户", "runas": "提权", "doas": "提权",
	// 系统配置
	"mount": "挂载", "umount": "卸载", "iptables": "改防火墙", "nft": "改防火墙",
	"ufw": "改防火墙", "firewall-cmd": "改防火墙", "netsh": "改网络配置",
	"systemctl": "改服务", "service": "改服务", "sc": "改服务", "reg": "改注册表",
	"crontab": "写计划任务", "schtasks": "写计划任务", "at": "写计划任务",
	"chmod": "改权限", "chown": "改属主", "chattr": "改文件属性", "attrib": "改文件属性",
	// 隧道/反弹 shell 常用
	"nc": "反弹 shell 常用", "ncat": "反弹 shell 常用", "netcat": "反弹 shell 常用",
	"socat": "建立隧道", "ssh": "远程登录", "scp": "传文件", "rsync": "传文件",
	"ftp": "传文件", "sftp": "传文件", "telnet": "明文远程登录",
	// 代码执行放大器（容易被用来绕过前面所有限制）
	"powershell": "可执行任意脚本", "pwsh": "可执行任意脚本",
	"cmd": "可执行任意命令", "wmic": "可执行任意命令", "cscript": "可执行脚本", "wscript": "可执行脚本",
}

// deniedPatterns 是参数级危险模式：即使二进制在白名单里也要拦。
var deniedPatterns = []struct {
	re  *regexp.Regexp
	why string
}{
	{regexp.MustCompile(`(?i)\brm\s+(-[a-z]*[rf][a-z]*\s+)+/(\s|$)`), "递归删除根目录"},
	{regexp.MustCompile(`(?i)\b(nmap|nuclei|nikto)\b.*--script`), "脚本引擎可反弹 shell"},
	{regexp.MustCompile(`(?i)\bsqlmap\b.*--(os-shell|os-pwn|os-smbrelay|os-bof|file-write|file-read|sql-shell)`), "sqlmap 接管参数"},
	{regexp.MustCompile(`(?i)\bcurl\b.*(\s-T\s|\s--upload-file\b)`), "curl 上传文件"},
	{regexp.MustCompile(`(?i)/dev/tcp/`), "bash 反弹 shell"},
	{regexp.MustCompile(`(?i)\b(bash|sh|zsh)\s+-i\s+>&`), "交互式反弹 shell"},
	{regexp.MustCompile(`(?i)>\s*(/etc/|/boot/|/dev/sd|/dev/nvme|C:\\Windows)`), "覆盖系统文件"},
	{regexp.MustCompile(`(?i)\b(base64\s+(-d|--decode)\s*\|\s*(bash|sh))\b`), "编码后执行"},
	{regexp.MustCompile(`(?i)\b(eval|exec)\s*\(`), "动态求值执行"},
	{regexp.MustCompile(`(?i)\bchmod\s+[0-7]*7[0-7]*\s+/`), "放开系统路径权限"},
}

// splitSegments 按 shell 管道/串接符切分，便于逐个检查二进制名。
func splitSegments(cmd string) []string {
	repl := strings.NewReplacer("&&", "\n", "||", "\n", ";", "\n", "|", "\n")
	return strings.Split(repl.Replace(cmd), "\n")
}

// firstToken 取一段命令里的第一个"像二进制"的 token（跳过 VAR=value 前缀）。
func firstToken(seg string) string {
	for _, tok := range strings.Fields(seg) {
		if strings.HasPrefix(tok, "-") {
			continue
		}
		if i := strings.Index(tok, "="); i > 0 && !strings.Contains(tok[:i], "/") && !strings.Contains(tok[:i], `\`) {
			continue // FOO=bar cmd 里的环境变量前缀
		}
		return strings.Trim(tok, `"'`)
	}
	return ""
}

// binName 归一化成 basename（跨平台路径分隔符、去 .exe、小写）。
func binName(bin string) string {
	b := strings.ReplaceAll(bin, `\`, "/")
	b = strings.ToLower(path.Base(b))
	return strings.TrimSuffix(b, ".exe")
}
