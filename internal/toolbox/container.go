package toolbox

import (
	"context"
	"fmt"
	"net/netip"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"time"
)

// ContainerConfig 是"每意图一次性容器"的执行配置。
//
// 为什么需要它：同机沙箱（toolbox 的白名单 + 无 shell + 受限环境）防的是"模型乱写命令"，
// 防不住"工具本身的 0day"和"工具读到宿主机文件"。容器把这两件事一起解决：
// 只读根、无 capabilities、非 root、独立 PID/内存/CPU 上限、只挂载任务工作目录。
//
// 网络策略的三档（由 egress 网络决定，而不是靠提示词）：
//   - Network = "none"：完全无网（dig/nmap 之类的离线分析）；
//   - Network = 自定义 bridge（如 argus-egress）：出网必须经过该网络的网关策略；
//   - 无论哪档，**目标 IP 都由闸门解析后通过 --add-host 钉进容器**，
//     容器内 DNS 拿到的就是闸门批准过的 IP，不存在"容器自己解析到另一个地址"。
type ContainerConfig struct {
	Runtime   string // docker | podman
	Image     string // 例：argus-toolbox:latest
	Network   string // "" = none
	User      string // 默认 65534:65534（nobody）
	Memory    string // 默认 512m
	CPUs      string // 默认 1
	PidsLimit int    // 默认 256
	TmpfsSize string // 默认 64m
	// Proxy 是出口网关地址（例 http://egress:3128）。设置后容器内所有 HTTP 客户端
	// 都通过它出网，网关按 argus egress 生成的白名单放行——这是网络层的最终形态。
	Proxy string
}

func (c ContainerConfig) withDefaults() ContainerConfig {
	if c.Runtime == "" {
		c.Runtime = "docker"
	}
	if c.Image == "" {
		c.Image = "argus-toolbox:latest"
	}
	if c.Network == "" {
		c.Network = "none"
	}
	if c.User == "" {
		c.User = "65534:65534"
	}
	if c.Memory == "" {
		c.Memory = "512m"
	}
	if c.CPUs == "" {
		c.CPUs = "1"
	}
	if c.PidsLimit <= 0 {
		c.PidsLimit = 256
	}
	if c.TmpfsSize == "" {
		c.TmpfsSize = "64m"
	}
	return c
}

// Available 探测容器运行时是否存在且守护进程可用。
// 不存在时返回错误——调用方应当**拒绝启动**，而不是悄悄退化成本机执行。
func (c ContainerConfig) Available() error {
	c = c.withDefaults()
	if _, err := exec.LookPath(c.Runtime); err != nil {
		return fmt.Errorf("容器运行时不可用：找不到 %s（安装 docker/podman，或改用 -exec real 的同机沙箱）", c.Runtime)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, c.Runtime, "version", "--format", "{{.Server.Version}}").CombinedOutput()
	if err != nil {
		return fmt.Errorf("容器运行时无法连接守护进程：%s（%s）", strings.TrimSpace(string(out)), err)
	}
	return nil
}

// BuildArgv 构造完整的容器命令行（可直接喂给 exec.CommandContext）。
//
// 安全参数一个都不能少：只读根 + cap-drop ALL + no-new-privileges + 非 root +
// pids/内存/CPU 上限 + tmpfs 隔离 + 只挂载工作目录。
func (c ContainerConfig) BuildArgv(p *Plan, workdir, name string, pins map[string][]netip.Addr) []string {
	c = c.withDefaults()
	argv := []string{
		"run", "--rm",
		"--name", name,
		"--network", c.Network,
		"--user", c.User,
		"--cap-drop", "ALL",
		"--security-opt", "no-new-privileges",
		"--pids-limit", strconv.Itoa(c.PidsLimit),
		"--memory", c.Memory,
		"--cpus", c.CPUs,
		"--read-only",
		"--tmpfs", "/tmp:rw,noexec,nosuid,size=" + c.TmpfsSize,
		"-v", workdir + ":/work:rw",
		"-w", "/work",
		"--entrypoint", p.Bin,
	}
	// 出口网关：容器内所有 HTTP 客户端只能走这里，网关按白名单放行
	if c.Proxy != "" {
		for _, k := range []string{"HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"} {
			argv = append(argv, "-e", k+"="+c.Proxy)
		}
		argv = append(argv, "-e", "NO_PROXY=127.0.0.1,localhost")
	}

	// 把闸门解析结果钉进容器：容器内 DNS 与闸门判定必须是同一份答案
	hosts := make([]string, 0, len(pins))
	for h := range pins {
		hosts = append(hosts, h)
	}
	sort.Strings(hosts)
	for _, h := range hosts {
		for _, ip := range pins[h] {
			argv = append(argv, "--add-host", h+":"+ip.String())
		}
	}
	argv = append(argv, c.Image)
	argv = append(argv, p.Args...)
	return argv
}

// ContainerName 生成合法的容器名：argus-<intent>-<unix>。
func ContainerName(intentID int64, suffix string) string {
	name := fmt.Sprintf("argus-%d-%d", intentID, time.Now().Unix())
	if suffix != "" {
		name += "-" + suffix
	}
	return name
}
