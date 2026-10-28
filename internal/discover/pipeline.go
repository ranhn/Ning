package discover

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/argus/argus/internal/toolbox"
)

// AliveHost 是 httpx 探活出来的一台活主机。
type AliveHost struct {
	URL    string   `json:"url"`
	Status int      `json:"status"`
	Title  string   `json:"title,omitempty"`
	Tech   []string `json:"tech,omitempty"`
}

// PipelineResult 是「扩面 → 探活」两阶段的产出。
// 派生后续意图由调用方负责（它才知道任务上下文与去重注册表）。
type PipelineResult struct {
	Domain string      `json:"domain"`
	Source string      `json:"source"` // subfinder | builtin
	Subs   []string    `json:"subs"`
	Alive  []AliveHost `json:"alive"`
}

// RunPipeline 执行「子域枚举 → 批量探活」。
//
// 为什么不再用内置的 120 词字典：那份字典只能覆盖常见子域名，
// 真实资产大量藏在证书透明度、DNS 数据集里。subfinder 多源枚举 + httpx 批量探活，
// 才能把"一个根域"扩成"一批可打的 URL"。
//
// 工具不可用时返回错误，调用方回退到内置字典（保持原有能力不退化）。
func RunPipeline(ctx context.Context, o Options, exec *toolbox.Executor) (PipelineResult, error) {
	out := PipelineResult{Domain: o.Domain, Source: "builtin"}
	if exec == nil || strings.TrimSpace(o.Domain) == "" {
		return out, fmt.Errorf("pipeline 需要工具箱与域名")
	}

	subs, source := enumerateSubs(ctx, o, exec)
	out.Source, out.Subs = source, subs
	if source != "subfinder" || len(subs) == 0 {
		return out, fmt.Errorf("subfinder 不可用或未返回结果")
	}

	alive, err := probeBatch(ctx, o, exec, subs)
	if err != nil {
		return out, err
	}
	out.Alive = alive
	return out, nil
}

// enumerateSubs 用 subfinder 枚举子域。
func enumerateSubs(ctx context.Context, o Options, exec *toolbox.Executor) ([]string, string) {
	p, err := exec.Plan("subfinder -d " + o.Domain + " -silent")
	if err != nil {
		return nil, "builtin"
	}
	res, err := exec.RunIn(ctx, p, exec.WorkDir, "subfinder", nil)
	if err != nil || res.Exit != 0 {
		return nil, "builtin"
	}
	subs := uniqueLines(res.Output)
	if len(subs) == 0 {
		return nil, "builtin"
	}
	return subs, "subfinder"
}

// probeBatch 把子域写成文件交给 httpx 批量探活。
//
// 为什么必须落文件：httpx 没有「多个 -u」的写法，而沙箱禁止绝对路径参数。
// 工作目录内的相对路径是允许的，所以写 subs.txt 再 `-l subs.txt`。
func probeBatch(ctx context.Context, o Options, exec *toolbox.Executor, subs []string) ([]AliveHost, error) {
	dir := exec.WorkDir
	if dir == "" {
		return nil, fmt.Errorf("工具箱缺少工作目录")
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(dir, "subs.txt"), []byte(strings.Join(subs, "\n")+"\n"), 0o600); err != nil {
		return nil, err
	}

	p, err := exec.Plan("httpx -l subs.txt -silent -status-code -title -tech-detect -timeout 8")
	if err != nil {
		return nil, err
	}
	res, err := exec.RunIn(ctx, p, dir, "httpx", nil)
	if err != nil {
		return nil, err
	}

	out := make([]AliveHost, 0, len(subs))
	for _, line := range strings.Split(res.Output, "\n") {
		h, ok := parseHttpxLine(strings.TrimSpace(line))
		if !ok {
			continue
		}
		out = append(out, h)
	}

	// 闸门授权：探活命中的主机逐个放行（域名在范围内才放，越界仍拒）。
	// 不做这一步，后面 katana/nuclei 去连它们时会被自己的网络层拦掉。
	for _, h := range out {
		host := hostOfURL(h.URL)
		if host == "" || o.Gate == nil {
			continue
		}
		if ips, err := o.Gate.Lookup(ctx, host); err == nil && len(ips) > 0 {
			_ = o.Gate.AdmitHost(host, ips)
		}
	}
	return out, nil
}

// parseHttpxLine 解析 httpx 的 silent 输出：
//
//	https://a.example.com [200] [Welcome] [nginx,PHP]
func parseHttpxLine(line string) (AliveHost, bool) {
	if line == "" || !strings.Contains(line, "://") {
		return AliveHost{}, false
	}
	parts := strings.Split(line, "[")
	var h AliveHost
	h.URL = strings.TrimSpace(parts[0])
	if len(parts) > 1 {
		h.Status, _ = strconv.Atoi(strings.TrimSpace(strings.TrimSuffix(parts[1], "]")))
	}
	if len(parts) > 2 {
		h.Title = strings.TrimSpace(strings.TrimSuffix(parts[2], "]"))
	}
	if len(parts) > 3 {
		for _, t := range strings.Split(strings.TrimSuffix(parts[3], "]"), ",") {
			if s := strings.TrimSpace(t); s != "" {
				h.Tech = append(h.Tech, s)
			}
		}
	}
	return h, h.Status > 0
}

func uniqueLines(s string) []string {
	seen := make(map[string]bool, 64)
	out := make([]string, 0, 64)
	for _, line := range strings.Split(s, "\n") {
		v := strings.TrimSpace(line)
		if v == "" || seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	return out
}

// hostOfURL 取 URL 的主机名（失败返回空）。
func hostOfURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return u.Hostname()
}
