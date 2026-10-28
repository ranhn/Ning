// Package discover 实现"只给根域，自动完成子域枚举 + 可用性确认"。
//
// 为什么需要它：渗透测试的第一步永远是扩面——从 one.example.com 找到
// admin.example.com / api.example.com。让模型自己"猜"子域既不可靠也不经济，
// 所以把它做成内建动作：给定根域，按字典并发解析，解析成功的才算资产。
//
// 安全边界：
//   - 解析出的每个 IP 都要过 gate.CheckDial 才算有效（越界子域直接丢弃并记证据）；
//   - 只做 DNS 查询与一次 HTTP GET，不做任何写操作；
//   - 全部结果写入资产图（带 task_id）与证据链。
package discover

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/argus/argus/internal/evidence"
	"github.com/argus/argus/internal/gate"
	"github.com/argus/argus/internal/store"
)

// 内置子域字典：覆盖 Web、运维、研发、环境四类常见命名。
// 刻意保持精简（~120 条）——字典越大噪声越多，真正的扩面靠证书透明度和被动源。
var defaultWords = []string{
	"www", "m", "mobile", "app", "api", "open", "gateway", "gw", "rest", "graphql",
	"admin", "manage", "manager", "console", "dashboard", "portal", "backend", "boss",
	"shop", "store", "mall", "buy", "pay", "payment", "order", "cart", "member", "user",
	"account", "login", "sso", "auth", "oauth", "id", "passport", "profile", "center",
	"support", "help", "service", "kefu", "feedback", "docs", "doc", "wiki", "faq",
	"blog", "news", "media", "video", "img", "image", "static", "assets", "cdn", "file",
	"download", "upload", "files", "oss", "s3", "storage", "data", "analytics", "report",
	"bi", "stat", "stats", "monitor", "grafana", "prometheus", "kibana", "elastic",
	"jenkins", "ci", "cd", "git", "gitlab", "github", "svn", "nexus", "harbor", "registry",
	"docker", "k8s", "kube", "rancher", "jira", "confluence", "sonar", "quality",
	"test", "testing", "qa", "uat", "stage", "staging", "pre", "preview", "dev", "develop",
	"development", "sandbox", "demo", "beta", "alpha", "release", "prod", "production",
	"mail", "email", "smtp", "imap", "pop", "webmail", "mx", "ns1", "ns2", "dns",
	"vpn", "proxy", "gate", "firewall", "jump", "bastion", "ssh", "ftp", "sftp",
	"db", "mysql", "redis", "mongo", "pg", "postgres", "es", "mq", "rabbit",
	"log", "logs", "trace", "apm", "alert", "sms", "push", "im", "chat", "meeting",
	"crm", "erp", "oa", "hr", "finance", "invoice", "contract", "supplier", "partner",
	"channel", "agent", "reseller", "affiliate", "promo", "activity", "coupon", "seckill",
	"search", "sitemap", "robots", "status", "health", "info", "about", "contact",
	"careers", "job", "recruit", "privacy", "terms", "legal", "security", "trust",
}

// Options 是一次枚举的参数。
type Options struct {
	TaskID   int64
	IntentID int64
	Domain   string
	Words    []string
	Gate     *gate.Gate
	HTTP     *http.Client
	St       store.Store
	Ev       *evidence.Store
	Timeout  time.Duration
	Probe    int // 并发度，默认 16
}

// Host 是一个被发现的主机。
type Host struct {
	FQDN     string   `json:"fqdn"`
	IPs      []string `json:"ips"`
	Live     bool     `json:"live"`     // HTTP 有响应（任意状态码都算活着）
	Status   int      `json:"status"`   // HTTP 状态码，0 = 未响应
	Scheme   string   `json:"scheme"`   // http / https
	Err      string   `json:"err,omitempty"`
	Skipped  bool     `json:"skipped"`  // 解析出的 IP 越界
}

// Result 是枚举结果。
type Result struct {
	Domain   string `json:"domain"`
	Tried    int    `json:"tried"`
	Resolved int    `json:"resolved"`
	Live     int    `json:"live"`
	Hosts    []Host `json:"hosts"`
}

// Run 执行枚举：DNS 解析 → 闸门校验 → HTTP 可用性确认。
func Run(ctx context.Context, o Options) (Result, error) {
	domain := strings.ToLower(strings.TrimSpace(o.Domain))
	domain = strings.TrimPrefix(strings.TrimPrefix(domain, "*."), ".")
	if domain == "" {
		return Result{}, fmt.Errorf("domain 为空")
	}
	words := o.Words
	if len(words) == 0 {
		words = defaultWords
	}
	conc := o.Probe
	if conc <= 0 {
		conc = 16
	}
	timeout := o.Timeout
	if timeout <= 0 {
		timeout = 4 * time.Second
	}

	cands := make([]string, 0, len(words)+1)
	cands = append(cands, domain) // 根域本身也要探测
	for _, w := range words {
		w = strings.ToLower(strings.TrimSpace(w))
		if w == "" || strings.Contains(w, ".") {
			continue
		}
		cands = append(cands, w+"."+domain)
	}

	var (
		mu    sync.Mutex
		hosts = make([]Host, 0, 16)
		wg    sync.WaitGroup
		sem   = make(chan struct{}, conc)
	)

	for _, fqdn := range cands {
		select {
		case <-ctx.Done():
			return Result{}, ctx.Err()
		default:
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(fqdn string) {
			defer wg.Done()
			defer func() { <-sem }()
			h := probeHost(ctx, o, fqdn, timeout)
			if h == nil {
				return
			}
			mu.Lock()
			hosts = append(hosts, *h)
			mu.Unlock()
		}(fqdn)
	}
	wg.Wait()

	sort.Slice(hosts, func(i, j int) bool { return hosts[i].FQDN < hosts[j].FQDN })

	res := Result{Domain: domain, Tried: len(cands), Hosts: hosts}
	for _, h := range hosts {
		if len(h.IPs) > 0 {
			res.Resolved++
		}
		if h.Live {
			res.Live++
		}
	}

	// 落库：资产 + 事实 + 证据（都带 task_id）
	if o.St != nil {
		for _, h := range hosts {
			if len(h.IPs) == 0 || h.Skipped {
				continue
			}
			o.St.UpsertAsset(o.TaskID, "subdomain", h.FQDN)
			kind := "reachable"
			if !h.Live {
				kind = "note"
			}
			text := fmt.Sprintf("%s → %s（%s）", h.FQDN, strings.Join(h.IPs, ","), "无 HTTP 响应")
			if h.Live {
				text = fmt.Sprintf("%s → %s（%s %d）", h.FQDN, strings.Join(h.IPs, ","), h.Scheme, h.Status)
			}
			_, _ = o.St.AddFact(store.Fact{TaskID: o.TaskID, IntentID: o.IntentID, Kind: kind, Text: text})
		}
	}
	if o.Ev != nil {
		_, _ = o.Ev.Append(o.TaskID, o.IntentID, "discover", map[string]any{
			"domain": domain, "tried": res.Tried, "resolved": res.Resolved,
			"live": res.Live, "hosts": res.Hosts,
		})
	}
	return res, nil
}

// probeHost 解析并探测单个主机；解析不到返回 nil（不算资产）。
func probeHost(ctx context.Context, o Options, fqdn string, timeout time.Duration) *Host {
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// 必须与拨号器**同一份解析结果**（闸门的 resolver）：CDN 会轮询返回不同 IP，
	// 两套 DNS 各查一次就会出现"放行了 A、去连 B"的错位。
	var ips []string
	if o.Gate != nil {
		addrs, err := o.Gate.Lookup(cctx, fqdn)
		if err != nil || len(addrs) == 0 {
			return nil
		}
		for _, a := range addrs {
			ips = append(ips, a.String())
		}
	} else {
		hosts, err := net.DefaultResolver.LookupHost(cctx, fqdn)
		if err != nil || len(hosts) == 0 {
			return nil
		}
		ips = hosts
	}

	h := &Host{FQDN: fqdn}
	parsed := make([]netip.Addr, 0, len(ips))
	for _, s := range ips {
		ip, perr := netip.ParseAddr(s)
		if perr != nil {
			continue
		}
		ip = ip.Unmap()
		h.IPs = append(h.IPs, ip.String())
		parsed = append(parsed, ip)
	}
	if len(h.IPs) == 0 {
		return nil
	}
	// 授权判定（而不是越界判定）：子域在范围内 → 它解析出的 IP 立即放行，
	// 否则下面这次 HTTP 探测会被自己的网络层拦掉，并在界面上刷出一片越界记录。
	if o.Gate != nil {
		if derr := o.Gate.AdmitHost(fqdn, parsed); derr != nil {
			h.Skipped = true
			h.Err = derr.Error()
			return h
		}
	}

	// HTTP 可用性：先 https 再 http（很多站点只开其一）
	if o.HTTP != nil {
		for _, scheme := range []string{"https", "http"} {
			url := scheme + "://" + fqdn + "/"
			req, rerr := http.NewRequestWithContext(cctx, http.MethodGet, url, nil)
			if rerr != nil {
				h.Err = rerr.Error()
				continue
			}
			resp, derr := o.HTTP.Do(req)
			if derr != nil {
				h.Err = derr.Error()
				continue
			}
			_ = resp.Body.Close()
			h.Live = true
			h.Status = resp.StatusCode
			h.Scheme = scheme
			h.Err = ""
			break
		}
	}
	return h
}
