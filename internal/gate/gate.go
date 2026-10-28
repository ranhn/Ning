// Package gate 实现 ARGUS 的安全内核：三层递进的授权范围闸门。
//
//	第 1 层 intent   —— 模型"想去哪"（派发意图 / 写资产）
//	第 2 层 exec     —— 工具"要打哪"（解析 Bash/URL/主机名，先解析再判定）
//	第 3 层 network  —— 包"实际发到哪"（Dialer.Control，模型无法绕过）
//
// 三层任何一层命中即 deny（不是 ask：人工审批可能被误点通过）。
// 与 ARTEX 及十家 fork 的根本差异：空范围 = 全部拒绝。
package gate

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/argus/argus/internal/scope"
)

// Layer 标识闸门层。
type Layer string

const (
	LayerIntent  Layer = "intent"
	LayerExec    Layer = "exec"
	LayerNetwork Layer = "network"
)

// ErrOutOfScope 是越界的统一错误，便于调用方 errors.Is 判断。
var ErrOutOfScope = errors.New("目标不在授权范围内")

// Violation 是一次越界尝试的记账。它不是错误日志，而是运营看板与事后追责的证据。
type Violation struct {
	TaskID   int64     `json:"task_id"`
	IntentID int64     `json:"intent_id,omitempty"`
	Layer    Layer     `json:"layer"`
	Tool     string    `json:"tool,omitempty"`
	Target   string    `json:"target"`
	Reason   string    `json:"reason"`
	Raw      string    `json:"raw,omitempty"`
	TS       time.Time `json:"ts"`
}

// Sink 接收越界记录（内存 store、数据库、SIEM 均可实现）。
type Sink interface {
	RecordViolation(Violation)
}

// Resolver 把主机名解析为 IP。抽成接口是为了可测试（避免测试依赖真实 DNS）。
type Resolver interface {
	Lookup(ctx context.Context, host string) ([]netip.Addr, error)
}

// LookupFunc 让普通函数满足 Resolver。
type LookupFunc func(ctx context.Context, host string) ([]netip.Addr, error)

// Lookup 实现 Resolver。
func (f LookupFunc) Lookup(ctx context.Context, host string) ([]netip.Addr, error) {
	return f(ctx, host)
}

// Decision 是一次判定结果。
type Decision struct {
	Allowed bool   `json:"allowed"`
	Layer   Layer  `json:"layer"`
	Target  string `json:"target,omitempty"`
	Reason  string `json:"reason,omitempty"`
}

// Err 在拒绝时返回包装了 ErrOutOfScope 的错误。
func (d Decision) Err() error {
	if d.Allowed {
		return nil
	}
	return fmt.Errorf("%w: %s (%s)", ErrOutOfScope, d.Target, d.Reason)
}

// metadataAddrs 是云元数据地址，属于"永远禁止"集合，与范围配置无关。
var metadataAddrs = map[netip.Addr]string{
	netip.MustParseAddr("169.254.169.254"): "云元数据 IMDS",
	netip.MustParseAddr("169.254.170.2"):   "ECS 任务元数据",
	netip.MustParseAddr("100.100.100.200"): "阿里云元数据",
	netip.MustParseAddr("192.0.0.192"):     "Oracle 元数据",
	netip.MustParseAddr("fd00:ec2::254"):   "AWS IMDSv6",
}

// metadataHosts 是元数据服务的常见主机名。
var metadataHosts = map[string]bool{
	"metadata":                 true,
	"metadata.google.internal": true,
	"metadata.azure.com":       true,
	"instance-data":            true,
}

// Gate 是安全内核。并发安全。
type Gate struct {
	sc   *scope.Scope
	res  Resolver
	sink Sink

	mu     sync.RWMutex
	pinned map[netip.Addr]time.Time // 域名授权后钉住其解析 IP，供第 3 层独立判定
	ttl    time.Duration

	now func() time.Time
}

// Option 配置 Gate。
type Option func(*Gate)

// WithPinTTL 设置钉住 IP 的有效期（默认 10 分钟）。
func WithPinTTL(d time.Duration) Option {
	return func(g *Gate) {
		if d > 0 {
			g.ttl = d
		}
	}
}

// WithClock 注入时钟（测试用）。
func WithClock(now func() time.Time) Option {
	return func(g *Gate) {
		if now != nil {
			g.now = now
		}
	}
}

// New 构造闸门。res 为 nil 时使用系统 DNS。
func New(sc *scope.Scope, res Resolver, sink Sink, opts ...Option) *Gate {
	if res == nil {
		res = systemResolver{}
	}
	g := &Gate{
		sc:     sc,
		res:    res,
		sink:   sink,
		pinned: map[netip.Addr]time.Time{},
		ttl:    10 * time.Minute,
		now:    time.Now,
	}
	for _, o := range opts {
		o(g)
	}
	return g
}

// Scope 返回底层范围（只读）。
func (g *Gate) Scope() *scope.Scope { return g.sc }

// CheckIntent 是第 1 层：校验"想派发的目标"。
func (g *Gate) CheckIntent(ctx context.Context, taskID, intentID int64, tool string, targets []string) Decision {
	return g.check(ctx, LayerIntent, taskID, intentID, tool, targets, "")
}

// CheckTool 是第 2 层：从工具输入中抽取目标并校验。
// 抽不到任何目标时放行——真正的兜底在第 3 层（网络层不依赖解析）。
func (g *Gate) CheckTool(ctx context.Context, taskID, intentID int64, tool string, input json.RawMessage) Decision {
	targets := scope.Targets(tool, input)
	if len(targets) == 0 {
		return Decision{Allowed: true, Layer: LayerExec, Reason: "未从输入中抽取到目标"}
	}
	return g.check(ctx, LayerExec, taskID, intentID, tool, targets, string(input))
}

// CheckURL 是第 2 层的便捷入口（用于 WebFetch 这类明确给 URL 的工具）。
func (g *Gate) CheckURL(ctx context.Context, taskID, intentID int64, tool, rawURL string) Decision {
	return g.check(ctx, LayerExec, taskID, intentID, tool, []string{rawURL}, "")
}

func (g *Gate) check(ctx context.Context, layer Layer, taskID, intentID int64, tool string, targets []string, raw string) Decision {
	if g.sc == nil || g.sc.Empty() {
		return g.deny(layer, taskID, intentID, tool, "", "未配置授权范围，默认拒绝", raw)
	}
	for _, t := range targets {
		host, _ := scope.SplitTarget(strings.TrimSpace(t))
		if host == "" {
			continue
		}
		if ip, err := netip.ParseAddr(host); err == nil {
			ip = ip.Unmap()
			if why, bad := blockedAddr(ip); bad {
				return g.deny(layer, taskID, intentID, tool, ip.String(), why, raw)
			}
			if g.sc.AllowsIP(ip) || g.isPinned(ip) {
				continue
			}
			return g.deny(layer, taskID, intentID, tool, ip.String(), "IP 不在授权范围", raw)
		}

		h := strings.ToLower(host)
		if metadataHosts[h] {
			return g.deny(layer, taskID, intentID, tool, h, "云元数据主机名被禁止", raw)
		}
		if !g.sc.AllowsHost(h) {
			return g.deny(layer, taskID, intentID, tool, h, "域名不在授权范围", raw)
		}
		// 域名授权成立后立即解析并钉住 IP：这样第 3 层不依赖再次解析，
		// 同时也暴露了"域名指向元数据/链路本地地址"的情况（拒绝，而不是悄悄放行）。
		ips, err := g.res.Lookup(ctx, h)
		if err != nil || len(ips) == 0 {
			return g.deny(layer, taskID, intentID, tool, h, "无法解析目标，按失败关闭处理", raw)
		}
		for _, ip := range ips {
			ip = ip.Unmap()
			if why, bad := blockedAddr(ip); bad {
				return g.deny(layer, taskID, intentID, tool, h+" → "+ip.String(), why, raw)
			}
			g.pin(ip)
		}
	}
	return Decision{Allowed: true, Layer: layer}
}

// CheckDial 是第 3 层：网络层兜底，判定"实际要连的 IP"。
// 它不解析任何主机名，只认 IP，因此无法被 DNS 重绑定或脚本绕过。
func (g *Gate) CheckDial(ip netip.Addr) error {
	if !ip.IsValid() {
		return fmt.Errorf("%w: 无效地址", ErrOutOfScope)
	}
	ip = ip.Unmap()
	if why, bad := blockedAddr(ip); bad {
		return fmt.Errorf("%w: %s (%s)", ErrOutOfScope, ip, why)
	}
	if g.sc != nil && g.sc.AllowsIP(ip) {
		return nil
	}
	if g.isPinned(ip) {
		return nil
	}
	if g.sink != nil {
		g.sink.RecordViolation(Violation{
			Layer: LayerNetwork, Target: ip.String(),
			Reason: "网络层拦截：目标 IP 不在授权范围", TS: g.now(),
		})
	}
	return fmt.Errorf("%w: %s (网络层)", ErrOutOfScope, ip)
}

// Lookup 暴露闸门使用的解析器，让出站 HTTP 客户端与闸门**共用同一份解析结果**，
// 避免"闸门校验一个 IP、真正拨号却连到另一个 IP"的 DNS 不一致问题。
func (g *Gate) Lookup(ctx context.Context, host string) ([]netip.Addr, error) {
	if g.res == nil {
		return nil, fmt.Errorf("未配置解析器")
	}
	return g.res.Lookup(ctx, host)
}

// PinHost 把主机名解析出的 IP 钉住（供 demo 与测试使用）。
func (g *Gate) PinHost(ctx context.Context, host string) error {
	ips, err := g.res.Lookup(ctx, host)
	if err != nil {
		return err
	}
	for _, ip := range ips {
		g.pin(ip.Unmap())
	}
	return nil
}

// Pinned 返回当前钉住的 IP 数量（观测用）。
func (g *Gate) Pinned() int {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return len(g.pinned)
}

func (g *Gate) pin(ip netip.Addr) {
	g.mu.Lock()
	g.pinned[ip] = g.now().Add(g.ttl)
	g.mu.Unlock()
}

func (g *Gate) isPinned(ip netip.Addr) bool {
	g.mu.RLock()
	exp, ok := g.pinned[ip]
	g.mu.RUnlock()
	if !ok {
		return false
	}
	if g.now().After(exp) {
		g.mu.Lock()
		delete(g.pinned, ip)
		g.mu.Unlock()
		return false
	}
	return true
}

func (g *Gate) deny(layer Layer, taskID, intentID int64, tool, target, reason, raw string) Decision {
	if g.sink != nil {
		g.sink.RecordViolation(Violation{
			TaskID: taskID, IntentID: intentID, Layer: layer, Tool: tool,
			Target: target, Reason: reason, Raw: truncate(raw, 512), TS: g.now(),
		})
	}
	return Decision{Allowed: false, Layer: layer, Target: target, Reason: reason}
}

// blockedAddr 判断是否属于"永远禁止"的地址（云元数据 / 链路本地 / 组播 / 未指定）。
// 注意 loopback 不在禁止集合内：它必须显式写进范围才会被放行。
func blockedAddr(ip netip.Addr) (string, bool) {
	if why, ok := metadataAddrs[ip]; ok {
		return why + " 被禁止", true
	}
	switch {
	case ip.IsLinkLocalUnicast():
		return "链路本地地址被禁止", true
	case ip.IsLinkLocalMulticast(), ip.IsInterfaceLocalMulticast(), ip.IsMulticast():
		return "组播地址被禁止", true
	case ip.IsUnspecified():
		return "未指定地址被禁止", true
	}
	return "", false
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// systemResolver 使用系统 DNS，带 2 秒超时。
type systemResolver struct{}

func (systemResolver) Lookup(ctx context.Context, host string) ([]netip.Addr, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	return netDefaultLookup(ctx, host)
}
