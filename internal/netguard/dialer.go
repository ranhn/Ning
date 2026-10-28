// Package netguard 实现第 3 层（网络层）闸门：在拨号阶段校验实际目标 IP。
//
// 这一层刻意不解析域名：它只认 IP，因此 DNS 重绑定、CNAME 跳转、脚本内计算目标
// 都无法绕过。任何上层闸门被绕过时，这里仍然会失败。
package netguard

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"syscall"
	"time"
)

// DialChecker 判定一个 IP 是否可拨号。*gate.Gate 满足该接口。
type DialChecker interface {
	CheckDial(ip netip.Addr) error
}

// Dialer 返回带闸门的 net.Dialer。Control 回调在真正建立 socket 前触发。
func Dialer(chk DialChecker, timeout time.Duration) *net.Dialer {
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	return &net.Dialer{
		Timeout:   timeout,
		KeepAlive: 30 * time.Second,
		Control: func(network, address string, _ syscall.RawConn) error {
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				return fmt.Errorf("netguard: 无法解析拨号地址 %q: %w", address, err)
			}
			ip, err := netip.ParseAddr(host)
			if err != nil {
				return fmt.Errorf("netguard: 拨号地址不是 IP %q: %w", host, err)
			}
			if err := chk.CheckDial(ip.Unmap()); err != nil {
				return err
			}
			return nil
		},
	}
}

// LookupFunc 与闸门共用的解析签名。
type LookupFunc func(ctx context.Context, host string) ([]netip.Addr, error)

// HTTPClient 返回所有出站 HTTP 都过闸门的 client。pentest worker 必须用它，
// 不允许直接 http.DefaultClient。
func HTTPClient(chk DialChecker, timeout time.Duration) *http.Client {
	return HTTPClientWithLookup(chk, timeout, nil)
}

// HTTPClientWithLookup 让出站请求**使用与闸门同一份解析结果**再拨号：
// "闸门校验的 IP" 与 "实际连接的 IP" 必然一致，DNS 重绑定/解析漂移都无效。
func HTTPClientWithLookup(chk DialChecker, timeout time.Duration, lookup LookupFunc) *http.Client {
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	d := Dialer(chk, timeout)
	dial := d.DialContext
	if lookup != nil {
		dial = func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, fmt.Errorf("netguard: 拨号地址非法 %q: %w", addr, err)
			}
			if ip, err := netip.ParseAddr(host); err == nil {
				if err := chk.CheckDial(ip.Unmap()); err != nil {
					return nil, err
				}
				return d.DialContext(ctx, network, addr)
			}
			ips, err := lookup(ctx, host)
			if err != nil {
				return nil, fmt.Errorf("netguard: 解析 %s 失败: %w", host, err)
			}
			if len(ips) == 0 {
				return nil, fmt.Errorf("netguard: %s 未解析到任何地址", host)
			}
			ip := ips[0].Unmap()
			if err := chk.CheckDial(ip); err != nil {
				return nil, err
			}
			return d.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
		}
	}
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			Proxy:               nil, // 显式禁用环境变量代理，避免绕过闸门
			DialContext:         dial,
			MaxIdleConns:        32,
			MaxIdleConnsPerHost: 4,
			IdleConnTimeout:     60 * time.Second,
			TLSHandshakeTimeout: 15 * time.Second,
		},
	}
}

// Probe 主动检查一个 IP:port 是否被闸门放行（nil 表示可拨）。
// 用于"部署后自检"：不通的目标必须表现为被拦截，而不是超时。
func Probe(_ context.Context, chk DialChecker, hostport string) error {
	host, _, err := net.SplitHostPort(hostport)
	if err != nil {
		return err
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return fmt.Errorf("Probe 需要 IP:port，收到 %q", hostport)
	}
	return chk.CheckDial(ip.Unmap())
}
