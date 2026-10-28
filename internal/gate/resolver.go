package gate

import (
	"context"
	"net"
	"net/netip"
)

// netDefaultLookup 是 systemResolver 的实现细节，单独抽出便于平台相关替换。
func netDefaultLookup(ctx context.Context, host string) ([]netip.Addr, error) {
	ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, err
	}
	out := make([]netip.Addr, 0, len(ips))
	for _, ip := range ips {
		out = append(out, ip.Unmap())
	}
	return out, nil
}

// StaticResolver 是测试与实验室环境用的固定映射解析器。
type StaticResolver struct {
	Map map[string][]string
	Err error
}

// Lookup 实现 Resolver。
func (r StaticResolver) Lookup(_ context.Context, host string) ([]netip.Addr, error) {
	if r.Err != nil {
		return nil, r.Err
	}
	raw, ok := r.Map[host]
	if !ok {
		return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
	}
	out := make([]netip.Addr, 0, len(raw))
	for _, s := range raw {
		ip, err := netip.ParseAddr(s)
		if err != nil {
			return nil, err
		}
		out = append(out, ip.Unmap())
	}
	return out, nil
}
