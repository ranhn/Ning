// Package scope 实现「授权范围」这一核心事实：范围内是什么，范围外是什么。
//
// 与 ARTEX 及全部十家 fork 的关键区别：**空范围 = 拒绝一切**（默认拒绝），
// 而不是「没配规则就全放行」。范围是结构化数据，不是提示词里的一句话。
package scope

import (
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"sort"
	"strings"
)

// Kind 是范围规则的种类。
type Kind string

const (
	// KindExactDomain 精确匹配该域名（不含子域）。
	KindExactDomain Kind = "exact_domain"
	// KindDomainSuffix 后缀匹配，形如 example.com，匹配 example.com 与 *.example.com。
	KindDomainSuffix Kind = "domain_suffix"
	// KindCIDR 网段，形如 10.10.0.0/16。
	KindCIDR Kind = "cidr"
	// KindExactIP 单个 IP。
	KindExactIP Kind = "exact_ip"
	// KindExactURL 精确 URL（scheme + host + path 前缀）。
	KindExactURL Kind = "exact_url"
)

// Rule 是一条范围规则。
type Rule struct {
	Kind  Kind   `json:"kind"`
	Value string `json:"value"`
}

// ErrEmptyScope 表示未配置任何授权范围。按默认拒绝策略，此时一切目标都被拒绝。
var ErrEmptyScope = errors.New("未配置授权范围")

// Scope 是编译后的范围规则集合，匹配是只读的，可并发使用。
type Scope struct {
	rules    []Rule
	domains  map[string]struct{}
	suffixes []string
	prefixes []netip.Prefix
	ips      map[netip.Addr]struct{}
	urls     []*url.URL
}

// New 编译规则集合。任何一条规则非法都会返回错误（不做静默跳过，
// 否则一个拼错的网段会变成"看起来配了范围、实际什么都没配"）。
func New(rules []Rule) (*Scope, error) {
	s := &Scope{
		domains: map[string]struct{}{},
		ips:     map[netip.Addr]struct{}{},
	}
	for i, r := range rules {
		v := strings.TrimSpace(r.Value)
		if v == "" {
			return nil, fmt.Errorf("规则 #%d 的值为空", i+1)
		}
		switch r.Kind {
		case KindExactDomain:
			h, err := normalizeHost(v)
			if err != nil {
				return nil, fmt.Errorf("规则 #%d: %w", i+1, err)
			}
			s.domains[h] = struct{}{}
		case KindDomainSuffix:
			h, err := normalizeHost(strings.TrimPrefix(strings.TrimPrefix(v, "*."), "."))
			if err != nil {
				return nil, fmt.Errorf("规则 #%d: %w", i+1, err)
			}
			s.suffixes = append(s.suffixes, h)
		case KindCIDR:
			p, err := netip.ParsePrefix(v)
			if err != nil {
				return nil, fmt.Errorf("规则 #%d: CIDR 非法: %w", i+1, err)
			}
			s.prefixes = append(s.prefixes, p.Masked())
		case KindExactIP:
			ip, err := netip.ParseAddr(v)
			if err != nil {
				return nil, fmt.Errorf("规则 #%d: IP 非法: %w", i+1, err)
			}
			s.ips[ip.Unmap()] = struct{}{}
		case KindExactURL:
			u, err := url.Parse(v)
			if err != nil || u.Hostname() == "" {
				return nil, fmt.Errorf("规则 #%d: URL 非法", i+1)
			}
			s.urls = append(s.urls, u)
		default:
			return nil, fmt.Errorf("规则 #%d: 未知 kind %q", i+1, r.Kind)
		}
		s.rules = append(s.rules, Rule{Kind: r.Kind, Value: v})
	}
	sort.Strings(s.suffixes)
	return s, nil
}

// Len 返回规则条数。
func (s *Scope) Len() int {
	if s == nil {
		return 0
	}
	return len(s.rules)
}

// Empty 表示未配置任何规则。调用方应据此直接拒绝（fail-closed）。
func (s *Scope) Empty() bool { return s.Len() == 0 }

// Rules 返回规则副本，用于展示与审计。
func (s *Scope) Rules() []Rule {
	if s == nil {
		return nil
	}
	out := make([]Rule, len(s.rules))
	copy(out, s.rules)
	return out
}

// AllowsHost 判断主机名是否在范围内。IP 字面量会转到 AllowsIP。
func (s *Scope) AllowsHost(host string) bool {
	if s == nil || s.Empty() {
		return false
	}
	h, err := normalizeHost(host)
	if err != nil {
		return false
	}
	if ip, err := netip.ParseAddr(h); err == nil {
		return s.AllowsIP(ip)
	}
	if _, ok := s.domains[h]; ok {
		return true
	}
	for _, suf := range s.suffixes {
		if h == suf || strings.HasSuffix(h, "."+suf) {
			return true
		}
	}
	for _, u := range s.urls {
		if strings.EqualFold(u.Hostname(), h) {
			return true
		}
	}
	return false
}

// AllowsIP 判断 IP 是否在范围内（只看 cidr / exact_ip 规则）。
func (s *Scope) AllowsIP(ip netip.Addr) bool {
	if s == nil || s.Empty() || !ip.IsValid() {
		return false
	}
	ip = ip.Unmap()
	if _, ok := s.ips[ip]; ok {
		return true
	}
	for _, p := range s.prefixes {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

// AllowsURL 判断 URL 是否在范围内：host 命中域名规则，或完整 URL 前缀命中文档规则。
func (s *Scope) AllowsURL(raw string) bool {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Hostname() == "" {
		return false
	}
	for _, r := range s.rules {
		if r.Kind == KindExactURL {
			au, err := url.Parse(r.Value)
			if err != nil {
				continue
			}
			if strings.EqualFold(au.Scheme, u.Scheme) &&
				strings.EqualFold(au.Host, u.Host) &&
				strings.HasPrefix(u.Path, au.Path) {
				return true
			}
		}
	}
	return s.AllowsHost(u.Hostname())
}

// Describe 返回人类可读的规则列表（用于启动横幅与审计日志）。
func (s *Scope) Describe() []string {
	if s == nil {
		return nil
	}
	out := make([]string, 0, len(s.rules))
	for _, r := range s.rules {
		out = append(out, string(r.Kind)+":"+r.Value)
	}
	return out
}

// normalizeHost 归一化主机名：小写、去端口、去尾部点、拒绝空与含非法字符的输入。
func normalizeHost(host string) (string, error) {
	h := strings.TrimSpace(strings.ToLower(host))
	h = strings.TrimSuffix(h, ".")
	if h == "" {
		return "", errors.New("主机名为空")
	}
	// 去掉可能携带的端口（只在非 IPv6 场景下安全）。
	if strings.Count(h, ":") == 1 {
		if i := strings.LastIndex(h, ":"); i > 0 {
			h = h[:i]
		}
	}
	if strings.ContainsAny(h, " \t\r\n/\\?#@") {
		return "", fmt.Errorf("主机名含非法字符: %q", host)
	}
	return h, nil
}
