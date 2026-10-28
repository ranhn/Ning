// Package egress 把授权范围翻译成出口网关的白名单配置。
//
// 这是"网络层闸门"的最终形态：容器在 --internal 网络里没有 NAT，
// 唯一出口是 squid，squid 只放行这里生成的 dstdomain / dst 列表。
//
// 关键点：白名单**从 scope 生成**，与 gate 判定同源。
// 不是靠运维手写、也不是靠提示词里"只在授权范围内"。
package egress

import (
	"fmt"
	"sort"
	"strings"

	"github.com/Autumn-27/artex/internal/scope"
)

// Allowlist 是一个范围翻译出的出口白名单。
type Allowlist struct {
	Domains []string `json:"domains"` // 域名后缀 / 精确域名
	Nets    []string `json:"nets"`    // CIDR / 单个 IP
}

// FromScope 从授权范围生成白名单。
func FromScope(sc *scope.Scope) Allowlist {
	out := Allowlist{}
	if sc == nil {
		return out
	}
	seenD := map[string]bool{}
	seenN := map[string]bool{}
	for _, r := range sc.Rules() {
		v := strings.TrimSpace(r.Value)
		if v == "" {
			continue
		}
		switch r.Kind {
		case scope.KindDomainSuffix:
			d := "." + strings.TrimPrefix(strings.ToLower(v), ".")
			if !seenD[d] {
				seenD[d] = true
				out.Domains = append(out.Domains, d)
			}
		case scope.KindExactDomain:
			d := strings.ToLower(v)
			if !seenD[d] {
				seenD[d] = true
				out.Domains = append(out.Domains, d)
			}
		case scope.KindExactURL:
			// 从 URL 里取主机名；取不到就跳过（不猜）
			if host := hostOfURL(v); host != "" {
				d := strings.ToLower(host)
				if !seenD[d] {
					seenD[d] = true
					out.Domains = append(out.Domains, d)
				}
			}
		case scope.KindExactIP:
			if !seenN[v] {
				seenN[v] = true
				out.Nets = append(out.Nets, v)
			}
		case scope.KindCIDR:
			if !seenN[v] {
				seenN[v] = true
				out.Nets = append(out.Nets, v)
			}
		}
	}
	sort.Strings(out.Domains)
	sort.Strings(out.Nets)
	return out
}

func hostOfURL(raw string) string {
	s := raw
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	if i := strings.IndexAny(s, "/?#"); i >= 0 {
		s = s[:i]
	}
	if i := strings.LastIndex(s, "@"); i >= 0 {
		s = s[i+1:]
	}
	if i := strings.LastIndex(s, ":"); i >= 0 && !strings.Contains(s[i+1:], "]") {
		s = s[:i]
	}
	return strings.TrimSpace(s)
}

// SquidConf 生成 squid 的 conf.d 片段：只允许 CONNECT/GET 到白名单目标。
func (a Allowlist) SquidConf() string {
	var b strings.Builder
	b.WriteString("# 由 ARGUS 从任务授权范围生成，请勿手工编辑\n")
	b.WriteString("# 重新生成：argus egress -scope \"domain_suffix:lab.internal\" -o <file>\n\n")

	if len(a.Domains) > 0 {
		fmt.Fprintf(&b, "acl argus_domains dstdomain %s\n", strings.Join(a.Domains, " "))
	}
	if len(a.Nets) > 0 {
		fmt.Fprintf(&b, "acl argus_nets dst %s\n", strings.Join(a.Nets, " "))
	}
	b.WriteString("\nhttp_access allow CONNECT argus_domains\n")
	b.WriteString("http_access allow CONNECT argus_nets\n")
	b.WriteString("http_access allow argus_domains\n")
	b.WriteString("http_access allow argus_nets\n")
	b.WriteString("http_access deny all\n")
	b.WriteString("never_direct allow all\n")
	return b.String()
}

// HostsFile 生成纯文本主机清单（给 iptables/ipset 或人工核对用）。
func (a Allowlist) HostsFile() string {
	var b strings.Builder
	for _, d := range a.Domains {
		b.WriteString(strings.TrimPrefix(d, "."))
		b.WriteString("\n")
	}
	for _, n := range a.Nets {
		b.WriteString(n)
		b.WriteString("\n")
	}
	return b.String()
}

// ParseSpec 解析 `kind:value,kind:value` 形式的范围描述（CLI 用）。
func ParseSpec(spec string) ([]scope.Rule, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return nil, fmt.Errorf("scope 描述为空")
	}
	rules := make([]scope.Rule, 0, 4)
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		i := strings.Index(part, ":")
		if i <= 0 {
			return nil, fmt.Errorf("无法解析 %q，应为 kind:value 形式", part)
		}
		kind := strings.TrimSpace(part[:i])
		value := strings.TrimSpace(part[i+1:])
		if value == "" {
			return nil, fmt.Errorf("%q 缺少 value", part)
		}
		rules = append(rules, scope.Rule{Kind: scope.Kind(kind), Value: value})
	}
	if len(rules) == 0 {
		return nil, fmt.Errorf("scope 描述为空")
	}
	return rules, nil
}
