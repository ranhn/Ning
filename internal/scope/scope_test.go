package scope

import (
	"net/netip"
	"testing"
)

func TestScopeDefaultDeny(t *testing.T) {
	s, err := New(nil)
	if err != nil {
		t.Fatalf("New(nil): %v", err)
	}
	if !s.Empty() {
		t.Fatal("空规则集应视为 Empty")
	}
	if s.AllowsHost("example.com") {
		t.Fatal("空范围必须拒绝一切（默认拒绝）")
	}
	if s.AllowsIP(netip.MustParseAddr("10.0.0.1")) {
		t.Fatal("空范围必须拒绝一切 IP")
	}
}

func TestScopeDomainMatch(t *testing.T) {
	s, err := New([]Rule{
		{Kind: KindExactDomain, Value: "lab.internal"},
		{Kind: KindDomainSuffix, Value: "example.com"},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	cases := []struct {
		host string
		want bool
	}{
		{"lab.internal", true},
		{"LAB.INTERNAL", true},
		{"a.lab.internal", false}, // exact_domain 不含子域
		{"lab.internal:8080", true},
		{"lab.internal.", true},
		{"example.com", true},
		{"api.example.com", true},
		{"notexample.com", false},
		{"example.com.evil.io", false},
		{"evil.io", false},
		{"", false},
	}
	for _, c := range cases {
		if got := s.AllowsHost(c.host); got != c.want {
			t.Errorf("AllowsHost(%q)=%v want %v", c.host, got, c.want)
		}
	}
}

func TestScopeIPMatch(t *testing.T) {
	s, err := New([]Rule{
		{Kind: KindCIDR, Value: "10.10.0.0/16"},
		{Kind: KindExactIP, Value: "192.168.1.5"},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	cases := []struct {
		ip   string
		want bool
	}{
		{"10.10.0.1", true},
		{"10.10.255.254", true},
		{"10.11.0.1", false},
		{"192.168.1.5", true},
		{"192.168.1.6", false},
		{"8.8.8.8", false},
	}
	for _, c := range cases {
		if got := s.AllowsIP(netip.MustParseAddr(c.ip)); got != c.want {
			t.Errorf("AllowsIP(%s)=%v want %v", c.ip, got, c.want)
		}
	}
	if !s.AllowsHost("10.10.0.9") {
		t.Error("AllowsHost 应把 IP 字面量委托给 AllowsIP")
	}
}

func TestScopeExactURL(t *testing.T) {
	s, err := New([]Rule{{Kind: KindExactURL, Value: "http://lab.internal:8080/api"}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if !s.AllowsURL("http://lab.internal:8080/api/users") {
		t.Error("同 host+path 前缀应放行")
	}
	if s.AllowsURL("http://lab.internal:8080/admin") {
		t.Error("不同 path 前缀应拒绝")
	}
	if s.AllowsURL("https://lab.internal:8080/api") {
		t.Error("scheme 不同应拒绝")
	}
}

func TestScopeRejectsBadRules(t *testing.T) {
	bad := [][]Rule{
		{{Kind: KindCIDR, Value: "10.0.0.0"}},
		{{Kind: KindExactIP, Value: "not-an-ip"}},
		{{Kind: KindExactDomain, Value: "  "}},
		{{Kind: Kind("weird"), Value: "x"}},
		{{Kind: KindExactURL, Value: "nonsense"}},
	}
	for i, rules := range bad {
		if _, err := New(rules); err == nil {
			t.Errorf("第 %d 组非法规则应报错", i+1)
		}
	}
}

func TestTargetsFromBashCommand(t *testing.T) {
	got := FromText(`curl -sS "http://lab.internal:8080/api/users?id=1" -H "Host: other.example.com"`)
	want := map[string]bool{
		"http://lab.internal:8080/api/users?id=1": true,
		"other.example.com":                       true,
	}
	seen := map[string]bool{}
	for _, g := range got {
		seen[g] = true
	}
	for w := range want {
		if !seen[w] {
			t.Errorf("未抽取到 %q，实际=%v", w, got)
		}
	}
}

func TestTargetsFromJSON(t *testing.T) {
	input := []byte(`{"url":"https://api.example.com/v1","headers":{"X":"evil.io"},"note":"scan 8.8.8.8"}`)
	got := Targets("WebFetch", input)
	seen := map[string]bool{}
	for _, g := range got {
		seen[g] = true
	}
	for _, w := range []string{"https://api.example.com/v1", "8.8.8.8", "evil.io"} {
		if !seen[w] {
			t.Errorf("未抽取到 %q，实际=%v", w, got)
		}
	}
}

func TestTargetsSkipsFilenames(t *testing.T) {
	got := FromText("python3 manage.py runserver && vim index.php")
	for _, g := range got {
		if g == "index.php" || g == "manage.py" {
			t.Errorf("文件后缀不应被当作域名: %v", got)
		}
	}
}

func TestSplitTarget(t *testing.T) {
	h, raw := SplitTarget("http://lab.internal:8080/a")
	if h != "lab.internal" || raw == "" {
		t.Errorf("SplitTarget 结果错误: host=%q raw=%q", h, raw)
	}
	h2, _ := SplitTarget("10.0.0.1")
	if h2 != "10.0.0.1" {
		t.Errorf("IP 字面量应原样返回: %q", h2)
	}
	if !IsIPLiteral("10.0.0.1") || IsIPLiteral("10.0.0.1.5") {
		t.Error("IsIPLiteral 判定错误")
	}
}
