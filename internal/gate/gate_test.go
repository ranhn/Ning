package gate

import (
	"context"
	"encoding/json"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/argus/argus/internal/scope"
)

type recSink struct {
	mu sync.Mutex
	vs []Violation
}

func (r *recSink) RecordViolation(v Violation) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.vs = append(r.vs, v)
}

func (r *recSink) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.vs)
}

func testScope(t *testing.T) *scope.Scope {
	t.Helper()
	sc, err := scope.New([]scope.Rule{
		{Kind: scope.KindDomainSuffix, Value: "lab.internal"},
		{Kind: scope.KindCIDR, Value: "10.20.0.0/16"},
	})
	if err != nil {
		t.Fatalf("scope.New: %v", err)
	}
	return sc
}

var res = StaticResolver{Map: map[string][]string{
	"lab.internal":        {"10.20.0.5"},
	"api.lab.internal":    {"10.20.0.6"},
	"evil.example.com":    {"203.0.113.9"},
	"rebind.lab.internal": {"10.20.0.7", "203.0.113.10"},
	"meta.lab.internal":   {"169.254.169.254"},
}}

func TestEmptyScopeDeniesEverything(t *testing.T) {
	sc, _ := scope.New(nil)
	g := New(sc, res, nil)
	d := g.CheckTool(context.Background(), 1, 1, "Bash", json.RawMessage(`{"command":"curl http://lab.internal/"}`))
	if d.Allowed {
		t.Fatal("空范围必须拒绝")
	}
	if d.Layer != LayerExec {
		t.Fatalf("拒绝层应为 exec，实际 %s", d.Layer)
	}
	if err := g.CheckDial(netip.MustParseAddr("10.20.0.1")); err == nil {
		t.Fatal("空范围下任何拨号都应被拒")
	}
}

func TestOutOfScopeTargets(t *testing.T) {
	g := New(testScope(t), res, nil)
	cases := []struct{ name, tool, input string }{
		{"公网域名", "Bash", `{"command":"curl http://evil.example.com/x"}`},
		{"公网 IP", "Bash", `{"command":"nmap -Pn 8.8.8.8"}`},
		{"相似域名", "WebFetch", `{"url":"http://lab.internal.evil.io/"}`},
		{"DNS 外带", "Bash", `{"command":"dig @8.8.8.8 lab.internal"}`},
		{"Host 头走私", "Bash", `{"command":"curl -H 'Host: other.example.com' http://10.20.0.5/"}`},
		{"脚本内建连", "Bash", `{"command":"python3 -c 'connect(\"evil.example.com\",80)'"}`},
		{"云元数据", "Bash", `{"command":"curl http://169.254.169.254/latest/meta-data/"}`},
		{"解析到元数据", "Bash", `{"command":"curl http://meta.lab.internal/"}`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if d := g.CheckTool(context.Background(), 1, 1, c.tool, json.RawMessage(c.input)); d.Allowed {
				t.Fatalf("应拦截但放行: %s", c.input)
			}
		})
	}
}

func TestInScopeAllowedAndPinned(t *testing.T) {
	g := New(testScope(t), res, nil)
	d := g.CheckTool(context.Background(), 1, 1, "Bash", json.RawMessage(`{"command":"nmap -sV lab.internal"}`))
	if !d.Allowed {
		t.Fatalf("范围内应放行: %s", d.Reason)
	}
	if err := g.CheckDial(netip.MustParseAddr("10.20.0.5")); err != nil {
		t.Fatalf("钉住的 IP 应放行: %v", err)
	}
	if g.Pinned() != 1 {
		t.Fatalf("应钉住 1 个 IP，实际 %d", g.Pinned())
	}
	if err := g.CheckDial(netip.MustParseAddr("203.0.113.9")); err == nil {
		t.Fatal("未钉住的公网 IP 必须被拦截")
	}
}

func TestPinExpires(t *testing.T) {
	now := time.Now()
	g := New(testScope(t), res, nil, WithPinTTL(time.Minute), WithClock(func() time.Time { return now }))
	if d := g.CheckTool(context.Background(), 1, 1, "Bash", json.RawMessage(`{"command":"curl http://api.lab.internal/"}`)); !d.Allowed {
		t.Fatalf("应放行: %s", d.Reason)
	}
	now = now.Add(2 * time.Minute)
	// 10.20.0.6 仍命中 cidr，因此断言"钉住表被清理"而非拒绝。
	_ = g.CheckDial(netip.MustParseAddr("10.20.0.6"))
	if g.Pinned() != 0 {
		t.Fatalf("过期钉住项应被清理，实际 %d", g.Pinned())
	}
}

func TestIntentLayer(t *testing.T) {
	sink := &recSink{}
	g := New(testScope(t), res, sink)
	d := g.CheckIntent(context.Background(), 7, 3, "add_intent", []string{"evil.example.com"})
	if d.Allowed || d.Layer != LayerIntent {
		t.Fatalf("意图层应拦截，实际 %+v", d)
	}
	if sink.count() != 1 {
		t.Fatalf("应记录 1 条越界，实际 %d", sink.count())
	}
	v := sink.vs[0]
	if v.TaskID != 7 || v.IntentID != 3 || v.Target != "evil.example.com" {
		t.Fatalf("越界记录字段错误: %+v", v)
	}
}

type errNoDNS struct{}

func (errNoDNS) Error() string { return "dns down" }

func TestResolveFailureIsClosed(t *testing.T) {
	g := New(testScope(t), StaticResolver{Err: errNoDNS{}}, nil)
	d := g.CheckTool(context.Background(), 1, 1, "Bash", json.RawMessage(`{"command":"curl http://lab.internal/"}`))
	if d.Allowed {
		t.Fatal("解析失败必须失败关闭")
	}
}

func TestNoTargetsIsAllowedAtExecLayer(t *testing.T) {
	g := New(testScope(t), res, nil)
	// 命令里没有任何目标：第 2 层放行，由第 3 层兜底。这是有意设计。
	if d := g.CheckTool(context.Background(), 1, 1, "Bash", json.RawMessage(`{"command":"ls -la /tmp"}`)); !d.Allowed {
		t.Fatalf("无目标的命令应放行: %s", d.Reason)
	}
}
