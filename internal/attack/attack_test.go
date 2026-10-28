package attack

import (
	"strings"
	"testing"
)

func TestMapVariants(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"SQL 注入", "T1190"},
		{"sql injection", "T1190"},
		{"SQLInjection", "T1190"},
		{"命令注入", "T1059"},
		{"远程代码执行 RCE", "T1059"},
		{"反射型 XSS", "T1059.007"},
		{"SSRF", "T1190"},
		{"水平越权", "T1078"},
		{"任意文件读取", "T1005"},
		{"webshell 上传", "T1105"},
		{"弱口令", "T1078.001"},
		{"暴力破解", "T1110"},
		{"管理后台暴露", "T1133"},
		{"子域接管", "T1584.001"},
		{"OSS 未授权访问", "T1530"},
		{"云元数据", "T1552.005"},
		{"JWT 伪造", "T1550.001"},
		{"反弹 shell", "T1071"},
		{"端口扫描", "T1595.001"},
	}
	for _, c := range cases {
		got, ok := Map(c.in)
		if !ok {
			t.Errorf("%q 未命中映射表", c.in)
			continue
		}
		if got.ID != c.want {
			t.Errorf("%q 应映射 %s，实际 %s(%s)", c.in, c.want, got.ID, got.Name)
		}
		if got.Tactic == "" || got.Name == "" {
			t.Errorf("%q 映射结果缺少字段: %+v", c.in, got)
		}
	}
}

func TestMapFallback(t *testing.T) {
	got, ok := Map("某个没见过的类别")
	if ok {
		t.Fatal("未知类别应返回 ok=false（表示兜底）")
	}
	if got.ID != "T1190" {
		t.Fatalf("兜底应为 T1190，实际 %s", got.ID)
	}
}

func TestSigmaDraft(t *testing.T) {
	tech, _ := Map("SQL 注入")
	d := SigmaDraft(tech, "SQL 注入", "api.lab.internal", "ev-000003")
	for _, want := range []string{
		"title:", "id: argus-t1190-draft", "logsource:", "detection:",
		"api.lab.internal", "ev-000003", "attack.t1190",
	} {
		if !strings.Contains(d, want) {
			t.Errorf("Sigma 草稿缺少 %q\n%s", want, d)
		}
	}
	d2 := SigmaDraft(tech, "SQL 注入", "", "ev-1")
	if !strings.Contains(d2, "<按资产填写>") {
		t.Error("空资产应给出占位符")
	}
}
