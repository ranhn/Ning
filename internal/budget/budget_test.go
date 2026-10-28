package budget

import (
	"errors"
	"testing"
)

func TestChargeAndExceed(t *testing.T) {
	b := New()
	b.SetCap(ScopeTask, "1", KindSteps, 10)
	if err := b.Charge(ScopeTask, "1", KindSteps, 6); err != nil {
		t.Fatalf("首次记账失败: %v", err)
	}
	if err := b.Charge(ScopeTask, "1", KindSteps, 4); err != nil {
		t.Fatalf("正好用满不应失败: %v", err)
	}
	err := b.Charge(ScopeTask, "1", KindSteps, 1)
	if err == nil {
		t.Fatal("超额应报错")
	}
	var ex *Exceeded
	if !errors.As(err, &ex) {
		t.Fatalf("错误类型应为 *Exceeded，实际 %T", err)
	}
	if ex.Cap != 10 || ex.Used != 10 {
		t.Fatalf("错误信息字段不对: %+v", ex)
	}
	if got := b.Remaining(ScopeTask, "1", KindSteps); got != 0 {
		t.Fatalf("剩余应为 0，实际 %d", got)
	}
}

func TestChargeAllAtomic(t *testing.T) {
	b := New()
	b.SetCap(ScopeIntent, "i1", KindSteps, 100)
	b.SetCap(ScopeTask, "t1", KindSteps, 3)
	err := b.ChargeAll([]ChargeItem{
		{Scope: ScopeIntent, ID: "i1", Kind: KindSteps, N: 2},
		{Scope: ScopeTask, ID: "t1", Kind: KindSteps, N: 5},
	})
	if err == nil {
		t.Fatal("任一作用域超限应失败")
	}
	if b.Used(ScopeIntent, "i1", KindSteps) != 0 {
		t.Fatal("失败时不得部分扣减")
	}
	if err := b.ChargeAll([]ChargeItem{
		{Scope: ScopeIntent, ID: "i1", Kind: KindSteps, N: 2},
		{Scope: ScopeTask, ID: "t1", Kind: KindSteps, N: 2},
	}); err != nil {
		t.Fatalf("未超限应成功: %v", err)
	}
	if b.Used(ScopeTask, "t1", KindSteps) != 2 {
		t.Fatalf("用量应为 2，实际 %d", b.Used(ScopeTask, "t1", KindSteps))
	}
}

func TestNoCapMeansUnlimitedButTracked(t *testing.T) {
	b := New()
	if err := b.Charge(ScopeDay, "2026-01-01", KindTokens, 1<<40); err != nil {
		t.Fatalf("未设上限不应失败: %v", err)
	}
	if b.Remaining(ScopeDay, "2026-01-01", KindTokens) != -1 {
		t.Fatal("未设上限时 Remaining 应为 -1")
	}
}

func TestDefaultCapsAreNonZero(t *testing.T) {
	caps := DefaultCaps("1", "*", "2026-01-01")
	if len(caps) == 0 {
		t.Fatal("默认上限不能为空")
	}
	for _, c := range caps {
		if c.N <= 0 {
			t.Fatalf("默认上限必须为正（杜绝无限预算）: %+v", c)
		}
	}
	b := New()
	b.Apply(caps)
	for _, c := range caps {
		if got := b.Remaining(c.Scope, c.ID, c.Kind); got != c.N {
			t.Fatalf("%s/%s/%s 初始剩余应为 %d，实际 %d", c.Scope, c.ID, c.Kind, c.N, got)
		}
	}
}
