// Package budget 实现三层预算：per-intent / per-task / per-day。
//
// ARTEX 的缺口是"max_turns 默认 0 = 不限、token 只记账不熔断"。
// 这里把预算做成硬闸门：超限返回错误，调度器据此干净收尾。
package budget

import (
	"fmt"
	"sort"
	"sync"
)

// Kind 是预算种类。
type Kind string

const (
	KindTokens  Kind = "tokens"
	KindCost    Kind = "cost"    // 以"分"为单位的整数，避免浮点误差
	KindSteps   Kind = "steps"   // 工具调用次数
	KindSeconds Kind = "seconds" // 墙钟秒
)

// Scope 是预算作用域的三个层级。
type Scope string

const (
	ScopeIntent Scope = "intent"
	ScopeTask   Scope = "task"
	ScopeDay    Scope = "day"
)

// Exceeded 表示预算超限。
type Exceeded struct {
	Scope Scope
	ID    string
	Kind  Kind
	Cap   int64
	Used  int64
	Want  int64
}

func (e *Exceeded) Error() string {
	return fmt.Sprintf("预算超限: %s[%s] %s 已用 %d + 本次 %d > 上限 %d",
		e.Scope, e.ID, e.Kind, e.Used, e.Want, e.Cap)
}

type key struct {
	scope Scope
	id    string
	kind  Kind
}

// Budget 是并发安全的预算账本。
type Budget struct {
	mu   sync.Mutex
	caps map[key]int64
	used map[key]int64
}

// New 构造空账本。未设置上限的作用域视为"不限"，
// 但 DefaultCaps 提供了推荐值，生产环境应全部设置。
func New() *Budget {
	return &Budget{caps: map[key]int64{}, used: map[key]int64{}}
}

// SetCap 设置上限（cap<0 视为不限；cap==0 视为禁止任何消耗）。
func (b *Budget) SetCap(scope Scope, id string, kind Kind, cap int64) {
	b.mu.Lock()
	defer b.mu.Unlock()
	k := key{scope, id, kind}
	if cap < 0 {
		delete(b.caps, k)
		return
	}
	b.caps[k] = cap
}

// Charge 申请消耗 n。任一相关上限被突破则整体不扣减（原子性）。
func (b *Budget) Charge(scope Scope, id string, kind Kind, n int64) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	k := key{scope, id, kind}
	used := b.used[k]
	if cap, ok := b.caps[k]; ok && used+n > cap {
		return &Exceeded{Scope: scope, ID: id, Kind: kind, Cap: cap, Used: used, Want: n}
	}
	b.used[k] = used + n
	return nil
}

// ChargeItem 是 ChargeAll 的一项。
type ChargeItem struct {
	Scope Scope
	ID    string
	Kind  Kind
	N     int64
}

// ChargeAll 对多个作用域一起记账：全部成功才生效，否则一个都不扣。
func (b *Budget) ChargeAll(items []ChargeItem) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	delta := map[key]int64{}
	for _, it := range items {
		delta[key{it.Scope, it.ID, it.Kind}] += it.N
	}
	for k, n := range delta {
		if cap, ok := b.caps[k]; ok && b.used[k]+n > cap {
			return &Exceeded{Scope: k.scope, ID: k.id, Kind: k.kind, Cap: cap, Used: b.used[k], Want: n}
		}
	}
	for k, n := range delta {
		b.used[k] += n
	}
	return nil
}

// Used 返回已用量。
func (b *Budget) Used(scope Scope, id string, kind Kind) int64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.used[key{scope, id, kind}]
}

// Remaining 返回剩余量；未设上限时返回 -1。
func (b *Budget) Remaining(scope Scope, id string, kind Kind) int64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	k := key{scope, id, kind}
	cap, ok := b.caps[k]
	if !ok {
		return -1
	}
	return cap - b.used[k]
}

// Snapshot 返回可读的账本快照，按 key 排序，便于日志与看板。
func (b *Budget) Snapshot() []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	lines := make([]string, 0, len(b.used))
	for k, v := range b.used {
		cap, ok := b.caps[k]
		if ok {
			lines = append(lines, fmt.Sprintf("%s/%s:%s %d/%d", k.scope, k.id, k.kind, v, cap))
		} else {
			lines = append(lines, fmt.Sprintf("%s/%s:%s %d/-", k.scope, k.id, k.kind, v))
		}
	}
	sort.Strings(lines)
	return lines
}

// DefaultCaps 是推荐的默认上限：全部为非 0，杜绝"默认不限"。
// 单 intent 60 步 / 单任务 1200 步 / 单日 20000 步；token 同比例放大。
func DefaultCaps(taskID, intentID, day string) []ChargeItem {
	return []ChargeItem{
		{ScopeIntent, intentID, KindSteps, 60},
		{ScopeTask, taskID, KindSteps, 1200},
		{ScopeDay, day, KindSteps, 20000},
		{ScopeIntent, intentID, KindTokens, 120000},
		{ScopeTask, taskID, KindTokens, 3000000},
		{ScopeDay, day, KindTokens, 40000000},
		{ScopeTask, taskID, KindSeconds, 3600},
		{ScopeDay, day, KindSeconds, 28800},
		{ScopeTask, taskID, KindCost, 2000},
		{ScopeDay, day, KindCost, 20000},
	}
}

// Apply 把一批上限写入账本。
func (b *Budget) Apply(items []ChargeItem) {
	for _, it := range items {
		b.SetCap(it.Scope, it.ID, it.Kind, it.N)
	}
}
