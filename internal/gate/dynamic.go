package gate

import (
	"context"
	"encoding/json"
	"sync"
	"time"
)

// DynamicGate 让"任务范围"可以在运行期变化。
//
// ARTEX 的 scope 是活的：agent 可以调 add_task_scope 追加范围行，insertAssets 也会
// 自动累计。所以不能像单机版那样在启动时把 scope 固化成不可变对象 —— 这里按 TTL
// 重建底层 Gate，范围一变，下一次工具调用就按新范围判定。
type DynamicGate struct {
	TaskID int64
	Build  func() (*Gate, error)
	TTL    time.Duration

	mu  sync.Mutex
	g   *Gate
	at  time.Time
	err error
}

func (d *DynamicGate) current() (*Gate, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	ttl := d.TTL
	if ttl <= 0 {
		ttl = 30 * time.Second
	}
	// TTL 内复用；过期或从未构建过则重建
	if d.g != nil && time.Since(d.at) < ttl {
		return d.g, d.err
	}
	if d.Build == nil {
		return nil, nil
	}
	g, err := d.Build()
	d.g, d.err, d.at = g, err, time.Now()
	return g, err
}

// CheckToolRaw 实现 guard.ArgusGate。
//
// 语义（兼容模式）：
//   - 范围为空 → 放行。ARTEX 建任务时未声明 scope 是常见情况，此时若直接全拒会把
//     基线可用性打掉；一旦声明了范围，后面的判定就是硬约束。
//   - 范围非空 → 越界即拒，并把命中层（intent/exec/network）带进原因里。
func (d *DynamicGate) CheckToolRaw(ctx context.Context, tool string, input []byte) (bool, string) {
	g, err := d.current()
	if err != nil {
		return false, "范围加载失败，按失败关闭处理：" + err.Error()
	}
	if g == nil || g.Scope() == nil || g.Scope().Empty() {
		return true, ""
	}
	dec := g.CheckTool(ctx, d.TaskID, 0, tool, json.RawMessage(input))
	if dec.Allowed {
		return true, ""
	}
	layer := string(dec.Layer)
	if layer == "" {
		layer = "scope"
	}
	return false, "范围闸门拒绝（" + layer + " 层）：" + dec.Reason
}
