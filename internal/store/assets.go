package store

import (
	"fmt"
	"sort"
	"time"
)

// Asset 是过闸门后真实访问到的目标。它不是"扫到的资产"，而是"我们确认打过交道的主机"，
// 因此天然带任务归属（TaskID），不会出现 ARTEX 里"全局资产图跨任务污染"的问题。
type Asset struct {
	ID        int64     `json:"id"`
	TaskID    int64     `json:"task_id"`
	Type      string    `json:"type"` // ip | subdomain | endpoint
	Value     string    `json:"value"`
	Hits      int       `json:"hits"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
}

func assetKey(taskID int64, typ, value string) string {
	return fmt.Sprintf("%d|%s|%s", taskID, typ, value)
}

// UpsertAsset 记录一次资产访问：同一 (task,type,value) 只保留一条，累加 Hits。
func (m *Memory) UpsertAsset(taskID int64, typ, value string) Asset {
	m.mu.Lock()
	defer m.mu.Unlock()
	k := assetKey(taskID, typ, value)
	now := time.Now().UTC()
	if a, ok := m.assets[k]; ok {
		a.Hits++
		a.LastSeen = now
		m.touch()
		return *a
	}
	m.seqAsset++
	a := &Asset{
		ID: m.seqAsset, TaskID: taskID, Type: typ, Value: value,
		Hits: 1, FirstSeen: now, LastSeen: now,
	}
	m.assets[k] = a
	m.assetOrder = append(m.assetOrder, k)
	m.touch()
	return *a
}

// Assets 返回资产列表（新→旧）与总数。taskID<=0 表示全量。
func (m *Memory) Assets(taskID int64, typ string, limit, offset int) ([]Asset, int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	all := make([]Asset, 0, len(m.assetOrder))
	for i := len(m.assetOrder) - 1; i >= 0; i-- {
		a := m.assets[m.assetOrder[i]]
		if taskID > 0 && a.TaskID != taskID {
			continue
		}
		if typ != "" && a.Type != typ {
			continue
		}
		all = append(all, *a)
	}
	total := len(all)
	if offset > 0 {
		if offset >= len(all) {
			return nil, total
		}
		all = all[offset:]
	}
	if limit > 0 && len(all) > limit {
		all = all[:limit]
	}
	return all, total
}

// AssetCounts 返回按类型的资产数量。taskID<=0 表示全量。
func (m *Memory) AssetCounts(taskID int64) map[string]int {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := map[string]int{}
	for _, a := range m.assets {
		if taskID > 0 && a.TaskID != taskID {
			continue
		}
		out[a.Type]++
	}
	return out
}

// AssetTypes 返回出现过的资产类型（稳定排序，便于前端渲染 tab）。
func (m *Memory) AssetTypes(taskID int64) []string {
	counts := m.AssetCounts(taskID)
	out := make([]string, 0, len(counts))
	for k := range counts {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
