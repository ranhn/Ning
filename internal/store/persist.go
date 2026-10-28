package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/argus/argus/internal/gate"
)

// 持久化：内存存储的可选 JSON 快照。
//
// 为什么不用数据库：ARGUS 目前是零外部依赖形态，单机/单实例场景下
// "原子写快照 + 定期落盘"已经足够，而且不会引入驱动与迁移负担。
// 生产多副本时换成 internal/store 的 PG 实现即可（接口不变，schema.sql 已就绪）。
//
// 关键保证：
//   - 快照先写临时文件再 rename，避免半截文件；
//   - 写盘发生在锁外（先拷贝再落盘），不阻塞调度；
//   - 文件损坏时备份成 *.corrupt-<ts> 并重新开始，而不是让服务起不来
//     （本机 DLP 会把非白名单进程写的文件加密，这个分支真的会被走到）。

type snapshot struct {
	Version    int              `json:"version"`
	SavedAt    time.Time        `json:"saved_at"`
	Tasks      []Task           `json:"tasks"`
	Intents    []Intent         `json:"intents"`
	Findings   []Finding        `json:"findings"`
	Violations []gate.Violation `json:"violations"`
	Assets     []Asset          `json:"assets"`
	Facts      []Fact           `json:"facts"`
	Traffic    []Traffic        `json:"traffic"`
	Retests    []Retest         `json:"retests"`
	Rules      []Rule           `json:"rules"`
	Approvals  []Approval       `json:"approvals"`
	SeqTask    int64            `json:"seq_task"`
	SeqIntent  int64            `json:"seq_intent"`
	SeqFinding int64            `json:"seq_finding"`
	SeqAsset   int64            `json:"seq_asset"`
	SeqFact    int64            `json:"seq_fact"`
	SeqTraffic int64            `json:"seq_traffic"`
	SeqRetest  int64            `json:"seq_retest"`
	SeqRule    int64            `json:"seq_rule"`
	SeqApprove int64            `json:"seq_approve"`
}

const snapshotVersion = 1

// Open 打开（或创建）带持久化的存储。path 为空时退化为纯内存。
func Open(path string) (*Memory, error) {
	m := NewMemory()
	if path == "" {
		return m, nil
	}
	m.path = path
	if err := m.loadFile(); err != nil {
		bak := fmt.Sprintf("%s.corrupt-%d", path, time.Now().Unix())
		_ = os.Rename(path, bak)
		fmt.Fprintf(os.Stderr, "argus: 状态文件不可读（%v），已备份到 %s 并新建\n", err, bak)
	}
	go m.autoSave()
	return m, nil
}

// Save 立即落盘（幂等）。
func (m *Memory) Save() error {
	if m.path == "" {
		return nil
	}
	snap := m.snapshot()
	body, err := json.MarshalIndent(snap, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(m.path), 0o750); err != nil {
		return err
	}
	tmp := m.path + ".tmp"
	if err := os.WriteFile(tmp, body, 0o640); err != nil {
		return err
	}
	return os.Rename(tmp, m.path)
}

func (m *Memory) loadFile() error {
	body, err := os.ReadFile(m.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	if len(body) == 0 {
		return nil
	}
	var snap snapshot
	if err := json.Unmarshal(body, &snap); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, t := range snap.Tasks {
		m.tasks[t.ID] = t
		m.taskOrder = append(m.taskOrder, t.ID)
	}
	for _, it := range snap.Intents {
		m.intents[it.ID] = it
		m.intentOrder = append(m.intentOrder, it.ID)
	}
	for _, f := range snap.Findings {
		// 兼容旧快照：早期版本没有 status 字段，加载时补默认值而不是留空。
		if f.Status == "" {
			f.Status = "confirmed"
		}
		if f.UpdatedAt.IsZero() {
			f.UpdatedAt = f.CreatedAt
		}
		m.findings[f.TaskID] = append(m.findings[f.TaskID], f)
	}
	m.violations = append(m.violations, snap.Violations...)
	for i := range snap.Assets {
		a := snap.Assets[i]
		k := assetKey(a.TaskID, a.Type, a.Value)
		m.assets[k] = &a
		m.assetOrder = append(m.assetOrder, k)
	}
	m.facts = append(m.facts, snap.Facts...)
	m.traffic = append(m.traffic, snap.Traffic...)
	m.retests = append(m.retests, snap.Retests...)
	m.rules = append(m.rules, snap.Rules...)
	m.approvals = append(m.approvals, snap.Approvals...)
	m.seqTask, m.seqIntent = snap.SeqTask, snap.SeqIntent
	m.seqFinding, m.seqAsset = snap.SeqFinding, snap.SeqAsset
	m.seqFact, m.seqTraffic = snap.SeqFact, snap.SeqTraffic
	m.seqRetest, m.seqRule = snap.SeqRetest, snap.SeqRule
	m.seqApprove = snap.SeqApprove
	return nil
}

func (m *Memory) snapshot() snapshot {
	m.mu.Lock()
	defer m.mu.Unlock()
	s := snapshot{
		Version: snapshotVersion, SavedAt: time.Now().UTC(),
		SeqTask: m.seqTask, SeqIntent: m.seqIntent,
		SeqFinding: m.seqFinding, SeqAsset: m.seqAsset,
	}
	for _, id := range m.taskOrder {
		s.Tasks = append(s.Tasks, m.tasks[id])
	}
	for _, id := range m.intentOrder {
		s.Intents = append(s.Intents, m.intents[id])
	}
	for _, list := range m.findings {
		s.Findings = append(s.Findings, list...)
	}
	s.Violations = append(s.Violations, m.violations...)
	for _, k := range m.assetOrder {
		s.Assets = append(s.Assets, *m.assets[k])
	}
	s.Facts = append(s.Facts, m.facts...)
	s.Traffic = append(s.Traffic, m.traffic...)
	s.Retests = append(s.Retests, m.retests...)
	s.Rules = append(s.Rules, m.rules...)
	s.Approvals = append(s.Approvals, m.approvals...)
	s.SeqFact, s.SeqTraffic = m.seqFact, m.seqTraffic
	s.SeqRetest, s.SeqRule = m.seqRetest, m.seqRule
	s.SeqApprove = m.seqApprove
	return s
}

// touch 标记有变更（调用方通常已持有 m.mu，所以这里用独立的锁）。
func (m *Memory) touch() {
	if m.path == "" {
		return
	}
	m.dirtyMu.Lock()
	m.dirty = true
	m.dirtyMu.Unlock()
}

func (m *Memory) autoSave() {
	tick := time.NewTicker(500 * time.Millisecond)
	defer tick.Stop()
	for range tick.C {
		m.dirtyMu.Lock()
		need := m.dirty
		m.dirty = false
		m.dirtyMu.Unlock()
		if !need {
			continue
		}
		if err := m.Save(); err != nil {
			fmt.Fprintf(os.Stderr, "argus: 状态落盘失败: %v\n", err)
			m.dirtyMu.Lock()
			m.dirty = true
			m.dirtyMu.Unlock()
		}
	}
}

// PersistPath 返回持久化路径（空 = 纯内存），供启动横幅与运维检查。
func (m *Memory) PersistPath() string { return m.path }
