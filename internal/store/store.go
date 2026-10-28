// Package store 定义 ARGUS 的领域模型与存储接口。
//
// 生产实现应换成 PostgreSQL（见 schema.sql），但接口在这里定死，
// 让调度器、闸门、API 都不依赖具体数据库。
package store

import (
	"errors"
	"sync"
	"time"

	"github.com/Autumn-27/artex/internal/gate"
)

// 任务与意图的状态机。intent: open → running → done/blocked/exhausted。
const (
	TaskPending = "pending"
	TaskRunning = "running"
	TaskDone    = "done"
	TaskStopped = "stopped"

	IntentOpen      = "open"
	IntentRunning   = "running"
	IntentDone      = "done"
	IntentBlocked   = "blocked"
	IntentExhausted = "exhausted"
)

// ErrNotFound 表示对象不存在。
var ErrNotFound = errors.New("对象不存在")

// Task 是一次授权的测试任务。
type Task struct {
	ID        int64      `json:"id"`
	Name      string     `json:"name"`
	Goal      string     `json:"goal"`
	State     string     `json:"state"`
	CreatedAt time.Time  `json:"created_at"`
	Deadline  *time.Time `json:"deadline,omitempty"`
	Workers   int        `json:"workers"`
	// ScopeRules 是任务创建时声明的授权范围（"kind:value" 形式）。
	// 必须持久化：否则进程重启后任务还在、范围没了，闸门会按"空范围=默认拒绝"把一切拦下，
	// 报告与出口白名单也会变成空——这是"看起来正常、实际失忆"的最坏情况。
	ScopeRules []string `json:"scope_rules,omitempty"`
}

// Intent 是一条待执行的意图（探索图的节点）。
type Intent struct {
	ID        int64     `json:"id"`
	TaskID    int64     `json:"task_id"`
	Summary   string    `json:"summary"`
	Action    string    `json:"action"`
	AssetID   int64     `json:"asset_id"`
	ParamKey  string    `json:"param_key"`
	Target    string    `json:"target,omitempty"`
	VulnClass string    `json:"vuln_class,omitempty"`
	Severity  string    `json:"severity,omitempty"`
	FP        string    `json:"fp"`
	State     string    `json:"state"`
	Owner     string    `json:"owner,omitempty"`
	Priority  int       `json:"priority"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// Finding 是一条漏洞结论。必须先有证据才能入库（EvidenceID 非空）。
type Finding struct {
	ID         int64     `json:"id"`
	TaskID     int64     `json:"task_id"`
	IntentID   int64     `json:"intent_id"`
	VulnClass  string    `json:"vuln_class"`
	Severity   string    `json:"severity"`
	Title      string    `json:"title"`
	Target     string    `json:"target"`
	EvidenceID string    `json:"evidence_id"`
	Technique  string    `json:"technique"`
	Tactic     string    `json:"tactic"`
	Status     string    `json:"status"` // confirmed | fixed | false_positive | risk_accepted
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

// Command 是一次工具执行的记录（证据的一部分）。
type Command struct {
	Tool     string `json:"tool"`
	Input    string `json:"input"`
	Output   string `json:"output"`
	ExitCode int    `json:"exit_code"`
	Millis   int64  `json:"millis"`
}

// Store 是全部持久化能力的接口。
type Store interface {
	CreateTask(Task) (Task, error)
	GetTask(int64) (Task, bool)
	ListTasks() []Task
	SetTaskState(int64, string) bool

	AddIntent(Intent) (Intent, error)
	Frontier(taskID int64, limit int) []Intent
	ClaimIntent(taskID, id int64, owner string) bool
	CompleteIntent(id int64, state string) bool
	ActiveIntents(taskID int64) int
	Intents(taskID int64) []Intent

	AddFinding(Finding) (Finding, error)
	Findings(taskID int64) []Finding

	RecordViolation(gate.Violation)
	Violations(taskID int64) []gate.Violation

	// 资产：过闸门后记录到的真实目标（前端"资产"页用）
	UpsertAsset(taskID int64, typ, value string) Asset
	Assets(taskID int64, typ string, limit, offset int) ([]Asset, int)
	AssetCounts(taskID int64) map[string]int

	// DeleteTask 删除任务及其派生物（意图/漏洞/资产）
	DeleteTask(id int64) bool
	// ReconcileRunning 启动时把上次未跑完的任务标记为 stopped
	ReconcileRunning() int

	// facts：知识层（ARTEX 双图里的 fact 节点）
	AddFact(Fact) (Fact, error)
	Facts(taskID int64) []Fact

	// traffic：真实 HTTP 录制
	AddTraffic(Traffic) (Traffic, error)
	TrafficRows(taskID int64, limit int) []Traffic
	TrafficHosts(taskID int64) []TrafficHost
	GetTraffic(id int64) (Traffic, bool)

	// 发现生命周期
	GetFinding(id int64) (Finding, bool)
	UpdateFinding(id int64, fn func(*Finding)) bool
	AddRetest(Retest) Retest
	Retests(findingID int64) []Retest

	// 拦截规则 + 审批队列
	AddRule(Rule) Rule
	Rules() []Rule
	UpdateRule(id int64, fn func(*Rule)) bool
	DeleteRule(id int64) bool
	AddApproval(Approval) Approval
	Approvals(taskID int64, limit int) []Approval
	PendingApprovals() []Approval
	DecideApproval(id int64, decision, reason string) bool
}

// Memory 是并发安全的内存实现，用于开发、演示与单测。
type Memory struct {
	mu          sync.Mutex
	tasks       map[int64]Task
	taskOrder   []int64
	intents     map[int64]Intent
	intentOrder []int64
	findings    map[int64][]Finding
	violations  []gate.Violation
	assets      map[string]*Asset
	assetOrder  []string
	seqTask     int64
	seqIntent   int64
	seqFinding  int64
	seqAsset    int64

	facts      []Fact
	traffic    []Traffic
	retests    []Retest
	rules      []Rule
	approvals  []Approval
	seqFact    int64
	seqTraffic int64
	seqRetest  int64
	seqRule    int64
	seqApprove int64

	// 持久化（见 persist.go）：path 为空表示纯内存
	path    string
	dirtyMu sync.Mutex
	dirty   bool
}

// NewMemory 构造空存储。
func NewMemory() *Memory {
	return &Memory{
		tasks:    map[int64]Task{},
		intents:  map[int64]Intent{},
		findings: map[int64][]Finding{},
		assets:   map[string]*Asset{},
	}
}

// CreateTask 新建任务并返回带 ID 的对象。
func (m *Memory) CreateTask(t Task) (Task, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.seqTask++
	t.ID = m.seqTask
	if t.State == "" {
		t.State = TaskPending
	}
	if t.CreatedAt.IsZero() {
		t.CreatedAt = time.Now().UTC()
	}
	m.tasks[t.ID] = t
	m.taskOrder = append(m.taskOrder, t.ID)
	m.touch()
	return t, nil
}

// GetTask 取任务。
func (m *Memory) GetTask(id int64) (Task, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	t, ok := m.tasks[id]
	return t, ok
}

// ListTasks 列出全部任务（新→旧）。
func (m *Memory) ListTasks() []Task {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Task, 0, len(m.taskOrder))
	for i := len(m.taskOrder) - 1; i >= 0; i-- {
		out = append(out, m.tasks[m.taskOrder[i]])
	}
	return out
}

// SetTaskState 更新任务状态。
func (m *Memory) SetTaskState(id int64, state string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	t, ok := m.tasks[id]
	if !ok {
		return false
	}
	t.State = state
	m.tasks[id] = t
	m.touch()
	return true
}

// AddIntent 新增意图。
func (m *Memory) AddIntent(it Intent) (Intent, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.tasks[it.TaskID]; !ok {
		return Intent{}, ErrNotFound
	}
	m.seqIntent++
	it.ID = m.seqIntent
	if it.State == "" {
		it.State = IntentOpen
	}
	now := time.Now().UTC()
	it.CreatedAt, it.UpdatedAt = now, now
	m.intents[it.ID] = it
	m.intentOrder = append(m.intentOrder, it.ID)
	m.touch()
	return it, nil
}

// Frontier 返回可领取的意图（priority 高优先，其次 FIFO）。
// 返回的是快照，领取仍需走 ClaimIntent 的 CAS。
func (m *Memory) Frontier(taskID int64, limit int) []Intent {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []Intent
	for _, id := range m.intentOrder {
		it := m.intents[id]
		if it.TaskID != taskID || it.State != IntentOpen {
			continue
		}
		out = append(out, it)
	}
	for i := 1; i < len(out); i++ {
		for j := i; j > 0; j-- {
			if out[j].Priority > out[j-1].Priority ||
				(out[j].Priority == out[j-1].Priority && out[j].ID < out[j-1].ID) {
				out[j], out[j-1] = out[j-1], out[j]
				continue
			}
			break
		}
	}
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out
}

// ClaimIntent 用 CAS 语义领取意图：只有 open 才能变成 running。
// 并发正确性完全由这把锁 + 状态判断保证（生产实现对应
// UPDATE ... WHERE state='open' 的 RowsAffected==1）。
func (m *Memory) ClaimIntent(taskID, id int64, owner string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	it, ok := m.intents[id]
	if !ok || it.TaskID != taskID || it.State != IntentOpen {
		return false
	}
	it.State = IntentRunning
	it.Owner = owner
	it.UpdatedAt = time.Now().UTC()
	m.intents[id] = it
	m.touch()
	return true
}

// CompleteIntent 把 running 的意图置为终态。
func (m *Memory) CompleteIntent(id int64, state string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	it, ok := m.intents[id]
	if !ok || it.State != IntentRunning {
		return false
	}
	it.State = state
	it.UpdatedAt = time.Now().UTC()
	m.intents[id] = it
	m.touch()
	return true
}

// ActiveIntents 统计 open + running 的数量。
func (m *Memory) ActiveIntents(taskID int64) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for _, it := range m.intents {
		if it.TaskID == taskID && (it.State == IntentOpen || it.State == IntentRunning) {
			n++
		}
	}
	return n
}

// Intents 返回任务的全部意图（旧→新）。
func (m *Memory) Intents(taskID int64) []Intent {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Intent, 0, len(m.intentOrder))
	for _, id := range m.intentOrder {
		if it := m.intents[id]; it.TaskID == taskID {
			out = append(out, it)
		}
	}
	return out
}

// AddFinding 登记漏洞。证据缺失时拒绝（"没有证据不算结论"）。
func (m *Memory) AddFinding(f Finding) (Finding, error) {
	if f.EvidenceID == "" {
		return Finding{}, errors.New("finding 必须绑定证据（evidence_id 为空）")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.seqFinding++
	f.ID = m.seqFinding
	if f.Status == "" {
		f.Status = "confirmed"
	}
	if f.CreatedAt.IsZero() {
		f.CreatedAt = time.Now().UTC()
	}
	f.UpdatedAt = f.CreatedAt
	m.findings[f.TaskID] = append(m.findings[f.TaskID], f)
	m.touch()
	return f, nil
}

// Findings 返回任务的漏洞列表。
func (m *Memory) Findings(taskID int64) []Finding {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Finding, len(m.findings[taskID]))
	copy(out, m.findings[taskID])
	return out
}

// RecordViolation 实现 gate.Sink。
func (m *Memory) RecordViolation(v gate.Violation) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if v.TS.IsZero() {
		v.TS = time.Now().UTC()
	}
	m.violations = append(m.violations, v)
	m.touch()
}

// Violations 返回任务的越界记录。
func (m *Memory) Violations(taskID int64) []gate.Violation {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]gate.Violation, 0, len(m.violations))
	for _, v := range m.violations {
		// 严格按任务过滤：TaskID==0 的旧记录（早期版本没带任务号）
		// 不能再混进每个任务的视图，否则历史越界会永远挂在新任务下面。
		if v.TaskID == taskID && taskID > 0 {
			out = append(out, v)
		}
	}
	return out
}
