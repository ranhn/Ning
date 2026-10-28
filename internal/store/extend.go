package store

import (
	"errors"
	"sort"
	"time"
)

// ---------- facts：知识层 ----------
//
// ARTEX 的"双图"里，fact 是把"意图执行结果"沉淀成可复用知识的那一层。
// ARGUS 之前只有 intent，缺少事实，导致规划器每轮都在重复探索。
type Fact struct {
	ID        int64     `json:"id"`
	TaskID    int64     `json:"task_id"`
	IntentID  int64     `json:"intent_id"`
	Kind      string    `json:"kind"` // reachable | tech | credential | endpoint | note
	Text      string    `json:"text"`
	CreatedAt time.Time `json:"created_at"`
}

// AddFact 追加事实（同一任务里文本重复的会被忽略，避免污染知识层）。
func (m *Memory) AddFact(f Fact) (Fact, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if f.TaskID == 0 || f.Text == "" {
		return Fact{}, errors.New("fact 需要 task_id 与 text")
	}
	for _, old := range m.facts {
		if old.TaskID == f.TaskID && old.Text == f.Text {
			return old, nil
		}
	}
	m.seqFact++
	f.ID = m.seqFact
	if f.Kind == "" {
		f.Kind = "note"
	}
	if f.CreatedAt.IsZero() {
		f.CreatedAt = time.Now().UTC()
	}
	m.facts = append(m.facts, f)
	m.touch()
	return f, nil
}

// Facts 返回任务的（或全量的）事实，按时间正序。
func (m *Memory) Facts(taskID int64) []Fact {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Fact, 0, len(m.facts))
	for _, f := range m.facts {
		if taskID == 0 || f.TaskID == taskID {
			out = append(out, f)
		}
	}
	return out
}

// ---------- traffic：真实 HTTP 录制 ----------

// Traffic 是一次真实出站请求的记录（只在闸门放行后才会产生）。
type Traffic struct {
	ID          int64     `json:"id"`
	TaskID      int64     `json:"task_id"`
	IntentID    int64     `json:"intent_id"`
	Method      string    `json:"method"`
	URL         string    `json:"url"`
	Host        string    `json:"host"`
	Status      int       `json:"status"`
	ReqBody     string    `json:"req_body"`
	RespBody    string    `json:"resp_body"`
	ContentType string    `json:"content_type"`
	RespLen     int       `json:"resp_len"`
	Err         string    `json:"err,omitempty"`
	TS          time.Time `json:"ts"`
}

// TrafficHost 是一个被访问过的主机及次数。
type TrafficHost struct {
	Host  string `json:"host"`
	Count int    `json:"count"`
}

// AddTraffic 记录一次请求。
func (m *Memory) AddTraffic(t Traffic) (Traffic, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.seqTraffic++
	t.ID = m.seqTraffic
	if t.TS.IsZero() {
		t.TS = time.Now().UTC()
	}
	m.traffic = append(m.traffic, t)
	m.touch()
	return t, nil
}

// TrafficRows 返回最近的流量（新→旧）。
func (m *Memory) TrafficRows(taskID int64, limit int) []Traffic {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Traffic, 0, 32)
	for i := len(m.traffic) - 1; i >= 0; i-- {
		t := m.traffic[i]
		if taskID > 0 && t.TaskID != taskID {
			continue
		}
		out = append(out, t)
		if limit > 0 && len(out) >= limit {
			break
		}
	}
	return out
}

// TrafficHosts 汇总主机访问次数（降序）。
func (m *Memory) TrafficHosts(taskID int64) []TrafficHost {
	m.mu.Lock()
	defer m.mu.Unlock()
	counts := map[string]int{}
	for _, t := range m.traffic {
		if taskID > 0 && t.TaskID != taskID {
			continue
		}
		if t.Host != "" {
			counts[t.Host]++
		}
	}
	out := make([]TrafficHost, 0, len(counts))
	for h, n := range counts {
		out = append(out, TrafficHost{Host: h, Count: n})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Count > out[j].Count })
	return out
}

// GetTraffic 按 ID 取一条（详情页用）。
func (m *Memory) GetTraffic(id int64) (Traffic, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, t := range m.traffic {
		if t.ID == id {
			return t, true
		}
	}
	return Traffic{}, false
}

// ---------- 发现生命周期 ----------

// GetFinding 按 ID 取漏洞。
func (m *Memory) GetFinding(id int64) (Finding, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, list := range m.findings {
		for _, f := range list {
			if f.ID == id {
				return f, true
			}
		}
	}
	return Finding{}, false
}

// UpdateFinding 就地修改（状态/严重级别/标题）。
func (m *Memory) UpdateFinding(id int64, fn func(*Finding)) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	for tid, list := range m.findings {
		for i := range list {
			if list[i].ID == id {
				fn(&list[i])
				list[i].UpdatedAt = time.Now().UTC()
				m.findings[tid] = list
				m.touch()
				return true
			}
		}
	}
	return false
}

// Retest 是一次复测请求（针对已确认漏洞）。
type Retest struct {
	ID        int64     `json:"id"`
	FindingID int64     `json:"finding_id"`
	TaskID    int64     `json:"task_id"`
	IntentID  int64     `json:"intent_id"`
	State     string    `json:"state"` // pending | running | passed | failed
	Note      string    `json:"note"`
	CreatedAt time.Time `json:"created_at"`
}

// AddRetest 登记复测。
func (m *Memory) AddRetest(r Retest) Retest {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.seqRetest++
	r.ID = m.seqRetest
	if r.State == "" {
		r.State = "pending"
	}
	if r.CreatedAt.IsZero() {
		r.CreatedAt = time.Now().UTC()
	}
	m.retests = append(m.retests, r)
	m.touch()
	return r
}

// Retests 返回某漏洞的复测记录（0 = 全部）。
func (m *Memory) Retests(findingID int64) []Retest {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Retest, 0, 8)
	for _, r := range m.retests {
		if findingID == 0 || r.FindingID == findingID {
			out = append(out, r)
		}
	}
	return out
}

// ---------- 拦截规则 + 审批 ----------
//
// 与 ARTEX 的差别：ARTEX 的规则是"唯一防线"，我们的规则是**闸门之上的附加层**。
// 也就是说：规则全部删掉，三层范围闸门依然生效——这是刻意的纵深设计。
type Rule struct {
	ID          int64     `json:"id"`
	Name        string    `json:"name"`
	Enabled     bool      `json:"enabled"`
	Action      string    `json:"action"`       // deny | ask | allow
	MatchTarget string    `json:"match_target"` // tool_name | tool_input
	MatchType   string    `json:"match_type"`   // string | regex
	Pattern     string    `json:"pattern"`
	Message     string    `json:"message"`
	CreatedAt   time.Time `json:"created_at"`
}

// Approval 是一次待人工裁决的调用（action=ask 时产生）。
type Approval struct {
	ID        int64     `json:"id"`
	TaskID    int64     `json:"task_id"`
	IntentID  int64     `json:"intent_id"`
	RuleID    int64     `json:"rule_id"`
	Tool      string    `json:"tool"`
	Input     string    `json:"input"`
	Decision  string    `json:"decision"` // pending | allowed | denied
	Reason    string    `json:"reason"`
	CreatedAt time.Time `json:"created_at"`
}

// AddRule 新增规则。
func (m *Memory) AddRule(r Rule) Rule {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.seqRule++
	r.ID = m.seqRule
	if r.CreatedAt.IsZero() {
		r.CreatedAt = time.Now().UTC()
	}
	if r.MatchTarget == "" {
		r.MatchTarget = "tool_input"
	}
	if r.MatchType == "" {
		r.MatchType = "regex"
	}
	if r.Action == "" {
		r.Action = "deny"
	}
	m.rules = append(m.rules, r)
	m.touch()
	return r
}

// Rules 返回全部规则。
func (m *Memory) Rules() []Rule {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Rule, len(m.rules))
	copy(out, m.rules)
	return out
}

// UpdateRule 修改规则。
func (m *Memory) UpdateRule(id int64, fn func(*Rule)) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i := range m.rules {
		if m.rules[i].ID == id {
			fn(&m.rules[i])
			m.touch()
			return true
		}
	}
	return false
}

// DeleteRule 删除规则。
func (m *Memory) DeleteRule(id int64) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i := range m.rules {
		if m.rules[i].ID == id {
			m.rules = append(m.rules[:i], m.rules[i+1:]...)
			m.touch()
			return true
		}
	}
	return false
}

// AddApproval 入队一条待审批。
func (m *Memory) AddApproval(a Approval) Approval {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.seqApprove++
	a.ID = m.seqApprove
	if a.Decision == "" {
		a.Decision = "pending"
	}
	if a.CreatedAt.IsZero() {
		a.CreatedAt = time.Now().UTC()
	}
	m.approvals = append(m.approvals, a)
	m.touch()
	return a
}

// Approvals 返回审批记录（新→旧）。
func (m *Memory) Approvals(taskID int64, limit int) []Approval {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Approval, 0, 16)
	for i := len(m.approvals) - 1; i >= 0; i-- {
		a := m.approvals[i]
		if taskID > 0 && a.TaskID != taskID {
			continue
		}
		out = append(out, a)
		if limit > 0 && len(out) >= limit {
			break
		}
	}
	return out
}

// PendingApprovals 只返回待裁决的。
func (m *Memory) PendingApprovals() []Approval {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Approval, 0, 8)
	for _, a := range m.approvals {
		if a.Decision == "pending" {
			out = append(out, a)
		}
	}
	return out
}

// DecideApproval 裁决。
func (m *Memory) DecideApproval(id int64, decision, reason string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if decision != "allowed" && decision != "denied" {
		return false
	}
	for i := range m.approvals {
		if m.approvals[i].ID == id && m.approvals[i].Decision == "pending" {
			m.approvals[i].Decision = decision
			m.approvals[i].Reason = reason
			m.touch()
			return true
		}
	}
	return false
}
