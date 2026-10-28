// Package api 暴露 ARGUS 的 HTTP 接口。
//
// 设计原则：任务创建阶段就必须给出非空授权范围（目标歧义门禁），
// 没有范围的任务不允许创建——把"忘了配范围"从运行期问题变成创建期错误。
package api

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/argus/argus/internal/budget"
	"github.com/argus/argus/internal/dedupe"
	"github.com/argus/argus/internal/engine"
	"github.com/argus/argus/internal/evidence"
	"github.com/argus/argus/internal/gate"
	"github.com/argus/argus/internal/scope"
	"github.com/argus/argus/internal/settings"
	"github.com/argus/argus/internal/store"
)

// Deps 是 API 依赖装配。
type Deps struct {
	Store  store.Store
	Ev     *evidence.Store
	Budget *budget.Budget
	Token  string

	NewGate    func(taskID int64, sc *scope.Scope, sink gate.Sink) *gate.Gate
	NewExec    func(taskID int64, g *gate.Gate) engine.Executor
	NewPlanner func(taskID int64) engine.Planner

	// Settings 为运行期配置（LLM 接入参数）；为 nil 时相关接口返回 500。
	Settings *settings.Store
	// PlannerInfo 返回规划器运行统计（可选）。
	PlannerInfo func() map[string]any
}

// Server 是 HTTP 服务。
type Server struct {
	d Deps

	mu      sync.Mutex
	scopes  map[int64]*scope.Scope
	running map[int64]context.CancelFunc

	mux *http.ServeMux
}

// New 构造服务并注册路由。
func New(d Deps) *Server {
	s := &Server{
		d: d, scopes: map[int64]*scope.Scope{}, running: map[int64]context.CancelFunc{},
		mux: http.NewServeMux(),
	}
	s.mux.HandleFunc("GET /api/health", s.health)
	s.mux.HandleFunc("POST /api/tasks", s.createTask)
	s.mux.HandleFunc("GET /api/tasks", s.listTasks)
	s.mux.HandleFunc("GET /api/tasks/{id}", s.getTask)
	s.mux.HandleFunc("POST /api/tasks/{id}/start", s.startTask)
	s.mux.HandleFunc("POST /api/tasks/{id}/stop", s.stopTask)
	s.mux.HandleFunc("GET /api/tasks/{id}/intents", s.listIntents)
	s.mux.HandleFunc("GET /api/tasks/{id}/findings", s.listFindings)
	s.mux.HandleFunc("GET /api/tasks/{id}/violations", s.listViolations)
	s.mux.HandleFunc("GET /api/tasks/{id}/evidence", s.listEvidence)
	s.mux.HandleFunc("GET /api/findings", s.allFindings)
	s.mux.HandleFunc("GET /api/tasks/{id}/report", s.report)
	s.mux.HandleFunc("GET /api/evidence/{id}", s.getEvidence)
	s.mux.HandleFunc("GET /api/budget", s.getBudget)
	s.registerCompat()
	s.registerCompat2()
	s.registerLLM()
	s.registerFeatures()
	return s
}

// Handler 返回带鉴权中间件的 handler。
func (s *Server) Handler() http.Handler {
	return s.auth(s.mux)
}

func (s *Server) auth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/health" || s.d.Token == "" {
			next.ServeHTTP(w, r)
			return
		}
		tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if tok == "" {
			tok = r.URL.Query().Get("token")
		}
		if subtle.ConstantTimeCompare([]byte(tok), []byte(s.d.Token)) != 1 {
			writeErr(w, http.StatusUnauthorized, "未授权：缺少或错误的 Bearer token")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// ---------- handlers ----------

func (s *Server) health(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true, "service": "argus", "time": time.Now().UTC(),
		"evidence": s.d.Ev.Len(),
	})
}

type createReq struct {
	Name    string         `json:"name"`
	Goal    string         `json:"goal"`
	Scope   []scope.Rule   `json:"scope"`
	Workers int            `json:"workers"`
	Minutes int            `json:"minutes"`
	Seed    []store.Intent `json:"seed"`
}

func (s *Server) createTask(w http.ResponseWriter, r *http.Request) {
	var req createReq
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "请求体不是合法 JSON: "+err.Error())
		return
	}
	if strings.TrimSpace(req.Goal) == "" {
		writeErr(w, http.StatusBadRequest, "goal 不能为空（目标歧义门禁）")
		return
	}
	if len(req.Scope) == 0 {
		writeErr(w, http.StatusBadRequest, "scope 不能为空：未配置授权范围的任务不允许创建")
		return
	}
	sc, err := scope.New(req.Scope)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "范围规则非法: "+err.Error())
		return
	}
	t := store.Task{Name: req.Name, Goal: req.Goal, Workers: req.Workers}
	if req.Minutes > 0 {
		dl := time.Now().UTC().Add(time.Duration(req.Minutes) * time.Minute)
		t.Deadline = &dl
	}
	// 范围必须随任务一起落盘（见 Task.ScopeRules 注释）
	for _, r := range req.Scope {
		t.ScopeRules = append(t.ScopeRules, string(r.Kind)+":"+r.Value)
	}
	saved, err := s.d.Store.CreateTask(t)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.mu.Lock()
	s.scopes[saved.ID] = sc
	s.mu.Unlock()

	s.d.Budget.Apply(budget.DefaultCaps(strconv.FormatInt(saved.ID, 10), "*", time.Now().UTC().Format("2006-01-02")))

	added, skipped := 0, 0
	seen := map[string]bool{}
	for _, it := range req.Seed {
		it.TaskID = saved.ID
		if it.Action == "" {
			it.Action = "Bash"
		}
		// 种子同样过指纹去重：同一 (资产, 动作, 参数签名) 只入图一次。
		fp := dedupe.Fingerprint(it.AssetID, it.Action, it.ParamKey)
		if seen[fp] {
			skipped++
			continue
		}
		seen[fp] = true
		it.FP = fp
		if _, err := s.d.Store.AddIntent(it); err == nil {
			added++
		}
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"task": saved, "scope": sc.Describe(), "seed_intents": added, "seed_deduped": skipped,
	})
}

func (s *Server) listTasks(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"tasks": s.d.Store.ListTasks()})
}

func (s *Server) getTask(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	t, ok2 := s.d.Store.GetTask(id)
	if !ok2 {
		writeErr(w, http.StatusNotFound, "任务不存在")
		return
	}
	s.mu.Lock()
	_, running := s.running[id]
	s.mu.Unlock()
	// 重启后范围来自持久化规则，统一走 scopeOf
	sc := s.scopeOf(id)
	desc := []string{}
	if sc != nil {
		desc = sc.Describe()
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"task": t, "running": running,
		"scope": desc, "intents": len(s.d.Store.Intents(id)),
		"findings":   len(s.d.Store.Findings(id)),
		"violations": len(s.d.Store.Violations(id)),
		"evidence":   len(s.d.Ev.List(id, 0)),
	})
}

func (s *Server) startTask(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	t, ok2 := s.d.Store.GetTask(id)
	if !ok2 {
		writeErr(w, http.StatusNotFound, "任务不存在")
		return
	}
	// 范围可能在进程重启后来自持久化的 ScopeRules（scopeOf 会重建并缓存），
	// 所以必须**在持锁前**取，避免 scopeOf 内部再次加锁造成死锁。
	sc := s.scopeOf(id)
	if sc == nil {
		writeErr(w, http.StatusBadRequest, "任务缺少授权范围，拒绝启动")
		return
	}
	s.mu.Lock()
	if _, running := s.running[id]; running {
		s.mu.Unlock()
		writeErr(w, http.StatusConflict, "任务已在运行")
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	s.running[id] = cancel
	s.mu.Unlock()

	gt := s.d.NewGate(id, sc, s.d.Store)
	exec := s.d.NewExec(id, gt)
	pl := s.d.NewPlanner(id)
	eng := engine.New(s.d.Store, exec, pl, s.d.Budget, engine.DefaultConfig())

	go func() {
		defer func() {
			cancel()
			s.mu.Lock()
			delete(s.running, id)
			s.mu.Unlock()
		}()
		_, _ = eng.RunTask(ctx, t.ID)
	}()

	writeJSON(w, http.StatusAccepted, map[string]any{"started": true, "task_id": id})
}

func (s *Server) stopTask(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	s.mu.Lock()
	cancel, running := s.running[id]
	s.mu.Unlock()
	if !running {
		writeErr(w, http.StatusConflict, "任务未在运行")
		return
	}
	cancel()
	writeJSON(w, http.StatusOK, map[string]any{"stopping": true, "task_id": id})
}

func (s *Server) listIntents(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"intents": s.d.Store.Intents(id)})
}

func (s *Server) listFindings(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"findings": s.d.Store.Findings(id)})
}

func (s *Server) listViolations(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	v := s.d.Store.Violations(id)
	byLayer := map[string]int{}
	for _, x := range v {
		byLayer[string(x.Layer)]++
	}
	writeJSON(w, http.StatusOK, map[string]any{"violations": v, "by_layer": byLayer})
}

// allFindings 返回跨任务的漏洞列表（前端 Findings 页面用）。
func (s *Server) allFindings(w http.ResponseWriter, r *http.Request) {
	out := []store.Finding{}
	for _, t := range s.d.Store.ListTasks() {
		out = append(out, s.d.Store.Findings(t.ID)...)
	}
	writeJSON(w, http.StatusOK, map[string]any{"findings": out, "total": len(out)})
}

func (s *Server) listEvidence(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	limit := 50
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 500 {
			limit = n
		}
	}
	recs := s.d.Ev.List(id, limit)
	writeJSON(w, http.StatusOK, map[string]any{
		"evidence": recs, "total": len(s.d.Ev.List(id, 0)), "verified": s.d.Ev.Verify() == nil,
	})
}

func (s *Server) getEvidence(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	rec, ok := s.d.Ev.Get(id)
	if !ok {
		writeErr(w, http.StatusNotFound, "证据不存在")
		return
	}
	writeJSON(w, http.StatusOK, rec)
}

func (s *Server) getBudget(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"lines":             s.d.Budget.Snapshot(),
		"evidence_verified": s.d.Ev.Verify() == nil,
	})
}

func (s *Server) report(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	t, ok2 := s.d.Store.GetTask(id)
	if !ok2 {
		writeErr(w, http.StatusNotFound, "任务不存在")
		return
	}
	md := s.BuildReport(t, s.scopeOf(t.ID))
	w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(md))
}

// BuildReport 生成可交付的 Markdown 报告（finding 必须带证据才算数）。
func (s *Server) BuildReport(t store.Task, sc *scope.Scope) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# ARGUS 报告：%s\n\n", t.Name)
	fmt.Fprintf(&b, "- 任务 ID：%d\n- 目标：%s\n- 状态：%s\n- 创建时间：%s\n\n",
		t.ID, t.Goal, t.State, t.CreatedAt.Format(time.RFC3339))

	b.WriteString("## 授权范围\n\n")
	if sc == nil || sc.Empty() {
		b.WriteString("_（无范围：按默认拒绝处理）_\n")
	}
	for _, line := range sc.Describe() {
		fmt.Fprintf(&b, "- `%s`\n", line)
	}

	fs := s.d.Store.Findings(t.ID)
	fmt.Fprintf(&b, "\n## 漏洞（%d）\n\n", len(fs))
	if len(fs) == 0 {
		b.WriteString("_无。_\n")
	}
	for _, f := range fs {
		fmt.Fprintf(&b, "### [%s] %s\n\n", f.Severity, f.Title)
		fmt.Fprintf(&b, "- 类别：%s\n- 资产：%s\n- ATT&CK：%s（%s）\n- 证据：`%s`\n",
			f.VulnClass, f.Target, f.Technique, f.Tactic, f.EvidenceID)
		if rec, ok := s.d.Ev.Get(f.EvidenceID); ok {
			fmt.Fprintf(&b, "- 证据时间：%s；哈希：`%s`\n", rec.TS.Format(time.RFC3339), shortHash(rec.Hash))
		}
		s.writeReplay(&b, f)
		b.WriteString("\n")
	}

	vs := s.d.Store.Violations(t.ID)
	fmt.Fprintf(&b, "## 越界拦截（%d）\n\n", len(vs))
	if len(vs) == 0 {
		b.WriteString("_无越界尝试。_\n")
	}
	for _, v := range vs {
		fmt.Fprintf(&b, "- [%s] %s → %s（%s）\n", v.Layer, v.Target, v.Reason, v.Tool)
	}

	// 命令回放：复核人不需要去翻证据库，报告里直接能看到"跑了什么、看到什么"
	cmds := make([]store.Command, 0, 8)
	for _, rec := range s.d.Ev.List(t.ID, 0) {
		if rec.Kind != "command" {
			continue
		}
		var c store.Command
		if err := json.Unmarshal(rec.Payload, &c); err != nil {
			continue
		}
		cmds = append(cmds, c)
	}
	if len(cmds) > 20 {
		cmds = cmds[len(cmds)-20:]
	}
	fmt.Fprintf(&b, "\n## 命令回放（最近 %d 条）\n\n", len(cmds))
	if len(cmds) == 0 {
		b.WriteString("_无。_\n")
	}
	for _, c := range cmds {
		fmt.Fprintf(&b, "```console\n$ %s\n%s\n# exit %d\n```\n\n", c.Input, excerpt(c.Output, 6), c.ExitCode)
	}

	b.WriteString("\n## 探索路径\n\n")
	for _, it := range s.d.Store.Intents(t.ID) {
		fmt.Fprintf(&b, "- #%d [%s] %s\n", it.ID, it.State, it.Summary)
	}
	b.WriteString("\n## 预算\n\n")
	for _, line := range s.d.Budget.Snapshot() {
		fmt.Fprintf(&b, "- %s\n", line)
	}
	return b.String()
}

// writeReplay 给单个漏洞附上"原始命令 + 输出摘录"，让结论可复现。
func (s *Server) writeReplay(b *strings.Builder, f store.Finding) {
	rec, ok := s.d.Ev.Get(f.EvidenceID)
	if !ok {
		return
	}
	var c store.Command
	if err := json.Unmarshal(rec.Payload, &c); err != nil || c.Input == "" {
		return
	}
	fmt.Fprintf(b, "\n#### 证据回放\n\n```console\n$ %s\n%s\n# exit %d\n```\n", c.Input, excerpt(c.Output, 10), c.ExitCode)
}

// excerpt 取输出的前 n 行（超长内容不塞进报告）。
func excerpt(s string, n int) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	if len(lines) > n {
		lines = append(lines[:n], fmt.Sprintf("…（共 %d 行，已截断）", len(lines)))
	}
	out := strings.Join(lines, "\n")
	if len(out) > 2000 {
		out = out[:2000] + "…"
	}
	return out
}

// parseScopeRules 把 "kind:value" 列表还原成范围规则（value 里允许出现冒号，如 URL）。
func parseScopeRules(specs []string) []scope.Rule {
	out := make([]scope.Rule, 0, len(specs))
	for _, s := range specs {
		i := strings.Index(s, ":")
		if i <= 0 || i >= len(s)-1 {
			continue
		}
		out = append(out, scope.Rule{Kind: scope.Kind(s[:i]), Value: s[i+1:]})
	}
	return out
}

// scopeOf 取任务的范围；内存里没有就从持久化的 ScopeRules 重建并缓存。
// 这样重启后闸门、报告、出口白名单看到的范围与创建时完全一致。
func (s *Server) scopeOf(id int64) *scope.Scope {
	s.mu.Lock()
	sc := s.scopes[id]
	s.mu.Unlock()
	if sc != nil {
		return sc
	}
	t, ok := s.d.Store.GetTask(id)
	if !ok || len(t.ScopeRules) == 0 {
		return nil
	}
	rules := parseScopeRules(t.ScopeRules)
	if len(rules) == 0 {
		return nil
	}
	rebuilt, err := scope.New(rules)
	if err != nil {
		return nil
	}
	s.mu.Lock()
	s.scopes[id] = rebuilt
	s.mu.Unlock()
	return rebuilt
}

func shortHash(h string) string {
	if len(h) > 16 {
		return h[:16]
	}
	return h
}

// ---------- helpers ----------

func pathID(w http.ResponseWriter, r *http.Request) (int64, bool) {
	raw := r.PathValue("id")
	id, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || id <= 0 {
		writeErr(w, http.StatusBadRequest, "ID 非法")
		return 0, false
	}
	return id, true
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}
