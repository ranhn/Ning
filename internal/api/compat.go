package api

import (
	"encoding/json"
	"net/http"
	"sort"
	"strconv"
	"strings"

	"github.com/argus/argus/internal/store"
)

// 本文件提供 ARTEX 前端需要、而 ARGUS 领域模型没有直接对应的「兼容接口」。
//
// 设计取舍：**返回值直接就是 ARTEX 原生的形状**（与 frontend 的 lib/types.ts 对齐），
// 这样前端只需要把对应方法从 mock 切到 /argus/*，不需要再做一层字段映射。
// 数据全部来自 ARGUS 自己的 store / evidence —— 没有就返回空，不编造。

func (s *Server) registerCompat() {
	s.mux.HandleFunc("GET /api/stats", s.cStats)
	s.mux.HandleFunc("GET /api/assets", s.cAssets)
	s.mux.HandleFunc("GET /api/assets/counts", s.cAssetCounts)
	s.mux.HandleFunc("GET /api/commands", s.cCommands)
	s.mux.HandleFunc("GET /api/commands/stats", s.cCommandStats)
	s.mux.HandleFunc("GET /api/exploration/intents", s.cIntents)
	s.mux.HandleFunc("GET /api/exploration/activity", s.cActivity)
	s.mux.HandleFunc("GET /api/exploration/graph", s.cGraph)
	s.mux.HandleFunc("GET /api/exploration/findings/stats", s.cFindingStats)
	s.mux.HandleFunc("GET /api/tasks/{id}/scope", s.cTaskScope)
	s.mux.HandleFunc("GET /api/tokens/usage", s.cTokensUsage)
	s.mux.HandleFunc("GET /api/tokens/daily", s.cTokensDaily)
	s.mux.HandleFunc("GET /api/intercept/rules", s.cInterceptRules)
	s.mux.HandleFunc("GET /api/asset-intercept/rules", s.cAssetInterceptRules)
}

func qInt(r *http.Request, key string, def int) int {
	if v := r.URL.Query().Get(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

func qTaskID(r *http.Request) int64 {
	v := r.URL.Query().Get("task")
	if v == "" {
		v = r.URL.Query().Get("task_id")
	}
	n, _ := strconv.ParseInt(v, 10, 64)
	return n
}

// ---- 资产 ----

func (s *Server) cStats(w http.ResponseWriter, r *http.Request) {
	taskID := qTaskID(r)
	counts := s.d.Store.AssetCounts(taskID)
	totalAssets := 0
	for _, n := range counts {
		totalAssets += n
	}
	confirmed := len(s.allFindingsList(taskID))
	engineMode := "idle"
	resp := map[string]any{
		"assets":             totalAssets,
		"engine_mode":        engineMode,
		"llm_configured":     false,
		"roe_enabled":        true,
		"findings_confirmed": confirmed,
	}
	if taskID > 0 {
		if t, ok := s.d.Store.GetTask(taskID); ok {
			if t.State == store.TaskRunning {
				engineMode = "exploring"
				resp["engine_mode"] = engineMode
			}
			resp["active_task"] = map[string]any{
				"id": strconv.FormatInt(t.ID, 10), "name": t.Name,
				"goal": t.Goal, "status": t.State,
			}
		}
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) cAssets(w http.ResponseWriter, r *http.Request) {
	taskID := qTaskID(r)
	typ := r.URL.Query().Get("type")
	limit := qInt(r, "limit", 50)
	offset := qInt(r, "offset", 0)
	list, total := s.d.Store.Assets(taskID, typ, limit, offset)

	out := make([]map[string]any, 0, len(list))
	for _, a := range list {
		item := map[string]any{
			"id":         a.ID,
			"type":       a.Type,
			"task_ids":   []int64{a.TaskID},
			"created_at": a.FirstSeen,
		}
		if a.Type == "ip" {
			item["ip"] = a.Value
		} else {
			item["domain"] = a.Value
		}
		out = append(out, item)
	}
	writeJSON(w, http.StatusOK, map[string]any{"count": len(out), "total": total, "assets": out})
}

func (s *Server) cAssetCounts(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.d.Store.AssetCounts(qTaskID(r)))
}

// ---- 工具执行记录（来自证据链）----

type commandRow struct {
	ID            int64  `json:"id"`
	ExplorationID int64  `json:"exploration_id"`
	Worker        string `json:"worker"`
	Tool          string `json:"tool"`
	Command       string `json:"command"`
	Output        string `json:"output"`
	ExitCode      int    `json:"exit_code"`
	IsError       bool   `json:"is_error"`
	CreatedAt     string `json:"created_at"`
}

func (s *Server) commandRows(taskID int64, needle string) []commandRow {
	rows := make([]commandRow, 0, 32)
	for _, rec := range s.d.Ev.List(taskID, 0) {
		if rec.Kind != "command" {
			continue
		}
		var cmd store.Command
		if err := json.Unmarshal(rec.Payload, &cmd); err != nil {
			continue
		}
		if needle != "" {
			low := strings.ToLower(needle)
			if !strings.Contains(strings.ToLower(cmd.Input), low) && !strings.Contains(strings.ToLower(cmd.Output), low) {
				continue
			}
		}
		rows = append(rows, commandRow{
			ID: rec.Seq, ExplorationID: rec.IntentID, Worker: "worker",
			Tool: cmd.Tool, Command: cmd.Input, Output: cmd.Output,
			ExitCode: cmd.ExitCode, IsError: cmd.ExitCode != 0,
			CreatedAt: rec.TS.Format("2006-01-02 15:04:05"),
		})
	}
	return rows
}

func (s *Server) cCommands(w http.ResponseWriter, r *http.Request) {
	rows := s.commandRows(qTaskID(r), r.URL.Query().Get("q"))
	total := len(rows)
	page := qInt(r, "page", 0)
	size := qInt(r, "size", 50)
	start := page * size
	if start > len(rows) {
		start = len(rows)
	}
	end := start + size
	if end > len(rows) {
		end = len(rows)
	}
	writeJSON(w, http.StatusOK, map[string]any{"commands": rows[start:end], "total": total})
}

func (s *Server) cCommandStats(w http.ResponseWriter, r *http.Request) {
	rows := s.commandRows(qTaskID(r), r.URL.Query().Get("q"))
	type agg struct{ total, errors int }
	m := map[string]*agg{}
	for _, row := range rows {
		a, ok := m[row.Tool]
		if !ok {
			a = &agg{}
			m[row.Tool] = a
		}
		a.total++
		if row.IsError {
			a.errors++
		}
	}
	tools := make([]string, 0, len(m))
	for k := range m {
		tools = append(tools, k)
	}
	sort.Strings(tools)
	stats := make([]map[string]any, 0, len(tools))
	for _, t := range tools {
		stats = append(stats, map[string]any{"tool": t, "total": m[t].total, "errors": m[t].errors})
	}
	writeJSON(w, http.StatusOK, map[string]any{"stats": stats})
}

// ---- 探索图（意图/活动/图）----

func (s *Server) cIntents(w http.ResponseWriter, r *http.Request) {
	taskID := qTaskID(r)
	nodes := make([]map[string]any, 0, 32)
	tasks := s.d.Store.ListTasks()
	for _, t := range tasks {
		if taskID > 0 && t.ID != taskID {
			continue
		}
		for _, it := range s.d.Store.Intents(t.ID) {
			nodes = append(nodes, map[string]any{
				"id":       strconv.FormatInt(it.ID, 10),
				"type":     "intent",
				"payload":  it.Summary,
				"priority": it.Priority,
				"state":    it.State,
				"origin":   it.Owner,
				"ts":       it.UpdatedAt.Format("2006-01-02 15:04:05"),
			})
		}
	}
	writeJSON(w, http.StatusOK, nodes)
}

func (s *Server) cActivity(w http.ResponseWriter, r *http.Request) {
	taskID := qTaskID(r)
	limit := qInt(r, "limit", 100)
	items := make([]map[string]any, 0, 32)
	seq := 0
	tasks := s.d.Store.ListTasks()
	for _, t := range tasks {
		if taskID > 0 && t.ID != taskID {
			continue
		}
		for _, it := range s.d.Store.Intents(t.ID) {
			seq++
			items = append(items, map[string]any{
				"seq": seq, "intent_id": strconv.FormatInt(it.ID, 10),
				"worker": it.Owner, "ts": it.UpdatedAt.Format("2006-01-02 15:04:05"),
				"kind": "text", "summary": it.Summary + " → " + it.State,
			})
		}
		for _, v := range s.d.Store.Violations(t.ID) {
			seq++
			items = append(items, map[string]any{
				"seq": seq, "worker": "gate", "ts": v.TS.Format("2006-01-02 15:04:05"),
				"kind": "text", "summary": "[" + string(v.Layer) + "] 拦截 " + v.Target + "：" + v.Reason,
			})
		}
	}
	if len(items) > limit {
		items = items[len(items)-limit:]
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "cursor": seq})
}

func (s *Server) cGraph(w http.ResponseWriter, r *http.Request) {
	taskID := qTaskID(r)
	nodes := make([]map[string]any, 0, 32)
	edges := make([]map[string]any, 0, 16)
	tasks := s.d.Store.ListTasks()
	for _, t := range tasks {
		if taskID > 0 && t.ID != taskID {
			continue
		}
		for _, it := range s.d.Store.Intents(t.ID) {
			nodes = append(nodes, map[string]any{
				"id": "i" + strconv.FormatInt(it.ID, 10), "type": "intent",
				"payload": it.Summary, "state": it.State, "priority": it.Priority,
				"ts": it.UpdatedAt.Format("2006-01-02 15:04:05"),
			})
		}
		for _, f := range s.d.Store.Findings(t.ID) {
			fid := "f" + strconv.FormatInt(f.ID, 10)
			nodes = append(nodes, map[string]any{
				"id": fid, "type": "finding", "payload": f.Title,
				"state": "confirmed", "ts": f.CreatedAt.Format("2006-01-02 15:04:05"),
			})
			edges = append(edges, map[string]any{
				"id": "e" + fid, "source": "i" + strconv.FormatInt(f.IntentID, 10), "target": fid,
			})
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"nodes": nodes, "edges": edges})
}

// ---- 发现页统计 ----

func (s *Server) allFindingsList(taskID int64) []store.Finding {
	out := []store.Finding{}
	for _, t := range s.d.Store.ListTasks() {
		if taskID > 0 && t.ID != taskID {
			continue
		}
		out = append(out, s.d.Store.Findings(t.ID)...)
	}
	return out
}

func (s *Server) cFindingStats(w http.ResponseWriter, _ *http.Request) {
	fs := s.allFindingsList(0)
	resp := map[string]any{
		"total": len(fs), "pending": 0,
		"critical": 0, "high": 0, "medium": 0, "low": 0,
		"vulnclasses": []string{}, "tasks": []any{},
	}
	classes := map[string]bool{}
	byTask := map[int64]int{}
	for _, f := range fs {
		switch strings.ToLower(f.Severity) {
		case "critical":
			resp["critical"] = resp["critical"].(int) + 1
		case "high":
			resp["high"] = resp["high"].(int) + 1
		case "medium":
			resp["medium"] = resp["medium"].(int) + 1
		default:
			resp["low"] = resp["low"].(int) + 1
		}
		if f.VulnClass != "" {
			classes[f.VulnClass] = true
		}
		byTask[f.TaskID]++
	}
	cl := make([]string, 0, len(classes))
	for k := range classes {
		cl = append(cl, k)
	}
	sort.Strings(cl)
	resp["vulnclasses"] = cl

	tasks := make([]map[string]any, 0, len(byTask))
	for id, n := range byTask {
		name := ""
		if t, ok := s.d.Store.GetTask(id); ok {
			name = t.Name
		}
		tasks = append(tasks, map[string]any{
			"id": strconv.FormatInt(id, 10), "name": name, "description": "", "count": n,
		})
	}
	sort.Slice(tasks, func(i, j int) bool { return tasks[i]["name"].(string) < tasks[j]["name"].(string) })
	resp["tasks"] = tasks
	writeJSON(w, http.StatusOK, resp)
}

// ---- 任务授权范围（真实数据）----

func (s *Server) cTaskScope(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	sc := s.scopeOf(id)
	rows := []map[string]any{}
	if sc != nil {
		for i, rule := range sc.Rules() {
			rows = append(rows, map[string]any{
				"id": i + 1, "kind": string(rule.Kind), "value": rule.Value,
				"reason": "任务创建时声明",
			})
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"scope": rows})
}

// ---- token / 规则（当前没有对应数据，返回空结构而不是假数据）----

func (s *Server) cTokensUsage(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"by_profile": []any{}, "daily": []any{}})
}

func (s *Server) cTokensDaily(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, []any{})
}

func (s *Server) cInterceptRules(w http.ResponseWriter, _ *http.Request) {
	rules := s.d.Store.Rules()
	out := make([]map[string]any, 0, len(rules))
	for _, r := range rules {
		out = append(out, map[string]any{
			"id": r.ID, "name": r.Name, "enabled": r.Enabled, "priority": 0,
			"match_target": r.MatchTarget, "match_type": r.MatchType,
			"pattern": r.Pattern, "action": r.Action, "message": r.Message,
			"timeout_enabled": false, "timeout_seconds": 0, "timeout_action": "deny",
			"created_at": r.CreatedAt, "updated_at": r.CreatedAt,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"rules": out})
}

func (s *Server) cAssetInterceptRules(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"rules": []any{}})
}
