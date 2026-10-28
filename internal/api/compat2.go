package api

import (
	"net/http"
	"sort"
	"strconv"
	"strings"
)

// 第二批兼容接口：发现页资产树、任务覆盖度、目标、token 统计、流量（当前无录制能力，返回空结构）。
func (s *Server) registerCompat2() {
	s.mux.HandleFunc("GET /api/exploration/findings/asset-tree", s.cFindingAssetTree)
	s.mux.HandleFunc("GET /api/tasks/{id}/coverage", s.cTaskCoverage)
	s.mux.HandleFunc("GET /api/tasks/{id}/goals", s.cTaskGoals)
	s.mux.HandleFunc("GET /api/tasks/{id}/intent-assets", s.cIntentAssets)
	s.mux.HandleFunc("GET /api/exploration/tokens", s.cTokenStats)
	s.mux.HandleFunc("GET /api/traffic", s.cTraffic)
	s.mux.HandleFunc("GET /api/traffic/hosts", s.cTrafficHosts)
}

// 发现页左侧资产树：按 finding 的目标地址聚合（含严重级别分桶）。
// 我们没有 ARTEX 的多级资产层级（企业→根域→子域→服务），所以扁平化到"目标"这一层，
// kind 按 IP / 域名区分，避免出现没有意义的假层级。
func (s *Server) cFindingAssetTree(w http.ResponseWriter, _ *http.Request) {
	type bucket struct {
		total, critical, high, medium, low int
		last                               string
		kind                               string
	}
	m := map[string]*bucket{}
	for _, f := range s.allFindingsList(0) {
		label := f.Target
		if label == "" {
			label = "（未关联资产）"
		}
		b, ok := m[label]
		if !ok {
			kind := "subdomain"
			if _, err := strconv.Atoi(strings.ReplaceAll(label, ".", "")); err == nil {
				kind = "ip"
			}
			b = &bucket{kind: kind}
			m[label] = b
		}
		b.total++
		switch strings.ToLower(f.Severity) {
		case "critical":
			b.critical++
		case "high":
			b.high++
		case "medium":
			b.medium++
		default:
			b.low++
		}
		ts := f.CreatedAt.Format("2006-01-02 15:04:05")
		if ts > b.last {
			b.last = ts
		}
	}

	labels := make([]string, 0, len(m))
	for k := range m {
		labels = append(labels, k)
	}
	sort.Strings(labels)

	nodes := make([]map[string]any, 0, len(labels))
	total := 0
	for _, label := range labels {
		b := m[label]
		total += b.total
		nodes = append(nodes, map[string]any{
			"key": "a:" + label, "kind": b.kind, "label": label,
			"self": b.total, "total": b.total,
			"critical": b.critical, "high": b.high, "medium": b.medium, "low": b.low,
			"last_found_at": b.last,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"nodes": nodes, "finding_total": total, "truncated": false,
	})
}

// 任务覆盖度：分母 = 该任务已确认接触过的资产数，分子 = 其中产出过 fact/finding 的资产数。
// 我们的口径比 ARTEX 更实：只统计"过闸门后真的碰过"的资产，不把扫到的域名算作已测。
func (s *Server) cTaskCoverage(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	assets, _ := s.d.Store.Assets(id, "", 0, 0)
	byType := map[string]int{}
	for _, a := range assets {
		byType[a.Type]++
	}
	testedTypes := map[string]bool{}
	for _, f := range s.d.Store.Findings(id) {
		for _, a := range assets {
			if strings.EqualFold(a.Value, f.Target) {
				testedTypes[a.Type] = true
			}
		}
	}
	tested := 0
	for _, a := range assets {
		if testedTypes[a.Type] {
			tested++
		}
	}
	denominator := len(assets)
	var pct any
	if denominator > 0 {
		pct = int(float64(tested) / float64(denominator) * 100)
	}
	types := make([]string, 0, len(byType))
	for t := range byType {
		types = append(types, t)
	}
	sort.Strings(types)
	byTypeRows := make([]map[string]any, 0, len(types))
	for _, t := range types {
		byTypeRows = append(byTypeRows, map[string]any{
			"type": t, "total": byType[t], "tested": map[bool]int{true: byType[t], false: 0}[testedTypes[t]],
		})
	}
	sc := s.scopeOf(id)
	scopeRows := 0
	if sc != nil {
		scopeRows = sc.Len()
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"enabled": true, "scope_rows": scopeRows,
		"denominator": denominator, "tested": tested, "pct": pct,
		"by_type": byTypeRows,
	})
}

// 任务目标：ARGUS 的 goal 就是任务创建时声明的那一句，这里作为单条 goal 返回。
func (s *Server) cTaskGoals(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	t, ok2 := s.d.Store.GetTask(id)
	if !ok2 {
		writeJSON(w, http.StatusOK, map[string]any{"goals": []any{}})
		return
	}
	goals := []map[string]any{{
		"id": "g1", "text": t.Goal, "state": "open",
		"origin": "task", "ts": t.CreatedAt.Format("2006-01-02 15:04:05"),
	}}
	writeJSON(w, http.StatusOK, map[string]any{"goals": goals})
}

// 意图关联的资产（覆盖图节点抽屉用）：把该任务资产列出来即可。
func (s *Server) cIntentAssets(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	assets, _ := s.d.Store.Assets(id, "", 0, 0)
	out := make([]map[string]any, 0, len(assets))
	for _, a := range assets {
		out = append(out, map[string]any{
			"id": a.ID, "type": a.Type, "domain": a.Value, "ip": a.Value,
			"task_ids": []int64{a.TaskID},
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"assets": out})
}

// token 统计：ARGUS 目前还没有 LLM 计量（规划器尚未接入模型），返回零值结构而不是假数字。
func (s *Server) cTokenStats(w http.ResponseWriter, _ *http.Request) {
	zero := map[string]any{
		"input_tokens": 0, "output_tokens": 0, "cache_read_tokens": 0, "cache_write_tokens": 0,
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"workers": []any{}, "sessions": []any{}, "total": zero,
	})
}

// 流量：ARGUS 没有 MITM 录制（ARTEX 用 8788 代理实现）。这里返回 enabled=false，
// 让前端显示"未启用录制"，而不是 404 或编造数据。
// 流量：来自执行器的真实出站请求录制（不是 MITM 代理，但每条都对应一次真发出去的请求）。
func (s *Server) cTraffic(w http.ResponseWriter, r *http.Request) {
	taskID := qTaskID(r)
	rows := s.d.Store.TrafficRows(taskID, 0)
	page := qInt(r, "page", 0)
	size := qInt(r, "size", 100)
	start := page * size
	if start > len(rows) {
		start = len(rows)
	}
	end := start + size
	if end > len(rows) {
		end = len(rows)
	}
	out := make([]map[string]any, 0, end-start)
	for _, t := range rows[start:end] {
		ctype := t.ContentType
		if ctype == "" && t.Err != "" {
			ctype = "error"
		}
		out = append(out, map[string]any{
			"id": strconv.FormatInt(t.ID, 10), "ts": t.TS.Format("2006-01-02 15:04:05"),
			"host": t.Host, "method": t.Method, "url": t.URL,
			"status": t.Status, "content_type": ctype, "resp_len": t.RespLen,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"enabled": true, "proxy": "",
		"count": len(rows), "total": len(rows),
		"page": page, "size": size, "exchanges": out,
	})
}

func (s *Server) cTrafficHosts(w http.ResponseWriter, r *http.Request) {
	hosts := s.d.Store.TrafficHosts(qTaskID(r))
	out := make([]map[string]any, 0, len(hosts))
	for _, h := range hosts {
		out = append(out, map[string]any{"host": h.Host, "count": h.Count})
	}
	writeJSON(w, http.StatusOK, map[string]any{"hosts": out})
}
