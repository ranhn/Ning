package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/argus/argus/internal/attack"
	"github.com/argus/argus/internal/egress"
	"github.com/argus/argus/internal/store"
)

// 第三批接口：知识层 / 流量详情 / 发现生命周期 / 规则与审批 / Skill 注册表。
func (s *Server) registerFeatures() {
	s.mux.HandleFunc("GET /api/exploration/facts", s.fFacts)
	s.mux.HandleFunc("GET /api/traffic/exchange", s.fTrafficExchange)

	s.mux.HandleFunc("PATCH /api/findings/{id}", s.fPatchFinding)
	s.mux.HandleFunc("GET /api/findings/{id}/retests", s.fListRetests)
	s.mux.HandleFunc("POST /api/findings/{id}/retests", s.fCreateRetest)
	s.mux.HandleFunc("GET /api/findings/{id}/sigma", s.fSigma)
	s.mux.HandleFunc("GET /api/exploration/findings/export", s.fExportFindings)

	s.mux.HandleFunc("POST /api/intercept/rules", s.fCreateRule)
	s.mux.HandleFunc("PUT /api/intercept/rules/{id}", s.fUpdateRule)
	s.mux.HandleFunc("DELETE /api/intercept/rules/{id}", s.fDeleteRule)
	s.mux.HandleFunc("GET /api/intercept/pending", s.fPending)
	s.mux.HandleFunc("POST /api/intercept/pending/{id}/decide", s.fDecide)
	s.mux.HandleFunc("GET /api/intercept/history", s.fHistory)

	s.mux.HandleFunc("GET /api/skills", s.fSkills)
	s.mux.HandleFunc("GET /api/tasks/{id}/egress", s.fEgress)
}

// fEgress 把任务的授权范围翻译成出口网关白名单（与闸门同源，不是手写）。
func (s *Server) fEgress(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	al := egress.FromScope(s.scopeOf(id))
	writeJSON(w, http.StatusOK, map[string]any{
		"domains":    al.Domains,
		"nets":       al.Nets,
		"squid_conf": al.SquidConf(),
		"hosts_file": al.HostsFile(),
	})
}

// ---- 知识层 ----

func (s *Server) fFacts(w http.ResponseWriter, r *http.Request) {
	facts := s.d.Store.Facts(qTaskID(r))
	out := make([]map[string]any, 0, len(facts))
	for _, f := range facts {
		out = append(out, map[string]any{
			"id": f.ID, "task_id": f.TaskID, "intent_id": f.IntentID,
			"kind": f.Kind, "text": f.Text, "ts": f.CreatedAt.Format("2006-01-02 15:04:05"),
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"facts": out, "total": len(out)})
}

// ---- 流量详情 ----

func (s *Server) fTrafficExchange(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.URL.Query().Get("id"), 10, 64)
	t, ok := s.d.Store.GetTraffic(id)
	if !ok {
		writeErr(w, http.StatusNotFound, "流量记录不存在")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"id": t.ID, "ts": t.TS, "method": t.Method, "url": t.URL, "host": t.Host,
		"status": t.Status, "content_type": t.ContentType,
		"req": t.ReqBody, "resp": t.RespBody, "resp_len": t.RespLen, "err": t.Err,
	})
}

// ---- 发现生命周期 ----

// PATCH /api/findings/{id}：只允许改 status / severity / title（证据不可改）。
func (s *Server) fPatchFinding(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	var in struct {
		Status   string `json:"status"`
		Severity string `json:"severity"`
		Title    string `json:"title"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&in); err != nil {
		writeErr(w, http.StatusBadRequest, "请求体非法: "+err.Error())
		return
	}
	if in.Status != "" && !validFindingStatus(in.Status) {
		writeErr(w, http.StatusBadRequest, "status 非法（confirmed|fixed|false_positive|risk_accepted）")
		return
	}
	if in.Severity != "" && !validSeverity(in.Severity) {
		writeErr(w, http.StatusBadRequest, "severity 非法（critical|high|medium|low）")
		return
	}
	ok2 := s.d.Store.UpdateFinding(id, func(f *store.Finding) {
		if in.Status != "" {
			f.Status = in.Status
		}
		if in.Severity != "" {
			f.Severity = in.Severity
		}
		if in.Title != "" {
			f.Title = in.Title
		}
	})
	if !ok2 {
		writeErr(w, http.StatusNotFound, "漏洞不存在")
		return
	}
	f, _ := s.d.Store.GetFinding(id)
	writeJSON(w, http.StatusOK, f)
}

func validFindingStatus(s string) bool {
	switch s {
	case "confirmed", "fixed", "false_positive", "risk_accepted":
		return true
	}
	return false
}

func validSeverity(s string) bool {
	switch strings.ToLower(s) {
	case "critical", "high", "medium", "low":
		return true
	}
	return false
}

func (s *Server) fListRetests(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"retests": s.d.Store.Retests(id)})
}

// POST /api/findings/{id}/retests：把复测变成一条真实意图（重新过闸门、重新取证）。
func (s *Server) fCreateRetest(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	f, ok2 := s.d.Store.GetFinding(id)
	if !ok2 {
		writeErr(w, http.StatusNotFound, "漏洞不存在")
		return
	}
	var in struct {
		Notes string `json:"notes"`
	}
	_ = json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&in)

	it, err := s.d.Store.AddIntent(store.Intent{
		TaskID: f.TaskID, Action: "Bash", Summary: f.Target, Target: f.Target,
		ParamKey: "retest:" + strconv.FormatInt(f.ID, 10) + ":" + strconv.FormatInt(time.Now().Unix(), 10),
		Priority: 5,
	})
	if err != nil {
		writeErr(w, http.StatusBadRequest, "创建复测意图失败: "+err.Error())
		return
	}
	rt := s.d.Store.AddRetest(store.Retest{
		FindingID: f.ID, TaskID: f.TaskID, IntentID: it.ID, State: "pending", Note: in.Notes,
	})
	writeJSON(w, http.StatusCreated, rt)
}

// GET /api/findings/{id}/sigma：导出该漏洞的 Sigma 检测草稿（紫队闭环）。
func (s *Server) fSigma(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	f, ok2 := s.d.Store.GetFinding(id)
	if !ok2 {
		writeErr(w, http.StatusNotFound, "漏洞不存在")
		return
	}
	tech, _ := attack.Map(f.VulnClass)
	draft := attack.SigmaDraft(tech, f.VulnClass, f.Target, f.EvidenceID)
	w.Header().Set("Content-Type", "text/yaml; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="sigma-%d.yml"`, f.ID))
	_, _ = w.Write([]byte(draft))
}

// GET /api/exploration/findings/export?format=md|json|csv
func (s *Server) fExportFindings(w http.ResponseWriter, r *http.Request) {
	format := strings.ToLower(r.URL.Query().Get("format"))
	fs := s.allFindingsList(0)
	switch format {
	case "json", "":
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="findings.json"`)
		_ = json.NewEncoder(w).Encode(map[string]any{"findings": fs, "total": len(fs)})
	case "csv":
		var b strings.Builder
		b.WriteString("id,task_id,severity,status,vuln_class,target,technique,tactic,evidence_id,title\n")
		for _, f := range fs {
			fmt.Fprintf(&b, "%d,%d,%s,%s,%q,%q,%s,%s,%s,%q\n",
				f.ID, f.TaskID, f.Severity, f.Status, f.VulnClass, f.Target, f.Technique, f.Tactic, f.EvidenceID, f.Title)
		}
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="findings.csv"`)
		_, _ = w.Write([]byte(b.String()))
	case "md":
		var b strings.Builder
		fmt.Fprintf(&b, "# ARGUS 漏洞导出\n\n共 %d 条。\n\n", len(fs))
		for _, f := range fs {
			fmt.Fprintf(&b, "## [%s] %s\n\n", f.Severity, f.Title)
			fmt.Fprintf(&b, "- 类别：%s\n- 资产：%s\n- 状态：%s\n- ATT&CK：%s（%s）\n- 证据：`%s`\n\n",
				f.VulnClass, f.Target, f.Status, f.Technique, f.Tactic, f.EvidenceID)
		}
		w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="findings.md"`)
		_, _ = w.Write([]byte(b.String()))
	default:
		writeErr(w, http.StatusBadRequest, "format 仅支持 md|json|csv")
	}
}

// ---- 拦截规则 ----

func (s *Server) fCreateRule(w http.ResponseWriter, r *http.Request) {
	var in store.Rule
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&in); err != nil {
		writeErr(w, http.StatusBadRequest, "请求体非法: "+err.Error())
		return
	}
	if in.Name == "" || in.Pattern == "" {
		writeErr(w, http.StatusBadRequest, "name 与 pattern 必填")
		return
	}
	if in.Action != "" && in.Action != "deny" && in.Action != "ask" && in.Action != "allow" {
		writeErr(w, http.StatusBadRequest, "action 仅支持 deny|ask|allow")
		return
	}
	if strings.EqualFold(in.MatchType, "regex") {
		if _, err := regexp.Compile(in.Pattern); err != nil {
			writeErr(w, http.StatusBadRequest, "正则非法: "+err.Error())
			return
		}
	}
	in.Enabled = true
	writeJSON(w, http.StatusCreated, s.d.Store.AddRule(in))
}

func (s *Server) fUpdateRule(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	var in store.Rule
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&in); err != nil {
		writeErr(w, http.StatusBadRequest, "请求体非法: "+err.Error())
		return
	}
	if !s.d.Store.UpdateRule(id, func(x *store.Rule) {
		if in.Name != "" {
			x.Name = in.Name
		}
		if in.Pattern != "" {
			x.Pattern = in.Pattern
		}
		if in.Action != "" {
			x.Action = in.Action
		}
		if in.MatchTarget != "" {
			x.MatchTarget = in.MatchTarget
		}
		if in.MatchType != "" {
			x.MatchType = in.MatchType
		}
		if in.Message != "" {
			x.Message = in.Message
		}
		x.Enabled = in.Enabled
	}) {
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
		return
	}
	writeErr(w, http.StatusNotFound, "规则不存在")
}

func (s *Server) fDeleteRule(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	if s.d.Store.DeleteRule(id) {
		writeJSON(w, http.StatusOK, map[string]any{"deleted": id})
		return
	}
	writeErr(w, http.StatusNotFound, "规则不存在")
}

// ---- 审批 ----

func (s *Server) fPending(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"pending": s.d.Store.PendingApprovals()})
}

func (s *Server) fHistory(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"items": s.d.Store.Approvals(qTaskID(r), qInt(r, "limit", 100)),
	})
}

func (s *Server) fDecide(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	var in struct {
		Decision string `json:"decision"` // allowed | denied
		Reason   string `json:"reason"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&in); err != nil {
		writeErr(w, http.StatusBadRequest, "请求体非法: "+err.Error())
		return
	}
	if !s.d.Store.DecideApproval(id, in.Decision, in.Reason) {
		writeErr(w, http.StatusConflict, "审批不存在或已裁决")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "id": id, "decision": in.Decision})
}

// ---- Skill 注册表（扫描 ./skills/<name>/SKILL.md）----

func (s *Server) fSkills(w http.ResponseWriter, _ *http.Request) {
	dir := "skills"
	entries, err := os.ReadDir(dir)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"skills": []any{}, "dir": dir})
		return
	}
	out := make([]map[string]any, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		item := map[string]any{"name": e.Name(), "description": ""}
		if body, err := os.ReadFile(filepath.Join(dir, e.Name(), "SKILL.md")); err == nil {
			lines := strings.Split(string(body), "\n")
			for _, ln := range lines {
				ln = strings.TrimSpace(ln)
				if strings.HasPrefix(ln, "description:") {
					item["description"] = strings.TrimSpace(strings.TrimPrefix(ln, "description:"))
					break
				}
			}
			item["files"] = len(lines)
		}
		out = append(out, item)
	}
	sort.Slice(out, func(i, j int) bool { return out[i]["name"].(string) < out[j]["name"].(string) })
	writeJSON(w, http.StatusOK, map[string]any{"skills": out, "dir": dir})
}
