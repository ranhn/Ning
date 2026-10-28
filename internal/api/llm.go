package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/argus/argus/internal/planner"
	"github.com/argus/argus/internal/settings"
)

// LLM 配置接口：让用户在运行期配置模型（无需重启、密钥不回显）。
func (s *Server) registerLLM() {
	s.mux.HandleFunc("GET /api/llm", s.getLLM)
	s.mux.HandleFunc("PUT /api/llm", s.putLLM)
	s.mux.HandleFunc("POST /api/llm/test", s.testLLM)
	s.registerLLMProfiles()
}

func (s *Server) getLLM(w http.ResponseWriter, _ *http.Request) {
	if s.d.Settings == nil {
		writeErr(w, http.StatusInternalServerError, "配置存储未初始化")
		return
	}
	out := s.d.Settings.Masked()
	if s.d.PlannerInfo != nil {
		out["planner"] = s.d.PlannerInfo()
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) putLLM(w http.ResponseWriter, r *http.Request) {
	if s.d.Settings == nil {
		writeErr(w, http.StatusInternalServerError, "配置存储未初始化")
		return
	}
	var in settings.LLM
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&in); err != nil {
		writeErr(w, http.StatusBadRequest, "请求体不是合法 JSON: "+err.Error())
		return
	}
	// 语义：只改提交了的字段；api_key 传空字符串表示"保持原值"。
	err := s.d.Settings.Update(func(st *settings.Settings) {
		if in.Provider != "" {
			st.LLM.Provider = in.Provider
		}
		if in.Model != "" {
			st.LLM.Model = in.Model
		}
		if in.BaseURL != "" {
			st.LLM.BaseURL = in.BaseURL
		}
		if in.APIKey != "" {
			st.LLM.APIKey = in.APIKey
		}
		if in.MaxTokens > 0 {
			st.LLM.MaxTokens = in.MaxTokens
		}
		if in.Temperature > 0 {
			st.LLM.Temperature = in.Temperature
		}
		if in.TimeoutSeconds > 0 {
			st.LLM.TimeoutSeconds = in.TimeoutSeconds
		}
	})
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "保存配置失败: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, s.d.Settings.Masked())
}

func (s *Server) testLLM(w http.ResponseWriter, _ *http.Request) {
	if s.d.Settings == nil {
		writeErr(w, http.StatusInternalServerError, "配置存储未初始化")
		return
	}
	cfg := s.d.Settings.LLM()
	if !cfg.Configured() {
		writeErr(w, http.StatusBadRequest, "尚未配置完整：需要 base_url + model + api_key")
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	start := time.Now()
	reply, tokens, err := planner.TestConnection(ctx, cfg)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"ok": false, "error": err.Error(), "latency_ms": time.Since(start).Milliseconds(),
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true, "reply": reply, "tokens": tokens,
		"latency_ms": time.Since(start).Milliseconds(), "model": cfg.Model,
	})
}

func (s *Server) registerLLMProfiles() {
	s.mux.HandleFunc("GET /api/llm/profiles", s.listLLMProfiles)
	s.mux.HandleFunc("POST /api/llm/profiles", s.saveLLMProfile)
	s.mux.HandleFunc("DELETE /api/llm/profiles/{id}", s.deleteLLMProfile)
	s.mux.HandleFunc("POST /api/llm/profiles/active", s.activateLLMProfile)
	s.mux.HandleFunc("GET /api/llm/pool", s.llmPool)
	s.mux.HandleFunc("POST /api/llm/pool/reset", s.llmPoolReset)
}

// profileJSON 输出前端需要的形状（id 为字符串，密钥只给 hint）。
func profileJSON(p settings.LLMProfile, activeID int64) map[string]any {
	hint := ""
	if p.APIKey != "" {
		if len(p.APIKey) <= 8 {
			hint = "******"
		} else {
			hint = p.APIKey[:6] + "******"
		}
	}
	return map[string]any{
		"id": strconv.FormatInt(p.ID, 10), "name": p.Name, "format": p.Format,
		"model": p.Model, "base_url": p.BaseURL, "proxy": p.Proxy,
		"api_key_hint": hint,
		"rate_per_second": p.RatePerSecond, "rate_per_minute": p.RatePerMinute,
		"context_window_k": p.ContextWindowK, "max_tokens": p.MaxTokens,
		"max_tokens_field": p.MaxTokensField, "priority": p.Priority,
		"pool_exclude": p.PoolExclude, "streaming": p.Streaming,
		"thinking_type": p.ThinkingType, "reasoning_effort": p.ReasoningEffort,
		"session_header_key": p.SessionHeader,
		"is_default":         p.ID == activeID,
	}
}

func (s *Server) listLLMProfiles(w http.ResponseWriter, _ *http.Request) {
	if s.d.Settings == nil {
		writeErr(w, http.StatusInternalServerError, "配置存储未初始化")
		return
	}
	active := s.d.Settings.ActiveProfileID()
	ps := s.d.Settings.ListProfiles()
	out := make([]map[string]any, 0, len(ps))
	for _, p := range ps {
		out = append(out, profileJSON(p, active))
	}
	writeJSON(w, http.StatusOK, map[string]any{"profiles": out, "active_id": active})
}

func (s *Server) saveLLMProfile(w http.ResponseWriter, r *http.Request) {
	if s.d.Settings == nil {
		writeErr(w, http.StatusInternalServerError, "配置存储未初始化")
		return
	}
	var in settings.LLMProfile
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&in); err != nil {
		writeErr(w, http.StatusBadRequest, "请求体不是合法 JSON: "+err.Error())
		return
	}
	id, err := s.d.Settings.SaveProfile(in)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	// 第一条配置自动激活
	if s.d.Settings.ActiveProfileID() == 0 {
		s.d.Settings.ActivateProfile(id)
	}
	writeJSON(w, http.StatusOK, map[string]any{"id": id})
}

func (s *Server) deleteLLMProfile(w http.ResponseWriter, r *http.Request) {
	if s.d.Settings == nil {
		writeErr(w, http.StatusInternalServerError, "配置存储未初始化")
		return
	}
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	if !s.d.Settings.DeleteProfile(id) {
		writeErr(w, http.StatusNotFound, "配置不存在")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"deleted": 1})
}

func (s *Server) activateLLMProfile(w http.ResponseWriter, r *http.Request) {
	if s.d.Settings == nil {
		writeErr(w, http.StatusInternalServerError, "配置存储未初始化")
		return
	}
	var in struct {
		ID int64 `json:"id"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&in); err != nil {
		writeErr(w, http.StatusBadRequest, "请求体不是合法 JSON: "+err.Error())
		return
	}
	if !s.d.Settings.ActivateProfile(in.ID) {
		writeErr(w, http.StatusNotFound, "配置不存在")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// pool 是 ARTEX 的故障转移视图；ARGUS 目前是单配置直连，返回空链。
func (s *Server) llmPool(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"items": []any{}, "chain": []any{}, "total": 0, "active_id": s.d.Settings.ActiveProfileID(),
	})
}

func (s *Server) llmPoolReset(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"items": []any{}, "chain": []any{}, "total": 0})
}
