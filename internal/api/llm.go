package api

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/argus/argus/internal/planner"
	"github.com/argus/argus/internal/settings"
)

// LLM 配置接口：让用户在运行期配置模型（无需重启、密钥不回显）。
func (s *Server) registerLLM() {
	s.mux.HandleFunc("GET /api/llm", s.getLLM)
	s.mux.HandleFunc("PUT /api/llm", s.putLLM)
	s.mux.HandleFunc("POST /api/llm/test", s.testLLM)
	s.mux.HandleFunc("GET /api/llm/profiles", s.listLLMProfiles)
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

// 前端「LLM 配置」页期望 profiles 数组；ARGUS 目前是单配置，返回空数组保持兼容。
func (s *Server) listLLMProfiles(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"profiles": []any{}})
}
