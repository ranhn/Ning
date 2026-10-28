package settings

import (
	"errors"
	"strings"
	"time"
)

// LLMProfile 是一条模型接入配置。
//
// 字段对齐控制台的"模型配置"表单；ARGUS 目前只跑 OpenAI 兼容协议，
// 因此 Format 为 anthropic 时会在 planner 侧返回明确错误，而不是静默失败。
type LLMProfile struct {
	ID              int64  `json:"id"`
	Name            string `json:"name"`
	Format          string `json:"format"` // openai | anthropic | openai-responses
	Model           string `json:"model"`
	BaseURL         string `json:"base_url"`
	Proxy           string `json:"proxy"`
	APIKey          string `json:"api_key"`
	RatePerSecond   int    `json:"rate_per_second"`
	RatePerMinute   int    `json:"rate_per_minute"`
	ContextWindowK  int    `json:"context_window_k"`
	MaxTokens       int    `json:"max_tokens"`
	MaxTokensField  string `json:"max_tokens_field"`
	Priority        int    `json:"priority"`
	PoolExclude     bool   `json:"pool_exclude"`
	Streaming       bool   `json:"streaming"`
	ThinkingType    string `json:"thinking_type"`
	ReasoningEffort string `json:"reasoning_effort"`
	SessionHeader   string `json:"session_header_key"`
	IsDefault       bool   `json:"is_default"`
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
}

// ListProfiles 返回配置副本（含明文密钥，供服务端内部使用；API 层负责脱敏）。
func (s *Store) ListProfiles() []LLMProfile {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]LLMProfile, len(s.s.Profiles))
	copy(out, s.s.Profiles)
	return out
}

// GetProfile 按 ID 取一条。
func (s *Store) GetProfile(id int64) (LLMProfile, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, p := range s.s.Profiles {
		if p.ID == id {
			return p, true
		}
	}
	return LLMProfile{}, false
}

// ActiveProfileID 返回当前激活配置。
func (s *Store) ActiveProfileID() int64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.s.ActiveProfile
}

// SaveProfile 新建或更新一条配置。
//
// 语义：ID==0 新建；否则更新。更新时 APIKey 传空表示"保持原值"，
// 避免前端脱敏回显后把密钥覆盖成掩码。
func (s *Store) SaveProfile(in LLMProfile) (int64, error) {
	if strings.TrimSpace(in.Name) == "" {
		return 0, errors.New("name 不能为空")
	}
	if strings.TrimSpace(in.Model) == "" {
		return 0, errors.New("model 不能为空")
	}
	if in.Format == "" {
		in.Format = "openai"
	}
	// ARGUS 的规划器只实现 OpenAI 兼容协议；选 anthropic 会连通但协议不匹配，
	// 与其静默失败，不如在这里明确拒绝。
	if in.Format == "anthropic" {
		return 0, errors.New("暂不支持 anthropic 协议（ARGUS 只实现 OpenAI 兼容接口）；请把格式改为 openai，并填写对应网关地址")
	}
	now := time.Now().UTC()

	var saved int64
	err := s.Update(func(st *Settings) {
		if in.ID > 0 {
			for i := range st.Profiles {
				if st.Profiles[i].ID != in.ID {
					continue
				}
				old := st.Profiles[i]
				in.CreatedAt = old.CreatedAt
				if in.APIKey == "" {
					in.APIKey = old.APIKey
				}
				if in.UpdatedAt.IsZero() {
					in.UpdatedAt = now
				} else {
					in.UpdatedAt = now
				}
				st.Profiles[i] = in
				saved = in.ID
				return
			}
		}
		// 新建
		st.SeqProfile++
		in.ID = st.SeqProfile
		in.CreatedAt = now
		in.UpdatedAt = now
		if in.RatePerSecond == 0 {
			in.RatePerSecond = 4
		}
		if in.RatePerMinute == 0 {
			in.RatePerMinute = 120
		}
		if len(st.Profiles) == 0 {
			in.IsDefault = true
			st.ActiveProfile = in.ID
		}
		st.Profiles = append(st.Profiles, in)
		saved = in.ID
	})
	return saved, err
}

// DeleteProfile 删除配置；若删的是激活项，自动切到剩下的第一条。
func (s *Store) DeleteProfile(id int64) bool {
	ok := false
	_ = s.Update(func(st *Settings) {
		for i := range st.Profiles {
			if st.Profiles[i].ID != id {
				continue
			}
			st.Profiles = append(st.Profiles[:i], st.Profiles[i+1:]...)
			ok = true
			if st.ActiveProfile == id {
				st.ActiveProfile = 0
				if len(st.Profiles) > 0 {
					st.ActiveProfile = st.Profiles[0].ID
				}
			}
			return
		}
	})
	return ok
}

// ActivateProfile 设为当前激活配置。
func (s *Store) ActivateProfile(id int64) bool {
	ok := false
	_ = s.Update(func(st *Settings) {
		for i := range st.Profiles {
			if st.Profiles[i].ID != id {
				continue
			}
			st.ActiveProfile = id
			for j := range st.Profiles {
				st.Profiles[j].IsDefault = st.Profiles[j].ID == id
			}
			ok = true
			return
		}
	})
	return ok
}

// ActiveLLM 把激活配置翻译成 planner 需要的连接参数。
// 没有任何配置时返回零值（Configured()==false），规划器会退化为"只跑种子意图"。
func (s *Store) ActiveLLM() LLM {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.s.ActiveProfile != 0 {
		for _, p := range s.s.Profiles {
			if p.ID != s.s.ActiveProfile {
				continue
			}
			mt := p.MaxTokens
			if mt <= 0 {
				mt = 2048
			}
			base := p.BaseURL
			// openai 格式留空时用官方端点：绝大多数人只填 model + api_key，
			// 让"不填 base_url 就不可用"这种隐性要求消失。
			if base == "" && (p.Format == "" || p.Format == "openai" || p.Format == "openai-responses") {
				base = "https://api.openai.com/v1"
			}
			return LLM{
				Provider: p.Format, Model: p.Model, BaseURL: base, APIKey: p.APIKey,
				MaxTokens: mt, Temperature: 0.2, TimeoutSeconds: 120,
			}
		}
	}
	return s.s.LLM
}
