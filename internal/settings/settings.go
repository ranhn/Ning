// Package settings 保存运行期配置（目前是 LLM 接入参数）。
//
// 三个来源，优先级从低到高：内置默认值 → 环境变量 → settings.json。
// 写盘用"临时文件 + rename"保证原子性；API 只回显 api_key_set，不回显密钥本身。
package settings

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"
)

// LLM 是 OpenAI 兼容接口的接入参数。
type LLM struct {
	Provider       string  `json:"provider"`        // openai | deepseek | azure | 其它兼容实现
	Model          string  `json:"model"`           // 例如 gpt-4.1 / deepseek-chat
	BaseURL        string  `json:"base_url"`        // 例如 https://api.openai.com/v1
	APIKey         string  `json:"api_key"`         // 只在服务端保存，不回显
	MaxTokens      int     `json:"max_tokens"`      // 单次回复上限
	Temperature    float64 `json:"temperature"`     // 0 表示用服务端默认
	TimeoutSeconds int     `json:"timeout_seconds"` // 单次调用超时
}

// Configured 表示是否具备发起调用的最低条件。
func (l LLM) Configured() bool {
	return l.BaseURL != "" && l.Model != "" && l.APIKey != ""
}

// Settings 是整体配置。
type Settings struct {
	LLM LLM `json:"llm"`
	// 控制台"模型配置"里的多条配置；ActiveProfile 指向当前生效的那一条。
	Profiles      []LLMProfile `json:"profiles,omitempty"`
	ActiveProfile int64        `json:"active_profile,omitempty"`
	SeqProfile    int64        `json:"seq_profile,omitempty"`
	// 任务默认预算（0 = 用内置默认值）
	TaskSteps int64 `json:"task_steps"`
	TaskToken int64 `json:"task_tokens"`
}

func defaults() Settings {
	return Settings{
		LLM: LLM{
			Provider: "openai", MaxTokens: 2048, Temperature: 0.2, TimeoutSeconds: 120,
		},
	}
}

// Store 是并发安全的配置容器。
type Store struct {
	mu   sync.RWMutex
	path string
	s    Settings
}

// Open 加载配置（文件不存在则用 env/默认值初始化）。
func Open(path string) *Store {
	st := &Store{path: path, s: defaults()}
	st.applyEnv()
	if path != "" {
		if body, err := os.ReadFile(path); err == nil && len(body) > 0 {
			var s Settings
			if err := json.Unmarshal(body, &s); err == nil {
				st.merge(s)
			} else {
				fmt.Fprintf(os.Stderr, "argus: settings.json 解析失败（%v），使用默认值\n", err)
			}
		}
	}
	return st
}

func (s *Store) applyEnv() {
	if v := os.Getenv("ARGUS_LLM_BASE_URL"); v != "" {
		s.s.LLM.BaseURL = v
	}
	if v := os.Getenv("ARGUS_LLM_API_KEY"); v != "" {
		s.s.LLM.APIKey = v
	}
	if v := os.Getenv("ARGUS_LLM_MODEL"); v != "" {
		s.s.LLM.Model = v
	}
	if v := os.Getenv("ARGUS_LLM_PROVIDER"); v != "" {
		s.s.LLM.Provider = v
	}
	if v := os.Getenv("ARGUS_LLM_MAX_TOKENS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			s.s.LLM.MaxTokens = n
		}
	}
}

func (s *Store) merge(in Settings) {
	if in.LLM.Provider != "" {
		s.s.LLM.Provider = in.LLM.Provider
	}
	if in.LLM.Model != "" {
		s.s.LLM.Model = in.LLM.Model
	}
	if in.LLM.BaseURL != "" {
		s.s.LLM.BaseURL = in.LLM.BaseURL
	}
	if in.LLM.APIKey != "" {
		s.s.LLM.APIKey = in.LLM.APIKey
	}
	if in.LLM.MaxTokens > 0 {
		s.s.LLM.MaxTokens = in.LLM.MaxTokens
	}
	if in.LLM.Temperature > 0 {
		s.s.LLM.Temperature = in.LLM.Temperature
	}
	if in.LLM.TimeoutSeconds > 0 {
		s.s.LLM.TimeoutSeconds = in.LLM.TimeoutSeconds
	}
	if in.TaskSteps > 0 {
		s.s.TaskSteps = in.TaskSteps
	}
	if in.TaskToken > 0 {
		s.s.TaskToken = in.TaskToken
	}
	// 多配置列表必须完整带过来，否则"写盘成功、重启全丢"。
	if len(in.Profiles) > 0 {
		s.s.Profiles = in.Profiles
	}
	if in.ActiveProfile > 0 {
		s.s.ActiveProfile = in.ActiveProfile
	}
	if in.SeqProfile > 0 {
		s.s.SeqProfile = in.SeqProfile
	}
}

// Get 返回配置副本（含密钥，仅服务端内部使用）。
func (s *Store) Get() Settings {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.s
}

// LLM 返回生效的 LLM 配置：优先使用激活的 profile，否则回退到单配置。
func (s *Store) LLM() LLM { return s.ActiveLLM() }

// Update 修改配置并落盘。fn 里改什么就存什么。
func (s *Store) Update(fn func(*Settings)) error {
	s.mu.Lock()
	fn(&s.s)
	snap := s.s
	path := s.path
	s.mu.Unlock()
	if path == "" {
		return nil
	}
	body, err := json.MarshalIndent(snap, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, body, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// Masked 返回可安全回显的视图。
// 注意：必须用 ActiveLLM()（激活的 profile），否则控制台里配好了模型，
// /api/llm 仍会显示"未配置"——这正是之前"保存了但不生效"的来源。
func (s *Store) Masked() map[string]any {
	c := s.Get()
	l := s.ActiveLLM()
	return map[string]any{
		"configured":      l.Configured(),
		"provider":        l.Provider,
		"model":           l.Model,
		"base_url":        l.BaseURL,
		"api_key_set":     l.APIKey != "",
		"max_tokens":      l.MaxTokens,
		"temperature":     l.Temperature,
		"timeout_seconds": l.TimeoutSeconds,
		"task_steps":      c.TaskSteps,
		"task_tokens":     c.TaskToken,
		"profiles":        len(c.Profiles),
		"active_profile":  c.ActiveProfile,
		"saved_at":        time.Now().UTC(),
	}
}
