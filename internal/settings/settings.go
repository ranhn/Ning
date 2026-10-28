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
}

// Get 返回配置副本（含密钥，仅服务端内部使用）。
func (s *Store) Get() Settings {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.s
}

// LLM 返回 LLM 配置副本。
func (s *Store) LLM() LLM { return s.Get().LLM }

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
func (s *Store) Masked() map[string]any {
	c := s.Get()
	return map[string]any{
		"configured":      c.LLM.Configured(),
		"provider":        c.LLM.Provider,
		"model":           c.LLM.Model,
		"base_url":        c.LLM.BaseURL,
		"api_key_set":     c.LLM.APIKey != "",
		"max_tokens":      c.LLM.MaxTokens,
		"temperature":     c.LLM.Temperature,
		"timeout_seconds": c.LLM.TimeoutSeconds,
		"task_steps":      c.TaskSteps,
		"task_tokens":     c.TaskToken,
		"saved_at":        time.Now().UTC(),
	}
}
