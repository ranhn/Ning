// Package dedupe 实现意图指纹去重。
//
// ARTEX 的意图去重完全靠 LLM 自己比对（prompt 里写着"去重主要靠它与已有意图比对"），
// 这是长任务烧预算的结构性来源。这里把它变成硬约束：同一 (资产, 动作, 参数签名)
// 只允许派发一次。
package dedupe

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"sync"
)

// Fingerprint 计算意图指纹：sha256(assetID | action | 规范化参数签名)。
func Fingerprint(assetID int64, action, paramKey string) string {
	h := sha256.New()
	fmt.Fprintf(h, "%d|%s|%s", assetID,
		strings.ToLower(strings.TrimSpace(action)),
		normalizeParamKey(paramKey))
	return hex.EncodeToString(h.Sum(nil))
}

// normalizeParamKey 把参数签名规范化：小写、去空白、参数名排序，
// 使 "a=1&b=2" 与 "b=2 & a=1" 得到同一指纹。
func normalizeParamKey(raw string) string {
	s := strings.ToLower(strings.TrimSpace(raw))
	if s == "" {
		return ""
	}
	parts := strings.FieldsFunc(s, func(r rune) bool {
		return r == '&' || r == ';' || r == ',' || r == '\n'
	})
	for i := range parts {
		parts[i] = strings.Join(strings.Fields(parts[i]), "")
	}
	sort.Strings(parts)
	return strings.Join(parts, "&")
}

// Registry 是内存指纹表。生产实现应换成带唯一索引的表：
//
//	CREATE TABLE intent_fingerprint(task_id BIGINT, fp CHAR(64), intent_id BIGINT,
//	  PRIMARY KEY(task_id, fp));
type Registry struct {
	mu sync.Mutex
	m  map[string]int64
}

// New 构造空表。
func New() *Registry { return &Registry{m: map[string]int64{}} }

// Claim 尝试占用指纹。若已存在返回已有 intentID 与 true。
func (r *Registry) Claim(fp string, intentID int64) (int64, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if id, ok := r.m[fp]; ok {
		return id, true
	}
	r.m[fp] = intentID
	return intentID, false
}

// Bind 在拿到正式 intentID 后补写映射（先 Claim 占位、再 Bind 落地）。
func (r *Registry) Bind(fp string, intentID int64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.m[fp] = intentID
}

// Len 返回已占用指纹数。
func (r *Registry) Len() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.m)
}

// Reset 清空（测试用）。
func (r *Registry) Reset() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.m = map[string]int64{}
}
