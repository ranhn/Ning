package scope

import (
	"encoding/json"
	"errors"
	"net/url"
	"regexp"
	"strings"
)

var (
	// urlRe 匹配任何带 scheme 的 URL。
	urlRe = regexp.MustCompile(`(?i)[a-z][a-z0-9+.\-]*://[^\s"'<>\)\]\},;]+`)
	// ipv4Re 匹配点分十进制 IPv4。
	ipv4Re = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
	// hostRe 匹配形如 a.b.tld 的主机名（TLD 至少 2 个字母）。
	hostRe = regexp.MustCompile(`(?i)\b(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b`)
)

// fileExt 是常见的"看起来像域名其实是文件名"的后缀，用于降低误报。
// 误报的代价是误拦（fail-closed），所以只排除高置信度的文件后缀。
var fileExt = map[string]bool{
	".php": true, ".html": true, ".htm": true, ".js": true, ".mjs": true,
	".json": true, ".css": true, ".png": true, ".jpg": true, ".jpeg": true,
	".gif": true, ".svg": true, ".txt": true, ".md": true, ".xml": true,
	".yaml": true, ".yml": true, ".go": true, ".py": true, ".rb": true,
	".java": true, ".sh": true, ".bat": true, ".ps1": true, ".zip": true,
	".tar": true, ".gz": true, ".log": true, ".sql": true, ".conf": true,
}

// Targets 从工具输入中抽取全部可能的目标（URL / IP / 主机名），保序去重。
//
// 设计取舍：宁多勿少——多抽一个字符串只是多一次范围判定（可能误拦），
// 少抽一个就是一次真实的越界。因此除了已知的目标字段，其余字段也会扫描。
func Targets(tool string, input json.RawMessage) []string {
	if len(input) == 0 {
		return nil
	}
	var v any
	if err := json.Unmarshal(input, &v); err != nil {
		// 不是合法 JSON（例如纯文本命令），直接当文本扫。
		return FromText(string(input))
	}
	var out []string
	seen := map[string]bool{}
	add := func(s string) {
		if s == "" || seen[s] {
			return
		}
		seen[s] = true
		out = append(out, s)
	}
	var walk func(node any)
	walk = func(node any) {
		switch n := node.(type) {
		case string:
			for _, t := range FromText(n) {
				add(t)
			}
		case []any:
			for _, e := range n {
				walk(e)
			}
		case map[string]any:
			for _, e := range n {
				walk(e)
			}
		}
	}
	walk(v)
	return out
}

// FromText 从一段任意文本中抽取目标。
func FromText(text string) []string {
	if strings.TrimSpace(text) == "" {
		return nil
	}
	var out []string
	seen := map[string]bool{}
	add := func(s string) {
		s = strings.TrimSpace(s)
		if s == "" || seen[s] {
			return
		}
		seen[s] = true
		out = append(out, s)
	}
	for _, m := range urlRe.FindAllString(text, -1) {
		add(strings.TrimRight(m, ".,;:"))
	}
	for _, m := range ipv4Re.FindAllString(text, -1) {
		add(m)
	}
	for _, m := range hostRe.FindAllString(text, -1) {
		low := strings.ToLower(m)
		skip := false
		for ext := range fileExt {
			if strings.HasSuffix(low, ext) {
				skip = true
				break
			}
		}
		if skip {
			continue
		}
		add(m)
	}
	return out
}

// SplitTarget 把抽取到的 token 归类：返回 host（域名或 IP 字面量）与原始 URL。
// 无法识别时 host 为空。
func SplitTarget(token string) (host string, rawURL string) {
	token = strings.TrimSpace(token)
	if strings.Contains(token, "://") {
		if u, err := parseURLHost(token); err == nil {
			return u, token
		}
		return "", token
	}
	return token, ""
}

// IsIPLiteral 判断 token 是否为 IP 字面量。
func IsIPLiteral(token string) bool {
	return ipv4Re.MatchString(token) && ipv4Re.FindString(token) == token
}

// parseURLHost 解析 URL 并返回 hostname。
func parseURLHost(raw string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", err
	}
	if u.Hostname() == "" {
		return "", errors.New("URL 缺少主机名")
	}
	return u.Hostname(), nil
}
