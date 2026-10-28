package api

import (
	"encoding/json"
	"strings"

	"github.com/argus/argus/internal/scope"
	"github.com/argus/argus/internal/store"
)

// autoSeed 在没有提供种子意图时，按授权范围生成一批"最小可用"的探索意图。
//
// 目的：让"只填目标就能跑"成立。界面上新建任务只需要目标与范围类型，
// 不需要用户手写工具命令；生成出来的意图仍然要过三道闸门。
//
// 保守起见只生成只读动作（端口识别 + HTTP 响应头），最多 6 条。
func autoSeed(rules []scope.Rule) []store.Intent {
	out := make([]store.Intent, 0, 6)
	seen := map[string]bool{}

	add := func(cmd, key string) {
		if len(out) >= 6 || seen[key] {
			return
		}
		seen[key] = true
		summary, _ := json.Marshal(map[string]string{"command": cmd})
		out = append(out, store.Intent{Action: "Bash", Summary: string(summary), ParamKey: key})
	}

	for _, r := range rules {
		v := strings.TrimSpace(r.Value)
		if v == "" {
			continue
		}
		switch r.Kind {
		case scope.KindCIDR:
			add("nmap -sV -Pn --top-ports 100 "+v, "nmap:"+v)
		case scope.KindExactIP:
			add("nmap -sV -Pn --top-ports 100 "+v, "nmap:"+v)
			add("curl -sS -D - --max-time 8 http://"+v+"/", "curl:"+v)
		case scope.KindDomainSuffix, scope.KindExactDomain:
			// 域名只需要一条 Discover：内部完成"子域枚举 → 可用性确认"，
			// 再自动派生端口扫描与路径探测意图。调用方只给根域即可。
			h := strings.TrimPrefix(strings.TrimPrefix(strings.TrimPrefix(v, "*."), "."), ".")
			if len(out) >= 6 || seen["discover:"+h] {
				continue
			}
			seen["discover:"+h] = true
			summary, _ := json.Marshal(map[string]string{"domain": h})
			out = append(out, store.Intent{
				Action: "Discover", Summary: string(summary), ParamKey: "discover:" + h,
			})
		case scope.KindExactURL:
			add("curl -sS -D - --max-time 8 "+v, "curl:"+v)
		}
	}
	return out
}
