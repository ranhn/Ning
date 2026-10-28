package gate

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/Autumn-27/artex/internal/toolbox"
)

// ArgusAdapter 把 Gate 收成 guard 包要的窄接口 (allowed, reason)。
//
// guard 包位于 ARTEX 侧，只认识"允不允许 + 一句原因"；
// 闸门的 Decision 结构（层/目标/原因）不适合直接跨包传递，所以在这一层收口。
//
// 判定顺序（先硬后软）：
//  1. 命令沙箱：拦破坏性/提权/反弹 shell（与范围无关，始终生效）
//  2. 范围闸门：任务声明了范围才判定；未声明时保持基线行为
type ArgusAdapter struct {
	G      *Gate
	TaskID int64
	// Cap 是该任务的能力档位；空 = full。
	// 代码审计类任务设为 codeaudit，Bash/WebFetch/MCP 会被物理摘除。
	Cap Capability
}

// CheckToolRaw 实现 guard.ArgusGate。
func (a *ArgusAdapter) CheckToolRaw(ctx context.Context, tool string, input []byte) (bool, string) {
	// ⓪ 能力档位：最早判定。窄档位下"只读任务"连出网工具都拿不到，
	//    不依赖模型是否配合，也不依赖后续命令解析。
	cap := CapFull
	if a != nil && a.Cap != "" {
		cap = a.Cap
	}
	if !AllowTool(cap, tool) {
		return false, "能力档位 “" + string(cap) + "” 不允许使用工具：" + tool
	}

	// ① 命令层：ARTEX 的 Bash 是直通完整 shell，这一层挡住真正危险的动作。
	//    放在范围判定之前，因为"rm -rf /"即使在授权范围内也不该执行。
	if reason := sandboxCheck(tool, input); reason != "" {
		return false, reason
	}

	// ② 范围层
	if a == nil || a.G == nil {
		return true, ""
	}
	dec := a.G.CheckTool(ctx, a.TaskID, 0, tool, json.RawMessage(input))
	if dec.Allowed {
		return true, ""
	}
	layer := string(dec.Layer)
	if layer == "" {
		layer = "scope"
	}
	return false, fmt.Sprintf("范围闸门拒绝（%s 层）：%s", layer, dec.Reason)
}

// sandboxCheck 对"直通 shell"的工具做命令校验，返回空串表示通过。
func sandboxCheck(tool string, input []byte) string {
	switch {
	case strings.EqualFold(tool, "Bash"),
		strings.EqualFold(tool, "shell_open"),
		strings.EqualFold(tool, "shell_send"):
	default:
		return ""
	}
	var in struct {
		Command string `json:"command"`
		Text    string `json:"text"`
	}
	_ = json.Unmarshal(input, &in)
	cmd := in.Command
	if strings.TrimSpace(cmd) == "" {
		cmd = in.Text
	}
	if strings.TrimSpace(cmd) == "" {
		return ""
	}
	if err := toolbox.CheckCommand(cmd); err != nil {
		return "命令沙箱拒绝：" + err.Error()
	}
	return ""
}
