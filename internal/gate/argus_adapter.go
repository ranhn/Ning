package gate

import (
	"context"
	"encoding/json"
	"fmt"
)

// ArgusAdapter 鎶?Gate 鏀舵垚 guard 鍖呰鐨勭獎鎺ュ彛 (allowed, reason)銆?
//
// guard 鍖呬綅浜?ARTEX 渚э紝鍙璇?鍏佷笉鍏佽 + 涓€鍙ュ師鍥?锛?
// 闂搁棬鐨?Decision 缁撴瀯锛堝眰/鐩爣/鍘熷洜锛変笉閫傚悎鐩存帴璺ㄥ寘浼犻€掞紝鎵€浠ュ湪杩欎竴灞傛敹鍙ｃ€?
type ArgusAdapter struct {
	G      *Gate
	TaskID int64
}

// CheckToolRaw 瀹炵幇 guard.ArgusGate銆?
func (a *ArgusAdapter) CheckToolRaw(ctx context.Context, tool string, input []byte) (bool, string) {
	if a == nil || a.G == nil {
		return true, ""
	}
	var raw json.RawMessage = input
	dec := a.G.CheckTool(ctx, a.TaskID, 0, tool, raw)
	if dec.Allowed {
		return true, ""
	}
	layer := string(dec.Layer)
	if layer == "" {
		layer = "scope"
	}
	return false, fmt.Sprintf("鑼冨洿闂搁棬鎷掔粷锛?s 灞傦級锛?s", layer, dec.Reason)
}