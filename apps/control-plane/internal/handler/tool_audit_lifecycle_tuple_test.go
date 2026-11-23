package handler

import "testing"

// D5：网关对普通（非破坏性）MCP tools/call 也会带 operation_id（用于关联），但不带
// event_type。DB 约束 tool_call_logs_destructive_operation_tuple_check 要求二者同有同无，
// 控制面见到 operation_id 就走破坏性分支并以 "invalid destructive lifecycle tuple" 拒绝，
// 整行审计丢失（e2e：41 次 tools/call 只落 2 行）。入口必须把半截元组规整为普通日志。
func TestD5_NormalizeToolLogLifecycleTuple(t *testing.T) {
	cases := []struct {
		name                string
		op, evt             string
		wantOp, wantEvt     string
		wantDestructivePath bool
	}{
		{"plain without either", "", "", "", "", false},
		{"plain call carrying only operation_id", "op-1", "", "", "", false},
		{"blank operation_id with no event_type", "  ", "", "", "", false},
		{"destructive full tuple untouched", "op-1", "tool_destructive_intent", "op-1", "tool_destructive_intent", true},
		{"event_type without operation_id keeps event_type so repo rejects it", "", "tool_destructive_intent", "", "tool_destructive_intent", true},
	}
	for _, c := range cases {
		op, evt := normalizeToolLogLifecycleTuple(c.op, c.evt)
		if op != c.wantOp || evt != c.wantEvt {
			t.Fatalf("%s: got (%q,%q) want (%q,%q)", c.name, op, evt, c.wantOp, c.wantEvt)
		}
		if got := op != "" || evt != ""; got != c.wantDestructivePath {
			t.Fatalf("%s: destructive path = %v want %v", c.name, got, c.wantDestructivePath)
		}
	}
}
