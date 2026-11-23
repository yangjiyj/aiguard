package handler

import (
	"encoding/json"
	"testing"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/config"
)

// 2.9.21 r2921g 复核（filetool F1–F3）：经真实处理器送检时，下列本地文件工具参数都要写
// tool_may_egress=true（照 2.9.20 拦）。

func TestOutputProjectionFileToolPrefixR2921g(t *testing.T) {
	patch := "*** Begin Patch\n *** Add File: \\\\srv\\share\\x.txt\n+PROJ-G-AP CONFIDENTIAL AND PROPRIETARY\n*** End Patch"
	patchJSON, _ := json.Marshal(patch)
	patchArgs, _ := json.Marshal(map[string]any{"input": patch + "\nPROJ-G-FC"})
	patchArgsJSON, _ := json.Marshal(string(patchArgs))

	t.Run("Responses 非流式 custom_tool_call apply_patch 文件头前导空格", func(t *testing.T) {
		engine := newProjectionEngine(t)
		upstream := `{"id":"resp","object":"response","status":"completed","model":"test","output":[` +
			`{"id":"ctc_1","type":"custom_tool_call","call_id":"call_1","name":"apply_patch","input":` + string(patchJSON) + `}],` +
			`"usage":{"input_tokens":1,"output_tokens":2}}`
		projectionHTTP(t, "responses", &config.Config{}, false, upstream, engine.checker())
		calls := callsContaining(engine.outputCalls(), "PROJ-G-AP")
		if len(calls) == 0 {
			t.Fatalf("custom_tool_call 参数应送检：%v", engine.outputCalls())
		}
		for _, call := range calls {
			requireToolProjection(t, "custom_tool_call apply_patch", call, "apply_patch", true)
		}
	})

	t.Run("Responses 非流式 function_call apply_patch 文件头前导空格", func(t *testing.T) {
		engine := newProjectionEngine(t)
		upstream := `{"id":"resp","object":"response","status":"completed","model":"test","output":[` +
			`{"id":"fc_1","type":"function_call","call_id":"call_1","name":"apply_patch","arguments":` + string(patchArgsJSON) + `}],` +
			`"usage":{"input_tokens":1,"output_tokens":2}}`
		projectionHTTP(t, "responses", &config.Config{}, false, upstream, engine.checker())
		calls := callsContaining(engine.outputCalls(), "PROJ-G-FC")
		if len(calls) == 0 {
			t.Fatalf("function_call 参数应送检：%v", engine.outputCalls())
		}
		for _, call := range calls {
			requireToolProjection(t, "function_call apply_patch", call, "apply_patch", true)
		}
	})

	t.Run("Messages 非流式 Write 路径前导 U+FEFF", func(t *testing.T) {
		engine := newProjectionEngine(t)
		input, _ := json.Marshal(map[string]any{"file_path": "\ufeff\\\\srv\\share\\x.txt", "content": "PROJ-G-WRITE CONFIDENTIAL AND PROPRIETARY"})
		upstream := `{"id":"msg","type":"message","role":"assistant","model":"test","content":[` +
			`{"type":"tool_use","id":"toolu_w","name":"Write","input":` + string(input) + `}],` +
			`"stop_reason":"tool_use","usage":{"input_tokens":1,"output_tokens":2}}`
		projectionHTTP(t, "messages", &config.Config{}, false, upstream, engine.checker())
		calls := callsContaining(engine.outputCalls(), "PROJ-G-WRITE")
		if len(calls) != 1 {
			t.Fatalf("tool_use 参数应送检一次：%v", engine.outputCalls())
		}
		requireToolProjection(t, "Messages Write U+FEFF UNC", calls[0], "Write", true)
	})

	t.Run("Messages 非流式 Glob pattern 反斜杠 UNC", func(t *testing.T) {
		engine := newProjectionEngine(t)
		input, _ := json.Marshal(map[string]any{"pattern": "\\\\srv\\share\\PROJ-G-GLOB 这是机密文件\\*"})
		upstream := `{"id":"msg","type":"message","role":"assistant","model":"test","content":[` +
			`{"type":"tool_use","id":"toolu_g","name":"Glob","input":` + string(input) + `}],` +
			`"stop_reason":"tool_use","usage":{"input_tokens":1,"output_tokens":2}}`
		projectionHTTP(t, "messages", &config.Config{}, false, upstream, engine.checker())
		calls := callsContaining(engine.outputCalls(), "PROJ-G-GLOB")
		if len(calls) != 1 {
			t.Fatalf("tool_use 参数应送检一次：%v", engine.outputCalls())
		}
		requireToolProjection(t, "Messages Glob UNC pattern", calls[0], "Glob", true)
	})
}
