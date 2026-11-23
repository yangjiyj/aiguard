package agentguard

import (
	"context"
	"testing"
)

// TestAnalyzeToolCall_CodexShapes 覆盖 Codex 真实工具形态：argv 数组、字符串 command、
// JS 自由格式 exec_command 包装。三者必须得到一致的破坏性判定，且都不能落入
// system_tool_without_command（命令完全没被分析的旧缺陷）。
func TestAnalyzeToolCall_CodexShapes(t *testing.T) {
	shapes := []struct {
		name string
		args map[string]any
	}{
		{
			name: "argv 数组 bash -lc",
			args: map[string]any{"command": []any{"bash", "-lc", "rm -rf /"}},
		},
		{
			name: "字符串 command",
			args: map[string]any{"command": "rm -rf /"},
		},
		{
			name: "JS exec_command 包装",
			args: map[string]any{"input": `const r = await tools.exec_command({cmd:"rm -rf /",workdir:"/w"})`},
		},
	}

	reasons := make([]string, 0, len(shapes))
	for _, shape := range shapes {
		t.Run(shape.name, func(t *testing.T) {
			// ToolType 直接给 system：本测验证的是"参数形态能否被解析成命令"，
			// 与工具名分类解耦（分类见 TestClassifyToolType_CodexAndClaudeCodeNames）。
			decision := AnalyzeToolCall(context.Background(), ToolCallAnalysisInput{
				ToolName:  "exec",
				ToolType:  "system",
				Arguments: shape.args,
				Mode:      ModeStrict,
			})
			if decision.Reason == "system_tool_without_command" {
				t.Fatalf("命令未被解析（system_tool_without_command）: %#v", decision)
			}
			if decision.RawDecision != DecisionConfirm && decision.RawDecision != DecisionBlock {
				t.Fatalf("rm -rf / 应判定为 confirm/block，得到 %v reason=%s", decision.RawDecision, decision.Reason)
			}
			reasons = append(reasons, decision.Reason)
		})
	}

	if len(reasons) == 3 && (reasons[0] != reasons[1] || reasons[1] != reasons[2]) {
		t.Fatalf("三种形态 Reason 应一致，得到 %v", reasons)
	}
}

// TestClassifyToolType_CodexAndClaudeCodeNames 钉死 Codex / Claude Code 工具名的显式分类表。
func TestClassifyToolType_CodexAndClaudeCodeNames(t *testing.T) {
	cases := map[string]string{
		// exec 是 Codex 自由格式 custom 工具：input 是 JS 代码而非单条命令。
		// 归 unknown 避免整段 JS/裸词被当成 shell 命令撞 allowlist（既有契约：
		// exec+input:"pwd" 放行）；真正的内容分析靠 argv/JS 形态抽取与
		// structuredExecutionToolType 对 exec_command( 的识别。
		"exec":                     ToolTypeUnknown,
		"exec_command":             ToolTypeSystem,
		"shell":                    ToolTypeSystem,
		"local_shell":              ToolTypeSystem,
		"write_stdin":              ToolTypeSystem,
		"view_image":               ToolTypeFile,
		"read_file":                ToolTypeFile,
		"apply_patch":              ToolTypeFile,
		"spawn_agent":              ToolTypeUnknown,
		"wait":                     ToolTypeUnknown,
		"sleep":                    ToolTypeUnknown,
		"request_user_input_async": ToolTypeUnknown,
		"Read":                     ToolTypeFile,
		"mcp__filesystem__read":    ToolTypeMCP,
	}
	for name, want := range cases {
		if got := ClassifyToolType(name); got != want {
			t.Errorf("ClassifyToolType(%q) = %q, want %q", name, got, want)
		}
	}
}
