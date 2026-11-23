package agentguard

import (
	"context"
	"testing"
)

func restrictedPolicy(action string, patterns ...string) *EffectivePolicy {
	return &EffectivePolicy{
		RestrictedFiles: &RestrictedFilePolicy{Patterns: patterns, Action: action},
	}
}

func TestAnalyzeToolCall_RestrictedFiles(t *testing.T) {
	tests := []struct {
		name           string
		toolName       string
		toolType       string
		args           map[string]any
		action         string
		patterns       []string
		wantRaw        DecisionAction
		wantReason     string
		wantConfidence float64
	}{
		{
			name: "file 工具 path 命中 block", toolName: "read_file", toolType: "file",
			args: map[string]any{"path": "a.pdf"}, action: "block", patterns: []string{"*.pdf"},
			wantRaw: DecisionBlock, wantReason: "restricted_file_pattern", wantConfidence: 0.95,
		},
		{
			name: "Claude Code Read file_path 命中", toolName: "Read", toolType: "file",
			args: map[string]any{"file_path": "/x/合同.docx"}, action: "block", patterns: []string{"*.docx"},
			wantRaw: DecisionBlock, wantReason: "restricted_file_pattern", wantConfidence: 0.95,
		},
		{
			name: "shell 数组命令命中", toolName: "shell", toolType: "system",
			args: map[string]any{"command": []any{"bash", "-lc", "pdftotext a.pdf -"}}, action: "block", patterns: []string{"*.pdf"},
			wantRaw: DecisionBlock, wantReason: "restricted_file_pattern", wantConfidence: 0.95,
		},
		{
			name: "JS 形态命中", toolName: "exec_command", toolType: "system",
			args:   map[string]any{"input": `const r = await tools.exec_command({cmd:"pdftotext 合同.pdf -",workdir:"/w"})`},
			action: "block", patterns: []string{"*.pdf"},
			wantRaw: DecisionBlock, wantReason: "restricted_file_pattern", wantConfidence: 0.95,
		},
		{
			name: "apply_patch Update File 命中", toolName: "apply_patch", toolType: "file",
			args:   map[string]any{"patch": "*** Begin Patch\n*** Update File: docs/a.docx\n@@\n*** End Patch"},
			action: "block", patterns: []string{"*.docx"},
			wantRaw: DecisionBlock, wantReason: "restricted_file_pattern", wantConfidence: 0.95,
		},
		{
			name: "record 动作 → audit", toolName: "read_file", toolType: "file",
			args: map[string]any{"path": "a.pdf"}, action: "record", patterns: []string{"*.pdf"},
			wantRaw: DecisionAudit, wantReason: "restricted_file_pattern", wantConfidence: 0.95,
		},
		{
			name: "alert_allow 动作 → audit + alert 标记", toolName: "read_file", toolType: "file",
			args: map[string]any{"path": "a.pdf"}, action: "alert_allow", patterns: []string{"*.pdf"},
			wantRaw: DecisionAudit, wantReason: "restricted_file_pattern", wantConfidence: 0.95,
		},
		{
			name: "不命中", toolName: "read_file", toolType: "file",
			args: map[string]any{"path": "a.go"}, action: "block", patterns: []string{"*.pdf"},
			wantRaw: DecisionAllow, wantReason: "file_tool_no_risk",
		},
		{
			name: "粗略层命中（代码字符串内路径，词法切不出）", toolName: "exec_command", toolType: "system",
			args:   map[string]any{"input": `tools.exec_command({cmd:"python -c 'open(\"report.pdf\").read()'"})`},
			action: "block", patterns: []string{"*.pdf"},
			wantRaw: DecisionBlock, wantReason: "restricted_file_pattern",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			decision := AnalyzeToolCall(context.Background(), ToolCallAnalysisInput{
				ToolName: tt.toolName, ToolType: tt.toolType, Arguments: tt.args,
				Mode: ModeStrict, Policy: restrictedPolicy(tt.action, tt.patterns...),
			})
			if decision.RawDecision != tt.wantRaw {
				t.Fatalf("RawDecision=%v, want %v (reason=%s)", decision.RawDecision, tt.wantRaw, decision.Reason)
			}
			if tt.wantReason == "restricted_file_pattern" {
				if decision.Reason != "restricted_file_pattern" {
					t.Fatalf("Reason=%q, want restricted_file_pattern", decision.Reason)
				}
				if tt.wantConfidence != 0 && decision.Confidence != tt.wantConfidence {
					t.Fatalf("Confidence=%v, want %v", decision.Confidence, tt.wantConfidence)
				}
				// evidence 只有模式 + 脱敏目标，不含完整命令原文
				for _, ev := range decision.Evidence {
					if ev.RuleID == "restricted_file_pattern" && len(ev.MaskedPreview) > 0 && ev.MaskedPreview[0] != '<' && ev.Category != "alert" {
						t.Fatalf("evidence 未脱敏: %+v", ev)
					}
				}
			}
			if tt.name == "alert_allow 动作 → audit + alert 标记" {
				// 2.9.22：受限文件是防护项 agent.restricted_file，告警放行由防护项字段标记
				// （原 evidence 里的 alert 标记已去掉）。
				if !decision.ProtectionAlert() || decision.ProtectionItem != "agent.restricted_file" || !decision.NotificationRequired {
					t.Fatalf("alert_allow 缺告警标记: %+v", decision)
				}
			}
		})
	}
}

// 无策略时 decision 与改前逐字节一致（零值合并不改变结果）。
func TestAnalyzeToolCall_RestrictedFilesNoPolicyUnchanged(t *testing.T) {
	args := map[string]any{"path": "a.pdf"}
	withNil := AnalyzeToolCall(context.Background(), ToolCallAnalysisInput{
		ToolName: "read_file", ToolType: "file", Arguments: args, Mode: ModeStrict, Policy: nil,
	})
	withEmpty := AnalyzeToolCall(context.Background(), ToolCallAnalysisInput{
		ToolName: "read_file", ToolType: "file", Arguments: args, Mode: ModeStrict,
		Policy: restrictedPolicy("block"),
	})
	withEmptyPatterns := AnalyzeToolCall(context.Background(), ToolCallAnalysisInput{
		ToolName: "read_file", ToolType: "file", Arguments: args, Mode: ModeStrict,
		Policy: &EffectivePolicy{},
	})
	if withNil.RawDecision != withEmpty.RawDecision || withNil.Reason != withEmpty.Reason {
		t.Fatalf("nil vs empty policy mismatch: %+v vs %+v", withNil, withEmpty)
	}
	if withNil.RawDecision != withEmptyPatterns.RawDecision || withNil.Reason != withEmptyPatterns.Reason {
		t.Fatalf("nil vs no-restricted-field policy mismatch: %+v vs %+v", withNil, withEmptyPatterns)
	}
	if withNil.Reason == "restricted_file_pattern" {
		t.Fatalf("no policy should never produce restricted_file_pattern")
	}
}
