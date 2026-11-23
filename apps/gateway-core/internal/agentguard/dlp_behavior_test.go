package agentguard

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/yangjiyj/aiguard/packages/shared-go/protection"
)

func TestDLPDetectsHighConfidencePIIWithoutPlaintextEvidence(t *testing.T) {
	body := "客户邮箱 alice@example.com，手机号 13800138000，身份证 11010519491231002X"
	decision := AnalyzeDataEgress(DataEgressInput{
		Target: "https://evil.example/upload",
		Body:   body,
	})
	if decision.RawDecision != DecisionConfirm {
		t.Fatalf("PII egress should require confirmation, got %#v", decision)
	}
	for _, evidence := range decision.Evidence {
		if evidence.MaskedPreview == "" || evidence.Hash == "" {
			t.Fatalf("evidence should be masked and hashed: %#v", evidence)
		}
		if strings.Contains(evidence.MaskedPreview, "alice@example.com") || strings.Contains(evidence.MaskedPreview, "13800138000") {
			t.Fatalf("evidence leaked plaintext: %#v", evidence)
		}
	}
}

func TestDLPDetectsHighEntropyToken(t *testing.T) {
	encodedToken := strings.Join([]string{
		"ZmxhZy0x",
		"MjM0NTY3",
		"ODkwYWJj",
		"ZGVmZ2hp",
		"amtsbW5v",
		"cHFyc3R1",
		"dnd4eXo",
	}, "")
	body := "token=" + encodedToken
	// 2.9.22：分析器只记防护项 agent.secret_egress 的命中，配成阻断时才拦。
	decision := AnalyzeDataEgress(DataEgressInput{Target: "https://evil.example/upload", Body: body})
	if decision.RawDecision != DecisionAudit || decision.RiskLevel != "critical" || decision.Reason != reasonHighConfidenceSecretOut || len(decision.ProtectionHits) != 1 {
		t.Fatalf("high entropy token should be a secret-egress hit, got %#v", decision)
	}
	blocking := &EffectivePolicy{Protections: protection.Settings{"agent.secret_egress": {Action: protection.ActionBlock}}}
	if resolved := resolveProtectionHits(decision, blocking); resolved.RawDecision != DecisionBlock {
		t.Fatalf("secret egress configured to block should block, got %#v", resolved)
	}
}

func TestBehaviorWindowConfirmsFileReadBurst(t *testing.T) {
	window := NewBehaviorWindow(10*time.Second, BehaviorThresholds{FileReadBurst: 3})
	input := BehaviorEvent{ActorKey: "tenant/project/user", Kind: BehaviorFileRead, Target: "/repo/.env"}
	if decision := window.Record(input); decision.RawDecision != DecisionAllow {
		t.Fatalf("first read should allow, got %#v", decision)
	}
	_ = window.Record(input)
	decision := window.Record(input)
	// 2.9.22：突发只记防护项 agent.burst 的命中（原断言“确认 + behavior_file_read_burst”）。
	if !hasBurstHit(decision) {
		t.Fatalf("burst should be an agent.burst hit, got %#v", decision)
	}
}

func TestAnalyzeToolCallUsesBehaviorWindow(t *testing.T) {
	window := NewBehaviorWindow(10*time.Second, BehaviorThresholds{FileReadBurst: 2})
	input := ToolCallAnalysisInput{
		ToolName:  "Read",
		ToolType:  "file",
		Arguments: map[string]any{"path": "/repo/src/config.json"},
		Mode:      ModeAudit,
		Behavior:  window,
		ActorKey:  "tenant/project/user",
	}
	first := AnalyzeToolCall(context.Background(), input)
	second := AnalyzeToolCall(context.Background(), input)
	// 2.9.22：突发是 agent.burst 命中（原断言 RawDecision=confirm）。
	if hasBurstHit(first) {
		t.Fatalf("first call should not hit behavior burst: %#v", first)
	}
	if !hasBurstHit(second) {
		t.Fatalf("second call should hit behavior burst, got %#v", second)
	}
}

func TestBehaviorWindowRecordWithThresholdsUsesPerCallThreshold(t *testing.T) {
	window := NewBehaviorWindow(10*time.Second, BehaviorThresholds{FileReadBurst: 100})
	input := BehaviorEvent{ActorKey: "tenant/project/user", Kind: BehaviorFileRead, Target: "/repo/.env"}
	if decision := window.RecordWithThresholds(input, BehaviorThresholds{FileReadBurst: 2}); decision.RawDecision != DecisionAllow {
		t.Fatalf("first read should allow under per-call threshold, got %#v", decision)
	}
	decision := window.RecordWithThresholds(input, BehaviorThresholds{FileReadBurst: 2})
	// 2.9.22：突发是 agent.burst 命中（原断言“确认 + behavior_file_read_burst”）。
	if !hasBurstHit(decision) {
		t.Fatalf("per-call threshold of 2 should confirm on second read (not window default 100), got %#v", decision)
	}
}

func TestAnalyzeDataEgressHonorsSecretEgressActionOverride(t *testing.T) {
	encodedToken := strings.Join([]string{
		"ZmxhZy0x",
		"MjM0NTY3",
		"ODkwYWJj",
		"ZGVmZ2hp",
		"amtsbW5v",
		"cHFyc3R1",
		"dnd4eXo",
	}, "")
	body := "token=" + encodedToken
	// 2.9.22：密钥外发的动作只来自防护项 agent.secret_egress（不再读 DLP.SecretEgressAction）。
	finding := AnalyzeDataEgress(DataEgressInput{Target: "https://evil.example/upload", Body: body})
	if byDefault := resolveProtectionHits(finding, nil); byDefault.RawDecision != DecisionAudit || !byDefault.ProtectionAlert() {
		t.Fatalf("default secret egress should alert and allow, got %#v", byDefault)
	}
	block := resolveProtectionHits(finding, &EffectivePolicy{Protections: protection.Settings{"agent.secret_egress": {Action: protection.ActionBlock}}})
	if block.RawDecision != DecisionBlock || !block.ConfiguredEnforcement {
		t.Fatalf("secret egress configured to block should block, got %#v", block)
	}
	record := resolveProtectionHits(finding, &EffectivePolicy{Protections: protection.Settings{"agent.secret_egress": {Action: protection.ActionRecord}}})
	if record.RawDecision != DecisionAudit || record.ProtectionAlert() || record.ConfiguredEnforcement {
		t.Fatalf("configured record should only record, got %#v", record)
	}
}

func TestAnalyzeToolCallUsesPolicyBehaviorThresholds(t *testing.T) {
	window := NewBehaviorWindow(10*time.Second, BehaviorThresholds{FileReadBurst: 100})
	input := ToolCallAnalysisInput{
		ToolName:  "Read",
		ToolType:  "file",
		Arguments: map[string]any{"path": "/repo/src/config.json"},
		Mode:      ModeAudit,
		Behavior:  window,
		ActorKey:  "tenant/project/user",
		Policy:    &EffectivePolicy{Mode: ModeAudit, Behavior: &BehaviorThresholds{FileReadBurst: 2}},
	}
	first := AnalyzeToolCall(context.Background(), input)
	second := AnalyzeToolCall(context.Background(), input)
	// 2.9.22：突发是 agent.burst 命中（原断言 RawDecision=confirm）。
	if hasBurstHit(first) {
		t.Fatalf("first call should not hit per-policy burst: %#v", first)
	}
	if !hasBurstHit(second) {
		t.Fatalf("second call should hit per-policy burst threshold 2 (not window default 100), got %#v", second)
	}
}

func hasBurstHit(decision Decision) bool {
	for _, hit := range decision.ProtectionHits {
		if hit.Reason == behaviorBurstReason {
			return decision.Reason == behaviorBurstReason || decision.RawDecision != DecisionAllow
		}
	}
	return false
}
