package agentguard

import (
	"context"
	"testing"
	"time"

	"github.com/yangjiyj/aiguard/packages/shared-go/protection"
)

// 批次 2B：兜底项（短时调用过多、工具连续失败）、序列规则的“敏感”、删除与破坏的例外与确认通道。

func burstPolicy(settings protection.Settings, exceptions []PolicyException) *EffectivePolicy {
	return &EffectivePolicy{ID: "p", Mode: ModeStrict, RuleMode: ModeStrict, DefaultAction: DecisionAudit,
		ConfirmChannelEnabled: true, Behavior: &BehaviorThresholds{FileReadBurst: 1},
		Protections: settings, Exceptions: exceptions}
}

func benignRead(policy *EffectivePolicy, window *BehaviorWindow) ToolCallAnalysisInput {
	return ToolCallAnalysisInput{ToolName: "Read", ToolType: ToolTypeFile, Mode: ModeStrict,
		Arguments: map[string]any{"file_path": "/repo/src/main.go"}, Policy: policy,
		Behavior: window, ActorKey: "tenant/p/u"}
}

func TestBurst2922DefaultAlertsAndAllows(t *testing.T) {
	got := AnalyzeToolCall(context.Background(), benignRead(burstPolicy(nil, nil), NewBehaviorWindow(10*time.Second, BehaviorThresholds{})))
	if got.EffectiveDecision != DecisionAudit || !got.NotificationRequired || got.ProtectionItem != "agent.burst" || got.Reason != "behavior_burst" {
		t.Fatalf("burst must alert and allow by default: %+v", got)
	}
}

func TestBurst2922ConfiguredBlockBlocksAndExceptionReleases(t *testing.T) {
	blocking := protection.Settings{"agent.burst": {Action: protection.ActionBlock}}
	got := AnalyzeToolCall(context.Background(), benignRead(burstPolicy(blocking, nil), NewBehaviorWindow(10*time.Second, BehaviorThresholds{})))
	if got.EffectiveDecision != DecisionBlock || got.ProtectionItem != "agent.burst" {
		t.Fatalf("burst configured to block must block: %+v", got)
	}
	exception := []PolicyException{{ID: "e-burst", RuleID: "agent.burst", ExpiresAt: time.Now().Add(time.Hour)}}
	released := AnalyzeToolCall(context.Background(), benignRead(burstPolicy(blocking, exception), NewBehaviorWindow(10*time.Second, BehaviorThresholds{})))
	if released.EffectiveDecision != DecisionAudit || released.ProtectionAction != string(protection.ActionRecord) ||
		len(released.ProtectionExceptionIDs()) != 1 || released.ProtectionExceptionIDs()[0] != "e-burst" {
		t.Fatalf("an exception naming agent.burst must release it to record-only: %+v", released)
	}
}

func TestBurst2922WindowComesFromProtectionParam(t *testing.T) {
	policy := burstPolicy(protection.Settings{"agent.burst": {Action: protection.ActionBlock, Params: map[string]any{"window_seconds": 60}}}, nil)
	policy.Behavior = &BehaviorThresholds{FileReadBurst: 2}
	window := NewBehaviorWindow(10*time.Second, BehaviorThresholds{})
	start := time.Unix(1_700_000_000, 0)
	window.now = func() time.Time { return start }
	first := AnalyzeToolCall(context.Background(), benignRead(policy, window))
	window.now = func() time.Time { return start.Add(30 * time.Second) }
	second := AnalyzeToolCall(context.Background(), benignRead(policy, window))
	if first.EffectiveDecision == DecisionBlock || second.EffectiveDecision != DecisionBlock {
		t.Fatalf("two reads 30s apart are a burst under a 60s window: first=%s second=%+v", first.EffectiveDecision, second)
	}
	short := burstPolicy(protection.Settings{"agent.burst": {Action: protection.ActionBlock}}, nil)
	short.Behavior = &BehaviorThresholds{FileReadBurst: 2}
	window = NewBehaviorWindow(10*time.Second, BehaviorThresholds{})
	window.now = func() time.Time { return start }
	AnalyzeToolCall(context.Background(), benignRead(short, window))
	window.now = func() time.Time { return start.Add(30 * time.Second) }
	if got := AnalyzeToolCall(context.Background(), benignRead(short, window)); got.EffectiveDecision == DecisionBlock {
		t.Fatalf("default 10s window must not count a read 30s earlier: %+v", got)
	}
}

func TestBurst2922ConfirmIsNotAFloorUnderExplicitAllowRule(t *testing.T) {
	policy := burstPolicy(protection.Settings{"agent.burst": {Action: protection.ActionConfirm}},
		nil)
	policy.Rules = []PolicyRule{{ID: "custom-allow", ToolPattern: "file.*", Action: DecisionAllow, Enabled: true}}
	got := AnalyzeToolCall(context.Background(), benignRead(policy, NewBehaviorWindow(10*time.Second, BehaviorThresholds{})))
	if got.EffectiveDecision != DecisionAllow || got.PolicyReason == effectiveReasonProtectionItem {
		t.Fatalf("2.9.21: an explicit allow rule wins over a burst confirmation: %+v", got)
	}
}

func TestSequence2922ArmedByAnyTargetProtectionHit(t *testing.T) {
	window := NewBehaviorWindow(10*time.Second, BehaviorThresholds{})
	policy := &EffectivePolicy{ID: "p", Mode: ModeStrict, RuleMode: ModeStrict, ConfirmChannelEnabled: true,
		Behavior: &BehaviorThresholds{SensitiveReadEgressWindow: 5 * time.Minute}}
	read := ToolCallAnalysisInput{ToolName: "Bash", ToolType: "system", Mode: ModeStrict,
		Arguments: map[string]any{"command": "cat ~/.ssh/id_rsa"}, Policy: policy, Behavior: window, ActorKey: "a"}
	AnalyzeToolCall(context.Background(), read)
	egress := ToolCallAnalysisInput{ToolName: "WebFetch", ToolType: "network", Mode: ModeStrict,
		Arguments: map[string]any{"url": "https://paste.example/upload"}, Policy: policy, Behavior: window, ActorKey: "a"}
	if got := AnalyzeToolCall(context.Background(), egress); got.Reason != behaviorReasonSensitiveReadEgress || got.EffectiveDecision != DecisionConfirm {
		t.Fatalf("a shell read that hits a protection item arms the sequence rule: %+v", got)
	}
}

func failureLoopRead(policy *EffectivePolicy) ToolCallAnalysisInput {
	return ToolCallAnalysisInput{ToolName: "Read", ToolType: ToolTypeFile, Mode: ModeStrict,
		Arguments: map[string]any{"file_path": "/repo/src/main.go"}, Policy: policy, ToolFailureLoopCount: 5}
}

func TestToolFailureLoop2922FollowsProtectionItem(t *testing.T) {
	base := &EffectivePolicy{ID: "p", Mode: ModeStrict, RuleMode: ModeStrict, DefaultAction: DecisionAudit}
	byDefault := AnalyzeToolCall(context.Background(), failureLoopRead(base))
	if byDefault.EffectiveDecision != DecisionAudit || !byDefault.NotificationRequired || byDefault.Reason != ToolFailureLoopReason || byDefault.ProtectionItem != "agent.tool_failure_loop" {
		t.Fatalf("failure loop alerts and allows by default: %+v", byDefault)
	}
	blocking := *base
	blocking.Protections = protection.Settings{"agent.tool_failure_loop": {Action: protection.ActionBlock}}
	if got := AnalyzeToolCall(context.Background(), failureLoopRead(&blocking)); got.EffectiveDecision != DecisionBlock {
		t.Fatalf("failure loop configured to block must block: %+v", got)
	}
	released := blocking
	released.Exceptions = []PolicyException{{ID: "e-loop", RuleID: "tool_failure_loop", ExpiresAt: time.Now().Add(time.Hour)}}
	if got := AnalyzeToolCall(context.Background(), failureLoopRead(&released)); got.EffectiveDecision != DecisionAudit ||
		got.ProtectionAction != string(protection.ActionRecord) || len(got.ProtectionExceptionIDs()) != 1 || got.ProtectionExceptionIDs()[0] != "e-loop" {
		t.Fatalf("an exception naming tool_failure_loop must release it to record-only: %+v", got)
	}
	plain := AnalyzeToolCall(context.Background(), ToolCallAnalysisInput{ToolName: "Read", ToolType: ToolTypeFile, Mode: ModeStrict,
		Arguments: map[string]any{"file_path": "/repo/src/main.go"}, Policy: &blocking})
	if plain.ProtectionItem != "" || plain.EffectiveDecision == DecisionBlock {
		t.Fatalf("no failure loop, no hit: %+v", plain)
	}
}

// 2.9.21 的升级路径只带模式重算，丢了确认通道：命中确认规则的调用变成“无通道确认”被拦。
func TestToolFailureLoop2922ConfirmRuleStaysConfirmWithChannel(t *testing.T) {
	policy := &EffectivePolicy{ID: "p", Mode: ModeStrict, RuleMode: ModeStrict, ConfirmChannelEnabled: true,
		Rules:       []PolicyRule{{ID: "confirm-file", ToolPattern: "file.*", Action: DecisionConfirm, Enabled: true}},
		Protections: protection.Settings{"agent.tool_failure_loop": {Action: protection.ActionConfirm}}}
	got := AnalyzeToolCall(context.Background(), failureLoopRead(policy))
	if got.EffectiveDecision != DecisionConfirm {
		t.Fatalf("confirm rule with a confirmation channel must stay confirm: %+v", got)
	}
}

func destructiveRaw() Decision {
	return Decision{RawDecision: DecisionBlock, Reason: "deterministic_destructive_operation", RiskLevel: "high",
		RiskCategory: DestructiveRiskCategory, RiskSubcategory: "filesystem_delete", NormalizedTarget: "/data/build",
		OperationID: "op_1234"}
}

func destructiveInput(policy *EffectivePolicy) PolicyEvaluationInput {
	return PolicyEvaluationInput{ToolName: "Bash", ToolType: "system", Target: "/data/build", Policy: policy,
		CallerMode: ModeStrict, RiskCategory: DestructiveRiskCategory, HighConfidence: true}
}

func TestDestructive2922ExceptionReleasesTheCard(t *testing.T) {
	future := time.Now().Add(time.Hour)
	for _, tc := range []struct {
		name      string
		exception PolicyException
		released  bool
	}{
		{"subcategory and target", PolicyException{ID: "e1", RuleID: "filesystem_delete", TargetPattern: "/data/build", ExpiresAt: future}, true},
		{"card key", PolicyException{ID: "e2", RuleID: "destructive_operation", ExpiresAt: future}, true},
		{"operation id", PolicyException{ID: "e3", RuleID: "filesystem_delete", TargetPattern: "op_1234", ExpiresAt: future}, true},
		{"other target", PolicyException{ID: "e4", RuleID: "filesystem_delete", TargetPattern: "/srv", ExpiresAt: future}, false},
		{"other subcategory", PolicyException{ID: "e5", RuleID: "database_destroy", ExpiresAt: future}, false},
		{"expired", PolicyException{ID: "e6", RuleID: "filesystem_delete", ExpiresAt: time.Now().Add(-time.Hour)}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			policy := &EffectivePolicy{ID: "p", Mode: ModeStrict, Destructive: &DestructivePolicy{Mode: ModeStrict, Action: DestructiveActionBlock},
				Exceptions: []PolicyException{tc.exception}}
			got := ApplyEffectivePolicy(destructiveRaw(), destructiveInput(policy))
			if tc.released {
				if got.EffectiveDecision != DecisionAudit || got.EffectiveReason != effectiveReasonExceptionDowngrade || got.FinalAction != DestructiveActionRecord {
					t.Fatalf("exception must release the destructive card: %+v", got)
				}
				return
			}
			if got.EffectiveDecision != DecisionBlock {
				t.Fatalf("non-matching exception must not release: %+v", got)
			}
		})
	}
}

func TestDestructive2922ConfirmWithoutChannelFollowsStageItem(t *testing.T) {
	confirming := func(settings protection.Settings) *EffectivePolicy {
		return &EffectivePolicy{ID: "p", Mode: ModeStrict, Destructive: &DestructivePolicy{Mode: ModeStrict, Action: DestructiveActionConfirm, Protocol: "chat"},
			Protections: settings}
	}
	byDefault := ApplyEffectivePolicy(destructiveRaw(), destructiveInput(confirming(nil)))
	if byDefault.EffectiveDecision != DecisionAudit || !byDefault.NotificationRequired || byDefault.FinalAction != DestructiveActionAlertAllow {
		t.Fatalf("confirm without a channel alerts and allows by default: %+v", byDefault)
	}
	blocked := ApplyEffectivePolicy(destructiveRaw(), destructiveInput(confirming(protection.Settings{"agent.confirm_without_channel": {Action: protection.ActionBlock}})))
	if blocked.EffectiveDecision != DecisionBlock || blocked.EffectiveReason != effectiveReasonConfirmFailClosed {
		t.Fatalf("confirm_without_channel=block blocks: %+v", blocked)
	}
	withChannel := destructiveInput(confirming(nil))
	withChannel.DestructiveConfirmChannel = true
	if got := ApplyEffectivePolicy(destructiveRaw(), withChannel); got.EffectiveDecision != DecisionConfirm || got.FinalAction != DestructiveActionConfirm {
		t.Fatalf("with a channel the destructive confirmation stays: %+v", got)
	}
}

func TestDestructive2922ProtectionFloorAndGeneralVerdictTakeStricter(t *testing.T) {
	recording := &EffectivePolicy{ID: "p", Mode: ModeStrict, Destructive: &DestructivePolicy{Mode: ModeAudit, Action: DestructiveActionRecord},
		Protections: protection.Settings{"agent.ssh_private_key": {Action: protection.ActionBlock}}}
	raw := destructiveRaw()
	raw.ProtectionHits = []ProtectionHit{{Reason: "blocked_ssh_private_key_path", Target: "~/.ssh/id_rsa", MatchTarget: "~/.ssh/id_rsa", RiskLevel: "critical", Confidence: 0.95}}
	got := ApplyEffectivePolicy(raw, destructiveInput(recording))
	// 复审：下限胜出时 FinalAction、Mode 跟着改成阻断（原断言 FinalAction 仍是 record，工具日志与
	// 安全事件会把被拦的调用记成“仅记录”）。
	if got.EffectiveDecision != DecisionBlock || got.EffectiveReason != effectiveReasonProtectionItem ||
		got.FinalAction != DestructiveActionBlock || got.Mode != ModeStrict {
		t.Fatalf("a protection item configured to block beats a recording destructive card: %+v", got)
	}
	confirming := *recording
	confirming.Protections = protection.Settings{"agent.ssh_private_key": {Action: protection.ActionConfirm}}
	withChannel := destructiveInput(&confirming)
	withChannel.DestructiveConfirmChannel = true
	if got := ApplyEffectivePolicy(raw, withChannel); got.EffectiveDecision != DecisionConfirm ||
		got.FinalAction != DestructiveActionConfirm || got.Mode != ModeStrict {
		t.Fatalf("a protection item requiring confirmation makes the destructive final action confirm: %+v", got)
	}
	audit := destructiveInput(recording)
	audit.CallerMode = ModeAudit
	if got := ApplyEffectivePolicy(raw, audit); got.EffectiveDecision == DecisionBlock {
		t.Fatalf("global record mode records the protection floor too: %+v", got)
	}

	general := Decision{RawDecision: DecisionBlock, EffectiveDecision: DecisionBlock, EffectiveReason: effectiveReasonExplicitBlock,
		ConfiguredEnforcement: true, MatchedRuleID: "custom-block"}
	in := destructiveInput(&EffectivePolicy{ID: "p", Mode: ModeStrict, Destructive: &DestructivePolicy{Mode: ModeAudit, Action: DestructiveActionRecord}})
	in.General = &general
	if got := ApplyEffectivePolicy(destructiveRaw(), in); got.EffectiveDecision != DecisionBlock || got.MatchedRuleID != "custom-block" ||
		got.FinalAction != DestructiveActionBlock || got.Mode != ModeStrict ||
		got.OperationID != "op_1234" || got.RiskCategory != DestructiveRiskCategory || got.RiskSubcategory != "filesystem_delete" {
		t.Fatalf("an explicit block rule on the same call is kept, as a destructive record: %+v", got)
	}
	unconfigured := general
	unconfigured.ConfiguredEnforcement = false
	in.General = &unconfigured
	if got := ApplyEffectivePolicy(destructiveRaw(), in); got.EffectiveDecision != DecisionAudit {
		t.Fatalf("an unconfigured general verdict is not kept: %+v", got)
	}
}

func TestToolFailureWindow2922UsesTenantWindowAndThreshold(t *testing.T) {
	window := NewToolFailureWindow(10*time.Minute, 5)
	start := time.Unix(1_700_000_000, 0)
	for i, at := range []time.Duration{0, 20 * time.Minute} {
		count, reached := window.RecordFailureWithin(ToolFailureEvent{ActorKey: "a", ToolName: "Bash", Target: string(rune('a' + i)), Now: start.Add(at)}, time.Hour, 2)
		if i == 1 && (count != 2 || !reached) {
			t.Fatalf("two failures 20 minutes apart reach threshold 2 in a 1h window: count=%d reached=%v", count, reached)
		}
	}
	if got := window.CountWithin("a", "Bash", start.Add(21*time.Minute), time.Hour); got != 2 {
		t.Fatalf("1h window counts both: %d", got)
	}
	if got := window.CountWithin("a", "Bash", start.Add(21*time.Minute), 0); got != 1 {
		t.Fatalf("default 10m window counts only the recent one: %d", got)
	}
}

func TestRestrictedFile2922ScopeAndExceptionOutsideToolCall(t *testing.T) {
	policy := &EffectivePolicy{ID: "p", Mode: ModeStrict, RuleMode: ModeStrict,
		RestrictedFiles: &RestrictedFilePolicy{Patterns: []string{"*.docx"}, Action: "block",
			Scopes: []string{RestrictedFileScopeUserMention}, ScopesConfigured: true}}
	in := ToolCallAnalysisInput{ToolName: "Read", ToolType: ToolTypeFile, Mode: ModeStrict,
		Arguments: map[string]any{"file_path": "/data/plan.docx"}, Policy: policy}
	if got := AnalyzeToolCall(context.Background(), in); got.RestrictedFileMatched || got.EffectiveDecision == DecisionBlock {
		t.Fatalf("restricted files scoped away from tool calls must not apply there: %+v", got)
	}
	policy.RestrictedFiles.Scopes = []string{RestrictedFileScopeToolCall}
	if got := AnalyzeToolCall(context.Background(), in); got.EffectiveDecision != DecisionBlock {
		t.Fatalf("tool_call scope keeps blocking: %+v", got)
	}
	if !(&RestrictedFilePolicy{}).Applies(RestrictedFileScopeProxyOutput) {
		t.Fatal("scopes not delivered (older control plane) means all scopes")
	}
	if action, exception := ResolveRestrictedFileHit(policy, "/data/plan.docx"); action != protection.ActionBlock || exception != "" {
		t.Fatalf("user mention resolves like a tool call: %s %s", action, exception)
	}
	policy.Exceptions = []PolicyException{{ID: "e-plan", RuleID: "agent.restricted_file", TargetPattern: "/data/plan.docx", ExpiresAt: time.Now().Add(time.Hour)}}
	if action, exception := ResolveRestrictedFileHit(policy, "/data/plan.docx"); action != protection.ActionRecord || exception != "e-plan" {
		t.Fatalf("an exception naming the file releases it: %s %s", action, exception)
	}
	if action, _ := ResolveRestrictedFileHit(policy, "/data/other.docx"); action != protection.ActionBlock {
		t.Fatalf("other files stay blocked: %s", action)
	}
}

func TestDecidingProtectionItem2922(t *testing.T) {
	for _, tc := range []struct {
		name string
		d    Decision
		want string
	}{
		{"protection floor", Decision{EffectiveDecision: DecisionBlock, EffectiveReason: effectiveReasonProtectionItem, ProtectionItem: "agent.ssh_private_key", ProtectionAction: "block"}, "agent.ssh_private_key"},
		{"high risk stage", Decision{EffectiveDecision: DecisionBlock, EffectiveReason: effectiveReasonAnalyzerHighRisk, ProtectionItem: "agent.env_file", ProtectionAction: "alert_allow"}, protectionKeyHighRiskWithoutRule},
		{"no channel", Decision{EffectiveDecision: DecisionBlock, EffectiveReason: effectiveReasonConfirmFailClosed}, protectionKeyConfirmWithoutChannel},
		{"confirm with channel", Decision{EffectiveDecision: DecisionConfirm, EffectiveReason: effectiveReasonStrictConfirm, PolicyReason: effectiveReasonProtectionItem, ProtectionItem: "agent.env_file", ProtectionAction: "confirm"}, "agent.env_file"},
		{"explicit rule beside an alert", Decision{EffectiveDecision: DecisionBlock, EffectiveReason: effectiveReasonExplicitBlock, ProtectionItem: "agent.env_file", ProtectionAction: "alert_allow"}, ""},
		{"skill administrator", Decision{EffectiveDecision: DecisionBlock, EffectiveReason: effectiveReasonSkillAdministrator, ProtectionItem: "agent.env_file", ProtectionAction: "alert_allow"}, ""},
		{"burst confirm", Decision{EffectiveDecision: DecisionConfirm, EffectiveReason: effectiveReasonStrictConfirm, PolicyReason: effectiveReasonAnalyzerDefault, ProtectionItem: "agent.burst", ProtectionAction: "confirm"}, "agent.burst"},
		{"alert beside a stronger unconfigured reason", Decision{EffectiveDecision: DecisionAudit, EffectiveReason: effectiveReasonAnalyzerAlertOnly, Reason: "command_not_allowlisted", ProtectionItem: "agent.ssh_private_key", ProtectionAction: "alert_allow"}, "agent.ssh_private_key"},
	} {
		if got := DecidingProtectionItem(tc.d); got != tc.want {
			t.Errorf("%s: got %q want %q", tc.name, got, tc.want)
		}
	}
}
