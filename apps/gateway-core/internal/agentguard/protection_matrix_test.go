package agentguard

import (
	"context"
	"testing"
	"time"

	"github.com/yangjiyj/aiguard/packages/shared-go/protection"
)

func sshReadCall() ToolCallAnalysisInput {
	return ToolCallAnalysisInput{ToolName: "Read", ToolType: ToolTypeFile,
		Arguments: map[string]any{"file_path": "/home/u/.ssh/id_rsa"}, Mode: ModeStrict}
}

func policyWith(settings protection.Settings, rules []PolicyRule, exceptions []PolicyException) *EffectivePolicy {
	return &EffectivePolicy{ID: "p", Mode: ModeStrict, DefaultAction: DecisionAudit,
		ConfirmChannelEnabled: false, Rules: rules, Exceptions: exceptions, Protections: settings}
}

func analyzeMatrix(in ToolCallAnalysisInput) Decision {
	return AnalyzeToolCall(context.Background(), in)
}

func TestProtectionDefaultIsAlertAllow(t *testing.T) {
	in := sshReadCall()
	in.Policy = policyWith(nil, nil, nil)
	d := analyzeMatrix(in)
	if d.EffectiveDecision != DecisionAudit || !d.NotificationRequired || d.ProtectionItem != "agent.ssh_private_key" {
		t.Fatalf("got %+v", d)
	}
}

func TestProtectionBlockBlocksEvenWhenCardIsRecord(t *testing.T) {
	in := sshReadCall()
	in.Policy = policyWith(protection.Settings{"agent.ssh_private_key": {Action: protection.ActionBlock}},
		[]PolicyRule{{ID: "policy-center-file", ToolPattern: "file.*", Action: DecisionAudit, Enabled: true, PolicyCenterAction: "record"}}, nil)
	if d := analyzeMatrix(in); d.EffectiveDecision != DecisionBlock {
		t.Fatalf("got %+v", d)
	}
}

func TestProtectionRecordDoesNotBlockOrAlert(t *testing.T) {
	in := sshReadCall()
	in.Policy = policyWith(protection.Settings{"agent.ssh_private_key": {Action: protection.ActionRecord}}, nil, nil)
	d := analyzeMatrix(in)
	if d.EffectiveDecision != DecisionAudit || d.NotificationRequired || d.ProtectionAction != string(protection.ActionRecord) {
		t.Fatalf("got %+v", d)
	}
}

func TestProtectionExceptionReleasesOnlyItsItem(t *testing.T) {
	in := sshReadCall()
	exc := PolicyException{ID: "e1", RuleID: "blocked_ssh_private_key_path", TargetPattern: "id_rsa",
		Decision: DecisionAudit, ExpiresAt: time.Now().Add(time.Hour)}
	in.Policy = policyWith(protection.Settings{"agent.ssh_private_key": {Action: protection.ActionBlock}}, nil, []PolicyException{exc})
	if d := analyzeMatrix(in); d.EffectiveDecision != DecisionAudit || d.ProtectionAction != string(protection.ActionRecord) {
		t.Fatalf("exception must release: %+v", d)
	}
	// 卡片设为阻断时，针对防护项的例外放不开卡片。
	in.Policy = policyWith(nil, []PolicyRule{{ID: "policy-center-file", ToolPattern: "file.*", Action: DecisionBlock, Enabled: true}}, []PolicyException{exc})
	if d := analyzeMatrix(in); d.EffectiveDecision != DecisionBlock {
		t.Fatalf("card block must stay: %+v", d)
	}
}

func TestProtectionStrongestHitWinsAcrossMergedFindings(t *testing.T) {
	in := ToolCallAnalysisInput{ToolName: "Bash", ToolType: "system", Mode: ModeStrict,
		Arguments: map[string]any{"command": "cat ~/.ssh/id_rsa ~/.aws/credentials"}}
	in.Policy = policyWith(protection.Settings{
		"agent.ssh_private_key":  {Action: protection.ActionRecord},
		"agent.cloud_credential": {Action: protection.ActionBlock},
	}, nil, nil)
	d := analyzeMatrix(in)
	if d.EffectiveDecision != DecisionBlock || d.ProtectionItem != "agent.cloud_credential" {
		t.Fatalf("got %+v", d)
	}
}

func TestObserveModeNeverBlocksProtectionItems(t *testing.T) {
	in := sshReadCall()
	in.Mode = ModeObserve
	in.Policy = policyWith(protection.Settings{"agent.ssh_private_key": {Action: protection.ActionBlock}}, nil, nil)
	if d := analyzeMatrix(in); d.EffectiveDecision != DecisionAudit || d.RawDecision != DecisionBlock {
		t.Fatalf("got %+v", d)
	}
}

func TestHighRiskWithoutRuleFollowsSetting(t *testing.T) {
	in := ToolCallAnalysisInput{ToolName: "sql", ToolType: "database", Mode: ModeStrict,
		Arguments: map[string]any{"query": "DROP TABLE users"}}
	in.Policy = policyWith(nil, nil, nil)
	if d := analyzeMatrix(in); d.EffectiveDecision != DecisionAudit || !d.NotificationRequired {
		t.Fatalf("default must alert-allow: %+v", d)
	}
	in.Policy = policyWith(protection.Settings{"agent.high_risk_without_rule": {Action: protection.ActionBlock}}, nil, nil)
	if d := analyzeMatrix(in); d.EffectiveDecision != DecisionBlock {
		t.Fatalf("block setting: %+v", d)
	}
}

func TestConfirmWithoutChannelFollowsSetting(t *testing.T) {
	in := sshReadCall()
	in.Policy = policyWith(protection.Settings{"agent.ssh_private_key": {Action: protection.ActionConfirm}}, nil, nil)
	if d := analyzeMatrix(in); d.EffectiveDecision != DecisionAudit || !d.NotificationRequired || d.EffectiveReason != effectiveReasonConfirmFallbackAudit {
		t.Fatalf("default fallback must alert and allow: %+v", d)
	}
	in.Policy = policyWith(protection.Settings{
		"agent.ssh_private_key":         {Action: protection.ActionConfirm},
		"agent.confirm_without_channel": {Action: protection.ActionBlock},
	}, nil, nil)
	if d := analyzeMatrix(in); d.EffectiveDecision != DecisionBlock {
		t.Fatalf("fallback block: %+v", d)
	}
}

func TestNilPolicyUsesRegistryDefaults(t *testing.T) {
	in := sshReadCall()
	if d := analyzeMatrix(in); d.EffectiveDecision != DecisionAudit || !d.NotificationRequired || d.ProtectionItem != "agent.ssh_private_key" {
		t.Fatalf("got %+v", d)
	}
}
