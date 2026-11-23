package agentguard

import (
	"context"
	"testing"
	"time"

	"github.com/yangjiyj/aiguard/packages/shared-go/protection"
)

// 规格审查补测：取严只来自防护项与 Skill 隔离/撤销；其他配置结论（行为突发、序列规则）
// 保持 2.9.21 的优先级；阶段项例外、受限文件按原始路径的例外、破坏性分支的告警。

// burstReadCall：同一 actor 第一次读文件就触发读突发（阈值 1）；agent.burst 配成确认
// （2.9.22 起突发的动作只看这个防护项）。
func burstReadCall(path string, policy *EffectivePolicy) ToolCallAnalysisInput {
	policy.Behavior = &BehaviorThresholds{FileReadBurst: 1}
	policy.ConfirmChannelEnabled = true
	if policy.Protections == nil {
		policy.Protections = protection.Settings{}
	}
	if _, set := policy.Protections["agent.burst"]; !set {
		policy.Protections["agent.burst"] = protection.Setting{Action: protection.ActionConfirm}
	}
	return ToolCallAnalysisInput{
		ToolName: "Read", ToolType: ToolTypeFile, Arguments: map[string]any{"file_path": path},
		Mode: ModeStrict, Policy: policy, Behavior: NewBehaviorWindow(10*time.Second, BehaviorThresholds{}),
		ActorKey: "tenant/p/u",
	}
}

func TestConfiguredBehaviorConfirmKeeps2921RulePrecedence(t *testing.T) {
	for _, tc := range []struct {
		name       string
		rules      []PolicyRule
		want       DecisionAction
		wantPolicy string
	}{
		// 老卡片/自建规则不带 policy_center_action：是非托管显式规则，2.9.21 里它胜过行为确认。
		{"explicit audit rule wins", []PolicyRule{{ID: "policy-center-sensitive_resource", ToolPattern: "file.*", Action: DecisionAudit, Enabled: true}}, DecisionAudit, effectiveReasonExplicitAudit},
		{"explicit allow rule wins", []PolicyRule{{ID: "custom-allow", ToolPattern: "file.*", Action: DecisionAllow, Enabled: true}}, DecisionAllow, effectiveReasonExplicitAllow},
		// 托管卡片（仅记录/告警放行）不参与这类结论的匹配，行为确认照旧生效。
		{"managed record card skipped", []PolicyRule{{ID: "policy-center-sensitive_resource", ToolPattern: "file.*", Action: DecisionAudit, Enabled: true, PolicyCenterAction: "record"}}, DecisionConfirm, effectiveReasonAnalyzerDefault},
		{"managed alert card skipped", []PolicyRule{{ID: "policy-center-sensitive_resource", ToolPattern: "file.*", Action: DecisionAudit, Enabled: true, PolicyCenterAction: "alert_allow"}}, DecisionConfirm, effectiveReasonAnalyzerDefault},
		{"no rule", nil, DecisionConfirm, effectiveReasonAnalyzerDefault},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := AnalyzeToolCall(context.Background(), burstReadCall("/repo/pkg/secrets/manager.go", &EffectivePolicy{Mode: ModeStrict, Rules: tc.rules}))
			// 2.9.22：突发改成防护项 agent.burst，结论原因是 behavior_burst（原为 behavior_file_read_burst）。
			if got.Reason != behaviorBurstReason || got.ProtectionItem != "agent.burst" {
				t.Fatalf("fixture must carry the configured burst verdict: %+v", got)
			}
			if got.EffectiveDecision != tc.want || got.PolicyReason != tc.wantPolicy {
				t.Fatalf("effective=%s policy_reason=%s, want %s/%s: %+v", got.EffectiveDecision, got.PolicyReason, tc.want, tc.wantPolicy, got)
			}
			// 突发不是下限：原断言“不归到防护项”改为“不按防护项下限执行”（归因到 agent.burst 是对的）。
			if got.PolicyReason == effectiveReasonProtectionItem {
				t.Fatalf("a behavior confirmation must not act as a protection floor: %+v", got)
			}
		})
	}
}

func TestProtectionBlockStillBeatsExplicitAuditRule(t *testing.T) {
	policy := &EffectivePolicy{Mode: ModeStrict,
		Rules:       []PolicyRule{{ID: "custom-file-audit", ToolPattern: "file.*", Action: DecisionAudit, Enabled: true}},
		Protections: protection.Settings{"agent.sensitive_name": {Action: protection.ActionBlock}}}
	got := AnalyzeToolCall(context.Background(), burstReadCall("/repo/pkg/secrets/manager.yaml", policy))
	if got.EffectiveDecision != DecisionBlock || got.EffectiveReason != effectiveReasonProtectionItem || ProtectionItemLabel(got) != "名字像敏感文件" {
		t.Fatalf("a protection item configured to block beats an explicit audit rule: %+v", got)
	}
	in := sshReadCall()
	in.Policy = policyWith(protection.Settings{"agent.ssh_private_key": {Action: protection.ActionBlock}},
		[]PolicyRule{{ID: "custom-file-audit", ToolPattern: "file.*", Action: DecisionAudit, Enabled: true}}, nil)
	if d := analyzeMatrix(in); d.EffectiveDecision != DecisionBlock {
		t.Fatalf("ssh block beats explicit audit: %+v", d)
	}
}

// 2.9.21 语义：同级合并时配置标记会传给保留下来的结论（command_not_allowlisted），它因此
// 不被降为告警；但只有非托管显式规则以外才生效，显式 audit 规则照旧胜。
func TestConfiguredBurstMergedWithSameRankConfirmKeeps2921(t *testing.T) {
	merged := mergeAnalyzerDecision(
		Decision{RawDecision: DecisionConfirm, Reason: reasonCommandNotAllowlisted, RiskLevel: "high"},
		Decision{RawDecision: DecisionConfirm, Reason: "behavior_command_execute_burst", ConfiguredEnforcement: true},
	)
	if merged.Reason != reasonCommandNotAllowlisted || !merged.ConfiguredEnforcement {
		t.Fatalf("2.9.21 merge semantics changed: %+v", merged)
	}
	audit := ApplyEffectivePolicy(merged, PolicyEvaluationInput{ToolName: "Bash", ToolType: "system", CallerMode: ModeStrict,
		Policy: &EffectivePolicy{Mode: ModeStrict, ConfirmChannelEnabled: true, Rules: []PolicyRule{{ID: "custom-system", ToolPattern: "system.*", Action: DecisionAudit, Enabled: true}}}})
	if audit.EffectiveDecision != DecisionAudit {
		t.Fatalf("explicit audit rule must win over the merged configured confirm: %+v", audit)
	}
}

func TestProtectionExceptionReleasesOnlyItsItemWhenTwoHit(t *testing.T) {
	in := ToolCallAnalysisInput{ToolName: "Bash", ToolType: "system", Mode: ModeStrict,
		Arguments: map[string]any{"command": "cat ~/.ssh/id_rsa ~/.aws/credentials"}}
	in.Policy = policyWith(protection.Settings{
		"agent.ssh_private_key":  {Action: protection.ActionBlock},
		"agent.cloud_credential": {Action: protection.ActionBlock},
	}, nil, []PolicyException{{ID: "e-ssh", RuleID: "blocked_ssh_private_key_path", Decision: DecisionAudit, ExpiresAt: time.Now().Add(time.Hour)}})
	d := analyzeMatrix(in)
	if d.EffectiveDecision != DecisionBlock || d.ProtectionItem != "agent.cloud_credential" || len(d.ProtectionExceptionIDs()) != 1 {
		t.Fatalf("releasing one of two hits must keep the other blocking: %+v", d)
	}
}

func TestProtectionExceptionNamingSomethingElseKeepsItemBlocked(t *testing.T) {
	managed := PolicyRule{ID: "policy-center-file", ToolPattern: "file.*", Action: DecisionAudit, Enabled: true, PolicyCenterAction: "record"}
	explicit := PolicyRule{ID: "custom-file-audit", ToolPattern: "file.*", Action: DecisionAudit, Enabled: true}
	for _, tc := range []struct {
		name   string
		rule   PolicyRule
		ruleID string
	}{
		{"managed card", managed, managed.ID},
		{"explicit rule", explicit, explicit.ID},
		{"another protection item", explicit, "agent.cloud_credential"},
		{"another protection reason", explicit, "blocked_cloud_credential_path"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in := sshReadCall()
			in.Policy = policyWith(protection.Settings{"agent.ssh_private_key": {Action: protection.ActionBlock}},
				[]PolicyRule{tc.rule}, []PolicyException{{ID: "e", RuleID: tc.ruleID, Decision: DecisionAllow, ExpiresAt: time.Now().Add(time.Hour)}})
			if d := analyzeMatrix(in); d.EffectiveDecision != DecisionBlock || d.ProtectionItem != "agent.ssh_private_key" {
				t.Fatalf("an exception naming %s must not release agent.ssh_private_key: %+v", tc.ruleID, d)
			}
		})
	}
}

func TestStageItemExceptionsReleaseOnlyMatchingTargets(t *testing.T) {
	future := time.Now().Add(time.Hour)
	t.Run("high_risk_without_rule", func(t *testing.T) {
		raw := Decision{RawDecision: DecisionBlock, Reason: "destructive_sql", RiskLevel: "critical", NormalizedTarget: "db://orders"}
		evaluate := func(pattern string) Decision {
			return ApplyEffectivePolicy(raw, PolicyEvaluationInput{ToolName: "sql", ToolType: "database", Target: "db://orders", CallerMode: ModeStrict,
				Policy: &EffectivePolicy{Mode: ModeStrict, Protections: protection.Settings{"agent.high_risk_without_rule": {Action: protection.ActionBlock}},
					Exceptions: []PolicyException{{ID: "e-hr", RuleID: "agent.high_risk_without_rule", TargetPattern: pattern, Decision: DecisionAudit, ExpiresAt: future}}}})
		}
		if d := evaluate("orders"); d.EffectiveDecision == DecisionBlock || d.EffectiveReason != effectiveReasonExceptionDowngrade {
			t.Fatalf("exception naming the stage item must release it: %+v", d)
		}
		if d := evaluate("customers"); d.EffectiveDecision != DecisionBlock || d.EffectiveReason != effectiveReasonAnalyzerHighRisk {
			t.Fatalf("exception for another target must not release: %+v", d)
		}
	})
	t.Run("confirm_without_channel from an explicit rule", func(t *testing.T) {
		evaluate := func(pattern string) Decision {
			return ApplyEffectivePolicy(Decision{RawDecision: DecisionAllow, NormalizedTarget: "https://api.example.com/x"}, PolicyEvaluationInput{
				ToolName: "WebSearch", ToolType: "network", Target: "https://api.example.com/x", CallerMode: ModeStrict,
				Policy: &EffectivePolicy{Mode: ModeStrict,
					Rules:       []PolicyRule{{ID: "confirm-search", ToolPattern: "network.websearch", Action: DecisionConfirm, Enabled: true}},
					Protections: protection.Settings{"agent.confirm_without_channel": {Action: protection.ActionBlock}},
					Exceptions:  []PolicyException{{ID: "e-cw", RuleID: "agent.confirm_without_channel", TargetPattern: pattern, Decision: DecisionAudit, ExpiresAt: future}}}})
		}
		if d := evaluate("api.example.com"); d.EffectiveDecision == DecisionBlock || d.EffectiveDecision == DecisionConfirm {
			t.Fatalf("exception naming the stage item must release it: %+v", d)
		}
		if d := evaluate("other.example.com"); d.EffectiveDecision != DecisionBlock || d.EffectiveReason != effectiveReasonConfirmFailClosed {
			t.Fatalf("exception for another target must not release: %+v", d)
		}
	})
	t.Run("confirm_without_channel from a protection item", func(t *testing.T) {
		in := sshReadCall()
		in.Policy = policyWith(protection.Settings{
			"agent.ssh_private_key":         {Action: protection.ActionConfirm},
			"agent.confirm_without_channel": {Action: protection.ActionBlock},
		}, nil, []PolicyException{{ID: "e-cw", RuleID: "agent.confirm_without_channel", TargetPattern: "id_rsa", Decision: DecisionAudit, ExpiresAt: future}})
		if d := analyzeMatrix(in); d.EffectiveDecision != DecisionAudit || d.EffectiveReason != effectiveReasonExceptionDowngrade || d.NotificationRequired {
			t.Fatalf("exception naming confirm_without_channel must release the fail-closed block: %+v", d)
		}
	})
	if !isProtectionExceptionRule("agent.ssh_private_key") || isProtectionExceptionRule("agent.high_risk_without_rule") || isProtectionExceptionRule("agent.confirm_without_channel") {
		t.Fatal("stage items must not be treated as protection-item exceptions")
	}
}

func TestRestrictedFileExceptionMatchesTheRawFileName(t *testing.T) {
	evaluate := func(pattern string) Decision {
		return AnalyzeToolCall(context.Background(), ToolCallAnalysisInput{
			ToolName: "Read", ToolType: ToolTypeFile, Arguments: map[string]any{"file_path": "/x/plan.docx"}, Mode: ModeStrict,
			Policy: &EffectivePolicy{Mode: ModeStrict,
				RestrictedFiles: &RestrictedFilePolicy{Patterns: []string{"*.docx"}, Action: "block"},
				Exceptions:      []PolicyException{{ID: "e-file", RuleID: restrictedFileReason, TargetPattern: pattern, Decision: DecisionAudit, ExpiresAt: time.Now().Add(time.Hour)}}},
		})
	}
	released := evaluate("plan.docx")
	if released.EffectiveDecision != DecisionAudit || released.ProtectionAction != string(protection.ActionRecord) || len(released.ProtectionExceptionIDs()) != 1 {
		t.Fatalf("an exception written with the file name must release the restricted file: %+v", released)
	}
	if released.NormalizedTarget == "/x/plan.docx" {
		t.Fatalf("the decision must keep the redacted target: %q", released.NormalizedTarget)
	}
	for _, hit := range released.ProtectionHits {
		if hit.Target == "/x/plan.docx" {
			t.Fatalf("the serialized hit must keep the redacted target: %+v", hit)
		}
	}
	if blocked := evaluate("budget.docx"); blocked.EffectiveDecision != DecisionBlock {
		t.Fatalf("an exception for another file must not release: %+v", blocked)
	}
}

func TestDestructiveBranchNotifiesOnProtectionAlert(t *testing.T) {
	raw := protectionFinding(targetReasonSSHPrivateKey, "~/.ssh/id_rsa", "critical", nil)
	raw.RawDecision = DecisionBlock
	raw.Reason = "filesystem_delete"
	raw.RiskCategory = DestructiveRiskCategory
	policy := &EffectivePolicy{Mode: ModeStrict, Destructive: &DestructivePolicy{Action: DestructiveActionRecord, ScopeType: "tenant"}, ConfigSource: ConfigSourceTenantPolicy}
	got := ApplyEffectivePolicy(raw, PolicyEvaluationInput{ToolName: "Bash", ToolType: "system", Policy: policy, CallerMode: ModeStrict,
		RiskCategory: DestructiveRiskCategory, HighConfidence: true})
	if !got.ProtectionAlert() || !got.NotificationRequired || got.EffectiveDecision != DecisionAudit || got.FinalAction != DestructiveActionRecord {
		t.Fatalf("a recorded destructive call that hits an alerting protection item must notify: %+v", got)
	}
	recorded := ApplyEffectivePolicy(raw, PolicyEvaluationInput{ToolName: "Bash", ToolType: "system", Policy: policy, CallerMode: ModeAudit,
		RiskCategory: DestructiveRiskCategory, HighConfidence: true})
	if recorded.NotificationRequired {
		t.Fatalf("record-only posture never notifies: %+v", recorded)
	}
}

func TestHighRiskBlockPolicyReasonIsUnified(t *testing.T) {
	for _, action := range []protection.Action{protection.ActionBlock, protection.ActionConfirm} {
		got := ApplyPolicy(Decision{RawDecision: DecisionBlock, Reason: "destructive_sql"}, PolicyContext{Mode: ModeStrict, ConfirmChannelEnabled: true, HighRiskAction: action})
		if got.PolicyReason != effectiveReasonAnalyzerHighRisk {
			t.Fatalf("%s: policy reason=%s", action, got.PolicyReason)
		}
	}
}

// 高风险兜底配成“确认”且有确认通道时，EffectiveReason 是 confirm_channel_available，
// analyzer_high_risk_block 只在 PolicyReason 上；指向该阶段项的例外照样能放开。
func TestHighRiskConfirmStageExceptionMatchesPolicyReason(t *testing.T) {
	raw := Decision{RawDecision: DecisionBlock, Reason: "destructive_sql", RiskLevel: "critical", NormalizedTarget: "db://orders"}
	evaluate := func(pattern string) Decision {
		return ApplyEffectivePolicy(raw, PolicyEvaluationInput{ToolName: "sql", ToolType: "database", Target: "db://orders", CallerMode: ModeStrict,
			Policy: &EffectivePolicy{Mode: ModeStrict, ConfirmChannelEnabled: true,
				Protections: protection.Settings{"agent.high_risk_without_rule": {Action: protection.ActionConfirm}},
				Exceptions:  []PolicyException{{ID: "e-hr", RuleID: "agent.high_risk_without_rule", TargetPattern: pattern, Decision: DecisionAudit, ExpiresAt: time.Now().Add(time.Hour)}}}})
	}
	held := evaluate("customers")
	if held.EffectiveDecision != DecisionConfirm || held.EffectiveReason != effectiveReasonStrictConfirm || held.PolicyReason != effectiveReasonAnalyzerHighRisk {
		t.Fatalf("precondition: high-risk confirm with a channel, exception for another target: %+v", held)
	}
	if released := evaluate("orders"); released.EffectiveDecision == DecisionConfirm || released.EffectiveDecision == DecisionBlock ||
		released.EffectiveReason != effectiveReasonExceptionDowngrade {
		t.Fatalf("exception naming agent.high_risk_without_rule must release the confirmation: %+v", released)
	}
}

// Skill 隔离/撤销的归因稳定：不配规则和配放行规则时生效原因一致。
func TestSkillAdministratorAttributionIsStable(t *testing.T) {
	analyze := func(rules []PolicyRule) Decision {
		return AnalyzeToolCall(context.Background(), ToolCallAnalysisInput{
			ToolName: "use_skill", ToolType: ToolTypeSkill, Mode: ModeStrict, SkillAdmission: SkillAdmissionQuarantined,
			Arguments: map[string]any{"skill": "pdf", "version": "1.0.0", "bundle_hash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
			Policy:    &EffectivePolicy{Mode: ModeStrict, Rules: rules},
		})
	}
	noRule := analyze(nil)
	allowRule := analyze([]PolicyRule{{ID: "allow-skill", ToolPattern: "skill.*", Action: DecisionAllow, Enabled: true}})
	for _, d := range []Decision{noRule, allowRule} {
		if d.EffectiveDecision != DecisionBlock || d.EffectiveReason != effectiveReasonSkillAdministrator || d.PolicyReason != effectiveReasonSkillAdministrator {
			t.Fatalf("quarantine attribution must not depend on rules: %+v", d)
		}
	}
}

// 每条命中带自己的生效动作与例外；防护项、动作、告警、例外 ID 都由命中推出。
func TestProtectionFieldsComeFromResolvedHits(t *testing.T) {
	in := ToolCallAnalysisInput{ToolName: "Bash", ToolType: "system", Mode: ModeStrict,
		Arguments: map[string]any{"command": "cat ~/.ssh/id_rsa ~/.aws/credentials"}}
	in.Policy = policyWith(protection.Settings{"agent.cloud_credential": {Action: protection.ActionAlertAllow}}, nil,
		[]PolicyException{{ID: "e-ssh", RuleID: "agent.ssh_private_key", Decision: DecisionAllow, ExpiresAt: time.Now().Add(time.Hour)}})
	d := analyzeMatrix(in)
	actions := map[string]string{}
	for _, hit := range d.ProtectionHits {
		actions[hit.Reason] = hit.Action + "/" + hit.ExceptionID
	}
	// allow 例外也记为“仅记录”，不会出现有项无动作。
	if actions["blocked_ssh_private_key_path"] != "record/e-ssh" || actions["blocked_cloud_credential_path"] != "alert_allow/" {
		t.Fatalf("hits must carry their own action and exception: %v", actions)
	}
	if d.ProtectionItem != "agent.cloud_credential" || d.ProtectionAction != "alert_allow" || !d.ProtectionAlert() ||
		len(d.ProtectionExceptionIDs()) != 1 || d.ProtectionExceptionIDs()[0] != "e-ssh" {
		t.Fatalf("summary fields must follow the strictest hit: %+v", d)
	}
	if action, ok := ProtectionHitAction(d, "blocked_ssh_private_key_path"); !ok || action != protection.ActionRecord {
		t.Fatalf("lookup must return the resolved action: %s %v", action, ok)
	}
	if _, ok := ProtectionHitAction(d, restrictedFileReason); ok {
		t.Fatal("no restricted-file hit in this call")
	}

	released := sshReadCall()
	released.Policy = policyWith(protection.Settings{"agent.ssh_private_key": {Action: protection.ActionBlock}}, nil,
		[]PolicyException{{ID: "e-allow", RuleID: "blocked_ssh_private_key_path", Decision: DecisionAllow, ExpiresAt: time.Now().Add(time.Hour)}})
	if r := analyzeMatrix(released); r.ProtectionItem != "agent.ssh_private_key" || r.ProtectionAction != string(protection.ActionRecord) ||
		r.EffectiveDecision != DecisionAudit || r.NotificationRequired {
		t.Fatalf("an allow exception leaves the item recorded, never item-without-action: %+v", r)
	}
}

// MCP 合并：命中取并集，防护项、动作、告警取自动作最严的那条命中。
func TestMergeProtectionFieldsUsesTheStrictestHit(t *testing.T) {
	alerting := Decision{ProtectionItem: "agent.cloud_metadata", ProtectionAction: "alert_allow",
		ProtectionHits: []ProtectionHit{{Reason: targetReasonCloudMetadata, Target: "http://169.254.169.254", Action: "alert_allow"}}}
	blocking := Decision{ProtectionItem: "agent.ssh_private_key", ProtectionAction: "block",
		ProtectionHits: []ProtectionHit{{Reason: targetReasonSSHPrivateKey, Target: "~/.ssh/id_rsa", Action: "block", ExceptionID: ""}}}
	for _, pair := range [][2]Decision{{alerting, blocking}, {blocking, alerting}} {
		var merged Decision
		MergeProtectionFields(&merged, pair[0], pair[1])
		if len(merged.ProtectionHits) != 2 || merged.ProtectionItem != "agent.ssh_private_key" || merged.ProtectionAction != "block" || merged.ProtectionAlert() {
			t.Fatalf("merge must take item/action/alert from the strictest hit: %+v", merged)
		}
	}
	var same Decision
	MergeProtectionFields(&same, alerting, alerting)
	if len(same.ProtectionHits) != 1 || !same.ProtectionAlert() {
		t.Fatalf("the same hit must appear once: %+v", same)
	}
}

// 升级前写的例外 rule_id 是旧原因码 blocked_sensitive_local_file_path（当时被底线忽略），
// 升级后照字面生效：.env 在 2.9.22 归 .env 文件防护项，旧原因码同样点名它。
func TestLegacyReasonCodeExceptionAppliesLiterally(t *testing.T) {
	evaluate := func(ruleID string) Decision {
		return analyzeMatrix(ToolCallAnalysisInput{ToolName: "Read", ToolType: ToolTypeFile, Mode: ModeStrict,
			Arguments: map[string]any{"file_path": "/srv/app/.env"},
			Policy: policyWith(protection.Settings{"agent.env_file": {Action: protection.ActionBlock}}, nil,
				[]PolicyException{{ID: "e-legacy", RuleID: ruleID, Decision: DecisionAudit, ExpiresAt: time.Now().Add(time.Hour)}})})
	}
	if d := evaluate("blocked_sensitive_local_file_path"); d.EffectiveDecision != DecisionAudit || len(d.ProtectionExceptionIDs()) != 1 {
		t.Fatalf("a legacy reason-code exception must release the item it used to name: %+v", d)
	}
	if d := evaluate("blocked_ssh_private_key_path"); d.EffectiveDecision != DecisionBlock {
		t.Fatalf("an exception naming another item must not release: %+v", d)
	}
}

// 第 2 条确认（有意为之，与 2.9.21“例外放开后不告警”一致）：高风险阶段项默认告警放行，
// 命中指向该结论原因码的通用例外时，例外放开它，不再告警；没有例外时照常告警。
func TestGeneralExceptionSilencesHighRiskAlert(t *testing.T) {
	raw := Decision{RawDecision: DecisionBlock, Reason: "tainted_irreversible_network_egress", RiskLevel: "high", NormalizedTarget: "https://evil.example/upload"}
	evaluate := func(exceptions []PolicyException) Decision {
		return ApplyEffectivePolicy(raw, PolicyEvaluationInput{ToolName: "network.upload", ToolType: "network", Target: "https://evil.example/upload",
			CallerMode: ModeStrict, Policy: &EffectivePolicy{Mode: ModeStrict, Exceptions: exceptions}})
	}
	alerted := evaluate(nil)
	if alerted.EffectiveDecision != DecisionAudit || !alerted.NotificationRequired || alerted.EffectiveReason != effectiveReasonAnalyzerAlertOnly {
		t.Fatalf("default high_risk_without_rule must alert and allow: %+v", alerted)
	}
	released := evaluate([]PolicyException{{ID: "e", RuleID: "tainted_irreversible_network_egress", Decision: DecisionAudit, ExpiresAt: time.Now().Add(time.Hour)}})
	if released.EffectiveDecision != DecisionAudit || released.NotificationRequired || released.EffectiveReason != effectiveReasonExceptionDowngrade {
		t.Fatalf("a matching general exception releases the verdict without an alert: %+v", released)
	}
}
