package repository

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestAgentGuardPolicyTemplatesAreCommerciallyReadable(t *testing.T) {
	templates := AgentGuardPolicyTemplates()
	if len(templates) != 3 {
		t.Fatalf("templates length = %d, want 3", len(templates))
	}

	standard := findAgentGuardTemplate(t, templates, "standard")
	if standard.Name == "" || !strings.Contains(standard.Description, "误报") {
		t.Fatalf("standard template should have customer-readable Chinese copy: %#v", standard)
	}
	if standard.Policy.Mode != AgentGuardModeAudit || standard.Policy.DefaultAction != AgentGuardActionAudit || standard.Policy.FailPolicy != AgentGuardFailClosed {
		t.Fatalf("standard policy should start in audit/fail-closed mode: %#v", standard.Policy)
	}
	if rules, _ := standard.Policy.RulesJSON["rules"].([]map[string]any); len(rules) == 0 {
		t.Fatalf("standard template should include concrete rules: %#v", standard.Policy.RulesJSON)
	}

	strict := findAgentGuardTemplate(t, templates, "strict")
	if strict.Policy.Mode != AgentGuardModeStrict {
		t.Fatalf("strict template mode = %s, want strict", strict.Policy.Mode)
	}
	if strict.Policy.FailPolicy != AgentGuardFailClosed {
		t.Fatalf("strict template fail_policy = %s, want fail_closed", strict.Policy.FailPolicy)
	}
}

func TestBuildAgentGuardGovernanceStatsAggregatesFalsePositiveRates(t *testing.T) {
	now := time.Now().UTC()
	logs := []ToolCallLog{
		governanceLog("tc_fp", "network.upload", "network", "block", "critical", "tainted_irreversible_network_egress", `[{"rule_id":"argument_tainted"}]`, now),
		governanceLog("tc_ok", "network.upload", "network", "block", "critical", "tainted_irreversible_network_egress", `[{"rule_id":"argument_tainted"}]`, now),
		governanceLog("tc_audit", "file.read", "file", "audit", "high", "sensitive_file_path", `[{"rule_id":"sensitive_file_path"}]`, now),
		governanceLog("tc_hard", "db.exec", "database", "block", "critical", "destructive_sql", `[{"rule_id":"destructive_sql"}]`, now),
	}
	dispositions := []AuditDisposition{
		{SubjectType: "tool_call", SubjectID: "tc_fp", Status: "false_positive"},
		{SubjectType: "tool_call", SubjectID: "tc_ok", Status: "accepted"},
		{SubjectType: "tool_call", SubjectID: "tc_audit", Status: "resolved"},
	}

	stats := BuildAgentGuardGovernanceStats(logs, dispositions, now)
	argumentTainted := findAgentGuardStatsGroup(t, stats.ByRule, "argument_tainted")
	if argumentTainted.HitCount != 2 || argumentTainted.FalsePositiveCount != 1 || argumentTainted.AcceptedRiskCount != 1 {
		t.Fatalf("unexpected argument_tainted group: %#v", argumentTainted)
	}
	if argumentTainted.FalsePositiveRate != 0.5 {
		t.Fatalf("false_positive_rate = %.2f, want 0.50", argumentTainted.FalsePositiveRate)
	}
	if len(stats.Recommendations) == 0 || !strings.Contains(stats.Recommendations[0].SuggestedAction, "例外") {
		t.Fatalf("expected actionable false-positive recommendation: %#v", stats.Recommendations)
	}
}
func TestSimulateAgentGuardPolicyOnLogsReportsWouldBlockImpact(t *testing.T) {
	now := time.Now().UTC()
	policy := &AgentGuardPolicy{
		ID:            "agp_strict",
		TenantID:      "tenant-a",
		Name:          "网络外联强制策略",
		Mode:          AgentGuardModeStrict,
		DefaultAction: AgentGuardActionAudit,
		FailPolicy:    AgentGuardFailClosed,
		RulesJSON: map[string]any{"rules": []map[string]any{
			{"id": "block-network", "name": "阻断外联", "tool_pattern": "network.*", "action": AgentGuardActionBlock, "enabled": true},
		}},
	}
	logs := []ToolCallLog{
		governanceLog("tc_network", "network.upload", "network", "audit", "high", "network_tool_no_risk", `[]`, now),
		governanceLog("tc_file", "file.read", "file", "audit", "medium", "file_tool_no_risk", `[]`, now),
	}

	// audit_only 关闭：保留策略内在 what-if 投影，strict 规则命中 → 会阻断。
	result := SimulateAgentGuardPolicyOnLogs(policy, logs, 10, false)
	if result.TotalEvaluated != 2 || result.WouldBlockCount != 1 || result.WouldAuditCount != 1 {
		t.Fatalf("unexpected simulation result: %#v", result)
	}
	if len(result.Samples) != 1 || result.Samples[0].ToolCallID != "tc_network" || result.Samples[0].WouldDecision != AgentGuardActionBlock {
		t.Fatalf("unexpected samples: %#v", result.Samples)
	}
}

func TestBuildAgentGuardBehaviorBaselineFlagsBurstAndRiskyActor(t *testing.T) {
	now := time.Date(2026, 6, 5, 12, 0, 0, 0, time.UTC)
	logs := []ToolCallLog{}
	for i := 0; i < 6; i++ {
		log := governanceLog("tc_read_"+string(rune('a'+i)), "file.read", "file", "audit", "high", "sensitive_file_path", `[]`, now.Add(-time.Duration(i)*time.Minute))
		log.UserID = "agent-user-1"
		log.NormalizedTarget = "/workspace/secret-" + string(rune('a'+i)) + ".env"
		logs = append(logs, log)
	}
	logs = append(logs, governanceLog("tc_network", "network.upload", "network", "block", "critical", "argument_tainted", `[]`, now.Add(-2*time.Minute)))
	logs[len(logs)-1].UserID = "agent-user-1"

	baseline := BuildAgentGuardBehaviorBaseline(logs, now)
	profile := findAgentGuardActorProfile(t, baseline.Profiles, "agent-user-1")
	if profile.TotalCalls != 7 || profile.HighRiskCalls != 7 || profile.DistinctTargetCount < 6 {
		t.Fatalf("unexpected actor profile: %#v", profile)
	}
	if len(baseline.Anomalies) == 0 {
		t.Fatalf("expected burst/risky actor anomaly: %#v", baseline)
	}
}

func TestValidateAgentGuardRolloutRequiresScopedSafeConfig(t *testing.T) {
	valid := &AgentGuardRollout{TenantID: "tenant-a", PolicyID: "agp_1", ScopeType: "project", ScopeRef: "proj-1", RolloutMode: "audit", TrafficPercent: 20, Status: "active", ExpiresAt: time.Now().Add(24 * time.Hour)}
	if err := ValidateAgentGuardRollout(valid); err != nil {
		t.Fatalf("valid rollout rejected: %v", err)
	}
	missingScope := *valid
	missingScope.ScopeRef = ""
	if err := ValidateAgentGuardRollout(&missingScope); err == nil {
		t.Fatal("expected scoped rollout without scope_ref to be rejected")
	}
	badPercent := *valid
	badPercent.TrafficPercent = 101
	if err := ValidateAgentGuardRollout(&badPercent); err == nil {
		t.Fatal("expected traffic_percent > 100 to be rejected")
	}
}

func governanceLog(id, toolName, toolType, decision, risk, reason, evidence string, createdAt time.Time) ToolCallLog {
	return ToolCallLog{
		ID:                id,
		TenantID:          "tenant-a",
		UserID:            "user-a",
		ToolName:          toolName,
		ToolType:          toolType,
		RiskLevel:         risk,
		Status:            decision,
		RawDecision:       decision,
		EffectiveDecision: decision,
		EffectiveReason:   reason,
		MatchReason:       reason,
		EvidenceJSON:      json.RawMessage(evidence),
		CreatedAt:         createdAt,
	}
}

func findAgentGuardTemplate(t *testing.T, templates []AgentGuardPolicyTemplate, id string) AgentGuardPolicyTemplate {
	t.Helper()
	for _, item := range templates {
		if item.ID == id {
			return item
		}
	}
	t.Fatalf("template %s not found in %#v", id, templates)
	return AgentGuardPolicyTemplate{}
}

func findAgentGuardStatsGroup(t *testing.T, groups []AgentGuardStatsGroup, key string) AgentGuardStatsGroup {
	t.Helper()
	for _, item := range groups {
		if item.Key == key {
			return item
		}
	}
	t.Fatalf("stats group %s not found in %#v", key, groups)
	return AgentGuardStatsGroup{}
}

func findAgentGuardActorProfile(t *testing.T, profiles []AgentGuardActorProfile, actorID string) AgentGuardActorProfile {
	t.Helper()
	for _, item := range profiles {
		if item.ActorID == actorID {
			return item
		}
	}
	t.Fatalf("actor profile %s not found in %#v", actorID, profiles)
	return AgentGuardActorProfile{}
}

func TestSimulatePolicyUsesRuntimeToolMatchCandidates(t *testing.T) {
	policy := &AgentGuardPolicy{
		ID:            "agp_match",
		TenantID:      "tenant-a",
		Name:          "真实工具匹配",
		Mode:          AgentGuardModeStrict,
		DefaultAction: AgentGuardActionAllow,
		FailPolicy:    AgentGuardFailClosed,
		RulesJSON: map[string]any{"rules": []map[string]any{
			{"id": "empty-pattern-must-not-match", "tool_pattern": "", "action": AgentGuardActionAudit, "enabled": true},
			{"id": "block-web-search", "tool_pattern": "NETWORK.WEBSEARCH", "action": AgentGuardActionBlock, "enabled": true},
		}},
	}
	log := governanceLog("tc_web", "WebSearch", "network", "allow", "low", "tool_call_no_risk", `[]`, time.Now().UTC())

	decision, reason := simulateAgentGuardDecision(policy, log, false)
	if decision != AgentGuardActionBlock || reason != "block-web-search" {
		t.Fatalf("simulation should reuse runtime type.name matching, got %q/%q", decision, reason)
	}
}

func TestSimulatePolicyUsesSharedRulePrecedence(t *testing.T) {
	tests := []struct {
		name       string
		rules      []map[string]any
		wantAction string
		wantRuleID string
	}{
		{
			name: "specific block beats earlier wide allow",
			rules: []map[string]any{
				{"id": "allow-wide", "tool_pattern": "network.*", "action": AgentGuardActionAllow, "enabled": true},
				{"id": "block-specific", "tool_pattern": "network.websearch", "action": AgentGuardActionBlock, "enabled": true},
			},
			wantAction: AgentGuardActionBlock,
			wantRuleID: "block-specific",
		},
		{
			name: "confirm beats audit and allow",
			rules: []map[string]any{
				{"id": "allow-wide", "tool_pattern": "network.*", "action": AgentGuardActionAllow, "enabled": true},
				{"id": "audit-specific", "tool_pattern": "network.websearch", "action": AgentGuardActionAudit, "enabled": true},
				{"id": "confirm-specific", "tool_pattern": "network.websearch", "action": AgentGuardActionConfirm, "enabled": true},
			},
			wantAction: AgentGuardActionConfirm,
			wantRuleID: "confirm-specific",
		},
		{
			name: "same strength keeps first rule",
			rules: []map[string]any{
				{"id": "block-first", "tool_pattern": "network.*", "action": AgentGuardActionBlock, "enabled": true},
				{"id": "block-second", "tool_pattern": "network.websearch", "action": AgentGuardActionBlock, "enabled": true},
			},
			wantAction: AgentGuardActionBlock,
			wantRuleID: "block-first",
		},
	}

	log := governanceLog("tc_shared_precedence", "WebSearch", "network", "allow", "low", "tool_call_no_risk", `[]`, time.Now().UTC())
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policy := &AgentGuardPolicy{
				ID:            "agp_shared_precedence",
				TenantID:      "tenant-a",
				Name:          "共享规则优先级",
				Mode:          AgentGuardModeStrict,
				DefaultAction: AgentGuardActionAllow,
				FailPolicy:    AgentGuardFailClosed,
				RulesJSON:     map[string]any{"rules": tt.rules},
			}
			decision, reason := simulateAgentGuardDecision(policy, log, false)
			if decision != tt.wantAction || reason != tt.wantRuleID {
				t.Fatalf("simulation = %q/%q, want %q/%q", decision, reason, tt.wantAction, tt.wantRuleID)
			}
		})
	}
}

func TestSimulatePolicyLegacyRuleWithoutIDUsesNameAsReason(t *testing.T) {
	policy := &AgentGuardPolicy{
		ID:            "agp_legacy_reason",
		TenantID:      "tenant-a",
		Name:          "历史策略",
		Mode:          AgentGuardModeStrict,
		DefaultAction: AgentGuardActionAllow,
		FailPolicy:    AgentGuardFailClosed,
		RulesJSON: map[string]any{"rules": []map[string]any{
			{"name": "历史网络审计规则", "tool_pattern": "network.*", "action": AgentGuardActionAudit, "enabled": true},
		}},
	}
	log := governanceLog("tc_legacy_reason", "WebSearch", "network", "allow", "low", "tool_call_no_risk", `[]`, time.Now().UTC())

	decision, reason := simulateAgentGuardDecision(policy, log, false)
	if decision != AgentGuardActionAudit || reason != "历史网络审计规则" {
		t.Fatalf("legacy simulation = %q/%q, want audit/name fallback", decision, reason)
	}
}
