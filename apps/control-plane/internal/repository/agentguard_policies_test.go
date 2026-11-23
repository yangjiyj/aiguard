package repository

import (
	"testing"
	"time"
)

func TestAgentGuardPolicySpecificScopeWinsOverTemplate(t *testing.T) {
	now := time.Now()
	policies := []*AgentGuardPolicy{
		{
			ID:            "agp_template",
			TenantID:      "tenant-a",
			Name:          "默认模板",
			ScopeType:     "global_template",
			ScopeRef:      "default",
			Mode:          "audit",
			DefaultAction: "audit",
			Priority:      1,
			Enabled:       true,
			CreatedAt:     now.Add(-time.Hour),
		},
		{
			ID:            "agp_project",
			TenantID:      "tenant-a",
			Name:          "生产项目严格策略",
			ScopeType:     "project",
			ScopeRef:      "proj-1",
			Mode:          "strict",
			DefaultAction: "block",
			Priority:      1,
			Enabled:       true,
			CreatedAt:     now,
		},
	}

	resolved := ResolveAgentGuardPolicy(policies, AgentGuardPolicyScope{
		TenantID:  "tenant-a",
		ProjectID: "proj-1",
	})
	if resolved == nil {
		t.Fatal("expected a resolved policy")
	}
	if resolved.ID != "agp_project" || resolved.Mode != "strict" {
		t.Fatalf("resolved policy = %#v, want project strict policy", resolved)
	}
}
func TestAgentGuardPolicyVersionSnapshotIsReplayable(t *testing.T) {
	policy := &AgentGuardPolicy{
		ID:            "agp_1",
		TenantID:      "tenant-a",
		Name:          "生产项目严格策略",
		ScopeType:     "project",
		ScopeRef:      "proj-1",
		Mode:          "strict",
		DefaultAction: "audit",
		FailPolicy:    "fail_closed",
		RulesJSON:     map[string]any{"rules": []any{map[string]any{"action": "block", "tool": "network.upload"}}},
		Enabled:       true,
	}

	version, err := NewAgentGuardPolicyVersion(policy, "user-1")
	if err != nil {
		t.Fatalf("create version snapshot: %v", err)
	}
	if version.PolicyID != policy.ID || version.PolicyVersion == "" || version.ConfigHash == "" {
		t.Fatalf("version snapshot missing replay metadata: %#v", version)
	}
	if version.SnapshotJSON["mode"] != "strict" || version.SnapshotJSON["fail_policy"] != "fail_closed" {
		t.Fatalf("snapshot did not capture policy semantics: %#v", version.SnapshotJSON)
	}
}

func TestValidateAgentGuardPolicyRequiresAuditableRules(t *testing.T) {
	basePolicy := func(rules any) *AgentGuardPolicy {
		return &AgentGuardPolicy{
			TenantID:      "tenant-a",
			Name:          "可审计规则策略",
			ScopeType:     "tenant",
			Mode:          AgentGuardModeStrict,
			DefaultAction: AgentGuardActionAudit,
			FailPolicy:    AgentGuardFailClosed,
			RulesJSON:     map[string]any{"rules": rules},
		}
	}
	tests := []struct {
		name    string
		rules   any
		wantErr bool
	}{
		{
			name: "valid allow confirm and block rules",
			rules: []any{
				map[string]any{"id": "allow-read", "tool_pattern": "file.read", "action": AgentGuardActionAllow},
				map[string]any{"id": "confirm-shell", "tool_pattern": "system.*", "action": AgentGuardActionConfirm},
				map[string]any{"id": "block-network", "tool_pattern": "network.[w]ebsearch", "action": AgentGuardActionBlock},
			},
		},
		{
			name:    "missing id",
			rules:   []any{map[string]any{"tool_pattern": "network.*", "action": AgentGuardActionBlock}},
			wantErr: true,
		},
		{
			name:    "whitespace id",
			rules:   []any{map[string]any{"id": "   ", "tool_pattern": "network.*", "action": AgentGuardActionBlock}},
			wantErr: true,
		},
		{
			name: "trimmed duplicate ids",
			rules: []any{
				map[string]any{"id": "rule-1", "tool_pattern": "file.*", "action": AgentGuardActionAudit},
				map[string]any{"id": " rule-1 ", "tool_pattern": "network.*", "action": AgentGuardActionBlock},
			},
			wantErr: true,
		},
		{
			name:    "missing pattern",
			rules:   []any{map[string]any{"id": "rule-1", "action": AgentGuardActionAudit}},
			wantErr: true,
		},
		{
			name:    "invalid glob",
			rules:   []any{map[string]any{"id": "rule-1", "tool_pattern": "network.[", "action": AgentGuardActionAudit}},
			wantErr: true,
		},
		{
			name:    "invalid action",
			rules:   []any{map[string]any{"id": "rule-1", "tool_pattern": "network.*", "action": "execute"}},
			wantErr: true,
		},
		{name: "malformed rules collection", rules: "not-an-array", wantErr: true},
		{name: "non-object rule", rules: []any{"not-an-object"}, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateAgentGuardPolicy(basePolicy(tt.rules))
			if tt.wantErr && err == nil {
				t.Fatal("expected invalid rules to be rejected")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("valid rules rejected: %v", err)
			}
		})
	}
}

func TestValidateAgentGuardPolicyCanonicalizesOptionalRuleFields(t *testing.T) {
	tests := []struct {
		name          string
		field         string
		omit          bool
		value         any
		wantCanonical any
		wantErr       bool
	}{
		{name: "enabled missing defaults true", field: "enabled", omit: true, wantCanonical: true},
		{name: "enabled null defaults true", field: "enabled", value: nil, wantCanonical: true},
		{name: "enabled true preserved", field: "enabled", value: true, wantCanonical: true},
		{name: "enabled false preserved", field: "enabled", value: false, wantCanonical: false},
		{name: "enabled string rejected", field: "enabled", value: "true", wantErr: true},
		{name: "enabled number rejected", field: "enabled", value: float64(1), wantErr: true},
		{name: "enabled object rejected", field: "enabled", value: map[string]any{"value": true}, wantErr: true},
		{name: "name missing defaults empty", field: "name", omit: true, wantCanonical: ""},
		{name: "name null defaults empty", field: "name", value: nil, wantCanonical: ""},
		{name: "name string preserved", field: "name", value: "网络阻断", wantCanonical: "网络阻断"},
		{name: "name bool rejected", field: "name", value: true, wantErr: true},
		{name: "name number rejected", field: "name", value: float64(1), wantErr: true},
		{name: "name object rejected", field: "name", value: map[string]any{"zh": "网络阻断"}, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := map[string]any{
				"id":           "rule-1",
				"tool_pattern": "network.*",
				"action":       AgentGuardActionBlock,
			}
			if !tt.omit {
				rule[tt.field] = tt.value
			}
			policy := &AgentGuardPolicy{
				TenantID:      "tenant-a",
				Name:          "可选字段校验",
				ScopeType:     "tenant",
				Mode:          AgentGuardModeStrict,
				DefaultAction: AgentGuardActionAudit,
				FailPolicy:    AgentGuardFailClosed,
				RulesJSON:     map[string]any{"rules": []any{rule}},
			}

			err := ValidateAgentGuardPolicy(policy)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("%s=%#v should be rejected", tt.field, tt.value)
				}
				return
			}
			if err != nil {
				t.Fatalf("valid optional field rejected: %v", err)
			}
			if got, exists := rule[tt.field]; !exists || got != tt.wantCanonical {
				t.Fatalf("canonical %s = %#v (exists=%v), want %#v", tt.field, got, exists, tt.wantCanonical)
			}
		})
	}
}

func TestAgentGuardPolicyCompatibilityWritesRejectNil(t *testing.T) {
	repo := &AgentGuardPolicyRepository{}
	if err := repo.CreatePolicy(t.Context(), nil); err == nil {
		t.Fatal("CreatePolicy(nil) should return an error")
	}
	if updated, err := repo.UpdatePolicy(t.Context(), nil); err == nil || updated {
		t.Fatalf("UpdatePolicy(nil) = updated:%v err:%v, want false/error", updated, err)
	}
	if _, err := repo.CreateVersion(t.Context(), nil, "user-a"); err == nil {
		t.Fatal("CreateVersion(nil) should return an error")
	}
}
