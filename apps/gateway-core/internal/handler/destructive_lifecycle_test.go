package handler

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/agentguard"
)

func TestBuildAgentGuardDestructiveLifecyclePayloadsLinksIntentAndBlockedWithoutRawArguments(t *testing.T) {
	call := ToolCall{ID: "call-delete", Type: "function", Function: ToolCallFunc{
		Name:      "shell_command",
		Arguments: `{"command":"rm -rf /srv/fixture","authorization":"Bearer top-secret","cookie":"sid=secret"}`,
	}}
	decision := agentguard.Decision{
		RawDecision:           agentguard.DecisionBlock,
		EffectiveDecision:     agentguard.DecisionBlock,
		Mode:                  agentguard.ModeLight,
		OperationID:           "op-stable",
		TraceID:               "trace-public",
		RiskLevel:             "high",
		Confidence:            1,
		EffectiveReason:       "destructive_blocked",
		ConfigSource:          agentguard.ConfigSourceTenantPolicy,
		ModeDefaultAction:     agentguard.DestructiveActionAlertAllow,
		CustomAction:          agentguard.DestructiveActionBlock,
		FinalAction:           agentguard.DestructiveActionBlock,
		NotificationRequired:  true,
		NotifyChannelIDs:      []string{"channel-a"},
		RiskCategory:          agentguard.DestructiveRiskCategory,
		RiskSubcategory:       "filesystem_delete",
		ReasonSummary:         "destructive_shell_command",
		NormalizedTarget:      "filesystem_delete:1-targets",
		DiscardablePathReason: "sensitive_target",
		Evidence: []agentguard.Evidence{{
			RuleID:        "agent_destructive_command",
			Category:      agentguard.DestructiveRiskCategory,
			SourceField:   "command",
			MaskedPreview: "rm -rf [TARGET]",
			Length:        24,
		}},
	}

	payloads := buildAgentGuardToolAuditPayloads(call, decision, map[string]interface{}{
		"command":       "rm -rf /srv/fixture",
		"authorization": "Bearer top-secret",
		"cookie":        "sid=secret",
	})
	if len(payloads) != 2 {
		t.Fatalf("payload count = %d, want intent and blocked", len(payloads))
	}
	if payloads[0].EventType != "tool_destructive_intent" || payloads[1].EventType != "tool_attempt_blocked" {
		t.Fatalf("event types = %q, %q", payloads[0].EventType, payloads[1].EventType)
	}
	for i, payload := range payloads {
		if payload.OperationID != "op-stable" || payload.ToolCallID != "call-delete" {
			t.Fatalf("payload[%d] correlation = %+v", i, payload)
		}
		if payload.RiskCategory != agentguard.DestructiveRiskCategory ||
			payload.RiskSubcategory != "filesystem_delete" ||
			payload.ModeDefaultAction != "alert_allow" ||
			payload.CustomAction != "block" ||
			payload.FinalAction != "block" ||
			!payload.NotificationRequired ||
			payload.NotificationStatus != "pending" {
			t.Fatalf("payload[%d] governance facts = %+v", i, payload)
			if len(payload.NotifyChannelIDs) != 1 || payload.NotifyChannelIDs[0] != "channel-a" {
				t.Fatalf("payload[%d] notification channels = %#v", i, payload.NotifyChannelIDs)
			}
		}
		if payload.Parameters == nil || payload.Result != "" {
			t.Fatalf("payload[%d] dropped sanitized parameters or retained result: %+v", i, payload)
		}
		for key, want := range map[string]interface{}{
			"authorization": "<redacted:sensitive-key>",
			"cookie":        "<redacted:sensitive-key>",
		} {
			if payload.Parameters[key] != want {
				t.Fatalf("payload[%d] parameter %q = %#v, want %q", i, key, payload.Parameters[key], want)
			}
		}
		encoded, err := json.Marshal(payload)
		if err != nil {
			t.Fatal(err)
		}
		lower := strings.ToLower(string(encoded))
		for _, forbidden := range []string{"top-secret", "sid=secret", "bearer "} {
			if strings.Contains(lower, forbidden) {
				t.Fatalf("payload[%d] leaked %q: %s", i, forbidden, encoded)
			}
		}
	}
	if payloads[0].Status == "blocked" || payloads[0].ExecutionForwarded {
		t.Fatalf("intent payload asserted execution outcome: %+v", payloads[0])
	}
	if payloads[1].Status != "blocked" || payloads[1].ExecutionForwarded {
		t.Fatalf("blocked payload facts = %+v", payloads[1])
	}
}

func TestBuildAgentGuardDestructiveLifecyclePayloadsRetainsSanitizedParameters(t *testing.T) {
	decision := agentguard.Decision{
		RawDecision:       agentguard.DecisionBlock,
		EffectiveDecision: agentguard.DecisionBlock,
		Mode:              agentguard.ModeLight,
		OperationID:       "op-parameters",
		RiskLevel:         "high",
		Confidence:        1,
		RiskCategory:      agentguard.DestructiveRiskCategory,
		RiskSubcategory:   "filesystem_delete",
		ReasonSummary:     "destructive_shell_command",
		NormalizedTarget:  "filesystem_delete:1-targets",
		FinalAction:       agentguard.DestructiveActionBlock,
	}
	parameters := sanitizeToolCallParameters(map[string]interface{}{
		"command":       "rm -rf /srv/fixture",
		"authorization": "Bearer top-secret",
		"cookie":        "sid=secret",
	})
	payloads := buildAgentGuardToolAuditPayloads(ToolCall{
		ID: "call-parameters", Type: "function",
		Function: ToolCallFunc{Name: "shell_command"},
	}, decision, parameters)
	if len(payloads) != 2 {
		t.Fatalf("payload count = %d, want intent and blocked", len(payloads))
	}
	for i, payload := range payloads {
		if payload.Parameters == nil {
			t.Fatalf("payload[%d] dropped the sanitized parameters", i)
		}
		if got := payload.Parameters["authorization"]; got != "<redacted:sensitive-key>" {
			t.Fatalf("payload[%d] authorization = %#v, want redacted marker", i, got)
		}
		if got := payload.Parameters["cookie"]; got != "<redacted:sensitive-key>" {
			t.Fatalf("payload[%d] cookie = %#v, want redacted marker", i, got)
		}
		encoded, err := json.Marshal(payload.Parameters)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(strings.ToLower(string(encoded)), "top-secret") || strings.Contains(strings.ToLower(string(encoded)), "sid=secret") {
			t.Fatalf("payload[%d] leaked a sensitive value: %s", i, encoded)
		}
	}
}

func TestBuildAgentGuardDestructiveLifecyclePayloadsUsesOneIntentForAlertAllow(t *testing.T) {
	decision := agentguard.Decision{
		RawDecision:          agentguard.DecisionBlock,
		EffectiveDecision:    agentguard.DecisionAudit,
		Mode:                 agentguard.ModeStrict,
		OperationID:          "op-alert",
		RiskLevel:            "high",
		Confidence:           1,
		EffectiveReason:      "destructive_alert_allow",
		ConfigSource:         agentguard.ConfigSourceTenantPolicy,
		ModeDefaultAction:    agentguard.DestructiveActionBlock,
		CustomAction:         agentguard.DestructiveActionAlertAllow,
		FinalAction:          agentguard.DestructiveActionAlertAllow,
		NotificationRequired: true,
		RiskCategory:         agentguard.DestructiveRiskCategory,
		RiskSubcategory:      "filesystem_delete",
		ReasonSummary:        "destructive_shell_command",
		NormalizedTarget:     "filesystem_delete:1-targets",
	}
	payloads := buildAgentGuardToolAuditPayloads(ToolCall{
		ID: "call-alert", Type: "function",
		Function: ToolCallFunc{Name: "shell_command", Arguments: `{"command":"rm -rf ./build"}`},
	}, decision, map[string]interface{}{"command": "rm -rf ./build"})
	if len(payloads) != 1 || payloads[0].EventType != "tool_destructive_intent" {
		t.Fatalf("alert lifecycle payloads = %+v", payloads)
	}
	if payloads[0].Status != "alerted" || payloads[0].NotificationStatus != "pending" {
		t.Fatalf("alert facts = %+v", payloads[0])
	}
}
