package agentintent

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestAuthorizationReferenceMatchesPinnedT14Format(t *testing.T) {
	args := map[string]any{"path": "/tmp/report.txt"}
	argsHash, err := ArgumentsHash(args)
	if err != nil {
		t.Fatal(err)
	}
	if argsHash != "sha256:1fe0cddf61747d07406bc523ce49d6615b9b8f06a4e72bde1e3d900b2ca31d9c" {
		t.Fatalf("args hash=%s", argsHash)
	}
	key, err := AuthorizationIdempotencyKey("claude-code", "ep_a", "s_a", "tu_a", argsHash, "Read",
		AuthorizationFacet{Action: "file_read", ResourceType: "file", ResourceID: "/tmp/report.txt"})
	if err != nil {
		t.Fatal(err)
	}
	if key != "8c84f56f7452712beef46aee67eb51794469bf4442cb8f03063d6a8a203e295b" {
		t.Fatalf("T14 authorization key=%s", key)
	}
}

func TestAttachTerminalResultRequiresExactIdentityAndArguments(t *testing.T) {
	raw := intentEvidenceFixture(t)
	identity := validIntentCorrelation()
	terminal := validTerminalResult()

	updated, changed, err := AttachTerminalResult(raw, identity, terminal)
	if err != nil || !changed {
		t.Fatalf("terminal result not attached: changed=%v err=%v", changed, err)
	}
	if strings.Contains(string(updated), terminal.EventID) || strings.Contains(string(updated), identity.ToolCallID) {
		t.Fatal("raw event or tool-call identifier leaked into bounded T16 evidence")
	}
	var items []map[string]any
	if err := json.Unmarshal(updated, &items); err != nil {
		t.Fatal(err)
	}
	intent := items[1]["t16_intent"].(map[string]any)
	assessment := intent["assessment"].(map[string]any)
	step := assessment["steps"].([]any)[0].(map[string]any)
	if assessment["alignment"] != "aligned" || step["result_state"] != "observed_succeeded" ||
		step["result_event_ref_hash"] != DigestString(strings.ToLower(terminal.EventID)) {
		t.Fatalf("assessment not finalized from T02 metadata: %#v", assessment)
	}

	wrong := identity
	wrong.ArgumentsHash = "sha256:" + strings.Repeat("a", 64)
	if _, changed, err := AttachTerminalResult(raw, wrong, terminal); !errors.Is(err, ErrIntentEvidenceMismatch) || changed {
		t.Fatalf("argument mismatch was attached: changed=%v err=%v", changed, err)
	}
	wrong = identity
	wrong.PromptID = "prompt-other"
	if _, changed, err := AttachTerminalResult(raw, wrong, terminal); !errors.Is(err, ErrIntentEvidenceMismatch) || changed {
		t.Fatalf("prompt mismatch was attached: changed=%v err=%v", changed, err)
	}
}

func TestIntentProposalMatchesExactServerProposalBinding(t *testing.T) {
	identity := validIntentCorrelation()
	if !IntentProposalMatches(intentEvidenceFixture(t), identity) {
		t.Fatal("exact endpoint proposal did not match report")
	}
	mutations := []func(*IntentCorrelation){
		func(v *IntentCorrelation) { v.PromptID = "prompt-other" },
		func(v *IntentCorrelation) { v.ToolCallID = "tool-other" },
		func(v *IntentCorrelation) { v.ToolName = "Write" },
		func(v *IntentCorrelation) { v.ToolType = "system" },
		func(v *IntentCorrelation) { v.ArgumentsHash = "sha256:" + strings.Repeat("c", 64) },
	}
	for index, mutate := range mutations {
		changed := identity
		mutate(&changed)
		if IntentProposalMatches(intentEvidenceFixture(t), changed) {
			t.Fatalf("proposal mutation %d matched report", index)
		}
	}
}

func TestAttachTerminalResultMakesSecondDistinctOutcomeAmbiguous(t *testing.T) {
	raw := intentEvidenceFixture(t)
	identity := validIntentCorrelation()
	first, changed, err := AttachTerminalResult(raw, identity, validTerminalResult())
	if err != nil || !changed {
		t.Fatalf("first result not attached: changed=%v err=%v", changed, err)
	}
	secondResult := validTerminalResult()
	secondResult.EventID = "c17a1542-99d0-41ee-8765-ab1b8a2cd018"
	secondResult.EventType = "tool.failure"
	secondResult.Outcome = "failed"
	updated, changed, err := AttachTerminalResult(first, identity, secondResult)
	if err != nil || !changed {
		t.Fatalf("second result not marked ambiguous: changed=%v err=%v", changed, err)
	}
	var items []map[string]any
	if err := json.Unmarshal(updated, &items); err != nil {
		t.Fatal(err)
	}
	intent := items[1]["t16_intent"].(map[string]any)
	assessment := intent["assessment"].(map[string]any)
	step := assessment["steps"].([]any)[0].(map[string]any)
	terminal := intent["terminal_result"].(map[string]any)
	if assessment["alignment"] != "uncertain" || step["result_state"] != "ambiguous" ||
		terminal["status"] != "ambiguous" {
		t.Fatalf("conflicting terminal outcomes not uncertain: %#v", intent)
	}
	if _, exists := step["result_event_ref_hash"]; exists {
		t.Fatal("ambiguous terminal result retained one event reference as authoritative")
	}
}

func TestAttachTerminalResultRejectsInvalidEventOutcome(t *testing.T) {
	terminal := validTerminalResult()
	terminal.EventType = "tool.failure"
	if _, changed, err := AttachTerminalResult(intentEvidenceFixture(t), validIntentCorrelation(), terminal); !errors.Is(err, ErrIntentEvidenceInvalid) || changed {
		t.Fatalf("mismatched event/outcome accepted: changed=%v err=%v", changed, err)
	}
}

func validIntentCorrelation() IntentCorrelation {
	return IntentCorrelation{
		EndpointID: "endpoint-a", SessionID: "session-a", PromptID: "prompt-a",
		ToolCallID: "tool-call-a", ToolCallLogID: "server-log-1", ToolName: "Read", ToolType: "file",
		ArgumentsHash: "sha256:2d96610911fdc0f3f5b61660e1874c8c70f6b5ef590858b1a9429203f5a2f9ce",
	}
}

func validTerminalResult() TerminalResult {
	return TerminalResult{
		EventID:   "a17a1542-99d0-41ee-8765-ab1b8a2cd018",
		EventType: "tool.post", Outcome: "succeeded",
		ResultHash: "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		Length:     24, HasLength: true,
	}
}

func intentEvidenceFixture(t *testing.T) []byte {
	t.Helper()
	identity := validIntentCorrelation()
	value := []any{
		map[string]any{"rule_id": "policy-check", "category": "policy"},
		map[string]any{
			"rule_id": "intent_flow_assessment", "category": "intent_assessment",
			"t16_intent": map[string]any{
				"schema":                 "t16-intent/v1",
				"arguments_hash":         identity.ArgumentsHash,
				"endpoint_ref_hash":      DigestString(identity.EndpointID),
				"session_ref_hash":       DigestString(identity.SessionID),
				"prompt_ref_hash":        DigestString(identity.PromptID),
				"tool_call_ref_hash":     DigestString(identity.ToolCallID),
				"tool_name_ref_hash":     DigestString(identity.ToolName),
				"tool_type":              identity.ToolType,
				"tool_call_log_ref_hash": DigestString(identity.ToolCallLogID),
				"assessment": map[string]any{
					"alignment":       "uncertain",
					"completeness":    "partial",
					"review_required": true,
					"issues":          []string{"result_missing"},
					"steps": []any{map[string]any{
						"tool_call_ref_hash":  DigestString(identity.ToolCallID),
						"authorization_state": "matched",
						"result_state":        "missing",
						"issues":              []string{"result_missing"},
						"evidence_json":       []any{},
					}},
				},
			},
		},
	}
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestMergeIntentEvidenceBindsServerLogAndPreservesExistingEvidence(t *testing.T) {
	existing := []byte(`[{"rule_id":"policy","category":"policy"}]`)
	incoming := intentEvidenceFixture(t)
	merged, changed, err := MergeIntentEvidence(existing, incoming, "server-log-1")
	if err != nil || !changed {
		t.Fatalf("intent evidence not merged: changed=%v err=%v", changed, err)
	}
	var items []map[string]any
	if err := json.Unmarshal(merged, &items); err != nil {
		t.Fatal(err)
	}
	if len(items) != 2 || items[0]["rule_id"] != "policy" {
		t.Fatalf("existing evidence array was not preserved: %#v", items)
	}
	intent := items[1]["t16_intent"].(map[string]any)
	if intent["tool_call_log_ref_hash"] != DigestString("server-log-1") {
		t.Fatalf("server-owned log row was not bound: %#v", intent)
	}
	mergedAgain, changed, err := MergeIntentEvidence(merged, incoming, "server-log-1")
	if err != nil || changed {
		t.Fatalf("identical T16 report should be idempotent: changed=%v err=%v", changed, err)
	}
	var repeated []map[string]any
	if err := json.Unmarshal(mergedAgain, &repeated); err != nil || len(repeated) != 2 {
		t.Fatalf("idempotent merge duplicated evidence: items=%d err=%v", len(repeated), err)
	}
}

func TestMergeIntentEvidenceMarksDifferentCallObservationUncertain(t *testing.T) {
	existing, changed, err := MergeIntentEvidence([]byte(`[]`), intentEvidenceFixture(t), "server-log-1")
	if err != nil || !changed {
		t.Fatalf("initial report not merged: changed=%v err=%v", changed, err)
	}
	other := intentEvidenceFixture(t)
	var items []map[string]any
	if err := json.Unmarshal(other, &items); err != nil {
		t.Fatal(err)
	}
	intent := items[1]["t16_intent"].(map[string]any)
	intent["arguments_hash"] = "sha256:" + strings.Repeat("b", 64)
	other, _ = json.Marshal(items)
	merged, changed, err := MergeIntentEvidence(existing, other, "server-log-1")
	if err != nil || !changed {
		t.Fatalf("conflict not made uncertain: changed=%v err=%v", changed, err)
	}
	if strings.Contains(string(merged), strings.Repeat("b", 64)) {
		t.Fatal("conflicting caller observation replaced stored authority report")
	}
	var result []map[string]any
	if err := json.Unmarshal(merged, &result); err != nil {
		t.Fatal(err)
	}
	assessment := result[0]["t16_intent"].(map[string]any)["assessment"].(map[string]any)
	if assessment["alignment"] != "uncertain" || !containsStringValue(assessment["issues"], "authorization_observation_ambiguous") {
		t.Fatalf("conflicting report was not marked uncertain: %#v", assessment)
	}
}

func containsStringValue(raw any, want string) bool {
	values, _ := raw.([]any)
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func TestBindIntentTaskStepEvidenceRequiresExactHistorySnapshot(t *testing.T) {
	taskID := "3f2504e0-4f89-41d3-9a0c-0305e82c3301"
	historyHash := "sha256:" + strings.Repeat("a", 64)
	raw := intentEvidenceFixture(t)
	var items []map[string]any
	if err := json.Unmarshal(raw, &items); err != nil {
		t.Fatal(err)
	}
	intent := items[1]["t16_intent"].(map[string]any)
	intent["approved_task"] = map[string]any{
		"task_ref_hash":    DigestString(taskID),
		"history_ref_hash": historyHash,
	}
	raw, err := json.Marshal(items)
	if err != nil {
		t.Fatal(err)
	}
	if _, changed, err := BindIntentTaskStepEvidence(raw, taskID, "step-1", 1, "sha256:"+strings.Repeat("b", 64)); !errors.Is(err, ErrIntentEvidenceMismatch) || changed {
		t.Fatalf("changed history snapshot was accepted: changed=%v err=%v", changed, err)
	}
	bound, changed, err := BindIntentTaskStepEvidence(raw, taskID, "step-1", 1, historyHash)
	if err != nil || !changed {
		t.Fatalf("exact history snapshot not bound: changed=%v err=%v", changed, err)
	}
	var result []map[string]any
	if err := json.Unmarshal(bound, &result); err != nil {
		t.Fatal(err)
	}
	approved := result[1]["t16_intent"].(map[string]any)["approved_task"].(map[string]any)
	if approved["history_ref_hash"] != historyHash || approved["server_step_ref_hash"] != DigestString("step-1") || approved["lineage_assurance"] != "server_task_record" {
		t.Fatalf("server task binding missing exact refs: %#v", approved)
	}
}
