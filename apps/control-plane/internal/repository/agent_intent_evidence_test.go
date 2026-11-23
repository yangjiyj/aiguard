package repository

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/yangjiyj/aiguard/packages/shared-go/agentintent"
)

func TestEndpointProposalIntentIsBoundToExactServerRow(t *testing.T) {
	log := endpointIntentProposalFixture(t)
	bound, changed, err := prepareEndpointProposalEvidence(log, "server-log-1", nil, nil, false, true)
	if err != nil || !changed {
		t.Fatalf("new proposal intent was not bound: changed=%v err=%v", changed, err)
	}
	var evidence map[string]any
	if err := json.Unmarshal(bound, &evidence); err != nil {
		t.Fatal(err)
	}
	intent := evidence["t16_intent"].(map[string]any)
	if intent["tool_call_log_ref_hash"] != agentintent.DigestString("server-log-1") || evidence["policy_checksum"] != "fixture-policy" {
		t.Fatalf("server row binding or unrelated evidence lost: %#v", evidence)
	}
	if strings.Contains(string(bound), "/workspace/secret.txt") {
		t.Fatal("raw tool arguments leaked into T16 report")
	}
}

func TestEndpointProposalDropsMismatchedIncomingIntentAndMarksStoredConflict(t *testing.T) {
	log := endpointIntentProposalFixture(t)
	log.Parameters = map[string]any{"path": "/workspace/changed.txt"}
	stripped, changed, err := prepareEndpointProposalEvidence(log, "server-log-1", nil, nil, false, true)
	if err != nil || !changed {
		t.Fatalf("mismatched incoming intent was not filtered: changed=%v err=%v", changed, err)
	}
	var evidence map[string]any
	if err := json.Unmarshal(stripped, &evidence); err != nil {
		t.Fatal(err)
	}
	if _, exists := evidence["t16_intent"]; exists || evidence["policy_checksum"] != "fixture-policy" {
		t.Fatalf("mismatched intent survived or unrelated evidence was lost: %#v", evidence)
	}

	log = endpointIntentProposalFixture(t)
	stored, _, err := prepareEndpointProposalEvidence(log, "server-log-1", nil, nil, false, true)
	if err != nil {
		t.Fatal(err)
	}
	changedStored := []byte(`{"path":"/workspace/different.txt"}`)
	uncertain, changed, err := prepareEndpointProposalEvidence(log, "server-log-1", changedStored, stored, true, true)
	if err != nil || !changed {
		t.Fatalf("changed stored parameters were not made uncertain: changed=%v err=%v", changed, err)
	}
	var merged map[string]any
	if err := json.Unmarshal(uncertain, &merged); err != nil {
		t.Fatal(err)
	}
	intent := merged["t16_intent"].(map[string]any)
	assessment := intent["assessment"].(map[string]any)
	if assessment["alignment"] != "uncertain" || !containsIntentIssue(assessment["issues"], "proposal_identity_mismatch") {
		t.Fatalf("stored proposal mismatch not marked uncertain: %#v", assessment)
	}
}

func TestEndpointIntentTerminalCorrelationWorksInEitherArrivalOrder(t *testing.T) {
	log := endpointIntentProposalFixture(t)
	params, err := json.Marshal(log.Parameters)
	if err != nil {
		t.Fatal(err)
	}
	identity := agentintent.IntentCorrelation{
		EndpointID: log.EndpointID, SessionID: log.SessionID, PromptID: log.PromptID,
		ToolCallID: log.ToolCallID, ToolCallLogID: "server-log-1", ToolName: log.ToolName, ToolType: log.ToolType,
	}
	identity.ArgumentsHash, err = agentintent.ArgumentsHash(log.Parameters)
	if err != nil {
		t.Fatal(err)
	}
	proposalLockKey := endpointToolLifecycleIdentity(log.TenantID, log.EndpointID, log.SessionID, log.ToolCallID)
	eventLockKey := endpointToolLifecycleIdentity(log.TenantID, identity.EndpointID, identity.SessionID, identity.ToolCallID)
	if proposalLockKey != eventLockKey {
		t.Fatalf("proposal and accepted event do not share lifecycle lock identity")
	}
	terminal := agentintent.TerminalResult{
		EventID: "11111111-1111-7111-8111-111111111111", EventType: "tool.post", Outcome: "succeeded",
		ResultHash: "sha256:" + strings.Repeat("b", 64), Length: 24, HasLength: true,
	}

	decideFirst, changed, err := prepareEndpointProposalEvidence(log, identity.ToolCallLogID, nil, nil, false, true)
	if err != nil || !changed {
		t.Fatalf("decide-first proposal bind failed: changed=%v err=%v", changed, err)
	}
	decideFirst, changed, err = agentintent.AttachTerminalResult(decideFirst, identity, terminal)
	if err != nil || !changed {
		t.Fatalf("decide-first terminal attach failed: changed=%v err=%v", changed, err)
	}

	// Before a proposal exists, the terminal event has no evidence row to update.
	if agentintent.IntentEvidencePresent([]byte(`[]`)) {
		t.Fatal("event-first fixture unexpectedly has a proposal")
	}
	eventFirst, changed, err := prepareEndpointProposalEvidence(log, identity.ToolCallLogID, params, []byte(`[]`), true, true)
	if err != nil || !changed {
		t.Fatalf("event-first proposal merge failed: changed=%v err=%v", changed, err)
	}
	eventFirst, changed, err = agentintent.AttachTerminalResult(eventFirst, identity, terminal)
	if err != nil || !changed {
		t.Fatalf("event-first terminal reconcile failed: changed=%v err=%v", changed, err)
	}
	for name, raw := range map[string][]byte{"decide-first": decideFirst, "event-first": eventFirst} {
		var document any
		if err := json.Unmarshal(raw, &document); err != nil {
			t.Fatal(err)
		}
		var intent map[string]any
		switch value := document.(type) {
		case map[string]any:
			intent, _ = value["t16_intent"].(map[string]any)
		case []any:
			for _, item := range value {
				if itemMap, ok := item.(map[string]any); ok {
					if candidate, ok := itemMap["t16_intent"].(map[string]any); ok {
						intent = candidate
						break
					}
				}
			}
		}
		if intent == nil {
			t.Fatalf("%s sequence did not retain a T16 intent envelope", name)
		}
		terminalEvidence := intent["terminal_result"].(map[string]any)
		if intent["tool_call_log_ref_hash"] != agentintent.DigestString("server-log-1") || terminalEvidence["status"] != "observed" {
			t.Fatalf("%s sequence did not retain exact server-row and terminal binding: %#v", name, intent)
		}
	}

	wrong := identity
	wrong.ArgumentsHash = "sha256:" + strings.Repeat("c", 64)
	if _, changed, err := agentintent.AttachTerminalResult(decideFirst, wrong, terminal); err == nil || changed {
		t.Fatalf("terminal with changed argument digest was accepted: changed=%v err=%v", changed, err)
	}
}

func TestAcceptedT02TerminalLengthKeepsJSONIntegerPrecision(t *testing.T) {
	const exact = int64(9007199254740993)
	log := endpointIntentProposalFixture(t)
	argsHash, err := agentintent.ArgumentsHash(log.Parameters)
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte(`{"tool":{"tool_use_id":"tool-a","args_hash":"` + argsHash + `","result":{"hash":"sha256:` + strings.Repeat("b", 64) + `","len":9007199254740993,"success":true}}}`)
	var event map[string]any
	if err := decodeAcceptedT02EventPayload(payload, &event); err != nil {
		t.Fatal(err)
	}
	toolUseID, _, decodedArgsHash, resultHash, length, hasLength, success, hasSuccess := agentIntentEventMetadata(event)
	eventID := "11111111-1111-7111-8111-111111111111"
	terminal := terminalResultFromAcceptedEvent(eventID, "tool.post", resultHash, length, hasLength, success, hasSuccess)
	if toolUseID != log.ToolCallID || decodedArgsHash != argsHash || terminal.Length != int(exact) || terminal.ResultHash != resultHash {
		t.Fatalf("terminal projection lost metadata: tool_use=%q args_hash=%q length=%d result_hash=%q", toolUseID, decodedArgsHash, terminal.Length, resultHash)
	}

	evidence, changed, err := prepareEndpointProposalEvidence(log, "server-log-1", nil, nil, false, true)
	if err != nil || !changed {
		t.Fatalf("proposal evidence was not server-bound: changed=%v err=%v", changed, err)
	}
	identity := agentintent.IntentCorrelation{
		EndpointID: log.EndpointID, SessionID: log.SessionID, PromptID: log.PromptID,
		ToolCallID: log.ToolCallID, ToolCallLogID: "server-log-1",
		ToolName: log.ToolName, ToolType: log.ToolType, ArgumentsHash: argsHash,
	}
	updated, changed, err := agentintent.AttachTerminalResult(evidence, identity, terminal)
	if err != nil || !changed {
		t.Fatalf("accepted T02 terminal was not attached: changed=%v err=%v", changed, err)
	}
	decoder := json.NewDecoder(strings.NewReader(string(updated)))
	decoder.UseNumber()
	var document map[string]any
	if err := decoder.Decode(&document); err != nil {
		t.Fatal(err)
	}
	intent := document["t16_intent"].(map[string]any)
	storedTerminal := intent["terminal_result"].(map[string]any)
	storedLength, ok := storedTerminal["length"].(json.Number)
	if !ok || storedLength.String() != "9007199254740993" {
		t.Fatalf("stored terminal length lost integer precision: %#v", storedTerminal["length"])
	}
	zeroLength, zeroPresent := agentEventInt(json.Number("0"))
	zeroProposal, changed, err := prepareEndpointProposalEvidence(log, "server-log-1", nil, nil, false, true)
	if err != nil || !changed {
		t.Fatalf("zero-length proposal was not bound: changed=%v err=%v", changed, err)
	}
	zeroTerminal := terminalResultFromAcceptedEvent(eventID, "tool.post", resultHash, zeroLength, zeroPresent, true, true)
	zeroEvidence, changed, err := agentintent.AttachTerminalResult(zeroProposal, identity, zeroTerminal)
	if err != nil || !changed {
		t.Fatalf("explicit empty result length was not attached: changed=%v err=%v", changed, err)
	}
	var zeroDocument map[string]any
	zeroDecoder := json.NewDecoder(strings.NewReader(string(zeroEvidence)))
	zeroDecoder.UseNumber()
	if err := zeroDecoder.Decode(&zeroDocument); err != nil {
		t.Fatal(err)
	}
	zeroStored := zeroDocument["t16_intent"].(map[string]any)["terminal_result"].(map[string]any)
	if value, ok := zeroStored["length"].(json.Number); !ok || value.String() != "0" {
		t.Fatalf("explicit zero length was omitted or changed: %#v", zeroStored["length"])
	}

	absentLength, absentPresent := agentEventInt(nil)
	if absentPresent {
		t.Fatal("missing result.len was reported as present")
	}
	absentProposal, changed, err := prepareEndpointProposalEvidence(log, "server-log-1", nil, nil, false, true)
	if err != nil || !changed {
		t.Fatalf("absent-length proposal was not bound: changed=%v err=%v", changed, err)
	}
	absentTerminal := terminalResultFromAcceptedEvent(eventID, "tool.post", resultHash, absentLength, absentPresent, true, true)
	absentEvidence, changed, err := agentintent.AttachTerminalResult(absentProposal, identity, absentTerminal)
	if err != nil || !changed {
		t.Fatalf("terminal without optional result.len was not attached: changed=%v err=%v", changed, err)
	}
	var absentDocument map[string]any
	absentDecoder := json.NewDecoder(strings.NewReader(string(absentEvidence)))
	absentDecoder.UseNumber()
	if err := absentDecoder.Decode(&absentDocument); err != nil {
		t.Fatal(err)
	}
	absentStored := absentDocument["t16_intent"].(map[string]any)["terminal_result"].(map[string]any)
	if _, exists := absentStored["length"]; exists {
		t.Fatalf("absent result.len was serialized as a numeric length: %#v", absentStored)
	}
}

func TestAcceptedT02UnrepresentableTerminalLengthCannotBeObserved(t *testing.T) {
	length, hasLength := agentEventInt(json.Number("9223372036854775808"))
	if length != -1 || !hasLength {
		t.Fatalf("unrepresentable terminal length was normalized to %d", length)
	}
	log := endpointIntentProposalFixture(t)
	argsHash, err := agentintent.ArgumentsHash(log.Parameters)
	if err != nil {
		t.Fatal(err)
	}
	identity := agentintent.IntentCorrelation{
		EndpointID: log.EndpointID, SessionID: log.SessionID, PromptID: log.PromptID,
		ToolCallID: log.ToolCallID, ToolCallLogID: "server-log-1",
		ToolName: log.ToolName, ToolType: log.ToolType, ArgumentsHash: argsHash,
	}
	terminal := terminalResultFromAcceptedEvent(
		"11111111-1111-7111-8111-111111111111", "tool.post", "", length, hasLength, true, true,
	)
	evidence, changed, err := prepareEndpointProposalEvidence(log, identity.ToolCallLogID, nil, nil, false, true)
	if err != nil || !changed {
		t.Fatalf("proposal evidence was not bound: changed=%v err=%v", changed, err)
	}
	if _, changed, err := agentintent.AttachTerminalResult(evidence, identity, terminal); err == nil || changed {
		t.Fatalf("unrepresentable terminal length was accepted: changed=%v err=%v", changed, err)
	}
	uncertain, changed, err := agentintent.MarkIntentUncertainEvidence(evidence, "terminal_identity_mismatch")
	if err != nil || !changed {
		t.Fatalf("invalid terminal was not converted to uncertain evidence: changed=%v err=%v", changed, err)
	}
	var document map[string]any
	if err := json.Unmarshal(uncertain, &document); err != nil {
		t.Fatal(err)
	}
	intent := document["t16_intent"].(map[string]any)
	assessment := intent["assessment"].(map[string]any)
	if assessment["alignment"] != "uncertain" || !containsIntentIssue(assessment["issues"], "terminal_identity_mismatch") {
		t.Fatalf("unrepresentable terminal was not left uncertain: %#v", assessment)
	}
}

func endpointIntentProposalFixture(t *testing.T) *ToolCallLog {
	t.Helper()
	parameters := map[string]any{"path": "/workspace/secret.txt"}
	argsHash, err := agentintent.ArgumentsHash(parameters)
	if err != nil {
		t.Fatal(err)
	}
	intent := map[string]any{
		"schema": "t16-intent/v1", "arguments_hash": argsHash,
		"endpoint_ref_hash":  agentintent.DigestString("endpoint-a"),
		"session_ref_hash":   agentintent.DigestString("session-a"),
		"prompt_ref_hash":    agentintent.DigestString("prompt-a"),
		"tool_call_ref_hash": agentintent.DigestString("tool-a"),
		"tool_name_ref_hash": agentintent.DigestString("Read"), "tool_type": "file",
		"assessment": map[string]any{
			"alignment": "uncertain", "completeness": "partial", "issues": []string{"result_missing"},
			"steps": []any{map[string]any{
				"tool_call_ref_hash":  agentintent.DigestString("tool-a"),
				"authorization_state": "matched", "result_state": "missing", "issues": []string{"result_missing"},
			}},
		},
	}
	evidence, err := json.Marshal(map[string]any{"policy_checksum": "fixture-policy", "t16_intent": intent})
	if err != nil {
		t.Fatal(err)
	}
	return &ToolCallLog{
		TenantID: "tenant-a", EndpointID: "endpoint-a", SessionID: "session-a", PromptID: "prompt-a",
		ToolCallID: "tool-a", ToolName: "Read", ToolType: "file", Parameters: parameters, EvidenceJSON: evidence,
	}
}

func containsIntentIssue(value any, want string) bool {
	items, _ := value.([]any)
	for _, item := range items {
		if item == want {
			return true
		}
	}
	return false
}

func TestMissingToolPostSuccessRemainsUncertainAcrossTerminalProjection(t *testing.T) {
	eventID := "11111111-1111-7111-8111-111111111111"
	terminal := terminalResultFromAcceptedEvent(eventID, "tool.post", "", 0, false, false, false)
	if terminal.Outcome != "uncertain" {
		t.Fatalf("tool.post without success flag became %q", terminal.Outcome)
	}
	log := endpointIntentProposalFixture(t)
	argsHash, err := agentintent.ArgumentsHash(log.Parameters)
	if err != nil {
		t.Fatal(err)
	}
	identity := agentintent.IntentCorrelation{
		EndpointID: log.EndpointID, SessionID: log.SessionID, PromptID: log.PromptID,
		ToolCallID: log.ToolCallID, ToolCallLogID: "server-log-1",
		ToolName: log.ToolName, ToolType: log.ToolType, ArgumentsHash: argsHash,
	}
	evidence, changed, err := prepareEndpointProposalEvidence(log, identity.ToolCallLogID, nil, nil, false, true)
	if err != nil || !changed {
		t.Fatalf("proposal evidence was not bound: changed=%v err=%v", changed, err)
	}
	updated, changed, err := agentintent.AttachTerminalResult(evidence, identity, terminal)
	if err != nil || !changed {
		t.Fatalf("uncertain terminal was not attached: changed=%v err=%v", changed, err)
	}
	var document map[string]any
	if err := json.Unmarshal(updated, &document); err != nil {
		t.Fatal(err)
	}
	intent := document["t16_intent"].(map[string]any)
	assessment := intent["assessment"].(map[string]any)
	step := assessment["steps"].([]any)[0].(map[string]any)
	storedTerminal := intent["terminal_result"].(map[string]any)
	if step["result_state"] != "uncertain" || assessment["alignment"] != "uncertain" ||
		storedTerminal["outcome"] != "uncertain" || !containsIntentIssue(assessment["issues"], "result_outcome_uncertain") {
		t.Fatalf("terminal projections disagree or became successful: %#v", intent)
	}
}
