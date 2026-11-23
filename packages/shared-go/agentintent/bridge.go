// Package agentintent contains transport-neutral helpers shared by the
// authenticated Gateway and Control Plane T16 bridge.
package agentintent

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"
)

var (
	ErrInvalidAuthorizationReference = errors.New("invalid agent authorization reference")
	ErrIntentEvidenceMismatch        = errors.New("intent evidence does not match terminal event")
	ErrIntentEvidenceInvalid         = errors.New("invalid intent evidence")
	argsHashPattern                  = regexp.MustCompile(`(?i)^sha256:[0-9a-f]{64}$`)
	resultHashPattern                = regexp.MustCompile(`(?i)^(?:sha256:)?[0-9a-f]{64}$`)
	uuidPattern                      = regexp.MustCompile(`(?i)^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$`)
)

// AuthorizationFacet is one exact T13 action/resource request.
type AuthorizationFacet struct {
	Action       string `json:"action"`
	ResourceType string `json:"resource_type"`
	ResourceID   string `json:"resource_id"`
}

// AuthorizationResolveRequest is built from a server-authenticated endpoint
// decide call. EndpointID is deliberately supplied out-of-band by the
// Control-Plane endpoint-token middleware, not in this payload.
type AuthorizationResolveRequest struct {
	Product       string                  `json:"product"`
	IntentTaskID  string                  `json:"intent_task_id,omitempty"`
	SessionID     string                  `json:"session_id"`
	ToolUseID     string                  `json:"tool_use_id"`
	ArgumentsHash string                  `json:"arguments_hash"`
	ToolName      string                  `json:"tool_name"`
	Facets        []AuthorizationFacet    `json:"facets"`
	Sources       []IntentTaskSourceClaim `json:"sources,omitempty"`
}

// ResolvedIntentTask is returned only on the internal endpoint-authenticated
// resolver path. TaskID is a locator; Purpose and scopes are the immutable
// server-approved snapshot. It never grants T13 authority.
type ResolvedIntentTask struct {
	FacetScopeState   string                  `json:"facet_scope_state"`
	ID                string                  `json:"id"`
	Purpose           string                  `json:"purpose"`
	PurposeSHA256     string                  `json:"purpose_sha256"`
	SourceScope       IntentTaskSourceScope   `json:"source_scope"`
	SourceScopeSHA256 string                  `json:"source_scope_sha256"`
	ScopeSHA256       string                  `json:"scope_sha256"`
	ExpiresAt         time.Time               `json:"expires_at"`
	Grants            []IntentTaskGrantScope  `json:"grants"`
	History           []IntentTaskHistoryStep `json:"history"`
	HistoryTruncated  bool                    `json:"history_truncated"`
	HistorySHA256     string                  `json:"history_sha256"`
	SourceLinks       []IntentTaskSourceLink  `json:"source_links,omitempty"`
}

type IntentTaskSourceScope struct {
	AllowedKinds  []string `json:"allowed_kinds"`
	AllowedHashes []string `json:"allowed_hashes,omitempty"`
}

// CanonicalIntentTaskSourceScopeBytes returns the exact canonical JSON bytes
// used by the Control Plane to hash the immutable approved source scope.
func CanonicalIntentTaskSourceScopeBytes(scope IntentTaskSourceScope) []byte {
	scope.AllowedKinds = append([]string(nil), scope.AllowedKinds...)
	scope.AllowedHashes = append([]string(nil), scope.AllowedHashes...)
	sort.Strings(scope.AllowedKinds)
	sort.Strings(scope.AllowedHashes)
	raw, _ := json.Marshal(scope)
	return raw
}

type IntentTaskGrantScope struct {
	Action          string    `json:"action"`
	ResourceType    string    `json:"resource_type"`
	ResourceRefHash string    `json:"resource_ref_hash"`
	ExpiresAt       time.Time `json:"expires_at"`
}

type IntentTaskHistoryStep struct {
	Sequence           int                   `json:"sequence"`
	ToolName           string                `json:"tool_name"`
	Action             string                `json:"action"`
	ResourceType       string                `json:"resource_type"`
	ResourceRefHash    string                `json:"resource_ref_hash"`
	ArgumentsHash      string                `json:"arguments_hash"`
	AuthorizationState string                `json:"authorization_state"`
	ResultState        string                `json:"result_state"`
	ResultHash         string                `json:"result_hash,omitempty"`
	SourceRefs         []IntentTaskSourceRef `json:"source_refs,omitempty"`
}

// IntentTaskHistoryHash pins the exact bounded server history supplied to the
// pre-execution judge. A later server-side write must compare this snapshot.
func IntentTaskHistoryHash(steps []IntentTaskHistoryStep, truncated bool) string {
	raw, err := json.Marshal(struct {
		Steps     []IntentTaskHistoryStep `json:"steps"`
		Truncated bool                    `json:"truncated"`
	}{steps, truncated})
	if err != nil {
		return ""
	}
	return "sha256:" + DigestString(string(raw))
}

type IntentTaskSourceClaim struct {
	Kind        string `json:"kind"`
	ToolUseID   string `json:"tool_use_id,omitempty"`
	Hash        string `json:"hash"`
	PreviewHash string `json:"preview_hash,omitempty"`
}

type IntentTaskSourceLink struct {
	Index                int    `json:"index"`
	Kind                 string `json:"kind"`
	SourceHash           string `json:"source_hash"`
	LinkedStepSequence   int    `json:"linked_step_sequence,omitempty"`
	LineageState         string `json:"lineage_state"`
	ContentAssurance     string `json:"content_assurance"`
	AcceptedEventRefHash string `json:"accepted_event_ref_hash,omitempty"`
}

type IntentTaskSourceRef struct {
	Kind               string `json:"kind"`
	SourceHash         string `json:"source_hash"`
	LinkedStepSequence int    `json:"linked_step_sequence,omitempty"`
	LineageState       string `json:"lineage_state"`
	ContentAssurance   string `json:"content_assurance"`
}

type AuthorizationResolveResponse struct {
	Resolutions         []AuthorizationResolution `json:"resolutions"`
	AuthorizationStatus string                    `json:"authorization_status"`
	TaskStatus          string                    `json:"task_status"`
	Task                *ResolvedIntentTask       `json:"task,omitempty"`
}

// AuthorizationResolution contains server-read T13 decision data. Principal
// and grant identifiers are transient internal fields; callers must hash them
// before writing evidence and must never use client-supplied copies.
type AuthorizationResolution struct {
	Facet          AuthorizationFacet `json:"facet"`
	IdempotencyKey string             `json:"idempotency_key"`
	Allowed        bool               `json:"allowed"`
	Reason         string             `json:"reason"`
	PrincipalID    string             `json:"principal_id"`
	GrantID        string             `json:"grant_id,omitempty"`
}

// ArgumentsHash matches hookd event.HashJSON, including its sha256: prefix.
func ArgumentsHash(arguments any) (string, error) {
	raw, err := json.Marshal(arguments)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

// AuthorizationIdempotencyKey mirrors the pinned T14 hookd key format. The
// field order and default Go JSON names are part of this cross-repository
// contract; ArgsHash is the exact event.HashJSON output.
func AuthorizationIdempotencyKey(product, endpointID, sessionID, toolUseID, argsHash, toolName string, facet AuthorizationFacet) (string, error) {
	if product == "" || endpointID == "" || sessionID == "" || toolUseID == "" ||
		toolName == "" || facet.Action == "" || facet.ResourceType == "" ||
		facet.ResourceID == "" || !argsHashPattern.MatchString(argsHash) {
		return "", ErrInvalidAuthorizationReference
	}
	identity, err := json.Marshal(struct {
		Product    string
		EndpointID string
		SessionID  string
		ToolUseID  string
		ArgsHash   string
		ToolName   string
		Action     string
		Type       string
		ResourceID string
	}{product, endpointID, sessionID, toolUseID, argsHash, toolName,
		facet.Action, facet.ResourceType, facet.ResourceID})
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(identity)
	return hex.EncodeToString(sum[:]), nil
}

// DigestString matches the T16 evidence reference hash (hex SHA-256, no prefix).
func DigestString(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

// IntentCorrelation contains endpoint/client identifiers only for exact
// correlation. Authority must already have been resolved server-side.
type IntentCorrelation struct {
	EndpointID, SessionID, PromptID, ToolCallID, ToolCallLogID, ToolName, ToolType, ArgumentsHash string
}

// IntentProposalMatches checks a Gateway-produced report against the exact
// server-side /decide proposal before that report is attached to a log row.
// The proposal arguments are transient input to the caller; this helper only
// compares their digest and never persists them.
func IntentProposalMatches(evidenceJSON []byte, identity IntentCorrelation) bool {
	if identity.EndpointID == "" || identity.SessionID == "" || identity.PromptID == "" ||
		identity.ToolCallID == "" || identity.ToolName == "" || identity.ToolType == "" ||
		!argsHashPattern.MatchString(identity.ArgumentsHash) {
		return false
	}
	document, err := decodeEvidenceDocument(evidenceJSON)
	if err != nil {
		return false
	}
	_, envelope, err := findIntentEnvelope(document)
	if err != nil || envelope == nil || rawString(envelope["schema"]) != "t16-intent/v1" {
		return false
	}
	return rawString(envelope["arguments_hash"]) == identity.ArgumentsHash &&
		rawString(envelope["endpoint_ref_hash"]) == DigestString(identity.EndpointID) &&
		rawString(envelope["session_ref_hash"]) == DigestString(identity.SessionID) &&
		rawString(envelope["prompt_ref_hash"]) == DigestString(identity.PromptID) &&
		rawString(envelope["tool_call_ref_hash"]) == DigestString(identity.ToolCallID) &&
		rawString(envelope["tool_name_ref_hash"]) == DigestString(identity.ToolName) &&
		rawString(envelope["tool_type"]) == identity.ToolType
}

// BindIntentEvidence sets the server-selected tool_call_logs row reference on
// one report while preserving the Gateway's surrounding evidence shape.
func BindIntentEvidence(evidenceJSON []byte, toolCallLogID string) ([]byte, bool, error) {
	if toolCallLogID == "" {
		return nil, false, ErrIntentEvidenceInvalid
	}
	document, err := decodeEvidenceDocument(evidenceJSON)
	if err != nil {
		return nil, false, err
	}
	index, envelope, err := findIntentEnvelope(document)
	if err != nil || index < 0 || rawString(envelope["schema"]) != "t16-intent/v1" {
		return nil, false, ErrIntentEvidenceInvalid
	}
	bound := DigestString(toolCallLogID)
	if current := rawString(envelope["tool_call_log_ref_hash"]); current != "" {
		if current == bound {
			raw, marshalErr := marshalEvidenceDocument(document)
			return raw, false, marshalErr
		}
		return nil, false, ErrIntentEvidenceMismatch
	}
	envelope["tool_call_log_ref_hash"], err = json.Marshal(bound)
	if err != nil {
		return nil, false, err
	}
	intentRaw, err := json.Marshal(envelope)
	if err != nil {
		return nil, false, err
	}
	if err := setIntentEnvelope(document, index, intentRaw); err != nil {
		return nil, false, err
	}
	raw, err := marshalEvidenceDocument(document)
	if err != nil {
		return nil, false, err
	}
	if len(raw) > 64<<10 {
		return nil, false, fmt.Errorf("%w: bound evidence exceeds size bound", ErrIntentEvidenceInvalid)
	}
	return raw, true, nil
}

// BindIntentTaskStepEvidence records a server-selected task step after the
// repository validates the approved task and exact call identity.
func BindIntentTaskStepEvidence(evidenceJSON []byte, taskID, stepID string, sequence int, historyHash string) ([]byte, bool, error) {
	if taskID == "" || stepID == "" || sequence < 1 || !argsHashPattern.MatchString(historyHash) {
		return nil, false, ErrIntentEvidenceInvalid
	}
	document, err := decodeEvidenceDocument(evidenceJSON)
	if err != nil {
		return nil, false, err
	}
	index, envelope, err := findIntentEnvelope(document)
	if err != nil || index < 0 {
		return nil, false, ErrIntentEvidenceInvalid
	}
	approvedTask, err := decodeJSONObject(envelope["approved_task"])
	if err != nil || rawString(approvedTask["task_ref_hash"]) != DigestString(taskID) {
		return nil, false, ErrIntentEvidenceMismatch
	}
	stepRef := DigestString(stepID)
	if existing := rawString(approvedTask["server_step_ref_hash"]); existing != "" && existing != stepRef {
		return nil, false, ErrIntentEvidenceMismatch
	}
	existingHistoryHash := rawString(approvedTask["history_ref_hash"])
	if existingHistoryHash == "" || existingHistoryHash != historyHash {
		return nil, false, ErrIntentEvidenceMismatch
	}
	if err := setJSONString(approvedTask, "server_step_ref_hash", stepRef); err != nil {
		return nil, false, err
	}
	if err := setJSONInt(approvedTask, "server_sequence", sequence); err != nil {
		return nil, false, err
	}
	if err := setJSONString(approvedTask, "history_ref_hash", historyHash); err != nil {
		return nil, false, err
	}
	if err := setJSONString(approvedTask, "lineage_assurance", "server_task_record"); err != nil {
		return nil, false, err
	}
	approvedRaw, err := json.Marshal(approvedTask)
	if err != nil {
		return nil, false, err
	}
	envelope["approved_task"] = approvedRaw
	intentRaw, err := json.Marshal(envelope)
	if err != nil {
		return nil, false, err
	}
	if err := setIntentEnvelope(document, index, intentRaw); err != nil {
		return nil, false, err
	}
	raw, err := marshalEvidenceDocument(document)
	if err != nil {
		return nil, false, err
	}
	if len(raw) > 64<<10 {
		return nil, false, fmt.Errorf("%w: task-bound evidence exceeds size bound", ErrIntentEvidenceInvalid)
	}
	return raw, true, nil
}

// IntentEvidencePresent reports whether evidence contains a T16 envelope.
func IntentEvidencePresent(evidenceJSON []byte) bool {
	document, err := decodeEvidenceDocument(evidenceJSON)
	if err != nil {
		return false
	}
	index, envelope, err := findIntentEnvelope(document)
	return err == nil && index >= 0 && envelope != nil
}

// RemoveIntentEvidence drops only the T16 envelope while retaining unrelated
// audit evidence. It is used when a proposal report fails server-side binding.
func RemoveIntentEvidence(evidenceJSON []byte) ([]byte, error) {
	document, err := decodeEvidenceDocument(evidenceJSON)
	if err != nil {
		return nil, err
	}
	if !document.isArray {
		delete(document.object, "t16_intent")
		return marshalEvidenceDocument(document)
	}
	items := make([]json.RawMessage, 0, len(document.items))
	for _, rawItem := range document.items {
		item, decodeErr := decodeJSONObject(rawItem)
		if decodeErr != nil {
			return nil, decodeErr
		}
		if _, present := item["t16_intent"]; present {
			var ruleID string
			_ = json.Unmarshal(item["rule_id"], &ruleID)
			if ruleID == "intent_flow_assessment" {
				continue
			}
			delete(item, "t16_intent")
			encoded, marshalErr := json.Marshal(item)
			if marshalErr != nil {
				return nil, marshalErr
			}
			rawItem = encoded
		}
		items = append(items, rawItem)
	}
	document.items = items
	return marshalEvidenceDocument(document)
}

// MarkIntentUncertainEvidence records a bounded reason when a server-selected
// event/log correlation fails. Caller-controlled details are never copied.
func MarkIntentUncertainEvidence(evidenceJSON []byte, issue string) ([]byte, bool, error) {
	if issue != "terminal_identity_mismatch" && issue != "proposal_identity_mismatch" {
		return nil, false, ErrIntentEvidenceInvalid
	}
	document, err := decodeEvidenceDocument(evidenceJSON)
	if err != nil {
		return nil, false, err
	}
	index, envelope, err := findIntentEnvelope(document)
	if err != nil || index < 0 {
		return nil, false, err
	}
	assessment, err := decodeJSONObject(envelope["assessment"])
	if err != nil {
		return nil, false, err
	}
	steps, err := decodeObjectArray(assessment["steps"])
	if err != nil || len(steps) != 1 {
		return nil, false, ErrIntentEvidenceInvalid
	}
	if err := setJSONString(assessment, "alignment", "uncertain"); err != nil {
		return nil, false, err
	}
	if err := setJSONString(assessment, "completeness", "partial"); err != nil {
		return nil, false, err
	}
	if err := addString(assessment, "issues", issue); err != nil {
		return nil, false, err
	}
	if err := addString(steps[0], "issues", issue); err != nil {
		return nil, false, err
	}
	stepsRaw, err := json.Marshal(steps)
	if err != nil {
		return nil, false, err
	}
	assessment["steps"] = stepsRaw
	assessmentRaw, err := json.Marshal(assessment)
	if err != nil {
		return nil, false, err
	}
	envelope["assessment"] = assessmentRaw
	terminal, err := decodeJSONObject(envelope["terminal_result"])
	if err == nil {
		if err := setJSONString(terminal, "status", "uncertain"); err != nil {
			return nil, false, err
		}
		terminalRaw, marshalErr := json.Marshal(terminal)
		if marshalErr != nil {
			return nil, false, marshalErr
		}
		envelope["terminal_result"] = terminalRaw
	}
	intentRaw, err := json.Marshal(envelope)
	if err != nil {
		return nil, false, err
	}
	if err := setIntentEnvelope(document, index, intentRaw); err != nil {
		return nil, false, err
	}
	raw, err := marshalEvidenceDocument(document)
	if err != nil {
		return nil, false, err
	}
	if len(raw) > 64<<10 {
		return nil, false, fmt.Errorf("%w: uncertain evidence exceeds size bound", ErrIntentEvidenceInvalid)
	}
	return raw, true, nil
}

// TerminalResult contains metadata from one already-accepted T02 event.
type TerminalResult struct {
	EventID, EventType, Outcome, ResultHash string
	Length                                  int
	HasLength                               bool
}

// AttachTerminalResult finalizes a pre-execution T16 report only when the
// accepted T02 event matches every stored correlation digest and the exact
// argument hash. It preserves unrelated evidence fields and never adds raw IDs
// or result content. A second distinct terminal event makes the step uncertain.
func AttachTerminalResult(evidenceJSON []byte, identity IntentCorrelation, terminal TerminalResult) ([]byte, bool, error) {
	if identity.EndpointID == "" || identity.SessionID == "" || identity.PromptID == "" ||
		identity.ToolCallID == "" || identity.ToolCallLogID == "" || identity.ToolName == "" || identity.ToolType == "" || !argsHashPattern.MatchString(identity.ArgumentsHash) ||
		!uuidPattern.MatchString(terminal.EventID) || (terminal.HasLength && terminal.Length < 0) ||
		(terminal.ResultHash != "" && !resultHashPattern.MatchString(terminal.ResultHash)) {
		return nil, false, ErrIntentEvidenceInvalid
	}
	if !validTerminalOutcome(terminal.EventType, terminal.Outcome) {
		return nil, false, ErrIntentEvidenceInvalid
	}

	document, err := decodeEvidenceDocument(evidenceJSON)
	if err != nil {
		return nil, false, ErrIntentEvidenceInvalid
	}
	itemIndex, envelope, err := findIntentEnvelope(document)
	if err != nil || itemIndex < 0 {
		return nil, false, nil
	}
	var schema string
	_ = json.Unmarshal(envelope["schema"], &schema)
	if schema != "t16-intent/v1" {
		return nil, false, nil
	}
	for field, expected := range map[string]string{
		"arguments_hash":         identity.ArgumentsHash,
		"endpoint_ref_hash":      DigestString(identity.EndpointID),
		"session_ref_hash":       DigestString(identity.SessionID),
		"prompt_ref_hash":        DigestString(identity.PromptID),
		"tool_call_ref_hash":     DigestString(identity.ToolCallID),
		"tool_name_ref_hash":     DigestString(identity.ToolName),
		"tool_type":              identity.ToolType,
		"tool_call_log_ref_hash": DigestString(identity.ToolCallLogID),
	} {
		var actual string
		if json.Unmarshal(envelope[field], &actual) != nil || !strings.EqualFold(actual, expected) {
			return nil, false, ErrIntentEvidenceMismatch
		}
	}

	assessment, err := decodeJSONObject(envelope["assessment"])
	if err != nil {
		return nil, false, ErrIntentEvidenceInvalid
	}
	steps, err := decodeObjectArray(assessment["steps"])
	if err != nil || len(steps) != 1 {
		return nil, false, ErrIntentEvidenceInvalid
	}
	var toolCallRef string
	if json.Unmarshal(steps[0]["tool_call_ref_hash"], &toolCallRef) != nil ||
		!strings.EqualFold(toolCallRef, DigestString(identity.ToolCallID)) {
		return nil, false, ErrIntentEvidenceMismatch
	}

	eventRefHash := DigestString(strings.ToLower(terminal.EventID))
	var priorResult map[string]json.RawMessage
	if json.Unmarshal(envelope["terminal_result"], &priorResult) == nil && priorResult != nil {
		var priorStatus string
		_ = json.Unmarshal(priorResult["status"], &priorStatus)
		var priorRef string
		_ = json.Unmarshal(priorResult["event_ref_hash"], &priorRef)
		if priorStatus == "ambiguous" {
			return marshalUpdatedIntent(document, itemIndex, envelope, assessment, steps[0], eventRefHash, terminal, "ambiguous", false)
		}
		if priorRef == eventRefHash && priorRef != "" {
			raw, err := marshalEvidenceDocument(document)
			return raw, false, err
		}
		return marshalUpdatedIntent(document, itemIndex, envelope, assessment, steps[0], eventRefHash, terminal, "ambiguous", false)
	}

	return marshalUpdatedIntent(document, itemIndex, envelope, assessment, steps[0], eventRefHash, terminal, "observed", true)
}

// MergeIntentEvidence preserves the existing evidence_json array contract and
// adds one server-produced T16 item. It binds the report to the server-owned
// tool_call_logs row before persistence. A second, different T16 report for the
// same row is retained as uncertain rather than replacing the first.
func MergeIntentEvidence(existingJSON, incomingJSON []byte, toolCallLogID string) ([]byte, bool, error) {
	if toolCallLogID == "" {
		return nil, false, ErrIntentEvidenceInvalid
	}
	existing, err := decodeEvidenceDocument(existingJSON)
	if err != nil {
		return nil, false, err
	}
	incoming, err := decodeEvidenceDocument(incomingJSON)
	if err != nil {
		return nil, false, err
	}
	incomingIndex, envelope, err := findIntentEnvelope(incoming)
	if err != nil || incomingIndex < 0 {
		return nil, false, ErrIntentEvidenceInvalid
	}
	if schema := rawString(envelope["schema"]); schema != "t16-intent/v1" {
		return nil, false, ErrIntentEvidenceInvalid
	}
	if existingIndex, prior, findErr := findIntentEnvelope(existing); findErr != nil {
		return nil, false, findErr
	} else if existingIndex >= 0 {
		if sameIntentIdentity(prior, envelope) && rawString(prior["tool_call_log_ref_hash"]) == DigestString(toolCallLogID) {
			raw, marshalErr := marshalEvidenceDocument(existing)
			return raw, false, marshalErr
		}
		if err := markIntentAmbiguous(existing, existingIndex, prior); err != nil {
			return nil, false, err
		}
		raw, marshalErr := marshalEvidenceDocument(existing)
		return raw, true, marshalErr
	}
	envelope["tool_call_log_ref_hash"], err = json.Marshal(DigestString(toolCallLogID))
	if err != nil {
		return nil, false, err
	}
	intentRaw, err := json.Marshal(envelope)
	if err != nil {
		return nil, false, err
	}
	var item map[string]json.RawMessage
	if incoming.isArray {
		item, err = decodeJSONObject(evidenceItem(incoming, incomingIndex))
	} else {
		item = make(map[string]json.RawMessage, len(incoming.object))
		for key, value := range incoming.object {
			item[key] = value
		}
	}
	if err != nil {
		return nil, false, err
	}
	item["t16_intent"] = intentRaw
	itemRaw, err := json.Marshal(item)
	if err != nil {
		return nil, false, err
	}
	if existing.isArray {
		existing.items = append(existing.items, itemRaw)
	} else {
		existing.object["t16_intent"] = intentRaw
	}
	raw, err := marshalEvidenceDocument(existing)
	if err != nil {
		return nil, false, err
	}
	if len(raw) > 64<<10 {
		return nil, false, fmt.Errorf("%w: merged evidence exceeds size bound", ErrIntentEvidenceInvalid)
	}
	return raw, true, nil
}

func validTerminalOutcome(eventType, outcome string) bool {
	switch {
	case eventType == "tool.post" && (outcome == "succeeded" || outcome == "failed" || outcome == "uncertain"):
		return true
	case eventType == "tool.failure" && outcome == "failed":
		return true
	case eventType == "tool.denied" && outcome == "denied":
		return true
	default:
		return false
	}
}

func decodeJSONObject(raw json.RawMessage) (map[string]json.RawMessage, error) {
	var value map[string]json.RawMessage
	err := json.Unmarshal(raw, &value)
	if err != nil || value == nil {
		return nil, ErrIntentEvidenceInvalid
	}
	return value, nil
}

func decodeObjectArray(raw json.RawMessage) ([]map[string]json.RawMessage, error) {
	var values []json.RawMessage
	if err := json.Unmarshal(raw, &values); err != nil || values == nil {
		return nil, ErrIntentEvidenceInvalid
	}
	result := make([]map[string]json.RawMessage, 0, len(values))
	for _, rawValue := range values {
		value, err := decodeJSONObject(rawValue)
		if err != nil {
			return nil, err
		}
		result = append(result, value)
	}
	return result, nil
}

func marshalUpdatedIntent(document evidenceDocument, itemIndex int, envelope, assessment, step map[string]json.RawMessage, eventRefHash string, terminal TerminalResult, status string, first bool) ([]byte, bool, error) {
	if first {
		resultState := "observed_" + terminal.Outcome
		if terminal.Outcome == "uncertain" {
			resultState = "uncertain"
			if err := addString(step, "issues", "result_outcome_uncertain"); err != nil {
				return nil, false, err
			}
			if err := addString(assessment, "issues", "result_outcome_uncertain"); err != nil {
				return nil, false, err
			}
			if err := setJSONString(assessment, "alignment", "uncertain"); err != nil {
				return nil, false, err
			}
			if err := setJSONString(assessment, "completeness", "partial"); err != nil {
				return nil, false, err
			}
		}
		if err := setJSONString(step, "result_state", resultState); err != nil {
			return nil, false, err
		}
		if err := setJSONString(step, "result_event_ref_hash", eventRefHash); err != nil {
			return nil, false, err
		}
		if err := removeString(step, "issues", "result_missing"); err != nil {
			return nil, false, err
		}
		if err := removeString(assessment, "issues", "result_missing"); err != nil {
			return nil, false, err
		}
		if err := appendEvidence(step, map[string]any{
			"rule_id": "intent_result_correlated", "category": "result",
			"source_field": "tool_call_event", "masked_preview": "<digest>",
			"hash": DigestString(terminal.EventID + "\x00" + terminal.EventType + "\x00" + terminal.Outcome),
		}); err != nil {
			return nil, false, err
		}
		var issues []string
		_ = json.Unmarshal(assessment["issues"], &issues)
		var alignment string
		_ = json.Unmarshal(assessment["alignment"], &alignment)
		var authState string
		_ = json.Unmarshal(step["authorization_state"], &authState)
		if alignment == "uncertain" && len(issues) == 0 && authState == "matched" {
			if err := setJSONString(assessment, "alignment", "aligned"); err != nil {
				return nil, false, err
			}
			if err := setJSONString(assessment, "completeness", "provided_observations_only"); err != nil {
				return nil, false, err
			}
		}
	} else {
		if err := setJSONString(step, "result_state", "ambiguous"); err != nil {
			return nil, false, err
		}
		delete(step, "result_event_ref_hash")
		if err := addString(step, "issues", "result_ambiguous"); err != nil {
			return nil, false, err
		}
		if err := addString(assessment, "issues", "result_ambiguous"); err != nil {
			return nil, false, err
		}
		if err := setJSONString(assessment, "alignment", "uncertain"); err != nil {
			return nil, false, err
		}
		if err := setJSONString(assessment, "completeness", "partial"); err != nil {
			return nil, false, err
		}
	}

	stepsRaw, err := json.Marshal([]map[string]json.RawMessage{step})
	if err != nil {
		return nil, false, err
	}
	assessment["steps"] = stepsRaw
	assessmentRaw, err := json.Marshal(assessment)
	if err != nil {
		return nil, false, err
	}
	envelope["assessment"] = assessmentRaw
	terminalFields := map[string]any{
		"status": status, "event_ref_hash": eventRefHash,
		"event_type": terminal.EventType, "outcome": terminal.Outcome,
		"result_hash": strings.TrimPrefix(strings.ToLower(terminal.ResultHash), "sha256:"),
	}
	if terminal.HasLength {
		terminalFields["length"] = terminal.Length
	}
	terminalJSON, err := json.Marshal(terminalFields)
	if err != nil {
		return nil, false, err
	}
	if status == "ambiguous" {
		terminalJSON, err = json.Marshal(map[string]any{
			"status": "ambiguous", "event_ref_hash": eventRefHash,
			"event_type": terminal.EventType, "outcome": terminal.Outcome,
		})
		if err != nil {
			return nil, false, err
		}
	}
	envelope["terminal_result"] = terminalJSON
	intentRaw, err := json.Marshal(envelope)
	if err != nil {
		return nil, false, err
	}
	if err := setIntentEnvelope(document, itemIndex, intentRaw); err != nil {
		return nil, false, err
	}
	raw, err := marshalEvidenceDocument(document)
	if err != nil {
		return nil, false, err
	}
	if len(raw) > 64<<10 {
		return nil, false, fmt.Errorf("%w: updated evidence exceeds size bound", ErrIntentEvidenceInvalid)
	}
	return raw, true, nil
}

type evidenceDocument struct {
	isArray bool
	items   []json.RawMessage
	object  map[string]json.RawMessage
}

func decodeEvidenceDocument(raw []byte) (evidenceDocument, error) {
	if len(strings.TrimSpace(string(raw))) == 0 || strings.TrimSpace(string(raw)) == "null" {
		return evidenceDocument{isArray: true, items: []json.RawMessage{}}, nil
	}
	if strings.HasPrefix(strings.TrimSpace(string(raw)), "[") {
		var items []json.RawMessage
		if err := json.Unmarshal(raw, &items); err != nil || items == nil {
			return evidenceDocument{}, ErrIntentEvidenceInvalid
		}
		return evidenceDocument{isArray: true, items: items}, nil
	}
	object, err := decodeJSONObject(raw)
	if err != nil {
		return evidenceDocument{}, err
	}
	return evidenceDocument{object: object}, nil
}

func marshalEvidenceDocument(document evidenceDocument) ([]byte, error) {
	if document.isArray {
		return json.Marshal(document.items)
	}
	return json.Marshal(document.object)
}

func evidenceItem(document evidenceDocument, index int) json.RawMessage {
	if document.isArray && index >= 0 && index < len(document.items) {
		return document.items[index]
	}
	return nil
}

func findIntentEnvelope(document evidenceDocument) (int, map[string]json.RawMessage, error) {
	if !document.isArray {
		candidate, present := document.object["t16_intent"]
		if !present {
			return -1, nil, nil
		}
		envelope, err := decodeJSONObject(candidate)
		return 0, envelope, err
	}
	found := -1
	var envelope map[string]json.RawMessage
	for index, raw := range document.items {
		item, err := decodeJSONObject(raw)
		if err != nil {
			return -1, nil, err
		}
		candidate, present := item["t16_intent"]
		if !present {
			continue
		}
		if found >= 0 {
			return -1, nil, ErrIntentEvidenceInvalid
		}
		found = index
		envelope, err = decodeJSONObject(candidate)
		if err != nil {
			return -1, nil, err
		}
	}
	return found, envelope, nil
}

func setIntentEnvelope(document evidenceDocument, index int, raw json.RawMessage) error {
	if !document.isArray {
		document.object["t16_intent"] = raw
		return nil
	}
	item, err := decodeJSONObject(document.items[index])
	if err != nil {
		return err
	}
	item["t16_intent"] = raw
	document.items[index], err = json.Marshal(item)
	return err
}

func rawString(raw json.RawMessage) string {
	var value string
	_ = json.Unmarshal(raw, &value)
	return value
}

func sameIntentIdentity(left, right map[string]json.RawMessage) bool {
	for _, field := range []string{"schema", "arguments_hash", "endpoint_ref_hash", "session_ref_hash", "prompt_ref_hash", "tool_call_ref_hash", "tool_name_ref_hash", "tool_type"} {
		if rawString(left[field]) == "" || rawString(left[field]) != rawString(right[field]) {
			return false
		}
	}
	return true
}

func markIntentAmbiguous(document evidenceDocument, index int, envelope map[string]json.RawMessage) error {
	assessment, err := decodeJSONObject(envelope["assessment"])
	if err != nil {
		return err
	}
	steps, err := decodeObjectArray(assessment["steps"])
	if err != nil || len(steps) != 1 {
		return ErrIntentEvidenceInvalid
	}
	if err := setJSONString(assessment, "alignment", "uncertain"); err != nil {
		return err
	}
	if err := setJSONString(assessment, "completeness", "partial"); err != nil {
		return err
	}
	if err := addString(assessment, "issues", "authorization_observation_ambiguous"); err != nil {
		return err
	}
	if err := addString(steps[0], "issues", "authorization_observation_ambiguous"); err != nil {
		return err
	}
	stepsRaw, err := json.Marshal(steps)
	if err != nil {
		return err
	}
	assessment["steps"] = stepsRaw
	assessmentRaw, err := json.Marshal(assessment)
	if err != nil {
		return err
	}
	envelope["assessment"] = assessmentRaw
	intentRaw, err := json.Marshal(envelope)
	if err != nil {
		return err
	}
	return setIntentEnvelope(document, index, intentRaw)
}

func setJSONString(target map[string]json.RawMessage, field, value string) error {
	raw, err := json.Marshal(value)
	if err == nil {
		target[field] = raw
	}
	return err
}

func setJSONInt(target map[string]json.RawMessage, field string, value int) error {
	raw, err := json.Marshal(value)
	if err == nil {
		target[field] = raw
	}
	return err
}

func removeString(target map[string]json.RawMessage, field, remove string) error {
	var values []string
	if len(target[field]) == 0 {
		return nil
	}
	if err := json.Unmarshal(target[field], &values); err != nil {
		return err
	}
	filtered := make([]string, 0, len(values))
	for _, value := range values {
		if value != remove {
			filtered = append(filtered, value)
		}
	}
	raw, err := json.Marshal(filtered)
	if err == nil {
		target[field] = raw
	}
	return err
}

func addString(target map[string]json.RawMessage, field, add string) error {
	var values []string
	if len(target[field]) > 0 {
		if err := json.Unmarshal(target[field], &values); err != nil {
			return err
		}
	}
	for _, value := range values {
		if value == add {
			return nil
		}
	}
	values = append(values, add)
	raw, err := json.Marshal(values)
	if err == nil {
		target[field] = raw
	}
	return err
}

func appendEvidence(step map[string]json.RawMessage, evidence map[string]any) error {
	var values []json.RawMessage
	if len(step["evidence_json"]) > 0 {
		if err := json.Unmarshal(step["evidence_json"], &values); err != nil {
			return err
		}
	}
	raw, err := json.Marshal(evidence)
	if err != nil {
		return err
	}
	values = append(values, raw)
	step["evidence_json"], err = json.Marshal(values)
	return err
}
