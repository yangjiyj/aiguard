package agentguard

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"net/url"
	"path"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/yangjiyj/aiguard/packages/shared-go/agentintent"
)

const (
	maxIntentSteps        = 32
	maxIntentSources      = 64
	maxIntentResults      = 64
	maxIntentSourceBytes  = 16 << 10
	maxIntentArgumentSize = 32 << 10
	maxIntentJudgeSize    = 32 << 10
	maxIntentPreview      = 512
	maxIntentOpaqueID     = 128
)

var (
	ErrIntentAssessmentInvalid = errors.New("invalid intent assessment input")
	intentEventIDPattern       = regexp.MustCompile(`(?i)^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$`)
	intentSHA256Pattern        = regexp.MustCompile(`(?i)^(?:sha256:)?[0-9a-f]{64}$`)
	intentBearerPattern        = regexp.MustCompile(`(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{6,}`)
	intentCredentialPattern    = regexp.MustCompile(`(?i)\b(api[_-]?key|access[_-]?token|refresh[_-]?token|token|secret|password|credential|authorization|cookie)\b\s*[:=]\s*["']?[^\s"',;]+`)
	intentCommonKeyPattern     = regexp.MustCompile(`(?i)\b(?:sk-[A-Za-z0-9_-]{12,}|sk-ant-[A-Za-z0-9_-]{12,}|gh[pousr]_[A-Za-z0-9]{12,}|glpat-[A-Za-z0-9_-]{12,}|AKIA[A-Z0-9]{16})\b`)
	intentPrivateKeyPattern    = regexp.MustCompile(`(?is)-----BEGIN [^-]*PRIVATE KEY-----.*?-----END [^-]*PRIVATE KEY-----`)
	intentEmailPattern         = regexp.MustCompile(`(?i)\b[A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,}\b`)
	intentPhonePattern         = regexp.MustCompile(`\b\+?[0-9][0-9 .()\-]{7,}[0-9]\b`)
	intentSensitiveURLQuery    = regexp.MustCompile(`(?i)([?&](?:token|access_token|api[_-]?key|secret|password|auth|key)=)[^&#\s]+`)
	intentHomePathPattern      = regexp.MustCompile(`(?:/home/[^/\s]+|[A-Za-z]:\\Users\\[^\\\s]+|~[/\\][^/\\\s]+)`)
)

// IntentAuthorizationResolver is the only authority input. Implementations
// must resolve the opaque reference against the authenticated tenant/principal
// in ctx and recheck active status, expiry, and exact grant scope. Tool args,
// event fields, and caller-supplied booleans are not authorization evidence.
type IntentAuthorizationResolver interface {
	ResolveActiveAuthorization(ctx context.Context, reference string) (ResolvedIntentAuthorization, error)
}

type ResolvedIntentAuthorization struct {
	Allowed      bool
	Action       string
	ResourceType string
	ResourceID   string
	// PrincipalID and GrantID are returned only by the server-side resolver.
	// They are not copied into the public assessment.
	PrincipalID string
	GrantID     string
}

type IntentFlowIdentity struct {
	EndpointID string
	SessionID  string
	PromptID   string
}

// IntentExternalSource is transient and always treated as untrusted. Content
// is omitted from JSON and never returned or persisted by this analyzer.
type IntentExternalSource struct {
	ID, Kind, EndpointID, SessionID, PromptID string
	Content                                   string `json:"-"`
	SourceHash, LineageState, EventRefHash    string `json:"-"`
	ContentAssurance                          string `json:"-"`
	LinkedStepSequence                        int    `json:"-"`
}

// IntentObservedStep carries raw evidence only for this in-memory call. A
// caller must obtain authority through IntentAuthorizationResolver.
type IntentObservedStep struct {
	AuthorizationRef, ToolCallID, EndpointID, SessionID, PromptID string         `json:"-"`
	Action, ResourceType, ResourceID, Destination                 string         `json:"-"`
	ToolName, ToolType, Product, MCPServer                        string         `json:"-"`
	Arguments                                                     map[string]any `json:"-"`
	SourceIDs                                                     []string       `json:"-"`
	RequiredAuthorizationDenied                                   bool           `json:"-"`
}

// IntentObservedResult accepts only result metadata, never raw result content.
type IntentObservedResult struct {
	ToolCallID, EventID, EndpointID, SessionID, PromptID string `json:"-"`
	EventType, ResultHash, Outcome                       string `json:"-"`
	Length                                               int    `json:"-"`
}

type IntentTaskHistorySourceRef struct {
	Kind, SourceHash, LineageState string
	ContentAssurance               string
	LinkedStepSequence             int
}

type IntentTaskHistoryStep struct {
	Sequence                                                   int
	ToolName, Action, ResourceType, ResourceRefHash            string
	ArgumentsHash, AuthorizationState, ResultState, ResultHash string
	SourceRefs                                                 []IntentTaskHistorySourceRef
}

type IntentTaskGrantScope struct {
	Action, ResourceType, ResourceRefHash string
}

type IntentApprovedTaskContext struct {
	FacetScopeState                                    string `json:"facet_scope_state"`
	State, TaskID, Purpose, PurposeSHA256, ScopeSHA256 string
	AllowedSourceKinds, AllowedSourceHashes            []string
	GrantScopes                                        []IntentTaskGrantScope
	History                                            []IntentTaskHistoryStep
	HistoryTruncated                                   bool
}

type IntentTaskAssessment struct {
	State            string `json:"state"`
	TaskRefHash      string `json:"task_ref_hash,omitempty"`
	PurposeRefHash   string `json:"purpose_ref_hash,omitempty"`
	ScopeRefHash     string `json:"scope_ref_hash,omitempty"`
	TaskScopeState   string `json:"task_scope_state"`
	SourceCoverage   string `json:"source_coverage"`
	HistoryStepCount int    `json:"history_step_count"`
	HistoryTruncated bool   `json:"history_truncated"`
	LineageAssurance string `json:"lineage_assurance"`
}

type IntentFlowInput struct {
	Identity             IntentFlowIdentity
	Resolver             IntentAuthorizationResolver `json:"-"`
	Sources              []IntentExternalSource      `json:"-"`
	Steps                []IntentObservedStep        `json:"-"`
	Results              []IntentObservedResult      `json:"-"`
	ApprovedTask         *IntentApprovedTaskContext  `json:"-"`
	SemanticJudge        SemanticJudge               `json:"-"`
	SemanticJudgeEnabled bool                        `json:"-"`
}

type IntentStepAssessment struct {
	Sequence               int            `json:"sequence"`
	ToolCallRefHash        string         `json:"tool_call_ref_hash,omitempty"`
	AuthorizationRefHash   string         `json:"authorization_ref_hash,omitempty"`
	ToolName               string         `json:"tool_name,omitempty"`
	ToolType               string         `json:"tool_type,omitempty"`
	Action                 string         `json:"action,omitempty"`
	ResourceType           string         `json:"resource_type,omitempty"`
	ResourceRefHash        string         `json:"resource_ref_hash,omitempty"`
	AuthorizedAction       string         `json:"authorized_action,omitempty"`
	AuthorizedResourceType string         `json:"authorized_resource_type,omitempty"`
	AuthorizedResourceHash string         `json:"authorized_resource_ref_hash,omitempty"`
	DestinationHash        string         `json:"destination_hash,omitempty"`
	SourceRefHashes        []string       `json:"source_ref_hashes,omitempty"`
	ResultEventRefHash     string         `json:"result_event_ref_hash,omitempty"`
	AuthorizationState     string         `json:"authorization_state"`
	ResultState            string         `json:"result_state"`
	RiskDecision           DecisionAction `json:"risk_decision,omitempty"`
	RiskLevel              string         `json:"risk_level,omitempty"`
	RiskReason             string         `json:"risk_reason,omitempty"`
	Provenance             Provenance     `json:"provenance,omitempty"`
	Evidence               []Evidence     `json:"evidence_json,omitempty"`
	Issues                 []string       `json:"issues,omitempty"`
}

// Semantic opinions are supplemental and observe-only. The assessment has no
// permission field, and an allow opinion is never included in the report.
type IntentSemanticObservation struct {
	Status     string         `json:"status"`
	Decision   DecisionAction `json:"decision,omitempty"`
	RiskLevel  string         `json:"risk_level,omitempty"`
	Reason     string         `json:"reason,omitempty"`
	Confidence float64        `json:"confidence,omitempty"`
}

type IntentFlowAssessment struct {
	Alignment      string                    `json:"alignment"`    // aligned, deviation, uncertain
	Completeness   string                    `json:"completeness"` // provided_observations_only, partial
	ReviewRequired bool                      `json:"review_required"`
	Task           IntentTaskAssessment      `json:"approved_task"`
	Steps          []IntentStepAssessment    `json:"steps"`
	Issues         []string                  `json:"issues,omitempty"`
	Semantic       IntentSemanticObservation `json:"semantic"`
}

// AssessIntentFlow compares steps with freshly resolved exact T13 scopes,
// correlates result metadata, applies existing deterministic AgentGuard risk
// analyzers, and optionally adds an observe-only SemanticJudge opinion.
func AssessIntentFlow(ctx context.Context, input IntentFlowInput) (IntentFlowAssessment, error) {
	if err := validateIntentFlowInput(input); err != nil {
		return IntentFlowAssessment{}, err
	}
	out := IntentFlowAssessment{
		Alignment: "aligned", Completeness: "provided_observations_only",
		Steps:    make([]IntentStepAssessment, len(input.Steps)),
		Semantic: IntentSemanticObservation{Status: "not_requested"},
		Task:     IntentTaskAssessment{State: "missing", TaskScopeState: "unresolved", SourceCoverage: "unknown", LineageAssurance: "endpoint_claimed"},
	}
	if input.ApprovedTask != nil {
		task := input.ApprovedTask
		out.Task.State = task.State
		if task.TaskID != "" {
			out.Task.TaskRefHash = intentDigest(task.TaskID)
		}
		if task.Purpose != "" {
			out.Task.PurposeRefHash = intentDigest(task.Purpose)
		}
		if task.ScopeSHA256 != "" {
			out.Task.ScopeRefHash = strings.TrimPrefix(strings.ToLower(task.ScopeSHA256), "sha256:")
		}
		out.Task.HistoryStepCount = len(task.History)
		out.Task.HistoryTruncated = task.HistoryTruncated
		if task.State != "resolved" || task.TaskID == "" || task.Purpose == "" || intentDigest(task.Purpose) != strings.TrimPrefix(strings.ToLower(task.PurposeSHA256), "sha256:") || len(task.ScopeSHA256) != 64 {
			out.Task.State = "unresolved"
			out.addIssue("approved_task_unresolved", true)
		} else {
			out.Task.TaskScopeState = task.FacetScopeState
			if task.FacetScopeState == "" {
				out.Task.TaskScopeState = "resolved_context_only"
			}
			if task.FacetScopeState == "mismatch" {
				out.addIssue("approved_task_effect_out_of_scope", false)
				out.Alignment = "deviation"
				out.ReviewRequired = true
			} else if task.FacetScopeState == "unverifiable" {
				out.addIssue("approved_task_effect_unverifiable", true)
			}
			out.Task.SourceCoverage = "server_linked_results_and_endpoint_claims"
			out.Task.LineageAssurance = "pending_server_step_binding"
		}
		if task.HistoryTruncated {
			out.addIssue("task_history_truncated", true)
		}
		for _, prior := range task.History {
			if prior.Sequence <= 0 || prior.ResultState == "uncertain" || prior.ResultState == "pending" {
				out.addIssue("task_history_result_gap", true)
			}
			switch prior.AuthorizationState {
			case "allowed":
			case "denied", "scope_mismatch":
				out.addIssue("task_history_authorization_deviation", false)
				out.Alignment = "deviation"
				out.ReviewRequired = true
			default:
				out.addIssue("task_history_authorization_unresolved", true)
			}
			for _, source := range prior.SourceRefs {
				if !intentTaskSourceRefAssured(source) {
					out.addIssue("task_history_source_lineage_gap", true)
				}
				if !intentTaskSourceRefHasCurrentBytes(source, input.Sources) {
					out.addIssue("task_history_source_content_unavailable", true)
				}
			}
		}
	}
	if input.Identity.EndpointID == "" || input.Identity.SessionID == "" || input.Identity.PromptID == "" {
		out.addIssue("flow_identity_incomplete", true)
	}
	sources := make(map[string]IntentExternalSource, len(input.Sources))
	for _, source := range input.Sources {
		sources[source.ID] = source
		if !intentIdentityMatches(input.Identity, source.EndpointID, source.SessionID, source.PromptID) {
			out.addIssue("source_identity_mismatch", true)
		}
		if input.ApprovedTask != nil && input.ApprovedTask.State == "resolved" {
			if !containsIntentString(input.ApprovedTask.AllowedSourceKinds, source.Kind) {
				out.addIssue("task_source_scope_mismatch", true)
				out.Alignment = "deviation"
				out.ReviewRequired = true
			} else if len(input.ApprovedTask.AllowedSourceHashes) > 0 && !intentHashInAllowlist(source.SourceHash, input.ApprovedTask.AllowedSourceHashes) {
				out.addIssue("task_source_hash_mismatch", true)
				out.Alignment = "deviation"
				out.ReviewRequired = true
			}
			if source.Kind == "tool_result" {
				if source.LineageState != "accepted_result_hash_match" {
					out.addIssue("task_source_lineage_unverified", true)
				}
				if source.ContentAssurance != "accepted_result_digest_match" {
					out.addIssue("task_source_content_unverified", true)
				}
			} else {
				if source.LineageState != "accepted_result_hash_match" && source.ContentAssurance != "approved_scope_digest_match" {
					out.addIssue("task_source_endpoint_claim", true)
				}
				if source.ContentAssurance != "approved_scope_digest_match" {
					out.addIssue("task_source_content_unverified", true)
				}
			}
			if source.Content == "" {
				out.addIssue("task_source_content_missing", true)
			}
		}
	}
	stepIndex := make(map[string]int, len(input.Steps))
	referencedSources := make(map[string]struct{}, len(input.Sources))
	for i, step := range input.Steps {
		stepIndex[step.ToolCallID] = i
	}
	results := make(map[string][]IntentObservedResult, len(input.Results))
	seenEventIDs := make(map[string]struct{}, len(input.Results))
	duplicateEventIDs := make(map[string]struct{})
	for _, result := range input.Results {
		if result.EventID != "" {
			eventID := strings.ToLower(result.EventID)
			if _, exists := seenEventIDs[eventID]; exists {
				duplicateEventIDs[eventID] = struct{}{}
				out.addIssue("duplicate_result_event_id", true)
			}
			seenEventIDs[eventID] = struct{}{}
		}
		if _, ok := stepIndex[result.ToolCallID]; !ok {
			out.addIssue("unmatched_result_event", true)
			continue
		}
		results[result.ToolCallID] = append(results[result.ToolCallID], result)
	}

	usedRefs := make(map[string]struct{}, len(input.Steps))
	judgeNeeded := len(input.Sources) > 0 || (input.ApprovedTask != nil && input.ApprovedTask.State == "resolved")
	for i, step := range input.Steps {
		item := IntentStepAssessment{
			Sequence: i + 1, ToolCallRefHash: intentDigest(step.ToolCallID),
			AuthorizationRefHash: intentDigest(step.AuthorizationRef),
			ToolName:             safeIntentText(step.ToolName, 128), ToolType: safeIntentText(step.ToolType, 32),
			Action: safeIntentText(step.Action, 128), ResourceType: safeIntentText(step.ResourceType, 64),
			AuthorizationState: "unresolved", ResultState: "missing",
		}
		effect, effectIssue := deriveObservedIntentEffect(step)
		if effectIssue != "" {
			item.Action, item.ResourceType = "", ""
			item.ResourceRefHash, item.DestinationHash = "", ""
			item.addIssue(effectIssue)
			out.addIssue(effectIssue, true)
			judgeNeeded = true
		} else {
			// These report fields describe the operation and target extracted from arguments.
			item.Action = safeIntentText(effect.Action, 128)
			item.ResourceType = safeIntentText(effect.ResourceType, 64)
			item.ResourceRefHash = intentDigest(effect.ResourceID)
			if effect.Destination != "" {
				item.DestinationHash = intentDigest(effect.Destination)
			}
		}
		if input.ApprovedTask != nil && input.ApprovedTask.State == "resolved" && effectIssue == "" && !intentTaskScopeAllowsEffect(input.ApprovedTask.GrantScopes, effect) {
			item.addIssue("approved_task_effect_out_of_scope")
			out.addIssue("approved_task_effect_out_of_scope", false)
			out.Alignment = "deviation"
			out.ReviewRequired = true
		}
		if !intentIdentityMatches(input.Identity, step.EndpointID, step.SessionID, step.PromptID) {
			item.addIssue("step_identity_mismatch")
			out.addIssue("step_identity_mismatch", true)
		}
		fragments := make([]ContextFragment, 0, len(step.SourceIDs))
		for _, sourceID := range step.SourceIDs {
			item.SourceRefHashes = append(item.SourceRefHashes, intentDigest(sourceID))
			referencedSources[sourceID] = struct{}{}
			source, ok := sources[sourceID]
			if !ok {
				item.addIssue("source_reference_unresolved")
				out.addIssue("source_reference_unresolved", true)
				continue
			}
			fragments = append(fragments, ContextFragment{ID: intentDigest(source.ID), Trust: ProvenanceUntrusted, Text: source.Content})
		}

		switch {
		case step.AuthorizationRef == "":
			item.AuthorizationState = "missing"
			item.addIssue("authorization_reference_missing")
			out.addIssue("authorization_reference_missing", true)
		case step.RequiredAuthorizationDenied:
			item.AuthorizationState = "denied"
			item.addIssue("required_authorization_facet_denied")
			out.addIssue("required_authorization_facet_denied", false)
			judgeNeeded = true
		case refWasUsed(usedRefs, step.AuthorizationRef):
			item.AuthorizationState = "reused"
			item.addIssue("authorization_reference_reused")
			out.addIssue("authorization_reference_reused", false)
			judgeNeeded = true
		default:
			usedRefs[step.AuthorizationRef] = struct{}{}
			authorization, err := input.Resolver.ResolveActiveAuthorization(ctx, step.AuthorizationRef)
			if err == nil {
				item.AuthorizedAction = safeIntentText(authorization.Action, 128)
				item.AuthorizedResourceType = safeIntentText(authorization.ResourceType, 64)
				if authorization.ResourceID != "" {
					item.AuthorizedResourceHash = intentDigest(authorization.ResourceID)
				}
			}
			switch {
			case err != nil:
				item.AuthorizationState = "unresolved"
				item.addIssue("authorization_resolution_unavailable")
				out.addIssue("authorization_resolution_unavailable", true)
			case !authorization.Allowed:
				item.AuthorizationState = "denied"
				item.addIssue("authorization_denied")
				out.addIssue("authorization_denied", false)
				judgeNeeded = true
			case authorization.Action == "" || authorization.ResourceType == "" || authorization.ResourceID == "":
				item.AuthorizationState = "invalid"
				item.addIssue("authorization_scope_incomplete")
				out.addIssue("authorization_scope_incomplete", true)
			case effectIssue != "":
				item.AuthorizationState = "unmodeled"
			case !intentAuthorizationMatches(authorization, effect):
				item.AuthorizationState = "scope_mismatch"
				item.addIssue("authorization_scope_mismatch")
				item.Evidence = append(item.Evidence, sanitizedEvidence("intent_scope_mismatch", "authorization", "actual_effect_scope_hashes",
					strings.Join([]string{authorization.Action, authorization.ResourceType, intentDigest(authorization.ResourceID), effect.Action, effect.ResourceType, intentDigest(effect.ResourceID)}, "\x00")))
				out.addIssue("authorization_scope_mismatch", false)
				judgeNeeded = true
			case !intentDeclarationMatches(step, effect):
				item.AuthorizationState = "scope_mismatch"
				item.addIssue("declared_scope_mismatch")
				item.Evidence = append(item.Evidence, sanitizedEvidence("intent_scope_mismatch", "observation", "declaration_vs_actual_hashes",
					strings.Join([]string{step.Action, step.ResourceType, intentDigest(step.ResourceID), intentDigest(step.Destination), effect.Action, effect.ResourceType, intentDigest(effect.ResourceID)}, "\x00")))
				out.addIssue("declared_scope_mismatch", false)
				judgeNeeded = true
			default:
				item.AuthorizationState = "matched"
			}
		}

		wireMCPSupported := strings.HasPrefix(step.ToolName, "mcp__") && effectIssue == ""
		if (!supportedIntentToolType(step.ToolType) && !wireMCPSupported) || step.ToolName == "" {
			item.RiskDecision, item.RiskLevel, item.RiskReason = DecisionAudit, "medium", "intent_tool_type_unmodeled"
			item.addIssue("intent_tool_type_unmodeled")
			out.addIssue("intent_tool_type_unmodeled", true)
			out.ReviewRequired = true
			judgeNeeded = true
		} else {
			args := copyIntentArguments(step.Arguments)
			risk := AnalyzeToolCall(ctx, ToolCallAnalysisInput{
				ToolName: step.ToolName, ToolType: step.ToolType, Arguments: args,
				ContextFragments: fragments, Mode: ModeAudit,
				// This path invokes SemanticJudge separately with a redacted flow view.
				SemanticJudge: nil,
			})
			item.RiskDecision, item.RiskLevel = risk.RawDecision, risk.RiskLevel
			item.RiskReason, item.Provenance = safeIntentText(risk.Reason, 128), risk.Provenance
			for _, evidence := range risk.Evidence {
				item.Evidence = append(item.Evidence, sanitizeIntentEvidence(evidence))
			}
			if risk.RawDecision != DecisionAllow || risk.Provenance == ProvenanceTainted {
				out.ReviewRequired, judgeNeeded = true, true
			}
		}

		joined := results[step.ToolCallID]
		switch {
		case len(joined) == 0:
			item.ResultState = "missing"
			item.addIssue("result_missing")
			out.addIssue("result_missing", true)
		case len(joined) > 1:
			item.ResultState = "ambiguous"
			item.addIssue("result_ambiguous")
			out.addIssue("result_ambiguous", true)
		default:
			result := joined[0]
			if _, duplicate := duplicateEventIDs[strings.ToLower(result.EventID)]; duplicate {
				item.ResultState = "ambiguous"
				item.addIssue("result_event_id_reused")
				out.addIssue("result_event_id_reused", true)
			} else if !intentIdentityMatches(input.Identity, result.EndpointID, result.SessionID, result.PromptID) {
				item.ResultState = "identity_mismatch"
				item.addIssue("result_identity_mismatch")
				out.addIssue("result_identity_mismatch", true)
			} else if !intentEventIDPattern.MatchString(result.EventID) || !validOptionalIntentHash(result.ResultHash) ||
				(result.EventType != "tool.post" && result.EventType != "tool.failure" && result.EventType != "tool.denied") {
				item.ResultState = "invalid"
				item.addIssue("result_metadata_invalid")
				out.addIssue("result_metadata_invalid", true)
			} else {
				switch result.Outcome {
				case "succeeded":
					if result.EventType == "tool.post" {
						item.ResultState = "observed_succeeded"
					} else {
						item.ResultState = "invalid"
					}
				case "failed":
					if result.EventType == "tool.failure" {
						item.ResultState = "observed_failed"
					} else {
						item.ResultState = "invalid"
					}
				case "denied":
					if result.EventType == "tool.denied" {
						item.ResultState = "observed_denied"
					} else {
						item.ResultState = "invalid"
					}
				default:
					item.ResultState = "outcome_unknown"
				}
				if item.ResultState == "invalid" || item.ResultState == "outcome_unknown" {
					item.addIssue("result_outcome_unknown")
					out.addIssue("result_outcome_unknown", true)
				} else {
					item.ResultEventRefHash = intentDigest(result.EventID)
					item.Evidence = append(item.Evidence, sanitizedEvidence("intent_result_correlated", "result", "tool_call_event", result.ToolCallID+"\x00"+result.EventID))
					if result.ResultHash != "" {
						item.Evidence = append(item.Evidence, Evidence{RuleID: "intent_result_digest", Category: "result", SourceField: "result_hash", MaskedPreview: "<digest>", Hash: strings.TrimPrefix(strings.ToLower(result.ResultHash), "sha256:"), Length: result.Length})
					}
				}
			}
		}
		if item.AuthorizationState == "scope_mismatch" || item.AuthorizationState == "denied" || item.AuthorizationState == "reused" {
			out.Alignment = "deviation"
			out.ReviewRequired = true
		} else if item.AuthorizationState != "matched" && out.Alignment != "deviation" {
			out.Alignment = "uncertain"
		}
		if item.ResultState != "observed_succeeded" && item.ResultState != "observed_failed" && item.ResultState != "observed_denied" && out.Alignment != "deviation" {
			out.Alignment = "uncertain"
		}
		if item.RiskDecision != "" && item.RiskDecision != DecisionAllow {
			out.ReviewRequired = true
		}
		out.Steps[i] = item
	}

	for _, source := range input.Sources {
		if _, referenced := referencedSources[source.ID]; !referenced {
			out.addIssue("unreferenced_external_source", true)
		}
	}

	if judgeNeeded && !input.SemanticJudgeEnabled {
		out.Semantic.Status = "disabled"
		if input.ApprovedTask != nil && input.ApprovedTask.State == "resolved" {
			out.addIssue("semantic_review_disabled", true)
		}
	} else if judgeNeeded && input.SemanticJudge == nil {
		out.Semantic.Status = "unavailable"
		out.addIssue("semantic_review_unavailable", true)
	} else if judgeNeeded {
		payload, err := buildIntentJudgePayload(input, out)
		if err != nil {
			out.Semantic.Status = "skipped_size_limit"
			out.addIssue("semantic_payload_unavailable", true)
		} else if opinion, err := input.SemanticJudge.Judge(ctx, "intent_flow_assessment", payload); err != nil {
			out.Semantic.Status = "unavailable"
			out.addIssue("semantic_review_unavailable", true)
		} else {
			out.Semantic.Status = "completed"
			if opinion.RawDecision != "" && opinion.RawDecision != DecisionAllow {
				clamped := clampSemanticDecision(opinion)
				if clamped.RawDecision == DecisionAudit {
					out.Semantic.Decision = DecisionAudit
					out.Semantic.RiskLevel = safeIntentText(clamped.RiskLevel, 32)
					out.Semantic.Reason = safeIntentText(clamped.Reason, 128)
					out.Semantic.Confidence = clamped.Confidence
					out.ReviewRequired = true
				}
			}
		}
	}
	return out, nil
}

func validateIntentFlowInput(input IntentFlowInput) error {
	if input.Resolver == nil || len(input.Steps) == 0 || len(input.Steps) > maxIntentSteps || len(input.Sources) > maxIntentSources || len(input.Results) > maxIntentResults {
		return ErrIntentAssessmentInvalid
	}
	if len(input.Identity.EndpointID) > maxIntentOpaqueID || len(input.Identity.SessionID) > maxIntentOpaqueID || len(input.Identity.PromptID) > maxIntentOpaqueID {
		return ErrIntentAssessmentInvalid
	}
	if input.ApprovedTask != nil && (len(input.ApprovedTask.Purpose) > 2048 || len(input.ApprovedTask.History) > 32 ||
		len(input.ApprovedTask.AllowedSourceKinds) > 16 || len(input.ApprovedTask.AllowedSourceHashes) > 64) {
		return ErrIntentAssessmentInvalid
	}
	sources := make(map[string]struct{}, len(input.Sources))
	for _, source := range input.Sources {
		if source.ID == "" || len(source.ID) > maxIntentOpaqueID || len(source.Kind) > 64 || len(source.Content) > maxIntentSourceBytes || len(source.SourceHash) > 72 || len(source.LineageState) > 64 || len(source.EventRefHash) > 64 || len(source.ContentAssurance) > 64 {
			return ErrIntentAssessmentInvalid
		}
		if _, exists := sources[source.ID]; exists {
			return ErrIntentAssessmentInvalid
		}
		sources[source.ID] = struct{}{}
	}
	calls := make(map[string]struct{}, len(input.Steps))
	for _, step := range input.Steps {
		if step.ToolCallID == "" || len(step.ToolCallID) > maxIntentOpaqueID || len(step.AuthorizationRef) > maxIntentOpaqueID ||
			len(step.Action) > 128 || len(step.ResourceType) > 64 || len(step.ResourceID) > 512 || len(step.Destination) > 2048 ||
			len(step.ToolName) > 255 || len(step.ToolType) > 32 || len(step.SourceIDs) > maxIntentSources ||
			len(step.EndpointID) > maxIntentOpaqueID || len(step.SessionID) > maxIntentOpaqueID || len(step.PromptID) > maxIntentOpaqueID {
			return ErrIntentAssessmentInvalid
		}
		if _, exists := calls[step.ToolCallID]; exists {
			return ErrIntentAssessmentInvalid
		}
		calls[step.ToolCallID] = struct{}{}
		encoded, err := json.Marshal(step.Arguments)
		if err != nil || len(encoded) > maxIntentArgumentSize {
			return ErrIntentAssessmentInvalid
		}
	}
	for _, result := range input.Results {
		if result.ToolCallID == "" || len(result.ToolCallID) > maxIntentOpaqueID || len(result.EventID) > maxIntentOpaqueID ||
			len(result.EndpointID) > maxIntentOpaqueID || len(result.SessionID) > maxIntentOpaqueID || len(result.PromptID) > maxIntentOpaqueID ||
			len(result.EventType) > 32 || len(result.ResultHash) > 72 || result.Length < 0 || len(result.Outcome) > 16 {
			return ErrIntentAssessmentInvalid
		}
	}
	return nil
}

func (a *IntentFlowAssessment) addIssue(issue string, uncertain bool) {
	if !containsIntentString(a.Issues, issue) {
		a.Issues = append(a.Issues, issue)
	}
	if uncertain {
		a.Completeness = "partial"
		a.ReviewRequired = true
		if a.Alignment != "deviation" {
			a.Alignment = "uncertain"
		}
	}
}
func (s *IntentStepAssessment) addIssue(issue string) {
	if !containsIntentString(s.Issues, issue) {
		s.Issues = append(s.Issues, issue)
	}
}
func containsIntentString(values []string, value string) bool {
	for _, item := range values {
		if item == value {
			return true
		}
	}
	return false
}
func refWasUsed(refs map[string]struct{}, ref string) bool {
	if _, ok := refs[ref]; ok {
		return true
	}
	refs[ref] = struct{}{}
	return false
}
func intentTaskSourceRefAssured(source IntentTaskHistorySourceRef) bool {
	if source.LineageState == "source_scope_mismatch" {
		return false
	}
	if source.Kind == "tool_result" {
		return source.LineageState == "accepted_result_hash_match" && source.ContentAssurance == "accepted_result_digest_match"
	}
	return source.ContentAssurance == "approved_scope_digest_match"
}

func intentTaskSourceRefHasCurrentBytes(ref IntentTaskHistorySourceRef, current []IntentExternalSource) bool {
	expected := strings.TrimPrefix(strings.ToLower(strings.TrimSpace(ref.SourceHash)), "sha256:")
	if !intentSHA256Pattern.MatchString(expected) || !intentTaskSourceRefAssured(ref) {
		return false
	}
	for _, source := range current {
		actual := strings.TrimPrefix(strings.ToLower(strings.TrimSpace(source.SourceHash)), "sha256:")
		if source.Kind != ref.Kind || actual != expected || source.Content == "" ||
			strings.TrimPrefix(strings.ToLower(strings.TrimSpace(source.SourceHash)), "sha256:") != intentDigest(source.Content) {
			continue
		}
		if source.Kind == "tool_result" {
			if source.LineageState == "accepted_result_hash_match" && source.ContentAssurance == "accepted_result_digest_match" {
				return true
			}
		} else if source.ContentAssurance == "approved_scope_digest_match" {
			return true
		}
	}
	return false
}

func intentIdentityMatches(expected IntentFlowIdentity, endpointID, sessionID, promptID string) bool {
	return expected.EndpointID != "" && expected.SessionID != "" && endpointID == expected.EndpointID && sessionID == expected.SessionID && (expected.PromptID == "" || promptID == expected.PromptID)
}
func validOptionalIntentHash(value string) bool {
	return value == "" || intentSHA256Pattern.MatchString(value)
}
func intentHashInAllowlist(value string, allowlist []string) bool {
	normalize := func(raw string) string { return strings.TrimPrefix(strings.ToLower(strings.TrimSpace(raw)), "sha256:") }
	value = normalize(value)
	if value == "" {
		return false
	}
	for _, allowed := range allowlist {
		if normalize(allowed) == value {
			return true
		}
	}
	return false
}

type observedIntentEffect struct {
	Action       string
	ResourceType string
	ResourceID   string
	Destination  string
}

// IntentEffect is the bounded operation/resource extracted from actual
// pre-execution arguments. It is an internal integration API, not a caller
// authorization claim.
type IntentEffect struct {
	Action       string
	ResourceType string
	ResourceID   string
	Destination  string
}

// DeriveIntentEffect exposes the existing conservative effect extractor to
// trusted T13 adapters so they can construct the exact server-side lookup key.
func DeriveIntentEffect(step IntentObservedStep) (IntentEffect, string) {
	effect, issue := deriveObservedIntentEffect(step)
	return IntentEffect(effect), issue
}

var (
	intentSQLSelectEffectPattern = regexp.MustCompile("(?i)^\\s*SELECT\\s+\\*\\s+FROM\\s+([a-z_][a-z0-9_$]*(?:\\.[a-z_][a-z0-9_$]*)*)(?:\\s+WHERE\\s+[a-z_][a-z0-9_$]*\\s*(?:<>|!=|<=|>=|=|<|>)\\s*(?:-?[0-9]+(?:\\.[0-9]+)?|true|false|null))?\\s*$")
	intentSQLIdentifierPattern   = regexp.MustCompile("(?i)^[a-z_][a-z0-9_$]*(?:\\.[a-z_][a-z0-9_$]*)*$")
)

func deriveObservedIntentEffect(step IntentObservedStep) (observedIntentEffect, string) {
	toolType := strings.ToLower(strings.TrimSpace(step.ToolType))
	if step.ToolName == "" {
		return observedIntentEffect{}, "observed_tool_type_unmodeled"
	}
	if strings.HasPrefix(step.ToolName, "mcp__") {
		effect, _, err := agentintent.DeriveT16AuthorizationFacets(step.Product, step.ToolName, toolType, step.MCPServer, step.Arguments)
		if err != nil {
			return observedIntentEffect{}, "observed_mcp_effect_unsupported_or_ambiguous"
		}
		return observedIntentEffect{Action: effect.Action, ResourceType: effect.ResourceType, ResourceID: effect.ResourceID}, ""
	}
	if trustedT14DirectListOrFetch(step.Product, step.ToolName, toolType) {
		effect, _, err := agentintent.DeriveT16AuthorizationFacets(step.Product, step.ToolName, toolType, "", step.Arguments)
		if err != nil {
			return observedIntentEffect{}, "observed_effect_ambiguous"
		}
		return observedIntentEffect{Action: effect.Action, ResourceType: effect.ResourceType, ResourceID: effect.ResourceID}, ""
	}
	if !supportedIntentToolType(toolType) || ClassifyToolType(step.ToolName) != toolType {
		return observedIntentEffect{}, "observed_tool_type_unmodeled"
	}
	switch toolType {
	case ToolTypeFile:
		return deriveFileIntentEffect(step.ToolName, step.Arguments)
	case ToolTypeSystem:
		return deriveSystemIntentEffect(step.Arguments)
	case ToolTypeDatabase:
		return deriveDatabaseIntentEffect(step.ToolName, step.Arguments)
	case ToolTypeNetwork:
		return deriveNetworkIntentEffect(step.ToolName, step.Arguments)
	case ToolTypeSkill:
		return deriveSkillIntentEffect(step.ToolName, step.Arguments)
	default:
		return observedIntentEffect{}, "observed_tool_type_unmodeled"
	}
}

func deriveFileIntentEffect(toolName string, args map[string]any) (observedIntentEffect, string) {
	toolAction, toolActionKnown, toolActionIssue := inferFileIntentAction(toolName)
	if toolActionIssue != "" {
		return observedIntentEffect{}, toolActionIssue
	}
	argumentAction, hasArgumentAction, issue := normalizedIntentArgument(args, false, "observed_operation_unmodeled", "observed_effect_ambiguous", normalizeFileIntentAction, "operation", "op", "action")
	if issue != "" {
		return observedIntentEffect{}, issue
	}
	if !toolActionKnown && !hasArgumentAction {
		return observedIntentEffect{}, "observed_operation_unmodeled"
	}
	if toolActionKnown && hasArgumentAction && toolAction != argumentAction {
		return observedIntentEffect{}, "observed_operation_conflict"
	}
	action := toolAction
	if !toolActionKnown {
		action = argumentAction
	}
	allowedArguments := []string{"operation", "op", "action", "path", "file_path", "filepath", "file", "target"}
	if action == "file.write" {
		allowedArguments = append(allowedArguments, "content", "text", "data")
	}
	if !intentOnlyArguments(args, allowedArguments...) {
		return observedIntentEffect{}, "observed_arguments_unmodeled"
	}
	target, _, issue := normalizedIntentArgument(args, true, "observed_target_unmodeled", "observed_effect_ambiguous", normalizeIntentFileResource, "path", "file_path", "filepath", "file", "target")
	if issue != "" {
		return observedIntentEffect{}, issue
	}
	return observedIntentEffect{Action: action, ResourceType: "file", ResourceID: target}, ""
}

func inferFileIntentAction(toolName string) (string, bool, string) {
	if intentNameHasVerb(toolName, "copy", "move", "rename", "list", "search", "glob") {
		return "", false, "observed_multi_target_operation_unmodeled"
	}
	groups := []struct {
		action string
		verbs  []string
	}{
		{action: "file.read", verbs: []string{"read", "stat"}},
		{action: "file.write", verbs: []string{"write", "create", "edit", "update", "append", "mkdir", "touch"}},
		{action: "file.delete", verbs: []string{"delete", "remove", "unlink"}},
	}
	found := ""
	for _, group := range groups {
		if intentNameHasVerb(toolName, group.verbs...) {
			if found != "" && found != group.action {
				return "", false, "observed_operation_conflict"
			}
			found = group.action
		}
	}
	return found, found != "", ""
}

func intentNameHasVerb(name string, verbs ...string) bool {
	normalized := strings.NewReplacer("_", " ", "-", " ", ".", " ", "/", " ", ":", " ").Replace(strings.ToLower(name))
	for _, token := range strings.Fields(normalized) {
		for _, verb := range verbs {
			if token == verb {
				return true
			}
		}
	}
	return false
}

func normalizeFileIntentAction(raw string) (string, bool) {
	value := strings.ToLower(strings.TrimSpace(raw))
	for _, prefix := range []string{"file.", "file_"} {
		value = strings.TrimPrefix(value, prefix)
	}
	tokens := strings.Fields(strings.NewReplacer("_", " ", "-", " ", ".", " ").Replace(value))
	found := ""
	for _, token := range tokens {
		action := ""
		switch token {
		case "read", "stat":
			action = "file.read"
		case "write", "create", "edit", "update", "append", "mkdir", "touch":
			action = "file.write"
		case "delete", "remove", "unlink":
			action = "file.delete"
		}
		if action != "" {
			if found != "" && found != action {
				return "", false
			}
			found = action
		}
		if token == "copy" || token == "move" || token == "rename" {
			return "", false
		}
	}
	return found, found != ""
}

func deriveSystemIntentEffect(args map[string]any) (observedIntentEffect, string) {
	if !intentOnlyArguments(args, "operation", "op", "action", "command", "cmd", "script", "input", "executable", "program", "bin", "args", "argv", "arguments") {
		return observedIntentEffect{}, "observed_arguments_unmodeled"
	}
	action, hasAction, issue := normalizedIntentArgument(args, false, "observed_operation_unmodeled", "observed_effect_ambiguous", normalizeSystemIntentAction, "operation", "op", "action")
	if issue != "" {
		return observedIntentEffect{}, issue
	}
	if hasAction && action != "system.execute" {
		return observedIntentEffect{}, "observed_operation_conflict"
	}
	command, hasCommand, issue := normalizedIntentArgument(args, false, "observed_target_unmodeled", "observed_effect_ambiguous", normalizeIntentCommand, "command", "cmd", "script", "input")
	if issue != "" {
		return observedIntentEffect{}, issue
	}
	executable, hasExecutable, issue := normalizedIntentArgument(args, false, "observed_target_unmodeled", "observed_effect_ambiguous", normalizeIntentCommand, "executable", "program", "bin")
	if issue != "" {
		return observedIntentEffect{}, issue
	}
	argv, hasArgv, issue := intentStringSliceArgument(args, "args", "argv", "arguments")
	if issue != "" {
		return observedIntentEffect{}, issue
	}
	if hasCommand && (hasExecutable || hasArgv) {
		return observedIntentEffect{}, "observed_effect_ambiguous"
	}
	target := command
	if !hasCommand && hasExecutable {
		if !hasArgv {
			argv = []string{}
		}
		encoded, err := json.Marshal([]any{executable, argv})
		if err != nil {
			return observedIntentEffect{}, "observed_target_unmodeled"
		}
		target = string(encoded)
	}
	if target == "" {
		return observedIntentEffect{}, "observed_target_unmodeled"
	}
	return observedIntentEffect{Action: "system.execute", ResourceType: "command", ResourceID: target}, ""
}

func normalizeSystemIntentAction(raw string) (string, bool) {
	value := strings.ToLower(strings.TrimSpace(raw))
	for _, prefix := range []string{"system.", "system_"} {
		value = strings.TrimPrefix(value, prefix)
	}
	switch value {
	case "execute", "exec", "run", "command":
		return "system.execute", true
	default:
		return "", false
	}
}

func normalizeIntentCommand(raw string) (string, bool) {
	value := strings.TrimSpace(raw)
	return value, value != "" && utf8.ValidString(value) && !strings.ContainsRune(value, 0)
}

func intentStringSliceArgument(args map[string]any, aliases ...string) ([]string, bool, string) {
	var selected []string
	found := false
	for key, value := range args {
		if !intentIntentKeyMatches(key, aliases...) {
			continue
		}
		found = true
		items := []string{}
		switch typed := value.(type) {
		case []string:
			items = append(items, typed...)
		case []any:
			for _, item := range typed {
				text, ok := item.(string)
				if !ok {
					return nil, true, "observed_target_unmodeled"
				}
				items = append(items, text)
			}
		default:
			return nil, true, "observed_target_unmodeled"
		}
		for i := range items {
			items[i] = strings.TrimSpace(items[i])
			if items[i] == "" || strings.ContainsRune(items[i], 0) {
				return nil, true, "observed_target_unmodeled"
			}
		}
		if selected != nil && strings.Join(selected, "\x00") != strings.Join(items, "\x00") {
			return nil, true, "observed_effect_ambiguous"
		}
		selected = items
	}
	return selected, found, ""
}

func deriveDatabaseIntentEffect(toolName string, args map[string]any) (observedIntentEffect, string) {
	if !intentOnlyArguments(args, "database", "db", "schema", "connection", "dsn", "operation", "op", "action", "query", "sql", "statement", "command") {
		return observedIntentEffect{}, "observed_arguments_unmodeled"
	}
	if intentIntentKeyPresent(args, "database", "db", "schema", "connection", "dsn") {
		return observedIntentEffect{}, "observed_database_context_unmodeled"
	}
	query, _, issue := normalizedIntentArgument(args, true, "observed_operation_unmodeled", "observed_effect_ambiguous", normalizeIntentCommand, "query", "sql", "statement", "command")
	if issue != "" {
		return observedIntentEffect{}, issue
	}
	action, table, ok := parseIntentDatabaseQuery(query)
	if !ok {
		return observedIntentEffect{}, "observed_database_query_unmodeled"
	}
	if toolNameAction, known := inferDatabaseIntentAction(toolName); known && toolNameAction != action {
		return observedIntentEffect{}, "observed_operation_conflict"
	}
	argumentAction, hasArgumentAction, issue := normalizedIntentArgument(args, false, "observed_operation_unmodeled", "observed_effect_ambiguous", normalizeDatabaseIntentAction, "operation", "op", "action")
	if issue != "" {
		return observedIntentEffect{}, issue
	}
	if hasArgumentAction && argumentAction != action {
		return observedIntentEffect{}, "observed_operation_conflict"
	}
	return observedIntentEffect{Action: action, ResourceType: "table", ResourceID: table}, ""
}

func inferDatabaseIntentAction(toolName string) (string, bool) {
	groups := []struct {
		action string
		verbs  []string
	}{
		{action: "database.select", verbs: []string{"select", "read"}},
		{action: "database.insert", verbs: []string{"insert"}},
		{action: "database.update", verbs: []string{"update"}},
		{action: "database.delete", verbs: []string{"delete"}},
	}
	found := ""
	for _, group := range groups {
		if intentNameHasVerb(toolName, group.verbs...) {
			if found != "" && found != group.action {
				return "", false
			}
			found = group.action
		}
	}
	return found, found != ""
}

func normalizeDatabaseIntentAction(raw string) (string, bool) {
	value := strings.ToLower(strings.TrimSpace(raw))
	for _, prefix := range []string{"database.", "database_"} {
		value = strings.TrimPrefix(value, prefix)
	}
	switch value {
	case "select", "read", "query":
		return "database.select", true
	case "insert", "create":
		return "database.insert", true
	case "update", "write":
		return "database.update", true
	case "delete", "remove":
		return "database.delete", true
	default:
		return "", false
	}
}

func parseIntentDatabaseQuery(query string) (string, string, bool) {
	match := intentSQLSelectEffectPattern.FindStringSubmatch(strings.TrimSpace(query))
	if len(match) != 2 {
		return "", "", false
	}
	table := strings.ToLower(match[1])
	if !intentSQLIdentifierPattern.MatchString(table) {
		return "", "", false
	}
	return "database.select", table, true
}

func deriveNetworkIntentEffect(toolName string, args map[string]any) (observedIntentEffect, string) {
	if !intentOnlyArguments(args, "method", "http_method", "operation", "op", "action", "url", "uri", "endpoint", "host", "target", "destination", "body", "payload", "data") {
		return observedIntentEffect{}, "observed_arguments_unmodeled"
	}
	nameMethod, nameHasMethod, supportedName := inferHTTPIntentMethod(toolName)
	if !supportedName {
		return observedIntentEffect{}, "observed_tool_operation_unmodeled"
	}
	method, hasMethod, issue := normalizedIntentArgument(args, false, "observed_operation_unmodeled", "observed_effect_ambiguous", normalizeHTTPIntentMethod, "method", "http_method")
	if issue != "" {
		return observedIntentEffect{}, issue
	}
	if hasMethod && nameHasMethod && method != nameMethod {
		return observedIntentEffect{}, "observed_operation_conflict"
	}
	operation, hasOperation, issue := normalizedIntentArgument(args, false, "observed_operation_unmodeled", "observed_effect_ambiguous", normalizeNetworkIntentAction, "operation", "op", "action")
	if issue != "" {
		return observedIntentEffect{}, issue
	}
	if hasOperation && operation != "network.egress" {
		return observedIntentEffect{}, "observed_operation_conflict"
	}
	target, _, issue := normalizedIntentArgument(args, true, "observed_target_unmodeled", "observed_effect_ambiguous", normalizeIntentURLResource, "url", "uri", "endpoint", "host", "target", "destination")
	if issue != "" {
		return observedIntentEffect{}, issue
	}
	return observedIntentEffect{Action: "network.egress", ResourceType: "url", ResourceID: target, Destination: target}, ""
}

func normalizeHTTPIntentMethod(raw string) (string, bool) {
	value := strings.ToUpper(strings.TrimSpace(raw))
	switch value {
	case "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS":
		return value, true
	default:
		return "", false
	}
}

func inferHTTPIntentMethod(toolName string) (string, bool, bool) {
	normalized := strings.NewReplacer("-", "_").Replace(strings.ToLower(strings.TrimSpace(toolName)))
	switch normalized {
	case "http", "http_request", "httprequest":
		return "", false, true
	}
	for _, method := range []string{"get", "post", "put", "patch", "delete", "head", "options"} {
		if normalized == "http_"+method || normalized == "http"+method {
			return strings.ToUpper(method), true, true
		}
	}
	return "", false, false
}

func normalizeNetworkIntentAction(raw string) (string, bool) {
	value := strings.ToLower(strings.TrimSpace(raw))
	for _, prefix := range []string{"network.", "network_"} {
		value = strings.TrimPrefix(value, prefix)
	}
	switch value {
	case "egress", "request", "send", "http":
		return "network.egress", true
	default:
		return "", false
	}
}

func deriveSkillIntentEffect(toolName string, args map[string]any) (observedIntentEffect, string) {
	if !intentSkillInvocationTool(toolName) {
		return observedIntentEffect{}, "observed_operation_unmodeled"
	}
	if !intentOnlyArguments(args, "skill", "version", "bundle_hash", "source") {
		return observedIntentEffect{}, "observed_skill_arguments_unmodeled"
	}
	identity := ExtractSkillIdentity(args)
	if identity.Issue != "" || !identity.Complete() {
		return observedIntentEffect{}, "observed_skill_identity_unmodeled"
	}
	return observedIntentEffect{
		Action: "skill.invoke", ResourceType: "skill", ResourceID: canonicalIntentSkillResource(identity),
	}, ""
}

func intentSkillInvocationTool(toolName string) bool {
	normalized := strings.ToLower(strings.TrimSpace(toolName))
	switch normalized {
	case "skill", "use_skill", "use-skill", "useskill", "load_skill", "load-skill", "loadskill", "activate_skill", "activate-skill", "activateskill":
		return true
	}
	parts := strings.Fields(strings.NewReplacer("__", " ", "/", " ", "_", " ", "-", " ").Replace(normalized))
	if len(parts) != 2 || (parts[0] != "skill" && parts[0] != "skills") {
		return false
	}
	switch parts[1] {
	case "invoke", "use", "load", "activate":
		return true
	default:
		return false
	}
}

func canonicalIntentSkillResource(identity SkillIdentity) string {
	encoded, _ := json.Marshal([]string{identity.CanonicalName, identity.Version, identity.BundleHash})
	return string(encoded)
}

func normalizedIntentArgument(args map[string]any, required bool, unmodeledIssue, ambiguousIssue string, normalize func(string) (string, bool), aliases ...string) (string, bool, string) {
	selected := ""
	found := false
	for key, value := range args {
		if !intentIntentKeyMatches(key, aliases...) {
			continue
		}
		found = true
		raw, ok := value.(string)
		if !ok {
			return "", true, unmodeledIssue
		}
		candidate, ok := normalize(raw)
		if !ok {
			return "", true, unmodeledIssue
		}
		if selected != "" && selected != candidate {
			return "", true, ambiguousIssue
		}
		selected = candidate
	}
	if !found && required {
		return "", false, unmodeledIssue
	}
	return selected, found, ""
}

func intentOnlyArguments(args map[string]any, allowed ...string) bool {
	for key := range args {
		if !intentIntentKeyMatches(key, allowed...) {
			return false
		}
	}
	return true
}

func intentIntentKeyMatches(key string, aliases ...string) bool {
	key = strings.ToLower(strings.TrimSpace(key))
	for _, alias := range aliases {
		if key == alias {
			return true
		}
	}
	return false
}

func intentIntentKeyPresent(args map[string]any, aliases ...string) bool {
	for key := range args {
		if intentIntentKeyMatches(key, aliases...) {
			return true
		}
	}
	return false
}

func normalizeIntentFileResource(raw string) (string, bool) {
	// Whitespace is part of a literal file name, not transport padding.
	value := raw
	if value == "" || strings.ContainsAny(value, "*?${}") || strings.ContainsRune(value, 0) {
		return "", false
	}
	windowsDriveAbsolute := len(value) >= 3 && ((value[0] >= 'A' && value[0] <= 'Z') || (value[0] >= 'a' && value[0] <= 'z')) && value[1] == ':' && (value[2] == '/' || value[2] == 92)
	if windowsDriveAbsolute {
		value = strings.ToUpper(value[:1]) + strings.ReplaceAll(value[1:], string(rune(92)), "/")
	} else if strings.HasPrefix(value, "//") || !strings.HasPrefix(value, "/") {
		// Relative, tilde, and UNC paths depend on execution context we do not have.
		return "", false
	}
	for _, component := range strings.Split(value, "/") {
		if component == ".." {
			// Parent traversal can resolve differently through a symlink or junction.
			return "", false
		}
	}
	analysis := AnalyzeTarget(value)
	if analysis.Kind != TargetFile {
		return "", false
	}
	return path.Clean(value), true
}

func normalizeIntentURLResource(raw string) (string, bool) {
	if strings.ContainsAny(raw, "$\u007b\u007d") {
		return "", false
	}
	analysis := AnalyzeTarget(raw)
	if analysis.Kind != TargetURL || analysis.NormalizedTarget == "" {
		return "", false
	}
	parsed, err := url.Parse(analysis.NormalizedTarget)
	if err != nil || parsed.Host == "" || parsed.User != nil {
		return "", false
	}
	parsed.Scheme = strings.ToLower(parsed.Scheme)
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return "", false
	}
	return parsed.String(), true
}

func normalizeIntentTableResource(raw string) (string, bool) {
	value := strings.ToLower(strings.TrimSpace(raw))
	return value, intentSQLIdentifierPattern.MatchString(value)
}

func normalizeIntentSkillResource(raw string) (string, bool) {
	var parts []string
	if err := json.Unmarshal([]byte(strings.TrimSpace(raw)), &parts); err != nil || len(parts) != 3 {
		return "", false
	}
	identity := SkillIdentity{
		CanonicalName: CanonicalSkillName(parts[0]),
		Version:       boundedSkillValue(parts[1], 255),
		BundleHash:    strings.ToLower(strings.TrimSpace(parts[2])),
	}
	if identity.CanonicalName == "" || identity.CanonicalName != parts[0] ||
		identity.Version == "" || identity.Version != parts[1] ||
		identity.BundleHash != parts[2] || !identity.Complete() {
		return "", false
	}
	return canonicalIntentSkillResource(identity), true
}

// trustedT14DirectListOrFetch names the direct (non-MCP) T14 tools whose
// effect vocabulary is the exact T13 facet vocabulary (directory.list and
// network.connect/domain) rather than the legacy agentguard classification.
func trustedT14DirectListOrFetch(product, toolName, toolType string) bool {
	switch {
	case toolType == ToolTypeFile:
		return product == "claude-code" && toolName == "LS" || product == "opencode" && toolName == "list"
	case toolType == ToolTypeNetwork:
		return product == "claude-code" && toolName == "WebFetch" || product == "openclaw" && toolName == "web_fetch" ||
			product == "opencode" && toolName == "webfetch"
	default:
		return false
	}
}

func normalizeIntentDomainResource(raw string) (string, bool) {
	host := strings.ToLower(raw)
	if host == "" || len(host) > 253 || host != strings.TrimSpace(host) {
		return "", false
	}
	if net.ParseIP(host) != nil {
		return host, true
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", false
		}
		for _, r := range label {
			if !((r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-') {
				return "", false
			}
		}
	}
	return host, true
}

func normalizeIntentResource(resourceType, raw string) (string, bool) {
	switch resourceType {
	case "file", "directory":
		return normalizeIntentFileResource(raw)
	case "domain":
		return normalizeIntentDomainResource(raw)
	case "url":
		return normalizeIntentURLResource(raw)
	case "command":
		return normalizeIntentCommand(raw)
	case "table":
		return normalizeIntentTableResource(raw)
	case "skill":
		return normalizeIntentSkillResource(raw)
	default:
		return "", false
	}
}

func intentTaskScopeAllowsEffect(grants []IntentTaskGrantScope, effect observedIntentEffect) bool {
	action := ""
	switch effect.Action {
	case "file.read":
		action = "file_read"
	case "file.write":
		action = "file_write"
	case "directory.list":
		action = "directory_list"
	case "network.connect":
		action = "network_connect"
	default:
		return false
	}
	resourceHash := intentDigest(effect.ResourceID)
	for _, grant := range grants {
		if grant.Action == action && grant.ResourceType == effect.ResourceType && strings.EqualFold(strings.TrimPrefix(strings.ToLower(grant.ResourceRefHash), "sha256:"), resourceHash) {
			return true
		}
	}
	return false
}

func intentAuthorizationMatches(authorization ResolvedIntentAuthorization, effect observedIntentEffect) bool {
	if !intentAuthorizationActionMatches(authorization.Action, effect.Action) || authorization.ResourceType != effect.ResourceType {
		return false
	}
	resource, ok := normalizeIntentResource(authorization.ResourceType, authorization.ResourceID)
	return ok && resource == effect.ResourceID
}

func intentAuthorizationActionMatches(authorizedAction, observedAction string) bool {
	if authorizedAction == observedAction {
		return true
	}
	switch {
	case authorizedAction == "file_read" && observedAction == "file.read":
		return true
	case authorizedAction == "file_write" && observedAction == "file.write":
		return true
	case authorizedAction == "directory_list" && observedAction == "directory.list":
		return true
	case authorizedAction == "network_connect" && observedAction == "network.connect":
		return true
	default:
		return false
	}
}

func intentDeclarationMatches(step IntentObservedStep, effect observedIntentEffect) bool {
	if step.Action != "" && step.Action != effect.Action {
		return false
	}
	if step.ResourceType != "" && step.ResourceType != effect.ResourceType {
		return false
	}
	if step.ResourceID != "" {
		resourceType := effect.ResourceType
		if step.ResourceType != "" {
			resourceType = step.ResourceType
		}
		resource, ok := normalizeIntentResource(resourceType, step.ResourceID)
		if !ok || resource != effect.ResourceID {
			return false
		}
	}
	if step.Destination != "" {
		if effect.Destination == "" {
			return false
		}
		destination, ok := normalizeIntentURLResource(step.Destination)
		if !ok || destination != effect.Destination {
			return false
		}
	}
	return true
}

func supportedIntentToolType(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "system", "database", "network", "file", ToolTypeSkill, ToolTypeMCP:
		return true
	}
	return false
}
func copyIntentArguments(input map[string]any) map[string]any {
	output := make(map[string]any, len(input)+1)
	for key, value := range input {
		output[key] = value
	}
	return output
}
func firstIntentString(args map[string]any, keys ...string) string {
	for _, key := range keys {
		if value, ok := args[key].(string); ok && strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func buildIntentJudgePayload(input IntentFlowInput, assessment IntentFlowAssessment) (map[string]any, error) {
	payload := map[string]any{"contract": "intent-assessment-v1", "purpose": "supplemental-risk-analysis-only", "authority": "semantic-model-cannot-grant-or-expand-permission", "alignment": assessment.Alignment, "source_coverage": assessment.Task.SourceCoverage}
	if input.ApprovedTask != nil && input.ApprovedTask.State == "resolved" {
		payload["approved_task"] = map[string]any{"purpose": safeIntentText(input.ApprovedTask.Purpose, 2048), "purpose_hash": assessment.Task.PurposeRefHash,
			"scope_hash": assessment.Task.ScopeRefHash, "facet_scope_state": input.ApprovedTask.FacetScopeState, "source_kinds": append([]string(nil), input.ApprovedTask.AllowedSourceKinds...),
			"history_truncated": input.ApprovedTask.HistoryTruncated}
		history := make([]map[string]any, 0, len(input.ApprovedTask.History))
		for _, prior := range input.ApprovedTask.History {
			refs := make([]map[string]any, 0, len(prior.SourceRefs))
			for _, ref := range prior.SourceRefs {
				refs = append(refs, map[string]any{"kind": safeIntentText(ref.Kind, 64), "source_hash": strings.TrimPrefix(strings.ToLower(ref.SourceHash), "sha256:"), "lineage_state": safeIntentText(ref.LineageState, 64), "content_assurance": safeIntentText(ref.ContentAssurance, 64), "linked_step_sequence": ref.LinkedStepSequence})
			}
			history = append(history, map[string]any{"sequence": prior.Sequence, "tool_name": safeIntentText(prior.ToolName, 128), "action": safeIntentText(prior.Action, 128),
				"resource_type": safeIntentText(prior.ResourceType, 64), "resource_ref_hash": prior.ResourceRefHash, "arguments_hash": prior.ArgumentsHash,
				"authorization_state": prior.AuthorizationState, "result_state": prior.ResultState, "result_hash": prior.ResultHash, "sources": refs})
		}
		payload["approved_task_history"] = history
	}
	safeSources := make([]map[string]any, 0, len(input.Sources))
	for _, source := range input.Sources {
		safeSources = append(safeSources, map[string]any{"id_hash": intentDigest(source.ID), "kind": safeIntentText(source.Kind, 64), "content_hash": intentDigest(source.Content), "content_length": len(source.Content), "redacted_excerpt": safeIntentText(source.Content, maxIntentPreview),
			"lineage_state": safeIntentText(source.LineageState, 64), "content_assurance": safeIntentText(source.ContentAssurance, 64), "linked_step_sequence": source.LinkedStepSequence, "accepted_event_ref_hash": source.EventRefHash})
	}
	sort.Slice(safeSources, func(i, j int) bool { return safeSources[i]["id_hash"].(string) < safeSources[j]["id_hash"].(string) })
	payload["external_sources"] = safeSources
	safeSteps := make([]map[string]any, 0, len(input.Steps))
	for index, step := range input.Steps {
		item := assessment.Steps[index]
		safeSteps = append(safeSteps, map[string]any{"sequence": index + 1, "tool_call_ref_hash": intentDigest(step.ToolCallID), "authorization_state": item.AuthorizationState,
			"action": item.Action, "resource_type": item.ResourceType, "resource_hash": item.ResourceRefHash, "destination_hash": item.DestinationHash,
			"authorized_action": item.AuthorizedAction, "authorized_resource_type": item.AuthorizedResourceType, "authorized_resource_hash": item.AuthorizedResourceHash,
			"tool_name": item.ToolName, "tool_type": item.ToolType, "arguments": sanitizeIntentValue(step.Arguments, 0),
			"source_ref_hashes": item.SourceRefHashes, "result_state": item.ResultState, "result_event_ref_hash": item.ResultEventRefHash,
			"risk_decision": item.RiskDecision, "risk_level": item.RiskLevel, "risk_reason": item.RiskReason})
	}
	payload["steps"] = safeSteps
	encoded, err := json.Marshal(payload)
	if err != nil || len(encoded) > maxIntentJudgeSize {
		return nil, ErrIntentAssessmentInvalid
	}
	return payload, nil
}
func sanitizeIntentValue(value any, depth int) any {
	if depth > 5 {
		return "<redacted:depth>"
	}
	switch typed := value.(type) {
	case string:
		return safeIntentText(typed, maxIntentPreview)
	case map[string]any:
		keys := make([]string, 0, len(typed))
		for key := range typed {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		if len(keys) > 32 {
			keys = keys[:32]
		}
		out := make(map[string]any, len(keys))
		for _, key := range keys {
			if sensitiveIntentKey(key) {
				out[safeIntentText(key, 64)] = "<redacted:sensitive-key>"
			} else {
				out[safeIntentText(key, 64)] = sanitizeIntentValue(typed[key], depth+1)
			}
		}
		return out
	case []any:
		limit := len(typed)
		if limit > 32 {
			limit = 32
		}
		out := make([]any, 0, limit)
		for _, item := range typed[:limit] {
			out = append(out, sanitizeIntentValue(item, depth+1))
		}
		return out
	case []string:
		limit := len(typed)
		if limit > 32 {
			limit = 32
		}
		out := make([]any, 0, limit)
		for _, item := range typed[:limit] {
			out = append(out, safeIntentText(item, maxIntentPreview))
		}
		return out
	case nil, bool, float64, float32, int, int32, int64, uint, uint32, uint64:
		return typed
	default:
		return "<redacted:unsupported-value>"
	}
}
func sanitizeIntentEvidence(evidence Evidence) Evidence {
	evidence.RuleID = safeIntentText(evidence.RuleID, 128)
	evidence.Category = safeIntentText(evidence.Category, 64)
	evidence.SourceField = safeEvidenceSourceField(evidence.SourceField)
	evidence.MaskedPreview = safeIntentText(evidence.MaskedPreview, maxIntentPreview)
	if evidence.Hash != "" {
		if intentSHA256Pattern.MatchString(evidence.Hash) {
			evidence.Hash = strings.TrimPrefix(strings.ToLower(evidence.Hash), "sha256:")
		} else {
			evidence.Hash = intentDigest(evidence.Hash)
		}
	}
	if evidence.Length < 0 {
		evidence.Length = 0
	}
	return evidence
}

func safeEvidenceSourceField(value string) string {
	field := strings.ToLower(strings.TrimSpace(value))
	switch field {
	case "command", "statement", "url", "path", "tool_call_event", "result_hash", "action_resource_destination", "executable", "program", "argv", "args", "body", "data", "payload", "content", "file", "file_path", "host", "target":
		return field
	case "":
		return ""
	default:
		return "field#" + intentDigest(value)[:12]
	}
}

func sensitiveIntentKey(value string) bool {
	lower := strings.ToLower(strings.NewReplacer("-", "", "_", "", " ", "").Replace(value))
	for _, marker := range []string{"authorization", "token", "secret", "password", "credential", "cookie", "apikey", "accesskey", "accountkey", "sessionkey", "privatekey"} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}
func safeIntentText(value string, maxRunes int) string {
	if value == "" || maxRunes <= 0 {
		return ""
	}
	redacted := intentPrivateKeyPattern.ReplaceAllString(value, "<redacted:private-key>")
	redacted = intentBearerPattern.ReplaceAllString(redacted, "Bearer <redacted:credential>")
	redacted = intentCredentialPattern.ReplaceAllString(redacted, "$1=<redacted:credential>")
	redacted = intentCommonKeyPattern.ReplaceAllString(redacted, "<redacted:credential>")
	redacted = intentSensitiveURLQuery.ReplaceAllString(redacted, "$1<redacted:credential>")
	redacted = intentEmailPattern.ReplaceAllString(redacted, "<redacted:email>")
	redacted = intentPhonePattern.ReplaceAllString(redacted, "<redacted:number>")
	redacted = intentHomePathPattern.ReplaceAllString(redacted, "<redacted:path>")
	if utf8.RuneCountInString(redacted) > maxRunes {
		redacted = string([]rune(redacted)[:maxRunes]) + "…"
	}
	return redacted
}
func intentDigest(value string) string {
	digest := sha256.Sum256([]byte(value))
	return hex.EncodeToString(digest[:])
}
