package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/agentguard"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
	"github.com/yangjiyj/aiguard/packages/shared-go/agentintent"
)

const agentIntentResolvePath = "/admin/v1/internal/agent/intent-authorizations/resolve"

type endpointIntentResolver map[string]agentguard.ResolvedIntentAuthorization

func (resolver endpointIntentResolver) ResolveActiveAuthorization(_ context.Context, reference string) (agentguard.ResolvedIntentAuthorization, error) {
	value, ok := resolver[reference]
	if !ok {
		return agentguard.ResolvedIntentAuthorization{}, errors.New("authorization unresolved")
	}
	return value, nil
}

// assessEndpointToolIntent performs T16 analysis on the same authenticated
// pre-execution /decide path that has the raw arguments. Only the exact finite
// T14 facets (file, directory list, hookd web-fetch network_connect and
// canonical MCP) are re-resolved; unsupported or unavailable scopes remain
// uncertain.
// The T16 report contains hashes and bounded classifications; this does not
// change the existing T07 tool-call parameter persistence contract.
// t13Denied is true only when every required facet was re-resolved from
// persisted T13 decisions and at least one was explicitly denied. Missing,
// unresolved, or unsupported facets and all intent/semantic findings leave it
// false: they are evidence, never an authorization outcome.
func (g *AgentEndpointGateway) assessEndpointToolIntent(ctx context.Context, endpointToken, endpointID, tenantID, registeredProduct string, q endpointDecideRequest) (report map[string]any, t13Denied bool) {
	step := agentguard.IntentObservedStep{
		EndpointID: endpointID, SessionID: q.SessionID, PromptID: q.PromptID,
		ToolCallID: q.ToolUseID, ToolName: q.Tool.Name, ToolType: q.Tool.Type, Product: q.Agent.Product, MCPServer: q.Tool.MCPServer,
		Arguments: q.Arguments,
	}
	effect, effectIssue := agentguard.DeriveIntentEffect(step)
	argsHash, err := agentintent.ArgumentsHash(q.Arguments)
	if err != nil {
		return nil, false
	}
	step.Action, step.ResourceType, step.ResourceID = effect.Action, effect.ResourceType, effect.ResourceID
	step.AuthorizationRef = "unsupported:" + agentintent.DigestString(endpointID+"\x00"+q.SessionID+"\x00"+q.ToolUseID+"\x00"+argsHash)

	var facets []agentintent.AuthorizationFacet
	if registeredProduct != "" && registeredProduct == q.Agent.Product && effectIssue == "" {
		declaredEffect, declaredFacets, facetErr := agentintent.DeriveT16AuthorizationFacets(registeredProduct, q.Tool.Name, q.Tool.Type, q.Tool.MCPServer, q.Arguments)
		if facetErr == nil && declaredEffect.Action == effect.Action && declaredEffect.ResourceType == effect.ResourceType && declaredEffect.ResourceID == effect.ResourceID {
			effectFacet := declaredFacets[len(declaredFacets)-1]
			step.AuthorizationRef, err = agentintent.AuthorizationIdempotencyKey(registeredProduct, endpointID,
				q.SessionID, q.ToolUseID, argsHash, q.Tool.Name, effectFacet)
			if err == nil {
				facets = declaredFacets
			}
		}
	}

	resolver := endpointIntentResolver{}
	bindings := make([]map[string]any, 0, len(facets))
	resolutionState := "unsupported"
	taskStatus := "missing"
	var approvedTask *agentintent.ResolvedIntentTask
	if registeredProduct == "" || registeredProduct != q.Agent.Product {
		resolutionState = "endpoint_product_mismatch"
	}
	if (len(facets) > 0 || q.IntentTaskID != "") && err == nil {
		resolutionState = "unavailable"
		request := agentintent.AuthorizationResolveRequest{
			Product: registeredProduct, IntentTaskID: q.IntentTaskID, SessionID: q.SessionID, ToolUseID: q.ToolUseID,
			ArgumentsHash: argsHash, ToolName: q.Tool.Name, Facets: facets,
		}
		request.Sources = intentTaskSourceClaims(q.Context.Fragments)
		resolved, resolveErr := g.resolveEndpointIntentAuthorizations(ctx, endpointToken, request)
		if resolveErr == nil {
			taskStatus = resolved.TaskStatus
			switch resolved.AuthorizationStatus {
			case "resolved":
				if len(facets) == 0 && len(resolved.Resolutions) == 0 {
					resolutionState = "unsupported"
				} else if validEndpointIntentResolution(request, endpointID, resolved.Resolutions) {
					resolutionState = "resolved"
					allAllowed := true
					for _, item := range resolved.Resolutions {
						decision := "denied"
						if item.Allowed {
							decision = "allowed"
						} else {
							allAllowed = false
						}
						isEffect := item.Facet.Action != "tool_execute"
						bindings = append(bindings, map[string]any{
							"action": item.Facet.Action, "resource_type": item.Facet.ResourceType,
							"resource_ref_hash":      agentintent.DigestString(item.Facet.ResourceID),
							"authorization_ref_hash": agentintent.DigestString(item.IdempotencyKey),
							"principal_ref_hash":     agentintent.DigestString(item.PrincipalID),
							"grant_ref_hash":         agentintent.DigestString(item.GrantID),
							"decision":               decision,
						})
						if isEffect {
							resolver[item.IdempotencyKey] = agentguard.ResolvedIntentAuthorization{
								Allowed: item.Allowed, Action: item.Facet.Action,
								ResourceType: item.Facet.ResourceType, ResourceID: item.Facet.ResourceID,
								PrincipalID: item.PrincipalID, GrantID: item.GrantID,
							}
						}
					}
					step.RequiredAuthorizationDenied = !allAllowed
					t13Denied = !allAllowed
				} else {
					resolutionState = "unavailable"
				}
			case "unresolved":
				resolutionState = "unavailable"
			default:
				resolutionState = "unsupported"
			}
			if resolved.Task != nil && resolved.Task.ID == q.IntentTaskID && validResolvedIntentTask(resolved.Task) {
				approvedTask = resolved.Task
			}
		} else {
			resolutionState = "unavailable"
		}
	}

	step.SourceIDs = make([]string, 0, len(q.Context.Fragments))
	sources := make([]agentguard.IntentExternalSource, 0, len(q.Context.Fragments))
	for index, fragment := range q.Context.Fragments {
		sourceID := "fragment-" + strconv.Itoa(index)
		step.SourceIDs = append(step.SourceIDs, sourceID)
		previewHash := ""
		if fragment.Preview != "" {
			previewHash = "sha256:" + agentintent.DigestString(fragment.Preview)
		}
		source := agentguard.IntentExternalSource{
			ID: sourceID, Kind: fragment.Source, EndpointID: endpointID,
			SessionID: q.SessionID, PromptID: q.PromptID,
			SourceHash: fragment.Hash, LineageState: "endpoint_claimed",
			ContentAssurance: agentintent.IntentSourceContentAssurance(fragment.Hash, previewHash, nil, ""),
		}
		previewMatchesClaim := fragment.Preview != "" && strings.TrimPrefix(strings.ToLower(strings.TrimSpace(fragment.Hash)), "sha256:") == agentintent.DigestString(fragment.Preview)
		if previewMatchesClaim {
			source.Content = fragment.Preview
		} else if fragment.Preview != "" {
			source.LineageState = "preview_hash_mismatch"
		}
		if approvedTask != nil {
			for _, link := range approvedTask.SourceLinks {
				if link.Index == index {
					source.LineageState = link.LineageState
					source.ContentAssurance = link.ContentAssurance
					source.LinkedStepSequence = link.LinkedStepSequence
					source.EventRefHash = link.AcceptedEventRefHash
					if link.LineageState == "accepted_result_hash_match" && !previewMatchesClaim {
						source.LineageState = "accepted_result_preview_mismatch"
						source.Content = ""
					}
					break
				}
			}
		}
		sources = append(sources, source)
	}
	var taskContext *agentguard.IntentApprovedTaskContext
	if approvedTask != nil {
		taskContext = &agentguard.IntentApprovedTaskContext{
			State: "resolved", TaskID: approvedTask.ID, Purpose: approvedTask.Purpose,
			PurposeSHA256: approvedTask.PurposeSHA256, ScopeSHA256: approvedTask.ScopeSHA256,
			FacetScopeState:    approvedTask.FacetScopeState,
			AllowedSourceKinds: approvedTask.SourceScope.AllowedKinds, AllowedSourceHashes: approvedTask.SourceScope.AllowedHashes,
			History: make([]agentguard.IntentTaskHistoryStep, 0, len(approvedTask.History)), HistoryTruncated: approvedTask.HistoryTruncated,
		}
		for _, prior := range approvedTask.History {
			step := agentguard.IntentTaskHistoryStep{Sequence: prior.Sequence, ToolName: prior.ToolName, Action: prior.Action,
				ResourceType: prior.ResourceType, ResourceRefHash: prior.ResourceRefHash, ArgumentsHash: prior.ArgumentsHash,
				AuthorizationState: prior.AuthorizationState, ResultState: prior.ResultState, ResultHash: prior.ResultHash,
				SourceRefs: make([]agentguard.IntentTaskHistorySourceRef, 0, len(prior.SourceRefs))}
			for _, ref := range prior.SourceRefs {
				step.SourceRefs = append(step.SourceRefs, agentguard.IntentTaskHistorySourceRef{Kind: ref.Kind, SourceHash: ref.SourceHash,
					LineageState: ref.LineageState, ContentAssurance: ref.ContentAssurance, LinkedStepSequence: ref.LinkedStepSequence})
			}
			taskContext.History = append(taskContext.History, step)
		}
		for _, grant := range approvedTask.Grants {
			taskContext.GrantScopes = append(taskContext.GrantScopes, agentguard.IntentTaskGrantScope{Action: grant.Action,
				ResourceType: grant.ResourceType, ResourceRefHash: grant.ResourceRefHash})
		}
	}
	judge, judgeEnabled := g.intentSemanticJudge(ctx, tenantID, registeredProduct, q.SessionID)
	assessment, assessErr := agentguard.AssessIntentFlow(ctx, agentguard.IntentFlowInput{
		Identity: agentguard.IntentFlowIdentity{EndpointID: endpointID, SessionID: q.SessionID, PromptID: q.PromptID},
		Resolver: resolver, Sources: sources, Steps: []agentguard.IntentObservedStep{step}, ApprovedTask: taskContext,
		SemanticJudge: judge, SemanticJudgeEnabled: judgeEnabled,
	})
	if assessErr != nil {
		assessment = unavailableIntentAssessment()
	}
	approvedTaskEvidence := map[string]any{"state": taskStatus, "lineage_assurance": "endpoint_claimed"}
	if approvedTask != nil {
		approvedTaskEvidence = map[string]any{"state": "resolved", "task_ref_hash": agentintent.DigestString(approvedTask.ID),
			"purpose_ref_hash": approvedTask.PurposeSHA256, "scope_ref_hash": approvedTask.ScopeSHA256,
			"facet_scope_state": approvedTask.FacetScopeState, "history_ref_hash": approvedTask.HistorySHA256,
			"lineage_assurance": "pending_server_step_binding"}
	}
	authorizationOutcome := "not_enforced"
	if t13Denied {
		authorizationOutcome = "t13_denied_block_floor"
	}
	return map[string]any{
		"schema": "t16-intent/v1", "stage": "pre_execution",
		"authorization_outcome":      authorizationOutcome,
		"arguments_hash":             argsHash,
		"endpoint_ref_hash":          agentintent.DigestString(endpointID),
		"session_ref_hash":           agentintent.DigestString(q.SessionID),
		"prompt_ref_hash":            agentintent.DigestString(q.PromptID),
		"tool_call_ref_hash":         agentintent.DigestString(q.ToolUseID),
		"tool_name_ref_hash":         agentintent.DigestString(q.Tool.Name),
		"tool_type":                  q.Tool.Type,
		"authorization_lookup_state": resolutionState,
		"authorization_bindings":     bindings,
		"approved_task":              approvedTaskEvidence,
		"assessment":                 assessment,
		"terminal_result":            map[string]string{"status": "awaiting_authenticated_t02_event"},
	}, t13Denied
}

func validResolvedIntentTask(task *agentintent.ResolvedIntentTask) bool {
	if task == nil || task.ID == "" || len(task.Purpose) == 0 || len(task.Purpose) > 2048 ||
		len(task.PurposeSHA256) != 64 || len(task.ScopeSHA256) != 64 || len(task.SourceScopeSHA256) != 64 ||
		len(task.SourceScope.AllowedKinds) == 0 || len(task.SourceScope.AllowedKinds) > 16 || len(task.History) > 32 ||
		task.HistorySHA256 != agentintent.IntentTaskHistoryHash(task.History, task.HistoryTruncated) {
		return false
	}
	if agentintent.DigestString(task.Purpose) != strings.TrimPrefix(strings.ToLower(task.PurposeSHA256), "sha256:") ||
		agentintent.DigestString(string(agentintent.CanonicalIntentTaskSourceScopeBytes(task.SourceScope))) != strings.TrimPrefix(strings.ToLower(task.SourceScopeSHA256), "sha256:") ||
		len(task.SourceLinks) > 32 {
		return false
	}
	seenSourceIndexes := make(map[int]struct{}, len(task.SourceLinks))
	for _, link := range task.SourceLinks {
		if link.Index < 0 || link.Index >= 32 || len(link.Kind) > 64 || len(link.SourceHash) > 72 ||
			!agentintent.ValidIntentSourceContentAssurance(link.ContentAssurance) {
			return false
		}
		if _, exists := seenSourceIndexes[link.Index]; exists {
			return false
		}
		seenSourceIndexes[link.Index] = struct{}{}
	}
	return true
}

func (g *AgentEndpointGateway) resolveEndpointIntentAuthorizations(ctx context.Context, endpointToken string, request agentintent.AuthorizationResolveRequest) (agentintent.AuthorizationResolveResponse, error) {
	encoded, err := json.Marshal(request)
	if err != nil {
		return agentintent.AuthorizationResolveResponse{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, g.controlURL+agentIntentResolvePath, bytes.NewReader(encoded))
	if err != nil {
		return agentintent.AuthorizationResolveResponse{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+endpointToken)
	req.Header.Set("X-JJDGuard-Internal-Token", g.secret)
	resp, err := g.client.Do(req)
	if err != nil {
		return agentintent.AuthorizationResolveResponse{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return agentintent.AuthorizationResolveResponse{}, errors.New("authorization resolver unavailable")
	}
	var body agentintent.AuthorizationResolveResponse
	decoder := json.NewDecoder(io.LimitReader(resp.Body, 128<<10))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&body); err != nil {
		return agentintent.AuthorizationResolveResponse{}, err
	}
	return body, nil
}

func validEndpointIntentResolution(request agentintent.AuthorizationResolveRequest, endpointID string, got []agentintent.AuthorizationResolution) bool {
	if len(request.Facets) == 0 {
		return len(got) == 0
	}
	if len(got) != len(request.Facets) {
		return false
	}
	principal := ""
	for index, item := range got {
		facet := request.Facets[index]
		if item.Facet != facet || item.PrincipalID == "" ||
			(item.Allowed && item.GrantID == "") || (!item.Allowed && item.GrantID != "") {
			return false
		}
		key, err := agentintent.AuthorizationIdempotencyKey(request.Product, endpointID,
			request.SessionID, request.ToolUseID, request.ArgumentsHash, request.ToolName, facet)
		if err != nil || key != item.IdempotencyKey {
			return false
		}
		if principal == "" {
			principal = item.PrincipalID
		} else if principal != item.PrincipalID {
			return false
		}
	}
	return true
}

func unavailableIntentAssessment() agentguard.IntentFlowAssessment {
	return agentguard.IntentFlowAssessment{
		Alignment: "uncertain", Completeness: "partial", ReviewRequired: true,
		Issues:   []string{"intent_assessment_unavailable"},
		Semantic: agentguard.IntentSemanticObservation{Status: "not_requested"},
	}
}

func (g *AgentEndpointGateway) intentSemanticJudge(ctx context.Context, tenantID, product, sessionID string) (agentguard.SemanticJudge, bool) {
	enabled := os.Getenv("SECURITY_SEMANTIC_ENABLED") == "true" && os.Getenv("SECURITY_SEMANTIC_AGENT_ENABLED") == "true"
	if g.toolClient != nil {
		enabled = g.toolClient.SemanticAgentEnabled(ctx, enabled)
	}
	if !enabled {
		return nil, false
	}
	envelope := &modelrouter.RequestEnvelope{TenantID: tenantID, AgentType: product, AgentRuntime: "agent_hook", SessionID: sessionID}
	return intentFlowSemanticJudge{checker: g.securityClient, envelope: envelope}, true
}

type intentFlowSemanticJudge struct {
	checker  SecurityChecker
	envelope *modelrouter.RequestEnvelope
}

func (j intentFlowSemanticJudge) Judge(ctx context.Context, toolName string, args map[string]any) (agentguard.Decision, error) {
	if j.checker == nil {
		return agentguard.Decision{}, errors.New("semantic checker unavailable")
	}
	stageChecker, ok := j.checker.(semanticStageChecker)
	if !ok {
		return agentguard.Decision{}, errors.New("semantic stage unsupported")
	}
	checkCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	content := renderToolCallForJudge(toolName, args)
	findings, err := stageChecker.CheckSemanticStage(checkCtx, j.envelope, content, "agent")
	if err != nil {
		return agentguard.Decision{}, err
	}
	worst, found := worstSemanticFinding(findings)
	if !found {
		return agentguard.Decision{RawDecision: agentguard.DecisionAllow, Reason: "intent_semantic_no_finding", RiskLevel: "low"}, nil
	}
	return agentguard.Decision{RawDecision: agentguard.DecisionAudit, Reason: worst.Category, RiskLevel: worst.Severity, Confidence: worst.Confidence}, nil
}

func intentTaskSourceClaims(fragments []endpointDecideFragment) []agentintent.IntentTaskSourceClaim {
	claims := make([]agentintent.IntentTaskSourceClaim, 0, len(fragments))
	for _, fragment := range fragments {
		previewHash := ""
		if fragment.Preview != "" {
			previewHash = "sha256:" + agentintent.DigestString(fragment.Preview)
		}
		claims = append(claims, agentintent.IntentTaskSourceClaim{Kind: fragment.Source, ToolUseID: fragment.ToolUseID, Hash: fragment.Hash, PreviewHash: previewHash})
	}
	return claims
}
