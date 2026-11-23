package repository

import (
	"context"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/yangjiyj/aiguard/packages/shared-go/agentintent"
)

// bindIntentTaskProposal runs inside the same transaction and lifecycle identity
// lock as the authenticated /decide proposal. The client task ID is only a
// locator; the row, principal, grant snapshot, endpoint and product are read
// and revalidated here before a server sequence is assigned.
func bindIntentTaskProposal(ctx context.Context, tx pgx.Tx, log *ToolCallLog, toolCallLogID string) error {
	if log == nil || log.IntentTaskID == "" {
		return nil
	}
	var evidence []byte
	if err := tx.QueryRow(ctx, "SELECT COALESCE(evidence_json,'[]'::jsonb)::text FROM tool_call_logs WHERE tenant_id=$1 AND id=$2 FOR UPDATE", log.TenantID, toolCallLogID).Scan(&evidence); err != nil {
		return err
	}
	markUncertain := func() error {
		if !agentintent.IntentEvidencePresent(evidence) {
			return nil
		}
		updated, changed, err := agentintent.MarkIntentUncertainEvidence(evidence, "proposal_identity_mismatch")
		if err != nil || !changed {
			return err
		}
		_, err = tx.Exec(ctx, "UPDATE tool_call_logs SET evidence_json=$1::jsonb WHERE tenant_id=$2 AND id=$3", updated, log.TenantID, toolCallLogID)
		return err
	}
	taskID := log.IntentTaskID
	if !validIntentTaskLocator(taskID) || log.SessionID == "" || log.PromptID == "" || log.ToolCallID == "" || log.ToolName == "" {
		return markUncertain()
	}
	argsHash, err := agentintent.ArgumentsHash(log.Parameters)
	if err != nil {
		return markUncertain()
	}

	var product string
	err = tx.QueryRow(ctx, "SELECT agent_product FROM agent_endpoints WHERE tenant_id=$1 AND id=$2 AND status='active' FOR SHARE", log.TenantID, log.EndpointID).Scan(&product)
	if errors.Is(err, pgx.ErrNoRows) {
		return markUncertain()
	}
	if err != nil {
		return err
	}
	if product != "claude-code" && product != "openclaw" && product != "opencode" {
		return markUncertain()
	}

	effect, facets, effectErr := agentintent.DeriveT16AuthorizationFacets(product, log.ToolName, log.ToolType, log.MCPServer, log.Parameters)
	facetsSupported := effectErr == nil && len(facets) > 0
	authState := "unsupported"
	resolutions := []agentintent.AuthorizationResolution{}
	principalFromT13 := ""
	if facetsSupported {
		authState = "unresolved"
		request := agentintent.AuthorizationResolveRequest{
			Product: product, SessionID: log.SessionID, ToolUseID: log.ToolCallID,
			ArgumentsHash: argsHash, ToolName: log.ToolName, Facets: facets,
		}
		resolutions, err = resolveIntentAuthorizationsWithQuerier(ctx, tx, log.TenantID, log.EndpointID, request)
		if err == nil && len(resolutions) == len(facets) {
			authState = "allowed"
			for _, item := range resolutions {
				if principalFromT13 == "" {
					principalFromT13 = item.PrincipalID
				} else if principalFromT13 != item.PrincipalID {
					authState = "unresolved"
				}
				if !item.Allowed {
					authState = "denied"
				}
			}
		}
	}

	var task AgentIntentTask
	var sourceRaw []byte
	err = tx.QueryRow(ctx, "SELECT id::text,tenant_id,endpoint_id,product,principal_id::text,state,purpose,purpose_sha256,source_scope::text,source_scope_sha256,scope_sha256,approved_by,approved_at,expires_at FROM agent_intent_tasks WHERE tenant_id=$1 AND endpoint_id=$2 AND product=$3 AND id=$4 AND state='approved' AND expires_at>clock_timestamp() FOR UPDATE",
		log.TenantID, log.EndpointID, product, taskID).Scan(&task.ID, &task.TenantID, &task.EndpointID, &task.Product, &task.PrincipalID, &task.State,
		&task.Purpose, &task.PurposeSHA256, &sourceRaw, &task.SourceScopeSHA256, &task.ScopeSHA256, &task.ApprovedBy, &task.ApprovedAt, &task.ExpiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return markUncertain()
	}
	if err != nil {
		return err
	}
	if principalFromT13 != "" && principalFromT13 != task.PrincipalID {
		return markUncertain()
	}
	if json.Unmarshal(sourceRaw, &task.SourceScope) != nil || intentTaskHash([]byte(task.Purpose)) != task.PurposeSHA256 {
		return markUncertain()
	}
	canonicalScope, scopeErr := normalizeIntentTaskSourceScope(task.SourceScope.AllowedKinds, task.SourceScope.AllowedHashes)
	if scopeErr != nil || intentTaskHash(canonicalIntentTaskSourceScope(canonicalScope)) != task.SourceScopeSHA256 {
		return markUncertain()
	}
	task.SourceScope = canonicalScope

	var principalStatus string
	var principalRevoked, principalActive bool
	if err := tx.QueryRow(ctx, "SELECT status,revoked_at IS NOT NULL,expires_at>clock_timestamp() FROM agent_authorization_principals WHERE tenant_id=$1 AND id=$2 FOR SHARE",
		log.TenantID, task.PrincipalID).Scan(&principalStatus, &principalRevoked, &principalActive); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return markUncertain()
		}
		return err
	}
	if principalStatus != "active" || principalRevoked || !principalActive {
		return markUncertain()
	}

	rows, err := tx.Query(ctx, "SELECT grant_id::text,action,resource_type,resource_ref_hash,grant_expires_at FROM agent_intent_task_grants WHERE tenant_id=$1 AND task_id=$2 ORDER BY action,resource_type,resource_ref_hash FOR SHARE",
		log.TenantID, taskID)
	if err != nil {
		return err
	}
	var grants []AgentIntentTaskGrant
	for rows.Next() {
		var grant AgentIntentTaskGrant
		if err := rows.Scan(&grant.GrantID, &grant.Action, &grant.ResourceType, &grant.ResourceRefHash, &grant.ExpiresAt); err != nil {
			rows.Close()
			return err
		}
		grants = append(grants, grant)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()
	if len(grants) == 0 {
		return markUncertain()
	}
	for _, grant := range grants {
		var liveAction, liveType, liveResource string
		var liveExpiry time.Time
		err = tx.QueryRow(ctx, "SELECT action,resource_type,resource_id,expires_at FROM agent_authorization_grants WHERE tenant_id=$1 AND principal_id=$2 AND id=$3 AND expires_at>clock_timestamp() FOR SHARE",
			log.TenantID, task.PrincipalID, grant.GrantID).Scan(&liveAction, &liveType, &liveResource, &liveExpiry)
		if err != nil || liveAction != grant.Action || liveType != grant.ResourceType || agentintent.DigestString(liveResource) != grant.ResourceRefHash || !liveExpiry.Equal(grant.ExpiresAt) {
			if err != nil && !errors.Is(err, pgx.ErrNoRows) {
				return err
			}
			return markUncertain()
		}
	}
	sortTaskGrantScopes(grants)
	scopeBytes, err := intentTaskScopeSnapshotBytes(task.EndpointID, task.Product, task.PrincipalID, task.PurposeSHA256, task.SourceScope, grants)
	if err != nil || intentTaskHash(scopeBytes) != task.ScopeSHA256 {
		return markUncertain()
	}
	task.Grants = grants

	scopeMatched := false
	if facetsSupported {
		scopeMatched = true
		for _, facet := range facets {
			matches := 0
			for _, grant := range grants {
				if grant.Action == facet.Action && grant.ResourceType == facet.ResourceType && grant.ResourceRefHash == agentintent.DigestString(facet.ResourceID) {
					matches++
				}
			}
			if matches != 1 {
				scopeMatched = false
			}
		}
		if !scopeMatched {
			authState = "scope_mismatch"
		}
	}
	if principalFromT13 == "" {
		principalFromT13 = task.PrincipalID
	}

	history, historyTruncated, err := loadIntentTaskHistoryWithQuerier(ctx, tx, log.TenantID, taskID)
	if err != nil {
		return err
	}
	historyHash := agentintent.IntentTaskHistoryHash(history, historyTruncated)
	if historyHash == "" {
		return markUncertain()
	}
	sourceRefs, err := intentTaskSourceRefsWithQuerier(ctx, tx, log.TenantID, log.EndpointID, taskID, task.SourceScope, log.IntentTaskSources)
	if err != nil {
		return err
	}
	sourceJSON, err := json.Marshal(sourceRefs)
	if err != nil {
		return err
	}

	bindings := make([]map[string]any, 0, len(facets))
	grantIDs := make([]string, 0, len(resolutions))
	for _, item := range resolutions {
		grantRef := ""
		if item.GrantID != "" {
			grantRef = agentintent.DigestString(item.GrantID)
			grantIDs = append(grantIDs, item.GrantID)
		}
		decision := "denied"
		if item.Allowed {
			decision = "allowed"
		}
		bindings = append(bindings, map[string]any{
			"action": item.Facet.Action, "resource_type": item.Facet.ResourceType,
			"resource_ref_hash":      agentintent.DigestString(item.Facet.ResourceID),
			"authorization_ref_hash": agentintent.DigestString(item.IdempotencyKey),
			"principal_ref_hash":     agentintent.DigestString(item.PrincipalID),
			"grant_ref_hash":         grantRef, "decision": decision,
		})
	}
	if !facetsSupported {
		bindings = append(bindings, map[string]any{"state": "unsupported"})
	} else if len(resolutions) == 0 {
		bindings = append(bindings, map[string]any{"state": "unresolved"})
	}
	sort.Strings(grantIDs)
	bindingJSON, err := json.Marshal(bindings)
	if err != nil {
		return err
	}
	bindingsHash := intentTaskHash(bindingJSON)
	grantHash := agentintent.DigestString(strings.Join(grantIDs, "\x00"))
	resourceHash := agentintent.DigestString(effect.ResourceID)
	action, resourceType := effect.Action, effect.ResourceType
	if !facetsSupported {
		action, resourceType = "unsupported", "unknown"
	}
	lineageState := "uncertain"
	if facetsSupported && scopeMatched {
		lineageState = "server_task_record"
	}

	var priorID string
	var priorTaskID, priorEndpoint, priorProduct, priorSessionHash, priorPromptHash, priorToolUseHash, priorArgsHash string
	var priorSequence int
	err = tx.QueryRow(ctx, "SELECT id::text,task_id::text,endpoint_id,product,session_ref_hash,prompt_ref_hash,tool_use_ref_hash,arguments_hash,server_sequence FROM agent_intent_task_steps WHERE tenant_id=$1 AND tool_call_log_id=$2 FOR UPDATE",
		log.TenantID, toolCallLogID).Scan(&priorID, &priorTaskID, &priorEndpoint, &priorProduct, &priorSessionHash, &priorPromptHash, &priorToolUseHash, &priorArgsHash, &priorSequence)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	stepID := ""
	serverSequence := 0
	if err == nil {
		if priorTaskID != taskID || priorEndpoint != log.EndpointID || priorProduct != product ||
			priorSessionHash != agentintent.DigestString(log.SessionID) || priorPromptHash != agentintent.DigestString(log.PromptID) ||
			priorToolUseHash != agentintent.DigestString(log.ToolCallID) || priorArgsHash != argsHash {
			return markUncertain()
		}
		stepID, serverSequence = priorID, priorSequence
	} else {
		if err := tx.QueryRow(ctx, "SELECT COALESCE(MAX(server_sequence),0)+1 FROM agent_intent_task_steps WHERE tenant_id=$1 AND task_id=$2", log.TenantID, taskID).Scan(&serverSequence); err != nil {
			return err
		}
		stepID = uuid.NewString()
		_, err = tx.Exec(ctx, "INSERT INTO agent_intent_task_steps(id,tenant_id,task_id,server_sequence,endpoint_id,product,session_ref_hash,prompt_ref_hash,tool_use_ref_hash,tool_call_log_id,arguments_hash,tool_name,tool_type,action,resource_type,resource_ref_hash,authorization_state,authorization_bindings_hash,principal_ref_hash,grant_ref_hash,source_refs,lineage_state) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21::jsonb,$22)",
			stepID, log.TenantID, taskID, serverSequence, log.EndpointID, product,
			agentintent.DigestString(log.SessionID), agentintent.DigestString(log.PromptID), agentintent.DigestString(log.ToolCallID),
			toolCallLogID, argsHash, log.ToolName, strings.ToLower(log.ToolType), action, resourceType, resourceHash,
			authState, bindingsHash, agentintent.DigestString(principalFromT13), grantHash, sourceJSON, lineageState)
		if err != nil {
			return err
		}
	}

	if agentintent.IntentEvidencePresent(evidence) {
		updated, changed, bindErr := agentintent.BindIntentTaskStepEvidence(evidence, taskID, stepID, serverSequence, historyHash)
		if bindErr != nil {
			return markUncertain()
		}
		if changed {
			if _, err := tx.Exec(ctx, "UPDATE tool_call_logs SET evidence_json=$1::jsonb WHERE tenant_id=$2 AND id=$3", updated, log.TenantID, toolCallLogID); err != nil {
				return err
			}
		}
	}
	return nil
}

func loadIntentTaskHistoryWithQuerier(ctx context.Context, querier t13AuthorizationQuerier, tenantID, taskID string) ([]agentintent.IntentTaskHistoryStep, bool, error) {
	rows, err := querier.Query(ctx, "SELECT s.server_sequence,s.tool_name,s.action,s.resource_type,s.resource_ref_hash,s.arguments_hash,s.authorization_state,s.terminal_outcome,COALESCE(s.result_hash,''),COALESCE(s.source_refs,'[]'::jsonb)::text,s.terminal_event_id IS NOT NULL AND event.id IS NOT NULL FROM agent_intent_task_steps s LEFT JOIN agent_events event ON event.tenant_id=s.tenant_id AND event.id=s.terminal_event_id AND event.endpoint_id=s.endpoint_id AND event.tool_call_log_id=s.tool_call_log_id WHERE s.tenant_id=$1 AND s.task_id=$2 ORDER BY s.server_sequence DESC LIMIT 33", tenantID, taskID)
	if err != nil {
		return nil, false, err
	}
	defer rows.Close()
	var reverse []agentintent.IntentTaskHistoryStep
	truncated := false
	for rows.Next() {
		var step agentintent.IntentTaskHistoryStep
		var sequence int64
		var refsRaw string
		var acceptedEvent bool
		if err := rows.Scan(&sequence, &step.ToolName, &step.Action, &step.ResourceType, &step.ResourceRefHash, &step.ArgumentsHash, &step.AuthorizationState, &step.ResultState, &step.ResultHash, &refsRaw, &acceptedEvent); err != nil {
			return nil, false, err
		}
		if sequence < 1 || sequence > int64(^uint(0)>>1) {
			truncated = true
			continue
		}
		step.Sequence = int(sequence)
		if !acceptedEvent || step.ResultState == "pending" {
			step.ResultState = "uncertain"
		}
		if json.Unmarshal([]byte(refsRaw), &step.SourceRefs) != nil {
			step.SourceRefs = nil
			step.ResultState = "uncertain"
		}
		reverse = append(reverse, step)
	}
	if err := rows.Err(); err != nil {
		return nil, false, err
	}
	if len(reverse) > 32 {
		reverse = reverse[:32]
		truncated = true
	}
	for i, j := 0, len(reverse)-1; i < j; i, j = i+1, j-1 {
		reverse[i], reverse[j] = reverse[j], reverse[i]
	}
	return reverse, truncated, nil
}

func intentTaskSourceRefsWithQuerier(ctx context.Context, querier t13AuthorizationQuerier, tenantID, endpointID, taskID string, scope AgentIntentTaskSourceScope, claims []agentintent.IntentTaskSourceClaim) ([]map[string]any, error) {
	if len(claims) > AgentIntentTaskMaxSources {
		return []map[string]any{{"lineage_state": "source_count_exceeded"}}, nil
	}
	allowedKinds := make(map[string]bool, len(scope.AllowedKinds))
	for _, kind := range scope.AllowedKinds {
		allowedKinds[kind] = true
	}
	allowedHashes := make(map[string]bool, len(scope.AllowedHashes))
	for _, hash := range scope.AllowedHashes {
		allowedHashes[strings.TrimPrefix(strings.ToLower(hash), "sha256:")] = true
	}
	refs := make([]map[string]any, 0, len(claims))
	for _, claim := range claims {
		hash, ok := normalizedIntentSourceHash(claim.Hash)
		state := "endpoint_claimed"
		linkedSequence := 0
		eventRefHash := ""
		contentAssurance := agentintent.IntentSourceContentAssurance(claim.Hash, claim.PreviewHash, scope.AllowedHashes, "")
		if !ok || !allowedKinds[claim.Kind] || (len(allowedHashes) > 0 && !allowedHashes[hash]) {
			state = "source_scope_mismatch"
		} else if claim.Kind == "tool_result" {
			state = "accepted_result_missing_or_ambiguous"
			if claim.ToolUseID != "" {
				rows, err := querier.Query(ctx, "SELECT s.server_sequence,s.terminal_event_id,s.arguments_hash,s.result_hash,s.terminal_outcome,s.tool_use_ref_hash,e.event_type,e.endpoint_id,e.session_id,e.prompt_id,e.tool_use_id,e.tool_name,e.tool_type,e.payload,t.tool_call_id,t.tool_name,t.tool_type,t.parameters FROM agent_intent_task_steps s JOIN agent_events e ON e.tenant_id=s.tenant_id AND e.id=s.terminal_event_id AND e.endpoint_id=s.endpoint_id AND e.tool_call_log_id=s.tool_call_log_id JOIN tool_call_logs t ON t.tenant_id=s.tenant_id AND t.id=s.tool_call_log_id AND t.endpoint_id=s.endpoint_id WHERE s.tenant_id=$1 AND s.task_id=$2 AND s.endpoint_id=$3 AND s.tool_use_ref_hash=$4 AND s.result_hash=$5 AND s.terminal_event_id IS NOT NULL AND s.terminal_outcome IN ('succeeded','failed') AND e.event_type IN ('tool.post','tool.failure') AND e.tool_use_id=$6 ORDER BY s.server_sequence FOR SHARE OF s,e,t", tenantID, taskID, endpointID, agentintent.DigestString(claim.ToolUseID), hash, claim.ToolUseID)
				if err != nil {
					return nil, err
				}
				matches := 0
				for rows.Next() {
					var seq int
					var eventID, argsHash, resultHash, outcome, toolUseHash string
					var eventType, eventEndpoint, sessionID, promptID, eventToolUse, toolName, toolType, logCallID, logToolName, logToolType string
					var payload, parameters []byte
					if err := rows.Scan(&seq, &eventID, &argsHash, &resultHash, &outcome, &toolUseHash, &eventType, &eventEndpoint, &sessionID, &promptID, &eventToolUse, &toolName, &toolType, &payload, &logCallID, &logToolName, &logToolType, &parameters); err != nil {
						rows.Close()
						return nil, err
					}
					var event map[string]any
					if decodeAcceptedT02EventPayload(payload, &event) != nil || event == nil {
						continue
					}
					eventToolUseClaim, eventCallClaim, eventArgsHash, eventResultHash, _, _, _, _ := agentIntentEventMetadata(event)
					storedArgsHash, hashErr := hashStoredParameters(parameters)
					if eventType != "tool.post" && eventType != "tool.failure" || eventEndpoint != endpointID ||
						sessionID == "" || promptID == "" || eventToolUse != claim.ToolUseID || eventToolUseClaim != eventToolUse ||
						eventCallClaim != eventToolUse || logCallID != eventToolUse || logToolName != toolName || logToolType != toolType ||
						logToolName == "" || eventArgsHash != argsHash || hashErr != nil || storedArgsHash != argsHash ||
						strings.TrimPrefix(strings.ToLower(eventResultHash), "sha256:") != resultHash || toolUseHash != agentintent.DigestString(eventToolUse) {
						continue
					}
					matches++
					linkedSequence, eventRefHash = seq, agentintent.DigestString(eventID)
				}
				if err := rows.Err(); err != nil {
					rows.Close()
					return nil, err
				}
				rows.Close()
				if matches == 1 {
					state = "accepted_result_hash_match"
				} else {
					linkedSequence, eventRefHash = 0, ""
				}
			}
		}
		ref := map[string]any{"kind": claim.Kind, "source_hash": "sha256:" + hash, "lineage_state": state, "content_assurance": contentAssurance}
		if linkedSequence > 0 {
			ref["linked_step_sequence"] = linkedSequence
		}
		if eventRefHash != "" {
			ref["accepted_event_ref_hash"] = eventRefHash
		}
		refs = append(refs, ref)
	}
	return refs, nil
}

func attachIntentTaskTerminalFromAcceptedEvent(ctx context.Context, tx pgx.Tx, tenantID, endpointID, eventID, toolCallLogID string,
	eventType, storedEndpointID, sessionID, promptID, toolUseID, toolName, toolType string, payload []byte) error {
	if eventType != "tool.post" && eventType != "tool.failure" && eventType != "tool.denied" {
		return nil
	}
	var taskID, stepID, stepEndpoint, product, sessionHash, promptHash, useHash, argsHash, stepToolName, stepToolType string
	err := tx.QueryRow(ctx, "SELECT id::text,task_id::text,endpoint_id,product,session_ref_hash,prompt_ref_hash,tool_use_ref_hash,arguments_hash,tool_name,tool_type FROM agent_intent_task_steps WHERE tenant_id=$1 AND tool_call_log_id=$2 FOR UPDATE",
		tenantID, toolCallLogID).Scan(&stepID, &taskID, &stepEndpoint, &product, &sessionHash, &promptHash, &useHash, &argsHash, &stepToolName, &stepToolType)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	var lockedTaskID string
	if err := tx.QueryRow(ctx, "SELECT id::text FROM agent_intent_tasks WHERE tenant_id=$1 AND id=$2 FOR UPDATE", tenantID, taskID).Scan(&lockedTaskID); err != nil {
		return err
	}
	var parameters []byte
	var logCallID, logEndpointID, logSessionID, logToolName, logToolType string
	err = tx.QueryRow(ctx, "SELECT COALESCE(parameters,'{}'::jsonb)::text,COALESCE(tool_call_id,''),COALESCE(endpoint_id,''),COALESCE(session_id,''),tool_name,tool_type FROM tool_call_logs WHERE tenant_id=$1 AND id=$2 AND attribution_mode='endpoint_hook' FOR UPDATE",
		tenantID, toolCallLogID).Scan(&parameters, &logCallID, &logEndpointID, &logSessionID, &logToolName, &logToolType)
	if err != nil {
		return err
	}
	var event map[string]any
	if decodeAcceptedT02EventPayload(payload, &event) != nil || event == nil {
		return setTaskStepUncertain(ctx, tx, tenantID, stepID)
	}
	eventUseID, eventCallID, eventArgsHash, eventResultHash, length, hasLength, success, hasSuccess := agentIntentEventMetadata(event)
	storedArgsHash, hashErr := hashStoredParameters(parameters)
	if hashErr != nil || storedArgsHash != argsHash || storedEndpointID != logEndpointID || endpointID != stepEndpoint ||
		logCallID != eventUseID || eventUseID != eventCallID || eventUseID == "" ||
		sessionID == "" || sessionID != logSessionID || agentintent.DigestString(sessionID) != sessionHash ||
		promptID == "" || agentintent.DigestString(promptID) != promptHash ||
		agentintent.DigestString(eventUseID) != useHash ||
		toolUseID != eventUseID || toolName != stepToolName || toolName != logToolName ||
		toolType != stepToolType || toolType != logToolType || eventArgsHash != argsHash {
		return setTaskStepUncertain(ctx, tx, tenantID, stepID)
	}
	outcome := terminalResultFromAcceptedEvent(eventID, eventType, eventResultHash, length, hasLength, success, hasSuccess).Outcome
	var resultHash any
	if normalized, ok := normalizedIntentSourceHash(eventResultHash); ok {
		resultHash = normalized
	}
	var resultLength any
	if hasLength && length >= 0 {
		resultLength = int64(length)
	} else if hasLength {
		outcome = "uncertain"
	}
	var oldEventID string
	err = tx.QueryRow(ctx, "SELECT COALESCE(terminal_event_id,'') FROM agent_intent_task_steps WHERE tenant_id=$1 AND id=$2 FOR UPDATE", tenantID, stepID).Scan(&oldEventID)
	if err != nil {
		return err
	}
	if oldEventID != "" && oldEventID != eventID {
		_, err := tx.Exec(ctx, "UPDATE agent_intent_task_steps SET terminal_event_id=NULL,terminal_event_ref_hash=NULL,terminal_outcome='uncertain',result_hash=NULL,result_length=NULL,lineage_state='uncertain',updated_at=clock_timestamp() WHERE tenant_id=$1 AND id=$2", tenantID, stepID)
		return err
	}
	_, err = tx.Exec(ctx, "UPDATE agent_intent_task_steps SET terminal_event_id=$1,terminal_event_ref_hash=$2,terminal_outcome=$3,result_hash=$4,result_length=$5,updated_at=clock_timestamp() WHERE tenant_id=$6 AND id=$7",
		eventID, agentintent.DigestString(eventID), outcome, resultHash, resultLength, tenantID, stepID)
	return err
}

func setTaskStepUncertain(ctx context.Context, tx pgx.Tx, tenantID, stepID string) error {
	_, err := tx.Exec(ctx, "UPDATE agent_intent_task_steps SET terminal_event_id=NULL,terminal_event_ref_hash=NULL,terminal_outcome='uncertain',result_hash=NULL,result_length=NULL,lineage_state='uncertain',updated_at=clock_timestamp() WHERE tenant_id=$1 AND id=$2", tenantID, stepID)
	return err
}
