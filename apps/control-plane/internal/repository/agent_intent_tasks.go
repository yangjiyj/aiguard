package repository

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/yangjiyj/aiguard/packages/shared-go/agentintent"
)

var (
	ErrAgentIntentTaskInvalid    = errors.New("invalid approved intent task")
	ErrAgentIntentTaskUnresolved = errors.New("approved intent task is unresolved")
	intentTaskSHA256Pattern      = regexp.MustCompile(`(?i)^(?:sha256:)?[0-9a-f]{64}$`)
)

const (
	AgentIntentTaskMaxTTL     = 24 * time.Hour
	AgentIntentTaskRetention  = 30 * 24 * time.Hour
	AgentIntentTaskMaxSources = 16
)

type AgentIntentTaskGrantInput struct {
	GrantID string `json:"grant_id"`
}

type AgentIntentTaskCreate struct {
	EndpointID          string                      `json:"endpoint_id"`
	PrincipalID         string                      `json:"principal_id"`
	Purpose             string                      `json:"purpose"`
	ExpiresAt           time.Time                   `json:"expires_at"`
	Grants              []AgentIntentTaskGrantInput `json:"grants"`
	AllowedSourceKinds  []string                    `json:"allowed_source_kinds"`
	AllowedSourceHashes []string                    `json:"allowed_source_hashes,omitempty"`
}

type AgentIntentTaskSourceScope struct {
	AllowedKinds  []string `json:"allowed_kinds"`
	AllowedHashes []string `json:"allowed_hashes,omitempty"`
}

type AgentIntentTaskGrant struct {
	GrantID         string    `json:"grant_id"`
	Action          string    `json:"action"`
	ResourceType    string    `json:"resource_type"`
	ResourceRefHash string    `json:"resource_ref_hash"`
	ResourceID      string    `json:"-"`
	ExpiresAt       time.Time `json:"expires_at"`
}

// AgentIntentTask is an admin-visible, immutable approval snapshot. Only state
// and revocation metadata may change after creation; purpose and scopes never
// have an update operation.
type AgentIntentTask struct {
	ID                string                              `json:"id"`
	TenantID          string                              `json:"tenant_id,omitempty"`
	EndpointID        string                              `json:"endpoint_id"`
	Product           string                              `json:"product"`
	PrincipalID       string                              `json:"principal_id,omitempty"`
	State             string                              `json:"state"`
	Purpose           string                              `json:"purpose"`
	PurposeSHA256     string                              `json:"purpose_sha256"`
	SourceScope       AgentIntentTaskSourceScope          `json:"source_scope"`
	SourceScopeSHA256 string                              `json:"source_scope_sha256"`
	ScopeSHA256       string                              `json:"scope_sha256"`
	ApprovedBy        string                              `json:"approved_by"`
	ApprovedAt        time.Time                           `json:"approved_at"`
	ExpiresAt         time.Time                           `json:"expires_at"`
	RevokedBy         string                              `json:"revoked_by,omitempty"`
	RevokedAt         *time.Time                          `json:"revoked_at,omitempty"`
	Grants            []AgentIntentTaskGrant              `json:"grants"`
	History           []agentintent.IntentTaskHistoryStep `json:"-"`
	HistoryTruncated  bool                                `json:"-"`
	SourceLinks       []agentintent.IntentTaskSourceLink  `json:"-"`
	FacetScopeState   string                              `json:"-"`
}

func (r *AgentAuthorizationRepository) CreateIntentTask(ctx context.Context, tenantID, actorID string, input AgentIntentTaskCreate) (*AgentIntentTask, error) {
	tenantID, actorID = strings.TrimSpace(tenantID), strings.TrimSpace(actorID)
	input.EndpointID, input.PrincipalID = strings.TrimSpace(input.EndpointID), strings.ToLower(strings.TrimSpace(input.PrincipalID))
	purpose := normalizeApprovedIntentPurpose(input.Purpose)
	purpose = agentintent.SanitizeApprovedPurpose(purpose, 2048)
	if tenantID == "" || actorID == "" || len(actorID) > 128 || input.EndpointID == "" || len(input.EndpointID) > 128 ||
		!validIntentTaskUUID(input.PrincipalID) || purpose == "" || len(purpose) > 2048 || len(input.Grants) == 0 ||
		len(input.Grants) > AgentAuthorizationMaxGrants || len(input.AllowedSourceKinds) == 0 ||
		len(input.AllowedSourceKinds) > AgentIntentTaskMaxSources || len(input.AllowedSourceHashes) > 64 || input.ExpiresAt.IsZero() {
		return nil, ErrAgentIntentTaskInvalid
	}
	grants := make([]AgentIntentTaskGrantInput, 0, len(input.Grants))
	seenGrants := make(map[string]struct{}, len(input.Grants))
	for _, item := range input.Grants {
		id := strings.ToLower(strings.TrimSpace(item.GrantID))
		if !validIntentTaskUUID(id) {
			return nil, ErrAgentIntentTaskInvalid
		}
		if _, exists := seenGrants[id]; exists {
			return nil, ErrAgentIntentTaskInvalid
		}
		seenGrants[id] = struct{}{}
		grants = append(grants, AgentIntentTaskGrantInput{GrantID: id})
	}
	sourceScope, err := normalizeIntentTaskSourceScope(input.AllowedSourceKinds, input.AllowedSourceHashes)
	if err != nil {
		return nil, err
	}

	tx, err := r.db.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	var product string
	err = tx.QueryRow(ctx, `SELECT agent_product FROM agent_endpoints
		WHERE tenant_id=$1 AND id=$2 AND status='active' FOR SHARE`, tenantID, input.EndpointID).Scan(&product)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrAgentIntentTaskInvalid
	}
	if err != nil {
		return nil, err
	}
	if product != "claude-code" && product != "openclaw" && product != "opencode" {
		return nil, ErrAgentIntentTaskInvalid
	}

	var principalExpires time.Time
	err = tx.QueryRow(ctx, `SELECT expires_at FROM agent_authorization_principals
		WHERE tenant_id=$1 AND id=$2 AND status='active' AND revoked_at IS NULL
		AND expires_at>clock_timestamp() FOR SHARE`, tenantID, input.PrincipalID).Scan(&principalExpires)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrAgentIntentTaskInvalid
	}
	if err != nil {
		return nil, err
	}

	grantIDs := make([]string, 0, len(grants))
	for _, item := range grants {
		grantIDs = append(grantIDs, item.GrantID)
	}
	rows, err := tx.Query(ctx, `SELECT id::text,action,resource_type,resource_id,
		conditions_json::text,expires_at FROM agent_authorization_grants
		WHERE tenant_id=$1 AND principal_id=$2 AND id::text=ANY($3::text[])
		AND expires_at>clock_timestamp() ORDER BY id FOR SHARE`, tenantID, input.PrincipalID, grantIDs)
	if err != nil {
		return nil, err
	}
	grantScopes := make([]AgentIntentTaskGrant, 0, len(grants))
	minExpiry := principalExpires
	for rows.Next() {
		var item AgentIntentTaskGrant
		var conditionsRaw string
		if err := rows.Scan(&item.GrantID, &item.Action, &item.ResourceType, &item.ResourceID, &conditionsRaw, &item.ExpiresAt); err != nil {
			rows.Close()
			return nil, err
		}
		var conditions map[string]any
		if json.Unmarshal([]byte(conditionsRaw), &conditions) != nil || len(conditions) != 0 ||
			!validAgentAuthorizationLabel(item.Action) || !validAgentAuthorizationLabel(item.ResourceType) ||
			!validAgentAuthorizationResourceID(item.ResourceID) {
			rows.Close()
			return nil, ErrAgentIntentTaskInvalid
		}
		if item.ExpiresAt.Before(minExpiry) {
			minExpiry = item.ExpiresAt
		}
		item.ResourceRefHash = agentintent.DigestString(item.ResourceID)
		item.ResourceID = ""
		grantScopes = append(grantScopes, item)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	rows.Close()
	if len(grantScopes) != len(grants) {
		return nil, ErrAgentIntentTaskInvalid
	}
	sortTaskGrantScopes(grantScopes)
	var dbNow time.Time
	if err := tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&dbNow); err != nil {
		return nil, err
	}
	expiresAt := input.ExpiresAt.UTC()
	if !expiresAt.After(dbNow) || expiresAt.After(dbNow.Add(AgentIntentTaskMaxTTL)) || expiresAt.After(minExpiry) {
		return nil, ErrAgentIntentTaskInvalid
	}

	purposeHash := intentTaskHash([]byte(purpose))
	sourceJSON, err := json.Marshal(sourceScope)
	if err != nil {
		return nil, err
	}
	sourceHash := intentTaskHash(sourceJSON)
	scopeBytes, err := intentTaskScopeSnapshotBytes(input.EndpointID, product, input.PrincipalID, purposeHash, sourceScope, grantScopes)
	if err != nil {
		return nil, err
	}
	scopeHash := intentTaskHash(scopeBytes)
	taskID := uuid.NewString()
	var approvedAt time.Time
	err = tx.QueryRow(ctx, `INSERT INTO agent_intent_tasks
		(id,tenant_id,endpoint_id,product,principal_id,state,purpose,purpose_sha256,source_scope,source_scope_sha256,scope_sha256,approved_by,approved_at,expires_at)
		VALUES ($1,$2,$3,$4,$5,'approved',$6,$7,$8::jsonb,$9,$10,$11,clock_timestamp(),$12)
		RETURNING approved_at`, taskID, tenantID, input.EndpointID, product, input.PrincipalID, purpose,
		purposeHash, sourceJSON, sourceHash, scopeHash, actorID, expiresAt).Scan(&approvedAt)
	if err != nil {
		return nil, err
	}
	for _, item := range grantScopes {
		if _, err := tx.Exec(ctx, `INSERT INTO agent_intent_task_grants
			(tenant_id,task_id,grant_id,action,resource_type,resource_ref_hash,grant_expires_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7)`, tenantID, taskID, item.GrantID, item.Action,
			item.ResourceType, item.ResourceRefHash, item.ExpiresAt); err != nil {
			return nil, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return &AgentIntentTask{ID: taskID, TenantID: tenantID, EndpointID: input.EndpointID,
		Product: product, PrincipalID: input.PrincipalID, State: "approved", Purpose: purpose,
		PurposeSHA256: purposeHash, SourceScope: sourceScope, SourceScopeSHA256: sourceHash,
		ScopeSHA256: scopeHash, ApprovedBy: actorID, ApprovedAt: approvedAt, ExpiresAt: expiresAt, Grants: grantScopes}, nil
}

func (r *AgentAuthorizationRepository) GetIntentTask(ctx context.Context, tenantID, taskID string) (*AgentIntentTask, error) {
	if strings.TrimSpace(tenantID) == "" || !validIntentTaskUUID(taskID) {
		return nil, ErrAgentIntentTaskInvalid
	}
	var task AgentIntentTask
	var sourceRaw []byte
	var revokedBy *string
	var revokedAt *time.Time
	err := r.db.QueryRow(ctx, `SELECT id::text,tenant_id,endpoint_id,product,principal_id::text,state,purpose,
		purpose_sha256,source_scope::text,source_scope_sha256,scope_sha256,approved_by,approved_at,expires_at,revoked_by,revoked_at
		FROM agent_intent_tasks WHERE tenant_id=$1 AND id=$2`, tenantID, strings.ToLower(taskID)).Scan(
		&task.ID, &task.TenantID, &task.EndpointID, &task.Product, &task.PrincipalID, &task.State, &task.Purpose,
		&task.PurposeSHA256, &sourceRaw, &task.SourceScopeSHA256, &task.ScopeSHA256, &task.ApprovedBy, &task.ApprovedAt, &task.ExpiresAt, &revokedBy, &revokedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if json.Unmarshal(sourceRaw, &task.SourceScope) != nil {
		return nil, fmt.Errorf("invalid stored task source scope")
	}
	if revokedBy != nil {
		task.RevokedBy = *revokedBy
	}
	task.RevokedAt = revokedAt
	rows, err := r.db.Query(ctx, `SELECT grant_id::text,action,resource_type,resource_ref_hash,grant_expires_at
		FROM agent_intent_task_grants WHERE tenant_id=$1 AND task_id=$2 ORDER BY action,resource_type,resource_ref_hash`, tenantID, task.ID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var grant AgentIntentTaskGrant
		if err := rows.Scan(&grant.GrantID, &grant.Action, &grant.ResourceType, &grant.ResourceRefHash, &grant.ExpiresAt); err != nil {
			return nil, err
		}
		task.Grants = append(task.Grants, grant)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return &task, nil
}

func (r *AgentAuthorizationRepository) RevokeIntentTask(ctx context.Context, tenantID, actorID, taskID string) (bool, error) {
	if strings.TrimSpace(tenantID) == "" || strings.TrimSpace(actorID) == "" || !validIntentTaskUUID(taskID) {
		return false, ErrAgentIntentTaskInvalid
	}
	tag, err := r.db.Exec(ctx, `UPDATE agent_intent_tasks SET state='revoked',revoked_by=$3,revoked_at=clock_timestamp()
		WHERE tenant_id=$1 AND id=$2 AND state='approved' AND expires_at>clock_timestamp()`, tenantID, strings.ToLower(taskID), actorID)
	return tag.RowsAffected() == 1, err
}

// ResolveIntentTask treats the client-provided task ID only as a locator.
// Identity comes from the endpoint token; task context is non-authorizing and
// can be returned for unsupported or mismatched current effects.
func (r *AgentAuthorizationRepository) ResolveIntentTask(ctx context.Context, tenantID, endpointID, product, taskID, principalID string, facets []agentintent.AuthorizationFacet, sources []agentintent.IntentTaskSourceClaim) (*AgentIntentTask, error) {
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	task, err := resolveIntentTaskWithQuerier(ctx, tx, tenantID, endpointID, product, taskID, principalID, facets, sources)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return task, nil
}

func resolveIntentTaskWithQuerier(ctx context.Context, querier t13AuthorizationQuerier, tenantID, endpointID, product, taskID, principalID string, facets []agentintent.AuthorizationFacet, sources []agentintent.IntentTaskSourceClaim) (*AgentIntentTask, error) {
	tenantID, endpointID = strings.TrimSpace(tenantID), strings.TrimSpace(endpointID)
	if !validIntentTaskLocator(taskID) || tenantID == "" || endpointID == "" ||
		(product != "claude-code" && product != "openclaw" && product != "opencode") {
		return nil, ErrAgentIntentTaskUnresolved
	}
	var task AgentIntentTask
	var sourceRaw []byte
	err := querier.QueryRow(ctx, `SELECT id::text,tenant_id,endpoint_id,product,principal_id::text,state,purpose,
		purpose_sha256,source_scope::text,source_scope_sha256,scope_sha256,approved_by,approved_at,expires_at
		FROM agent_intent_tasks WHERE tenant_id=$1 AND endpoint_id=$2 AND product=$3 AND id=$4
		AND state='approved' AND expires_at>clock_timestamp() FOR SHARE`,
		tenantID, endpointID, product, taskID).Scan(
		&task.ID, &task.TenantID, &task.EndpointID, &task.Product, &task.PrincipalID, &task.State, &task.Purpose,
		&task.PurposeSHA256, &sourceRaw, &task.SourceScopeSHA256, &task.ScopeSHA256, &task.ApprovedBy, &task.ApprovedAt, &task.ExpiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrAgentIntentTaskUnresolved
	}
	if err != nil {
		return nil, err
	}
	if principalID != "" && principalID != task.PrincipalID {
		return nil, ErrAgentIntentTaskUnresolved
	}
	if json.Unmarshal(sourceRaw, &task.SourceScope) != nil || intentTaskHash([]byte(task.Purpose)) != task.PurposeSHA256 ||
		intentTaskHash(canonicalIntentTaskSourceScope(task.SourceScope)) != task.SourceScopeSHA256 {
		return nil, ErrAgentIntentTaskUnresolved
	}
	var principalStatus string
	var principalRevoked, principalActive bool
	if err := querier.QueryRow(ctx, `SELECT status,revoked_at IS NOT NULL,expires_at>clock_timestamp()
		FROM agent_authorization_principals WHERE tenant_id=$1 AND id=$2 FOR SHARE`,
		tenantID, task.PrincipalID).Scan(&principalStatus, &principalRevoked, &principalActive); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrAgentIntentTaskUnresolved
		}
		return nil, err
	}
	if principalStatus != "active" || principalRevoked || !principalActive {
		return nil, ErrAgentIntentTaskUnresolved
	}
	activeScopes, err := recheckIntentTaskGrantSnapshots(ctx, querier, tenantID, task.PrincipalID, task.ID)
	if err != nil {
		return nil, err
	}
	if len(activeScopes) == 0 {
		return nil, ErrAgentIntentTaskUnresolved
	}
	sortTaskGrantScopes(activeScopes)
	scopeBytes, err := intentTaskScopeSnapshotBytes(task.EndpointID, task.Product, task.PrincipalID, task.PurposeSHA256, task.SourceScope, activeScopes)
	if err != nil || intentTaskHash(scopeBytes) != task.ScopeSHA256 {
		return nil, ErrAgentIntentTaskUnresolved
	}
	task.Grants = activeScopes
	task.FacetScopeState = intentTaskFacetScopeState(facets, activeScopes)
	task.History, task.HistoryTruncated, err = loadIntentTaskHistoryWithQuerier(ctx, querier, tenantID, task.ID)
	if err != nil {
		return nil, err
	}
	task.SourceLinks, err = resolveIntentTaskSourcesWithQuerier(ctx, querier, tenantID, endpointID, task.ID, task.SourceScope, sources)
	if err != nil {
		return nil, err
	}
	return &task, nil
}

func recheckIntentTaskGrantSnapshots(ctx context.Context, querier t13AuthorizationQuerier, tenantID, principalID, taskID string) ([]AgentIntentTaskGrant, error) {
	rows, err := querier.Query(ctx, `SELECT grant_id::text,action,resource_type,resource_ref_hash,grant_expires_at
		FROM agent_intent_task_grants WHERE tenant_id=$1 AND task_id=$2 ORDER BY action,resource_type,resource_ref_hash FOR SHARE`,
		tenantID, taskID)
	if err != nil {
		return nil, err
	}
	snapshots, err := scanIntentTaskGrantSnapshots(rows)
	if err != nil {
		return nil, err
	}

	activeScopes := make([]AgentIntentTaskGrant, 0, len(snapshots))
	for _, snapshot := range snapshots {
		var liveID, liveAction, liveType, liveResource string
		var liveExpiry time.Time
		err := querier.QueryRow(ctx, `SELECT id::text,action,resource_type,resource_id,expires_at
			FROM agent_authorization_grants WHERE tenant_id=$1 AND principal_id=$2 AND id=$3
			AND expires_at>clock_timestamp() FOR SHARE`, tenantID, principalID, snapshot.GrantID).
			Scan(&liveID, &liveAction, &liveType, &liveResource, &liveExpiry)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return nil, ErrAgentIntentTaskUnresolved
			}
			return nil, err
		}
		if liveID != snapshot.GrantID || liveAction != snapshot.Action ||
			liveType != snapshot.ResourceType || agentintent.DigestString(liveResource) != snapshot.ResourceRefHash ||
			!liveExpiry.Equal(snapshot.ExpiresAt) {
			return nil, ErrAgentIntentTaskUnresolved
		}
		activeScopes = append(activeScopes, snapshot)
	}
	return activeScopes, nil
}

func scanIntentTaskGrantSnapshots(rows pgx.Rows) ([]AgentIntentTaskGrant, error) {
	snapshots := make([]AgentIntentTaskGrant, 0)
	for rows.Next() {
		var snapshot AgentIntentTaskGrant
		if err := rows.Scan(&snapshot.GrantID, &snapshot.Action, &snapshot.ResourceType, &snapshot.ResourceRefHash, &snapshot.ExpiresAt); err != nil {
			rows.Close()
			return nil, err
		}
		snapshots = append(snapshots, snapshot)
	}
	rowsErr := rows.Err()
	rows.Close()
	if rowsErr != nil {
		return nil, rowsErr
	}
	return snapshots, nil
}

func intentTaskFacetScopeState(facets []agentintent.AuthorizationFacet, scopes []AgentIntentTaskGrant) string {
	if len(facets) == 0 {
		return "unverifiable"
	}
	for _, facet := range facets {
		matches := 0
		for _, grant := range scopes {
			if grant.Action == facet.Action && grant.ResourceType == facet.ResourceType && grant.ResourceRefHash == agentintent.DigestString(facet.ResourceID) {
				matches++
			}
		}
		if matches != 1 {
			return "mismatch"
		}
	}
	return "matched"
}

func (r *AgentAuthorizationRepository) loadIntentTaskHistory(ctx context.Context, tenantID, taskID string) ([]agentintent.IntentTaskHistoryStep, bool, error) {
	rows, err := r.db.Query(ctx, `SELECT s.server_sequence,s.tool_name,s.action,s.resource_type,s.resource_ref_hash,
		s.arguments_hash,s.authorization_state,s.terminal_outcome,COALESCE(s.result_hash,''),
		COALESCE(s.source_refs,'[]'::jsonb)::text,s.terminal_event_id IS NOT NULL AND event.id IS NOT NULL
		FROM agent_intent_task_steps s
		LEFT JOIN agent_events event ON event.tenant_id=s.tenant_id AND event.id=s.terminal_event_id
		 AND event.endpoint_id=s.endpoint_id AND event.tool_call_log_id=s.tool_call_log_id
		WHERE s.tenant_id=$1 AND s.task_id=$2 ORDER BY s.server_sequence DESC LIMIT 33`, tenantID, taskID)
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
		if sequence > int64(^uint(0)>>1) {
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

func (r *AgentAuthorizationRepository) resolveIntentTaskSources(ctx context.Context, tenantID, endpointID, taskID string, scope AgentIntentTaskSourceScope, sources []agentintent.IntentTaskSourceClaim) ([]agentintent.IntentTaskSourceLink, error) {
	return resolveIntentTaskSourcesWithQuerier(ctx, r.db, tenantID, endpointID, taskID, scope, sources)
}

func resolveIntentTaskSourcesWithQuerier(ctx context.Context, querier t13AuthorizationQuerier, tenantID, endpointID, taskID string, scope AgentIntentTaskSourceScope, sources []agentintent.IntentTaskSourceClaim) ([]agentintent.IntentTaskSourceLink, error) {
	if len(sources) > 32 {
		return nil, ErrAgentIntentTaskUnresolved
	}
	allowedKinds := make(map[string]bool, len(scope.AllowedKinds))
	for _, kind := range scope.AllowedKinds {
		allowedKinds[kind] = true
	}
	allowedHashes := make(map[string]bool, len(scope.AllowedHashes))
	for _, hash := range scope.AllowedHashes {
		allowedHashes[strings.TrimPrefix(strings.ToLower(hash), "sha256:")] = true
	}
	links := make([]agentintent.IntentTaskSourceLink, 0, len(sources))
	for index, source := range sources {
		hash, ok := normalizedIntentSourceHash(source.Hash)
		link := agentintent.IntentTaskSourceLink{Index: index, Kind: source.Kind, SourceHash: "sha256:" + hash, LineageState: "endpoint_claimed"}
		link.ContentAssurance = agentintent.IntentSourceContentAssurance(source.Hash, source.PreviewHash, scope.AllowedHashes, "")
		if !ok || !allowedKinds[source.Kind] || (len(allowedHashes) > 0 && !allowedHashes[hash]) {
			link.LineageState = "source_scope_mismatch"
			links = append(links, link)
			continue
		}
		if source.Kind == "tool_result" {
			if source.ToolUseID == "" {
				link.LineageState = "accepted_result_unlinked"
				links = append(links, link)
				continue
			}
			rows, err := querier.Query(ctx, `SELECT s.server_sequence,s.terminal_event_id
				FROM agent_intent_task_steps s JOIN agent_events event ON event.tenant_id=s.tenant_id
				 AND event.id=s.terminal_event_id AND event.endpoint_id=s.endpoint_id AND event.tool_call_log_id=s.tool_call_log_id
				WHERE s.tenant_id=$1 AND s.task_id=$2 AND s.endpoint_id=$3
				 AND s.tool_use_ref_hash=$4 AND s.result_hash=$5 AND s.terminal_event_id IS NOT NULL
				 AND s.terminal_outcome IN ('succeeded','failed') AND event.event_type IN ('tool.post','tool.failure')`,
				tenantID, taskID, endpointID, agentintent.DigestString(source.ToolUseID), hash)
			if err != nil {
				return nil, err
			}
			var matches []struct {
				seq     int
				eventID string
			}
			for rows.Next() {
				var item struct {
					seq     int
					eventID string
				}
				if err := rows.Scan(&item.seq, &item.eventID); err != nil {
					rows.Close()
					return nil, err
				}
				matches = append(matches, item)
			}
			if err := rows.Err(); err != nil {
				rows.Close()
				return nil, err
			}
			rows.Close()
			if len(matches) == 1 {
				link.LinkedStepSequence = matches[0].seq
				link.AcceptedEventRefHash = agentintent.DigestString(matches[0].eventID)
				link.LineageState = "accepted_result_hash_match"
				link.ContentAssurance = agentintent.IntentSourceContentAssurance(source.Hash, source.PreviewHash, scope.AllowedHashes, hash)
			} else {
				link.LineageState = "accepted_result_missing_or_ambiguous"
			}
		}
		links = append(links, link)
	}
	return links, nil
}

func normalizedIntentSourceHash(value string) (string, bool) {
	value = strings.ToLower(strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(value), "sha256:")))
	if len(value) != 64 {
		return "", false
	}
	if _, err := hex.DecodeString(value); err != nil {
		return "", false
	}
	return value, true
}

// DeleteExpiredIntentTasks removes source/purpose snapshots 30 days after task
// expiry/revocation/completion. Task step FKs cascade; log/event records do not.
func (r *AgentAuthorizationRepository) DeleteExpiredIntentTasks(ctx context.Context) (int64, error) {
	tag, err := r.db.Exec(ctx, `DELETE FROM agent_intent_tasks WHERE
		(CASE WHEN state='revoked' THEN revoked_at WHEN state='completed' THEN completed_at ELSE expires_at END)
		< clock_timestamp()-$1::interval`, fmt.Sprintf("%d seconds", int64(AgentIntentTaskRetention.Seconds())))
	return tag.RowsAffected(), err
}

func normalizeApprovedIntentPurpose(value string) string {
	value = strings.ReplaceAll(strings.TrimSpace(value), "\r\n", "\n")
	if !utf8.ValidString(value) {
		return ""
	}
	for _, r := range value {
		if unicode.IsControl(r) && r != '\n' && r != '\t' {
			return ""
		}
	}
	return value
}
func validIntentTaskUUID(value string) bool {
	parsed, err := uuid.Parse(strings.TrimSpace(value))
	return err == nil && strings.EqualFold(strings.TrimSpace(value), parsed.String())
}
func validIntentTaskLocator(value string) bool {
	parsed, err := uuid.Parse(strings.TrimSpace(value))
	return err == nil && parsed.Version() == 4 && parsed.Variant() == uuid.RFC4122 && value == parsed.String()
}
func normalizeIntentTaskSourceScope(kinds, hashes []string) (AgentIntentTaskSourceScope, error) {
	allowed := map[string]bool{"user_prompt": true, "tool_result": true, "instruction_file": true, "mcp_description": true, "web": true}
	seen := map[string]bool{}
	scope := AgentIntentTaskSourceScope{}
	for _, kind := range kinds {
		kind = strings.TrimSpace(kind)
		if !allowed[kind] || seen[kind] {
			return scope, ErrAgentIntentTaskInvalid
		}
		seen[kind] = true
		scope.AllowedKinds = append(scope.AllowedKinds, kind)
	}
	seen = map[string]bool{}
	for _, hash := range hashes {
		hash = strings.ToLower(strings.TrimSpace(hash))
		if !intentTaskSHA256Pattern.MatchString(hash) {
			return scope, ErrAgentIntentTaskInvalid
		}
		if !strings.HasPrefix(hash, "sha256:") {
			hash = "sha256:" + hash
		}
		if seen[hash] {
			return scope, ErrAgentIntentTaskInvalid
		}
		seen[hash] = true
		scope.AllowedHashes = append(scope.AllowedHashes, hash)
	}
	sort.Strings(scope.AllowedKinds)
	sort.Strings(scope.AllowedHashes)
	return scope, nil
}
func canonicalIntentTaskSourceScope(scope AgentIntentTaskSourceScope) []byte {
	raw, _ := json.Marshal(scope)
	return raw
}
func intentTaskScopeSnapshotBytes(endpointID, product, principalID, purposeHash string, sourceScope AgentIntentTaskSourceScope, grants []AgentIntentTaskGrant) ([]byte, error) {
	sortTaskGrantScopes(grants)
	return json.Marshal(struct {
		EndpointID    string                     `json:"endpoint_id"`
		Product       string                     `json:"product"`
		PrincipalID   string                     `json:"principal_id"`
		PurposeSHA256 string                     `json:"purpose_sha256"`
		SourceScope   AgentIntentTaskSourceScope `json:"source_scope"`
		Grants        []AgentIntentTaskGrant     `json:"grants"`
	}{endpointID, product, principalID, purposeHash, sourceScope, grants})
}
func sortTaskGrantScopes(grants []AgentIntentTaskGrant) {
	sort.Slice(grants, func(i, j int) bool {
		if grants[i].Action != grants[j].Action {
			return grants[i].Action < grants[j].Action
		}
		if grants[i].ResourceType != grants[j].ResourceType {
			return grants[i].ResourceType < grants[j].ResourceType
		}
		return grants[i].ResourceRefHash < grants[j].ResourceRefHash
	})
}
func intentTaskHash(raw []byte) string { sum := sha256.Sum256(raw); return hex.EncodeToString(sum[:]) }
