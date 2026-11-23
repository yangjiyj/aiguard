package repository

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

const (
	AgentAuthorizationApprovalTTLSeconds     = 120
	AgentAuthorizationApprovalMaxTTLSeconds  = 300
	AgentAuthorizationExceptionMaxTTLSeconds = 300
)

var (
	ErrAgentAuthorizationApprovalInvalid        = errors.New("invalid agent authorization approval")
	ErrAgentAuthorizationApprovalConflict       = errors.New("agent authorization approval idempotency conflict")
	ErrAgentAuthorizationApprovalExpired        = errors.New("agent authorization approval expired")
	ErrAgentAuthorizationApprovalStateConflict  = errors.New("agent authorization approval state conflict")
	ErrAgentAuthorizationApprovalSelfResolution = errors.New("agent authorization approval self resolution forbidden")
	// ErrAgentAuthorizationApprovalHolderUnknown: the principal's creator or a credential
	// rotator cannot be established, so requester != approver cannot be proven (fail closed).
	ErrAgentAuthorizationApprovalHolderUnknown = errors.New("agent authorization principal credential holder unknown")
)

type AgentAuthorizationApprovalInput struct {
	Action                      string
	ResourceType                string
	ResourceID                  string
	ArgumentsSHA256             string
	AuthorizationIdempotencyKey string
	ApprovalIdempotencyKey      string
}

type AgentAuthorizationApprovalClaimInput struct {
	Action                      string
	ResourceType                string
	ResourceID                  string
	ArgumentsSHA256             string
	AuthorizationIdempotencyKey string
	ClaimIdempotencyKey         string
}

type AgentAuthorizationApproval struct {
	ID              string     `json:"approval_id"`
	PrincipalID     string     `json:"principal_id,omitempty"`
	GrantID         string     `json:"grant_id,omitempty"`
	Action          string     `json:"action,omitempty"`
	ResourceType    string     `json:"resource_type,omitempty"`
	ResourceID      string     `json:"resource_id,omitempty"`
	ArgumentsSHA256 string     `json:"arguments_sha256,omitempty"`
	Status          string     `json:"status"`
	ExpiresAt       time.Time  `json:"expires_at"`
	ExceptionID     string     `json:"exception_id,omitempty"`
	Claimed         bool       `json:"claimed,omitempty"`
	ClaimID         string     `json:"claim_id,omitempty"`
	ClaimedAt       *time.Time `json:"claimed_at,omitempty"`
	Reason          string     `json:"reason"`
	ResolvedBy      string     `json:"resolved_by,omitempty"`
	ResolvedAt      *time.Time `json:"resolved_at,omitempty"`
	ResolutionNote  string     `json:"resolution_note,omitempty"`
	CreatedAt       time.Time  `json:"created_at,omitempty"`
}

type AgentAuthorizationApprovalClaim struct {
	ApprovalID string `json:"approval_id"`
	Status     string `json:"status"`
	Allowed    bool   `json:"allowed"`
	Reason     string `json:"reason"`
	ClaimID    string `json:"claim_id,omitempty"`
}

type AgentAuthorizationApprovalExceptionInput struct {
	PrincipalID     string
	GrantID         string
	Action          string
	ResourceType    string
	ResourceID      string
	ArgumentsSHA256 string
	Reason          string
	TTLSeconds      int
	IdempotencyKey  string
}

type AgentAuthorizationApprovalException struct {
	ID              string     `json:"exception_id"`
	PrincipalID     string     `json:"principal_id"`
	GrantID         string     `json:"grant_id"`
	Action          string     `json:"action"`
	ResourceType    string     `json:"resource_type"`
	ResourceID      string     `json:"resource_id"`
	ArgumentsSHA256 string     `json:"arguments_sha256"`
	Reason          string     `json:"reason"`
	CreatedBy       string     `json:"created_by"`
	CreatedAt       time.Time  `json:"created_at"`
	ExpiresAt       time.Time  `json:"expires_at"`
	RevokedBy       string     `json:"revoked_by,omitempty"`
	RevokedAt       *time.Time `json:"revoked_at,omitempty"`
	Active          bool       `json:"active"`
}

var (
	ErrAgentAuthorizationApprovalExceptionNotFound = errors.New("agent authorization approval exception not found")
)

func hashAgentAuthorizationApprovalValue(value any) (string, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}

func validLowerSHA256(value string) bool {
	if len(value) != sha256.Size*2 || strings.ToLower(value) != value {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size
}

func validT15IdempotencyKey(value, prefix string) bool {
	if !strings.HasPrefix(value, prefix) || len(value) != len(prefix)+sha256.Size*2 {
		return false
	}
	return validLowerSHA256(strings.TrimPrefix(value, prefix))
}

func ValidateAgentAuthorizationApprovalInput(input AgentAuthorizationApprovalInput) error {
	if err := ValidateAgentAuthorizationRequest(AgentAuthorizationRequest{
		Action: input.Action, ResourceType: input.ResourceType, ResourceID: input.ResourceID,
		IdempotencyKey: input.AuthorizationIdempotencyKey,
	}); err != nil {
		return fmt.Errorf("%w: invalid T13 binding", ErrAgentAuthorizationApprovalInvalid)
	}
	if !validLowerSHA256(input.ArgumentsSHA256) ||
		!validT15IdempotencyKey(input.ApprovalIdempotencyKey, "t15:req:") {
		return fmt.Errorf("%w: invalid digest or request key", ErrAgentAuthorizationApprovalInvalid)
	}
	return nil
}

func ValidateAgentAuthorizationApprovalClaimInput(input AgentAuthorizationApprovalClaimInput) error {
	if err := ValidateAgentAuthorizationRequest(AgentAuthorizationRequest{
		Action: input.Action, ResourceType: input.ResourceType, ResourceID: input.ResourceID,
		IdempotencyKey: input.AuthorizationIdempotencyKey,
	}); err != nil {
		return fmt.Errorf("%w: invalid T13 binding", ErrAgentAuthorizationApprovalInvalid)
	}
	if !validLowerSHA256(input.ArgumentsSHA256) ||
		!validT15IdempotencyKey(input.ClaimIdempotencyKey, "t15:claim:") {
		return fmt.Errorf("%w: invalid digest or claim key", ErrAgentAuthorizationApprovalInvalid)
	}
	return nil
}

func ValidateAgentAuthorizationApprovalExceptionInput(input AgentAuthorizationApprovalExceptionInput) error {
	if input.PrincipalID == "" || input.GrantID == "" ||
		!validAgentAuthorizationLabel(input.Action) ||
		!validAgentAuthorizationLabel(input.ResourceType) ||
		!validAgentAuthorizationResourceID(input.ResourceID) ||
		!validLowerSHA256(input.ArgumentsSHA256) ||
		len(strings.TrimSpace(input.Reason)) == 0 || len(input.Reason) > 512 ||
		input.TTLSeconds < 1 || input.TTLSeconds > AgentAuthorizationExceptionMaxTTLSeconds ||
		!validT15IdempotencyKey(input.IdempotencyKey, "t15:exception:") {
		return fmt.Errorf("%w: invalid exception scope, reason, lifetime, or idempotency key", ErrAgentAuthorizationApprovalInvalid)
	}
	// Require the canonical lowercase form: uuid.Parse also accepts braces, urn:uuid:, and a
	// 38-byte value whose first and last bytes are dropped, which PostgreSQL may then reject (G1 N6).
	if parsed, err := uuid.Parse(input.PrincipalID); err != nil || parsed.String() != input.PrincipalID {
		return fmt.Errorf("%w: invalid principal id", ErrAgentAuthorizationApprovalInvalid)
	}
	if parsed, err := uuid.Parse(input.GrantID); err != nil || parsed.String() != input.GrantID {
		return fmt.Errorf("%w: invalid grant id", ErrAgentAuthorizationApprovalInvalid)
	}
	return nil
}

func agentAuthorizationApprovalRequestHash(tenantID, principalID, grantID string, input AgentAuthorizationApprovalInput) (string, error) {
	return hashAgentAuthorizationApprovalValue(struct {
		TenantID        string `json:"tenant_id"`
		PrincipalID     string `json:"principal_id"`
		GrantID         string `json:"grant_id"`
		Action          string `json:"action"`
		ResourceType    string `json:"resource_type"`
		ResourceID      string `json:"resource_id"`
		ArgumentsSHA256 string `json:"arguments_sha256"`
		T13KeySHA256    string `json:"t13_key_sha256"`
	}{tenantID, principalID, grantID, input.Action, input.ResourceType, input.ResourceID,
		input.ArgumentsSHA256, HashAgentToken(input.AuthorizationIdempotencyKey)})
}

type agentAuthorizationApprovalScanner interface{ Scan(...any) error }

func scanAgentAuthorizationApproval(row agentAuthorizationApprovalScanner) (*AgentAuthorizationApproval, error) {
	var value AgentAuthorizationApproval
	var claimed, resolved bool
	var claimedAt, resolvedAt time.Time
	err := row.Scan(&value.ID, &value.PrincipalID, &value.GrantID, &value.Action,
		&value.ResourceType, &value.ResourceID, &value.ArgumentsSHA256, &value.Status,
		&value.ExpiresAt, &value.ExceptionID, &claimed, &value.ClaimID, &claimedAt,
		&value.ResolvedBy, &value.Reason, &resolved, &resolvedAt, &value.ResolutionNote, &value.CreatedAt)
	if err != nil {
		return nil, err
	}
	value.Claimed = claimed
	if claimed {
		value.ClaimedAt = &claimedAt
	}
	if resolved {
		value.ResolvedAt = &resolvedAt
	}
	return &value, nil
}

const agentAuthorizationApprovalSelect = `
	SELECT id, agent_authorization_principal_id::text, agent_authorization_grant_id::text,
	       agent_authorization_action, agent_authorization_resource_type,
	       agent_authorization_resource_id, agent_authorization_arguments_sha256,
	       CASE WHEN status IN ('pending','approved') AND expires_at<=clock_timestamp() THEN 'expired' ELSE status END,
	       expires_at, COALESCE(agent_authorization_exception_id::text, ''),
	       agent_authorization_claimed_at IS NOT NULL, COALESCE(agent_authorization_claim_id, ''),
	       COALESCE(agent_authorization_claimed_at, 'epoch'::timestamptz), COALESCE(resolved_by,''),
	       COALESCE(reason,''), resolved_at IS NOT NULL,
	       COALESCE(resolved_at, 'epoch'::timestamptz), COALESCE(resolution_note,''), created_at
	FROM agentguard_confirmations
`

func lockAgentAuthorizationApprovalPrincipalAndGrant(ctx context.Context, tx pgx.Tx, principal TrustedAgentPrincipal,
	grantID, action, resourceType, resourceID string) (time.Time, time.Time, time.Time, error) {
	// Same lock order as Authorize: tree advisory lock, principal row, chain.
	if err := lockAgentDelegationHierarchy(ctx, tx, principal.TenantID, principal.ID); err != nil {
		return time.Time{}, time.Time{}, time.Time{}, err
	}
	var storedCredentialHash string
	var principalExpiresAt time.Time
	err := tx.QueryRow(ctx, `
		SELECT credential_hash, expires_at FROM agent_authorization_principals
		WHERE id=$1 AND tenant_id=$2 AND status='active' AND revoked_at IS NULL FOR UPDATE
	`, principal.ID, principal.TenantID).Scan(&storedCredentialHash, &principalExpiresAt)
	if errors.Is(err, pgx.ErrNoRows) ||
		(err == nil && subtle.ConstantTimeCompare([]byte(storedCredentialHash), []byte(principal.CredentialHash)) != 1) {
		return time.Time{}, time.Time{}, time.Time{}, ErrAgentAuthorizationPrincipalUnauthorized
	}
	if err != nil {
		return time.Time{}, time.Time{}, time.Time{}, err
	}
	var now time.Time
	if err := tx.QueryRow(ctx, "SELECT clock_timestamp()").Scan(&now); err != nil {
		return time.Time{}, time.Time{}, time.Time{}, err
	}
	if !principalExpiresAt.After(now) {
		return time.Time{}, time.Time{}, time.Time{}, ErrAgentAuthorizationPrincipalUnauthorized
	}

	var grantAction, grantType, grantResource, grantConditionsRaw string
	var grantExpires time.Time
	err = tx.QueryRow(ctx, `
		SELECT action, resource_type, resource_id, conditions_json::text, expires_at
		FROM agent_authorization_grants
		WHERE id=$1 AND tenant_id=$2 AND principal_id=$3 FOR UPDATE
	`, grantID, principal.TenantID, principal.ID).Scan(&grantAction, &grantType, &grantResource, &grantConditionsRaw, &grantExpires)
	if errors.Is(err, pgx.ErrNoRows) {
		return time.Time{}, time.Time{}, time.Time{}, ErrAgentAuthorizationGrantExpired
	}
	if err != nil {
		return time.Time{}, time.Time{}, time.Time{}, err
	}
	if grantAction != action || grantType != resourceType || grantResource != resourceID {
		return time.Time{}, time.Time{}, time.Time{}, ErrAgentAuthorizationApprovalInvalid
	}
	if !grantExpires.After(now) {
		return time.Time{}, time.Time{}, time.Time{}, ErrAgentAuthorizationGrantExpired
	}
	if err := recheckAgentAuthorizationApprovalAncestry(ctx, tx, principal.TenantID, principal.ID, grantID,
		action, resourceType, resourceID, grantConditionsRaw, now); err != nil {
		return time.Time{}, time.Time{}, time.Time{}, err
	}
	return principalExpiresAt, grantExpires, now, nil
}

// recheckAgentAuthorizationApprovalAncestry re-validates a delegated principal's
// whole ancestry (edges, parent principals and the mapped parent grants) inside
// the approval transaction, so a T15 request or claim cannot outlive an ancestor
// revocation or grant expiry. A child grant's conditions are a superset of every
// ancestor's conditions (enforced at delegation time), so they are the request
// context the ancestor conditions are matched against.
func recheckAgentAuthorizationApprovalAncestry(ctx context.Context, tx pgx.Tx, tenantID, principalID, grantID,
	action, resourceType, resourceID, grantConditionsRaw string, now time.Time) error {
	chain, err := lockAgentDelegationChain(ctx, tx, tenantID, principalID, now)
	if err != nil {
		return err
	}
	if len(chain) == 0 {
		return nil
	}
	for _, edge := range chain {
		if edge.ProjectID != chain[0].ProjectID {
			return ErrAgentAuthorizationPrincipalUnauthorized
		}
	}
	var conditions map[string]any
	if err := json.Unmarshal([]byte(grantConditionsRaw), &conditions); err != nil {
		return err
	}
	if conditions["project_id"] != chain[0].ProjectID {
		return ErrAgentAuthorizationPrincipalUnauthorized
	}
	_, err = ancestorGrantLimits(ctx, tx, tenantID, chain, grantID, action, resourceType, resourceID, conditions, now)
	if errors.Is(err, ErrAgentAuthorizationInvalid) {
		return ErrAgentAuthorizationPrincipalUnauthorized
	}
	return err
}

func (r *AgentAuthorizationRepository) CreateAgentAuthorizationApproval(ctx context.Context,
	principal TrustedAgentPrincipal, grantID string, input AgentAuthorizationApprovalInput) (*AgentAuthorizationApproval, bool, error) {
	if err := ValidateAgentAuthorizationApprovalInput(input); err != nil {
		return nil, false, err
	}
	requestHash, err := agentAuthorizationApprovalRequestHash(principal.TenantID, principal.ID, grantID, input)
	if err != nil {
		return nil, false, err
	}
	approvalKeyHash := HashAgentToken(input.ApprovalIdempotencyKey)
	t13KeyHash := HashAgentToken(input.AuthorizationIdempotencyKey)
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return nil, false, err
	}
	defer tx.Rollback(ctx)

	principalExpires, grantExpires, now, err := lockAgentAuthorizationApprovalPrincipalAndGrant(
		ctx, tx, principal, grantID, input.Action, input.ResourceType, input.ResourceID)
	if err != nil {
		return nil, false, err
	}

	exceptionID, exceptionExpires, hasException, err := agentAuthorizationSelectAutoApprovalException(ctx, tx, principal, grantID, input)
	if err != nil {
		return nil, false, err
	}
	status := "pending"
	if hasException {
		status = "approved"
	}

	newID := "agap_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	evidence, _ := json.Marshal(map[string]string{
		"principal_id": principal.ID, "grant_id": grantID, "action": input.Action,
		"resource_type": input.ResourceType, "resource_id": input.ResourceID,
		"arguments_sha256": input.ArgumentsSHA256,
	})
	var exceptionArg any
	var expiryExpression string
	args := []any{newID, principal.TenantID, principal.ID, grantID, input.Action, input.ResourceType,
		input.ResourceID, input.ArgumentsSHA256, t13KeyHash, approvalKeyHash, requestHash, status, evidence, exceptionArg}
	if hasException {
		args[13] = exceptionID
		expiryExpression = "LEAST(clock_timestamp()+interval '120 seconds',$15,$16,$17)"
		args = append(args, principalExpires, grantExpires, exceptionExpires)
	} else {
		expiryExpression = "LEAST(clock_timestamp()+interval '120 seconds',$15,$16)"
		args = append(args, principalExpires, grantExpires)
	}
	insertSQL := fmt.Sprintf(`
		INSERT INTO agentguard_confirmations (
			id, tenant_id, request_id, trace_id, tool_name, raw_decision, effective_decision,
			status, timeout_action, reason, evidence_json, expires_at, created_at,
			tool_call_id, tool_call_arguments, choice_index, source,
			agent_authorization_principal_id, agent_authorization_grant_id,
			agent_authorization_action, agent_authorization_resource_type, agent_authorization_resource_id,
			agent_authorization_arguments_sha256, agent_authorization_key_sha256,
			agent_authorization_approval_key_sha256, agent_authorization_request_sha256,
			agent_authorization_exception_id
		) VALUES ($1,$2,NULL,$11::text,$5,'confirm','confirm',$12,'block',
			'Agent authorization approval requested',$13,%s,clock_timestamp(),
			NULL,'',0,'agent_authorization',$3,$4,$5,$6,$7,$8,$9,$10,$11::text,$14)
		ON CONFLICT DO NOTHING
	`, expiryExpression)
	tag, err := tx.Exec(ctx, insertSQL, args...)
	if err != nil {
		return nil, false, err
	}
	created := tag.RowsAffected() == 1
	approval, err := scanAgentAuthorizationApproval(tx.QueryRow(ctx, agentAuthorizationApprovalSelect+`
		WHERE tenant_id=$1 AND agent_authorization_principal_id=$2
		  AND agent_authorization_approval_key_sha256=$3 AND source='agent_authorization' FOR UPDATE
	`, principal.TenantID, principal.ID, approvalKeyHash))
	if err != nil {
		return nil, false, err
	}
	var storedRequestHash string
	if err := tx.QueryRow(ctx, `SELECT agent_authorization_request_sha256 FROM agentguard_confirmations WHERE tenant_id=$1 AND id=$2`,
		principal.TenantID, approval.ID).Scan(&storedRequestHash); err != nil {
		return nil, false, err
	}
	if storedRequestHash != requestHash {
		return nil, false, ErrAgentAuthorizationApprovalConflict
	}
	if !approval.ExpiresAt.After(now) || approval.Status == "expired" {
		_, err := tx.Exec(ctx, `
			UPDATE agentguard_confirmations
			SET status='expired', resolved_at=COALESCE(resolved_at,clock_timestamp())
			WHERE tenant_id=$1 AND id=$2 AND source='agent_authorization'
			  AND status IN ('pending','approved') AND expires_at<=clock_timestamp()
		`, principal.TenantID, approval.ID)
		if err != nil {
			return nil, false, err
		}
		approval.Status = "expired"
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, false, err
	}
	return approval, created, nil
}

// agentAuthorizationSelectAutoApprovalException picks the exact active exception to auto-approve
// with, skipping any created by a current credential holder (G1 N1 defence in depth: a holder's
// exception is a self-approval). If holders cannot be established nothing is auto-approved.
func agentAuthorizationSelectAutoApprovalException(ctx context.Context, tx pgx.Tx, principal TrustedAgentPrincipal,
	grantID string, input AgentAuthorizationApprovalInput) (string, time.Time, bool, error) {
	rows, err := tx.Query(ctx, `
		SELECT id::text, expires_at, created_by FROM agent_authorization_approval_exceptions
		WHERE tenant_id=$1 AND principal_id=$2 AND grant_id=$3 AND action=$4
		  AND resource_type=$5 AND resource_id=$6 AND arguments_sha256=$7
		  AND revoked_at IS NULL AND expires_at>clock_timestamp()
		ORDER BY expires_at ASC, created_at ASC FOR UPDATE
	`, principal.TenantID, principal.ID, grantID, input.Action, input.ResourceType,
		input.ResourceID, input.ArgumentsSHA256)
	if err != nil {
		return "", time.Time{}, false, err
	}
	type candidate struct {
		id, createdBy string
		expires       time.Time
	}
	candidates, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (candidate, error) {
		var c candidate
		return c, row.Scan(&c.id, &c.expires, &c.createdBy)
	})
	if err != nil || len(candidates) == 0 {
		return "", time.Time{}, false, err
	}
	holders, err := agentAuthorizationPrincipalHolders(ctx, tx, principal.TenantID, principal.ID)
	if errors.Is(err, ErrAgentAuthorizationApprovalHolderUnknown) {
		log.Printf("agent authorization approval: principal %s exception not applied: reason=credential_holder_unknown", principal.ID)
		return "", time.Time{}, false, nil
	}
	if err != nil {
		return "", time.Time{}, false, err
	}
	for _, c := range candidates {
		if holders[c.createdBy] {
			log.Printf("agent authorization approval: principal %s exception %s skipped: reason=exception_creator_is_holder", principal.ID, c.id)
			continue
		}
		return c.id, c.expires, true, nil
	}
	return "", time.Time{}, false, nil
}

// agentAuthorizationRejectHolderAuthorizedClaim re-checks separation of duties at claim time
// (G1 N1/N2 defence in depth): whoever authorized the approval - the resolver, or the creator
// of the exception it was auto-approved by - must not be a current credential holder. Runs
// after the principal and approval rows are locked, so it also covers a racing rotation.
func agentAuthorizationRejectHolderAuthorizedClaim(ctx context.Context, tx pgx.Tx, principal TrustedAgentPrincipal,
	approval *AgentAuthorizationApproval) error {
	if approval.Status != "approved" {
		return nil
	}
	holders, err := agentAuthorizationPrincipalHolders(ctx, tx, principal.TenantID, principal.ID)
	if err != nil {
		return err
	}
	if approval.ResolvedBy != "" && holders[approval.ResolvedBy] {
		return ErrAgentAuthorizationApprovalSelfResolution
	}
	if approval.ExceptionID != "" {
		var exceptionCreator string
		err := tx.QueryRow(ctx, `SELECT created_by FROM agent_authorization_approval_exceptions WHERE tenant_id=$1 AND principal_id=$2 AND id=$3`,
			principal.TenantID, principal.ID, approval.ExceptionID).Scan(&exceptionCreator)
		if err != nil {
			return err
		}
		if holders[exceptionCreator] {
			return ErrAgentAuthorizationApprovalSelfResolution
		}
	}
	return nil
}

func agentAuthorizationApprovalClaimable(approval *AgentAuthorizationApproval, now time.Time) bool {
	return approval != nil && approval.Status == "approved" && !approval.Claimed && approval.ExpiresAt.After(now)
}

func replayAgentAuthorizationClaimResult(approval *AgentAuthorizationApproval, storedClaimKeyHash, requestedClaimKeyHash string) (*AgentAuthorizationApprovalClaim, error) {
	if approval == nil || !approval.Claimed || approval.ClaimID == "" ||
		!validLowerSHA256(storedClaimKeyHash) || !validLowerSHA256(requestedClaimKeyHash) {
		return nil, ErrAgentAuthorizationApprovalStateConflict
	}
	if subtle.ConstantTimeCompare([]byte(storedClaimKeyHash), []byte(requestedClaimKeyHash)) != 1 {
		return nil, ErrAgentAuthorizationApprovalConflict
	}
	return &AgentAuthorizationApprovalClaim{
		ApprovalID: approval.ID, Status: "claimed", Allowed: false,
		Reason: "approval_already_claimed", ClaimID: approval.ClaimID,
	}, nil
}

func (r *AgentAuthorizationRepository) ClaimAgentAuthorizationApproval(ctx context.Context,
	principal TrustedAgentPrincipal, grantID, approvalID string, input AgentAuthorizationApprovalClaimInput) (*AgentAuthorizationApprovalClaim, error) {
	if err := ValidateAgentAuthorizationApprovalClaimInput(input); err != nil {
		return nil, err
	}
	if len(approvalID) < 8 || len(approvalID) > 64 || !strings.HasPrefix(approvalID, "agap_") {
		return nil, ErrAgentAuthorizationApprovalInvalid
	}
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	_, _, now, err := lockAgentAuthorizationApprovalPrincipalAndGrant(ctx, tx, principal, grantID,
		input.Action, input.ResourceType, input.ResourceID)
	if err != nil {
		return nil, err
	}

	approval, err := scanAgentAuthorizationApproval(tx.QueryRow(ctx, agentAuthorizationApprovalSelect+`
		WHERE tenant_id=$1 AND id=$2 AND source='agent_authorization' FOR UPDATE
	`, principal.TenantID, approvalID))
	if errors.Is(err, pgx.ErrNoRows) {
		return &AgentAuthorizationApprovalClaim{ApprovalID: approvalID, Status: "not_found", Reason: "approval_not_found"}, nil
	}
	if err != nil {
		return nil, err
	}
	var keyHash, argsHash, action, resourceType, resourceIDStored, storedGrant string
	err = tx.QueryRow(ctx, `
		SELECT agent_authorization_key_sha256, agent_authorization_arguments_sha256,
		       agent_authorization_action, agent_authorization_resource_type,
		       agent_authorization_resource_id, agent_authorization_grant_id::text
		FROM agentguard_confirmations WHERE tenant_id=$1 AND id=$2 AND source='agent_authorization'
	`, principal.TenantID, approvalID).Scan(&keyHash, &argsHash, &action, &resourceType, &resourceIDStored, &storedGrant)
	if err != nil {
		return nil, err
	}
	if storedGrant != grantID || keyHash != HashAgentToken(input.AuthorizationIdempotencyKey) ||
		argsHash != input.ArgumentsSHA256 || action != input.Action ||
		resourceType != input.ResourceType || resourceIDStored != input.ResourceID {
		return nil, ErrAgentAuthorizationApprovalConflict
	}
	claimKeyHash := HashAgentToken(input.ClaimIdempotencyKey)
	if approval.Claimed {
		var storedClaimKey string
		if err := tx.QueryRow(ctx, "SELECT agent_authorization_claim_key_sha256 FROM agentguard_confirmations WHERE tenant_id=$1 AND id=$2",
			principal.TenantID, approvalID).Scan(&storedClaimKey); err != nil {
			return nil, err
		}
		result, err := replayAgentAuthorizationClaimResult(approval, storedClaimKey, claimKeyHash)
		if err != nil {
			return nil, err
		}
		if err := tx.Commit(ctx); err != nil {
			return nil, err
		}
		return result, nil
	}
	if !approval.ExpiresAt.After(now) || approval.Status == "expired" {
		_, err = tx.Exec(ctx, `UPDATE agentguard_confirmations SET status='expired',resolved_at=COALESCE(resolved_at,clock_timestamp()) WHERE tenant_id=$1 AND id=$2 AND source='agent_authorization' AND status IN ('pending','approved') AND expires_at<=clock_timestamp()`, principal.TenantID, approvalID)
		if err != nil {
			return nil, err
		}
		if err := tx.Commit(ctx); err != nil {
			return nil, err
		}
		return &AgentAuthorizationApprovalClaim{ApprovalID: approvalID, Status: "expired", Reason: "approval_expired"}, nil
	}
	if approval.ExceptionID != "" {
		var active bool
		err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM agent_authorization_approval_exceptions WHERE id=$1 AND tenant_id=$2 AND principal_id=$3 AND grant_id=$4 AND revoked_at IS NULL AND expires_at>clock_timestamp())`,
			approval.ExceptionID, principal.TenantID, principal.ID, grantID).Scan(&active)
		if err != nil {
			return nil, err
		}
		if !active {
			_, err = tx.Exec(ctx, `UPDATE agentguard_confirmations SET status='revoked', resolved_at=clock_timestamp(), resolution_note='approval exception expired or revoked' WHERE tenant_id=$1 AND id=$2 AND source='agent_authorization' AND status='approved' AND agent_authorization_claimed_at IS NULL`,
				principal.TenantID, approvalID)
			if err != nil {
				return nil, err
			}
			if err := tx.Commit(ctx); err != nil {
				return nil, err
			}
			return &AgentAuthorizationApprovalClaim{ApprovalID: approvalID, Status: "revoked", Reason: "approval_exception_inactive"}, nil
		}
	}
	if err := agentAuthorizationRejectHolderAuthorizedClaim(ctx, tx, principal, approval); err != nil {
		return nil, err
	}
	if !agentAuthorizationApprovalClaimable(approval, now) {
		if err := tx.Commit(ctx); err != nil {
			return nil, err
		}
		return &AgentAuthorizationApprovalClaim{ApprovalID: approvalID, Status: approval.Status, Reason: "approval_not_approved"}, nil
	}
	claimID := "agcl_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	tag, err := tx.Exec(ctx, `
		UPDATE agentguard_confirmations
		SET agent_authorization_claim_key_sha256=$3, agent_authorization_claim_id=$4,
		    agent_authorization_claimed_at=clock_timestamp()
		WHERE tenant_id=$1 AND id=$2 AND source='agent_authorization'
		  AND status='approved' AND expires_at>clock_timestamp() AND agent_authorization_claimed_at IS NULL
	`, principal.TenantID, approvalID, claimKeyHash, claimID)
	if err != nil {
		return nil, err
	}
	if tag.RowsAffected() != 1 {
		return nil, ErrAgentAuthorizationApprovalStateConflict
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return &AgentAuthorizationApprovalClaim{ApprovalID: approvalID, Status: "claimed", Allowed: true, Reason: "approved_once", ClaimID: claimID}, nil
}

func (r *AgentAuthorizationRepository) ListAgentAuthorizationApprovals(ctx context.Context, tenantID, status string, limit int) ([]*AgentAuthorizationApproval, error) {
	if limit < 1 || limit > 200 {
		limit = 50
	}
	// Materialize at most one page of expired tickets on each read. Remaining rows
	// are still projected as expired by the select until a later bounded pass.
	_, err := r.db.Exec(ctx, `
		UPDATE agentguard_confirmations
		SET status='expired', resolved_at=COALESCE(resolved_at,clock_timestamp())
		WHERE tenant_id=$1 AND id IN (
			SELECT id FROM agentguard_confirmations
			WHERE tenant_id=$1 AND source='agent_authorization'
			  AND status IN ('pending','approved') AND expires_at<=clock_timestamp()
			ORDER BY expires_at, created_at LIMIT $2 FOR UPDATE SKIP LOCKED
		)
	`, tenantID, limit)
	if err != nil {
		return nil, err
	}
	query := agentAuthorizationApprovalSelect + " WHERE tenant_id=$1 AND source='agent_authorization'"
	args := []any{tenantID}
	if status == "expired" {
		query += " AND (status='expired' OR (status IN ('pending','approved') AND expires_at<=clock_timestamp()))"
	} else if status != "" {
		args = append(args, status)
		query += fmt.Sprintf(" AND status=$%d AND (status NOT IN ('pending','approved') OR expires_at>clock_timestamp())", len(args))
	}
	args = append(args, limit)
	query += fmt.Sprintf(" ORDER BY created_at DESC LIMIT $%d", len(args))
	rows, err := r.db.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var approvals []*AgentAuthorizationApproval
	for rows.Next() {
		approval, err := scanAgentAuthorizationApproval(rows)
		if err != nil {
			return nil, err
		}
		approvals = append(approvals, approval)
	}
	return approvals, rows.Err()
}

func (r *AgentAuthorizationRepository) ResolveAgentAuthorizationApproval(ctx context.Context, tenantID, id, status, actorID, note string) (*AgentAuthorizationApproval, bool, error) {
	if (status != "approved" && status != "rejected") || actorID == "" || len(note) > 512 {
		return nil, false, ErrAgentAuthorizationApprovalInvalid
	}
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return nil, false, err
	}
	defer tx.Rollback(ctx)
	var principalID, grantID string
	if err := tx.QueryRow(ctx, "SELECT agent_authorization_principal_id::text, agent_authorization_grant_id::text FROM agentguard_confirmations WHERE tenant_id=$1 AND id=$2 AND source='agent_authorization'",
		tenantID, id).Scan(&principalID, &grantID); errors.Is(err, pgx.ErrNoRows) {
		return nil, false, nil
	} else if err != nil {
		return nil, false, err
	}
	// Separation of duties (G1): the principal's creator also created every one of its
	// grants (grants are only inserted inside RegisterPrincipal), so one check covers both.
	if err := agentAuthorizationRejectSelfResolution(ctx, tx, tenantID, principalID, actorID); err != nil {
		return nil, false, err
	}
	// Match the request/claim lock order exactly: principal, then grant, then approval.
	var principalExpires, grantExpires time.Time
	lockErr := tx.QueryRow(ctx, `
		SELECT expires_at FROM agent_authorization_principals
		WHERE tenant_id=$1 AND id=$2 AND status='active' AND revoked_at IS NULL FOR UPDATE
	`, tenantID, principalID).Scan(&principalExpires)
	if lockErr == nil {
		lockErr = tx.QueryRow(ctx, `
			SELECT expires_at FROM agent_authorization_grants
			WHERE tenant_id=$1 AND principal_id=$2 AND id=$3 FOR UPDATE
		`, tenantID, principalID, grantID).Scan(&grantExpires)
	}
	if lockErr != nil && !errors.Is(lockErr, pgx.ErrNoRows) {
		return nil, false, lockErr
	}
	var now time.Time
	if err := tx.QueryRow(ctx, "SELECT clock_timestamp()").Scan(&now); err != nil {
		return nil, false, err
	}
	approval, err := scanAgentAuthorizationApproval(tx.QueryRow(ctx, agentAuthorizationApprovalSelect+" WHERE tenant_id=$1 AND id=$2 AND source='agent_authorization' FOR UPDATE", tenantID, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	if approval.Claimed {
		return approval, false, ErrAgentAuthorizationApprovalStateConflict
	}
	if approval.Status == "expired" || !approval.ExpiresAt.After(now) {
		_, err := tx.Exec(ctx, "UPDATE agentguard_confirmations SET status='expired',resolved_at=COALESCE(resolved_at,clock_timestamp()) WHERE tenant_id=$1 AND id=$2 AND source='agent_authorization' AND status IN ('pending','approved') AND expires_at<=clock_timestamp()", tenantID, id)
		if err != nil {
			return nil, false, err
		}
		if err := tx.Commit(ctx); err != nil {
			return nil, false, err
		}
		approval.Status = "expired"
		return approval, false, ErrAgentAuthorizationApprovalExpired
	}
	if approval.Status == status {
		if err := tx.Commit(ctx); err != nil {
			return nil, false, err
		}
		return approval, false, nil
	}
	if approval.Status != "pending" {
		return approval, false, ErrAgentAuthorizationApprovalStateConflict
	}
	if status == "approved" {
		if errors.Is(lockErr, pgx.ErrNoRows) {
			return approval, false, ErrAgentAuthorizationApprovalStateConflict
		}
		if lockErr != nil {
			return nil, false, lockErr
		}
		if !principalExpires.After(now) {
			return approval, false, ErrAgentAuthorizationPrincipalUnauthorized
		}
		if !grantExpires.After(now) {
			return approval, false, ErrAgentAuthorizationGrantExpired
		}
	}
	tag, err := tx.Exec(ctx, `
		UPDATE agentguard_confirmations
		SET status=$3, resolved_by=$4, resolved_at=clock_timestamp(), resolution_note=$5
		WHERE tenant_id=$1 AND id=$2 AND source='agent_authorization'
		  AND status='pending' AND expires_at>clock_timestamp() AND agent_authorization_claimed_at IS NULL
	`, tenantID, id, status, actorID, note)
	if err != nil {
		return nil, false, err
	}
	if tag.RowsAffected() != 1 {
		return nil, false, ErrAgentAuthorizationApprovalStateConflict
	}
	approval, err = scanAgentAuthorizationApproval(tx.QueryRow(ctx, agentAuthorizationApprovalSelect+" WHERE tenant_id=$1 AND id=$2 AND source='agent_authorization'", tenantID, id))
	if err != nil {
		return nil, false, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, false, err
	}
	return approval, true, nil
}

func (r *AgentAuthorizationRepository) RevokeAgentAuthorizationApproval(ctx context.Context, tenantID, id, actorID, note string) (*AgentAuthorizationApproval, bool, error) {
	if actorID == "" || len(note) > 512 {
		return nil, false, ErrAgentAuthorizationApprovalInvalid
	}
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return nil, false, err
	}
	defer tx.Rollback(ctx)
	approval, err := scanAgentAuthorizationApproval(tx.QueryRow(ctx, agentAuthorizationApprovalSelect+" WHERE tenant_id=$1 AND id=$2 AND source='agent_authorization' FOR UPDATE", tenantID, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	if approval.Claimed {
		return approval, false, ErrAgentAuthorizationApprovalStateConflict
	}
	if approval.Status == "revoked" {
		if err := tx.Commit(ctx); err != nil {
			return nil, false, err
		}
		return approval, false, nil
	}
	var now time.Time
	if err := tx.QueryRow(ctx, "SELECT clock_timestamp()").Scan(&now); err != nil {
		return nil, false, err
	}
	if approval.Status == "expired" || !approval.ExpiresAt.After(now) {
		_, err := tx.Exec(ctx, "UPDATE agentguard_confirmations SET status='expired',resolved_at=COALESCE(resolved_at,clock_timestamp()) WHERE tenant_id=$1 AND id=$2 AND source='agent_authorization' AND status IN ('pending','approved') AND expires_at<=clock_timestamp()", tenantID, id)
		if err != nil {
			return nil, false, err
		}
		if err := tx.Commit(ctx); err != nil {
			return nil, false, err
		}
		approval.Status = "expired"
		return approval, false, ErrAgentAuthorizationApprovalExpired
	}
	if approval.Status != "pending" && approval.Status != "approved" {
		return approval, false, ErrAgentAuthorizationApprovalStateConflict
	}
	tag, err := tx.Exec(ctx, `
		UPDATE agentguard_confirmations SET status='revoked',resolved_by=$3,
		  resolved_at=clock_timestamp(),resolution_note=$4
		WHERE tenant_id=$1 AND id=$2 AND source='agent_authorization'
		  AND status IN ('pending','approved') AND agent_authorization_claimed_at IS NULL
	`, tenantID, id, actorID, note)
	if err != nil {
		return nil, false, err
	}
	if tag.RowsAffected() != 1 {
		return nil, false, ErrAgentAuthorizationApprovalStateConflict
	}
	approval.Status = "revoked"
	if err := tx.Commit(ctx); err != nil {
		return nil, false, err
	}
	return approval, true, nil
}

type agentAuthorizationExceptionScanner interface{ Scan(...any) error }

const agentAuthorizationExceptionSelect = `
	SELECT id::text, principal_id::text, grant_id::text, action, resource_type, resource_id,
	       arguments_sha256, reason, created_by, created_at, expires_at,
	       COALESCE(revoked_by,''), revoked_at IS NOT NULL,
	       COALESCE(revoked_at,'epoch'::timestamptz),
	       (revoked_at IS NULL AND expires_at>clock_timestamp())
	FROM agent_authorization_approval_exceptions
`

func scanAgentAuthorizationApprovalException(row agentAuthorizationExceptionScanner) (*AgentAuthorizationApprovalException, error) {
	var value AgentAuthorizationApprovalException
	var revoked bool
	var revokedAt time.Time
	err := row.Scan(&value.ID, &value.PrincipalID, &value.GrantID, &value.Action, &value.ResourceType,
		&value.ResourceID, &value.ArgumentsSHA256, &value.Reason, &value.CreatedBy,
		&value.CreatedAt, &value.ExpiresAt, &value.RevokedBy, &revoked, &revokedAt, &value.Active)
	if err != nil {
		return nil, err
	}
	if revoked {
		value.RevokedAt = &revokedAt
	}
	return &value, nil
}

func agentAuthorizationExceptionRequestHash(tenantID, actorID string, input AgentAuthorizationApprovalExceptionInput) (string, error) {
	return hashAgentAuthorizationApprovalValue(struct {
		TenantID        string `json:"tenant_id"`
		ActorID         string `json:"actor_id"`
		PrincipalID     string `json:"principal_id"`
		GrantID         string `json:"grant_id"`
		Action          string `json:"action"`
		ResourceType    string `json:"resource_type"`
		ResourceID      string `json:"resource_id"`
		ArgumentsSHA256 string `json:"arguments_sha256"`
		Reason          string `json:"reason"`
		TTLSeconds      int    `json:"ttl_seconds"`
	}{
		tenantID, actorID, input.PrincipalID, input.GrantID, input.Action,
		input.ResourceType, input.ResourceID, input.ArgumentsSHA256,
		strings.TrimSpace(input.Reason), input.TTLSeconds,
	})
}

func (r *AgentAuthorizationRepository) CreateAgentAuthorizationApprovalException(
	ctx context.Context, tenantID, actorID string, input AgentAuthorizationApprovalExceptionInput,
) (*AgentAuthorizationApprovalException, bool, error) {
	if err := ValidateAgentAuthorizationApprovalExceptionInput(input); err != nil ||
		strings.TrimSpace(tenantID) == "" || strings.TrimSpace(actorID) == "" {
		return nil, false, ErrAgentAuthorizationApprovalInvalid
	}
	requestHash, err := agentAuthorizationExceptionRequestHash(tenantID, actorID, input)
	if err != nil {
		return nil, false, err
	}
	keyHash := HashAgentToken(input.IdempotencyKey)
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return nil, false, err
	}
	defer tx.Rollback(ctx)

	var principalExpiry time.Time
	err = tx.QueryRow(ctx, `
		SELECT expires_at FROM agent_authorization_principals
		WHERE id=$1 AND tenant_id=$2 AND status='active' AND revoked_at IS NULL
		FOR UPDATE
	`, input.PrincipalID, tenantID).Scan(&principalExpiry)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, false, ErrAgentAuthorizationPrincipalNotFound
	}
	if err != nil {
		return nil, false, err
	}
	if err := agentAuthorizationRejectSelfResolution(ctx, tx, tenantID, input.PrincipalID, actorID); err != nil {
		return nil, false, err
	}

	var grantAction, grantType, grantResource string
	var grantExpiry time.Time
	err = tx.QueryRow(ctx, `
		SELECT action, resource_type, resource_id, expires_at
		FROM agent_authorization_grants
		WHERE id=$1 AND tenant_id=$2 AND principal_id=$3 FOR UPDATE
	`, input.GrantID, tenantID, input.PrincipalID).Scan(&grantAction, &grantType, &grantResource, &grantExpiry)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, false, ErrAgentAuthorizationGrantExpired
	}
	if err != nil {
		return nil, false, err
	}
	if grantAction != input.Action || grantType != input.ResourceType || grantResource != input.ResourceID {
		return nil, false, ErrAgentAuthorizationApprovalInvalid
	}
	var now, expires time.Time
	if err := tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		return nil, false, err
	}
	if err := tx.QueryRow(ctx, `SELECT LEAST(clock_timestamp()+($1 * interval '1 second'),$2,$3)`,
		input.TTLSeconds, principalExpiry, grantExpiry).Scan(&expires); err != nil {
		return nil, false, err
	}
	if !principalExpiry.After(now) || !grantExpiry.After(now) || !expires.After(now) {
		return nil, false, ErrAgentAuthorizationGrantExpired
	}

	id := uuid.NewString()
	tag, err := tx.Exec(ctx, `
		INSERT INTO agent_authorization_approval_exceptions (
			id, tenant_id, principal_id, grant_id, action, resource_type, resource_id,
			arguments_sha256, created_by, reason, idempotency_key_sha256, request_sha256,
			created_at, expires_at
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,clock_timestamp(),$13)
		ON CONFLICT (tenant_id, created_by, idempotency_key_sha256) DO NOTHING
	`, id, tenantID, input.PrincipalID, input.GrantID, input.Action, input.ResourceType,
		input.ResourceID, input.ArgumentsSHA256, actorID, strings.TrimSpace(input.Reason),
		keyHash, requestHash, expires)
	if err != nil {
		return nil, false, err
	}
	created := tag.RowsAffected() == 1
	exception, err := scanAgentAuthorizationApprovalException(tx.QueryRow(ctx,
		agentAuthorizationExceptionSelect+` WHERE tenant_id=$1 AND created_by=$2 AND idempotency_key_sha256=$3 FOR UPDATE`,
		tenantID, actorID, keyHash))
	if err != nil {
		return nil, false, err
	}
	var storedHash string
	if err := tx.QueryRow(ctx, `SELECT request_sha256 FROM agent_authorization_approval_exceptions WHERE tenant_id=$1 AND id=$2`,
		tenantID, exception.ID).Scan(&storedHash); err != nil {
		return nil, false, err
	}
	if storedHash != requestHash {
		return nil, false, ErrAgentAuthorizationApprovalConflict
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, false, err
	}
	return exception, created, nil
}

func (r *AgentAuthorizationRepository) ListAgentAuthorizationApprovalExceptions(
	ctx context.Context, tenantID string, limit int,
) ([]*AgentAuthorizationApprovalException, error) {
	if limit < 1 || limit > 200 {
		limit = 50
	}
	rows, err := r.db.Query(ctx, agentAuthorizationExceptionSelect+
		` WHERE tenant_id=$1 ORDER BY created_at DESC LIMIT $2`, tenantID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []*AgentAuthorizationApprovalException
	for rows.Next() {
		item, err := scanAgentAuthorizationApprovalException(rows)
		if err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (r *AgentAuthorizationRepository) RevokeAgentAuthorizationApprovalException(
	ctx context.Context, tenantID, id, actorID string,
) (*AgentAuthorizationApprovalException, bool, error) {
	if strings.TrimSpace(actorID) == "" || strings.TrimSpace(tenantID) == "" {
		return nil, false, ErrAgentAuthorizationApprovalInvalid
	}
	exceptionID, err := uuid.Parse(id)
	if err != nil {
		return nil, false, ErrAgentAuthorizationApprovalInvalid
	}
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return nil, false, err
	}
	defer tx.Rollback(ctx)

	var principalID, grantID string
	err = tx.QueryRow(ctx, `SELECT principal_id::text, grant_id::text FROM agent_authorization_approval_exceptions WHERE tenant_id=$1 AND id=$2`,
		tenantID, exceptionID).Scan(&principalID, &grantID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	// Keep the same principal -> grant -> exception -> approval order used by request/claim.
	var lockedID string
	if err := tx.QueryRow(ctx, `SELECT id::text FROM agent_authorization_principals WHERE tenant_id=$1 AND id=$2 FOR UPDATE`, tenantID, principalID).Scan(&lockedID); err != nil {
		return nil, false, err
	}
	if err := tx.QueryRow(ctx, `SELECT id::text FROM agent_authorization_grants WHERE tenant_id=$1 AND principal_id=$2 AND id=$3 FOR UPDATE`, tenantID, principalID, grantID).Scan(&lockedID); err != nil {
		return nil, false, err
	}
	if err := tx.QueryRow(ctx, `SELECT id::text FROM agent_authorization_approval_exceptions WHERE tenant_id=$1 AND id=$2 FOR UPDATE`, tenantID, exceptionID).Scan(&lockedID); err != nil {
		return nil, false, err
	}
	tag, err := tx.Exec(ctx, `
		UPDATE agent_authorization_approval_exceptions
		SET revoked_by=COALESCE(revoked_by,$3), revoked_at=COALESCE(revoked_at,clock_timestamp())
		WHERE tenant_id=$1 AND id=$2 AND revoked_at IS NULL
	`, tenantID, exceptionID, actorID)
	if err != nil {
		return nil, false, err
	}
	changed := tag.RowsAffected() == 1
	if changed {
		_, err = tx.Exec(ctx, `
			UPDATE agentguard_confirmations
			SET status='expired', resolved_at=COALESCE(resolved_at,clock_timestamp())
			WHERE tenant_id=$1 AND source='agent_authorization'
			  AND agent_authorization_exception_id=$2 AND status IN ('pending','approved')
			  AND expires_at<=clock_timestamp()
		`, tenantID, exceptionID)
		if err != nil {
			return nil, false, err
		}
		_, err = tx.Exec(ctx, `
			UPDATE agentguard_confirmations
			SET status='revoked', resolved_by=$3, resolved_at=clock_timestamp(),
			    resolution_note='approval exception revoked'
			WHERE tenant_id=$1 AND source='agent_authorization'
			  AND agent_authorization_exception_id=$2 AND status IN ('pending','approved')
			  AND expires_at>clock_timestamp() AND agent_authorization_claimed_at IS NULL
		`, tenantID, exceptionID, actorID)
		if err != nil {
			return nil, false, err
		}
	}
	exception, err := scanAgentAuthorizationApprovalException(tx.QueryRow(ctx,
		agentAuthorizationExceptionSelect+` WHERE tenant_id=$1 AND id=$2`, tenantID, exceptionID))
	if err != nil {
		return nil, false, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, false, err
	}
	return exception, changed, nil
}

// agentAuthorizationRejectSelfResolution enforces requester != approver. Everyone who has
// held a working credential for the principal - the admin who registered it (and thereby its
// grants) and every admin who rotated its credential - may not resolve its approvals or
// create exceptions for it. No role, including platform_admin, is exempt. If the creator is
// blank, or the credential was rotated before rotators were recorded, the holders cannot be
// established and the check fails closed.
func agentAuthorizationRejectSelfResolution(ctx context.Context, tx pgx.Tx, tenantID, principalID, actorID string) error {
	holders, err := agentAuthorizationPrincipalHolders(ctx, tx, tenantID, principalID)
	if err != nil {
		return err
	}
	if holders[actorID] {
		return ErrAgentAuthorizationApprovalSelfResolution
	}
	return nil
}

// agentAuthorizationPrincipalHolders returns everyone who has held a working credential for
// the principal: its creator plus every rotator. It fails closed exactly like
// agentAuthorizationRejectSelfResolution when the holders cannot be established. Callers must
// already hold the principal row lock so a concurrent rotation cannot slip in between.
// T22: a delegated child's credential can be minted by whoever holds any ancestor's
// credential, so the holders of every ancestor on the delegation chain (revoked edges
// included) are holders of the child too. An over-deep or cyclic chain fails closed.
func agentAuthorizationPrincipalHolders(ctx context.Context, tx pgx.Tx, tenantID, principalID string) (map[string]bool, error) {
	holders := map[string]bool{}
	seen := map[string]bool{}
	current := principalID
	for depth := 0; depth <= AgentDelegationMaxDepth; depth++ {
		if seen[current] {
			return nil, ErrAgentAuthorizationApprovalHolderUnknown
		}
		seen[current] = true
		var createdBy string
		var rotatedBy []string
		var rotated bool
		err := tx.QueryRow(ctx, `SELECT created_by, rotated_by, credential_rotated_at IS NOT NULL
			FROM agent_authorization_principals WHERE tenant_id=$1 AND id=$2`,
			tenantID, current).Scan(&createdBy, &rotatedBy, &rotated)
		if errors.Is(err, pgx.ErrNoRows) {
			if current == principalID {
				return nil, ErrAgentAuthorizationPrincipalNotFound
			}
			return nil, ErrAgentAuthorizationApprovalHolderUnknown
		}
		if err != nil {
			return nil, err
		}
		if strings.TrimSpace(createdBy) == "" || (rotated && len(rotatedBy) == 0) {
			return nil, ErrAgentAuthorizationApprovalHolderUnknown
		}
		holders[createdBy] = true
		for _, rotator := range rotatedBy {
			if strings.TrimSpace(rotator) == "" {
				return nil, ErrAgentAuthorizationApprovalHolderUnknown
			}
			holders[rotator] = true
		}
		var parentID string
		err = tx.QueryRow(ctx, `SELECT parent_principal_id::text FROM agent_delegations
			WHERE tenant_id=$1 AND child_principal_id=$2`, tenantID, current).Scan(&parentID)
		if errors.Is(err, pgx.ErrNoRows) {
			return holders, nil
		}
		if err != nil {
			return nil, err
		}
		current = parentID
	}
	return nil, ErrAgentAuthorizationApprovalHolderUnknown
}
