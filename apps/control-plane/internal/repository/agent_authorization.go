package repository

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

var (
	ErrAgentAuthorizationPrincipalUnauthorized = errors.New("agent principal is unauthorized")
	ErrAgentAuthorizationGrantExpired          = errors.New("agent authorization grant expired before authorization decision")
	ErrAgentAuthorizationPrincipalNotFound     = errors.New("agent principal not found")
	ErrAgentAuthorizationIdempotencyConflict   = errors.New("idempotency key was used for another request")
	ErrAgentAuthorizationInvalid               = errors.New("invalid agent authorization request")
)

const (
	AgentAuthorizationMaxPrincipalTTL       = 365 * 24 * time.Hour
	AgentAuthorizationIdempotencyTTL        = 24 * time.Hour
	AgentAuthorizationMaxQuotaWindowSeconds = 24 * 60 * 60
	AgentAuthorizationMaxGrants             = 64
)

type AgentAuthorizationGrant struct {
	ID                 string         `json:"id,omitempty"`
	Action             string         `json:"action"`
	ResourceType       string         `json:"resource_type"`
	ResourceID         string         `json:"resource_id"`
	Conditions         map[string]any `json:"conditions,omitempty"`
	ExpiresAt          time.Time      `json:"expires_at"`
	QuotaMax           int64          `json:"quota_max"`
	QuotaWindowSeconds int            `json:"quota_window_seconds"`
}

type AgentAuthorizationPrincipal struct {
	ID                  string     `json:"id"`
	TenantID            string     `json:"tenant_id"`
	Name                string     `json:"name"`
	TokenPrefix         string     `json:"token_prefix"`
	Status              string     `json:"status"`
	ExpiresAt           time.Time  `json:"expires_at"`
	RevokedAt           *time.Time `json:"revoked_at,omitempty"`
	CreatedBy           string     `json:"created_by"`
	CreatedAt           time.Time  `json:"created_at"`
	CredentialRotatedAt *time.Time `json:"credential_rotated_at,omitempty"`
	RotatedBy           []string   `json:"rotated_by"`
}

type AgentAuthorizationPrincipalCreate struct {
	Name      string
	ExpiresAt time.Time
	CreatedBy string
	Grants    []AgentAuthorizationGrant
}

type AgentAuthorizationPrincipalCreated struct {
	Principal  AgentAuthorizationPrincipal `json:"principal"`
	Credential string                      `json:"credential"`
	Grants     []AgentAuthorizationGrant   `json:"grants"`
}

type TrustedAgentPrincipal struct {
	ID             string
	TenantID       string
	CredentialHash string
	ExpiresAt      time.Time
}

type AgentAuthorizationRequest struct {
	Action         string         `json:"action"`
	ResourceType   string         `json:"resource_type"`
	ResourceID     string         `json:"resource_id"`
	Context        map[string]any `json:"context,omitempty"`
	IdempotencyKey string         `json:"idempotency_key"`
}

type AgentAuthorizationDecision struct {
	Allowed        bool   `json:"allowed"`
	Reason         string `json:"reason"`
	PrincipalID    string `json:"principal_id"`
	Action         string `json:"action"`
	ResourceType   string `json:"resource_type"`
	ResourceID     string `json:"resource_id"`
	IdempotencyKey string `json:"idempotency_key"`
	GrantID        string `json:"grant_id,omitempty"`
}

type agentAuthorizationDatabase interface {
	Begin(context.Context) (pgx.Tx, error)
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
	Query(context.Context, string, ...any) (pgx.Rows, error)
	QueryRow(context.Context, string, ...any) pgx.Row
}

type AgentAuthorizationRepository struct {
	db agentAuthorizationDatabase
}

func NewAgentAuthorizationRepository(db agentAuthorizationDatabase) *AgentAuthorizationRepository {
	return &AgentAuthorizationRepository{db: db}
}

func validAgentAuthorizationLabel(value string) bool {
	if value == "" || len(value) > 64 {
		return false
	}
	for i, ch := range value {
		if i == 0 && (ch < 'a' || ch > 'z') {
			return false
		}
		if (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') ||
			ch == '_' || ch == '-' || ch == '.' || ch == ':' {
			continue
		}
		return false
	}
	return true
}

func validAgentAuthorizationResourceID(value string) bool {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > 256 || strings.Contains(value, "*") {
		return false
	}
	for _, ch := range value {
		if ch < 0x21 || ch == 0x7f {
			return false
		}
	}
	return true
}

func validAgentAuthorizationContextKey(key string) bool {
	if !validAgentAuthorizationLabel(key) {
		return false
	}
	switch key {
	case "agent_id", "principal_id", "tenant_id", "user_id", "subject_id", "credential":
		return false
	default:
		return true
	}
}

func validAgentAuthorizationScalar(value any) bool {
	switch v := value.(type) {
	case string:
		return len(v) <= 512
	case bool:
		return true
	case float64:
		return !math.IsNaN(v) && !math.IsInf(v, 0)
	case float32:
		return !math.IsNaN(float64(v)) && !math.IsInf(float64(v), 0)
	case int, int32, int64, uint, uint32, uint64, json.Number:
		return true
	default:
		return false
	}
}

func validateAgentAuthorizationContext(values map[string]any) error {
	if len(values) > 32 {
		return fmt.Errorf("%w: too many context fields", ErrAgentAuthorizationInvalid)
	}
	for key, value := range values {
		if !validAgentAuthorizationContextKey(key) || !validAgentAuthorizationScalar(value) {
			return fmt.Errorf("%w: invalid context field", ErrAgentAuthorizationInvalid)
		}
	}
	return nil
}

func ValidateAgentAuthorizationPrincipalCreate(input AgentAuthorizationPrincipalCreate, now time.Time) error {
	if strings.TrimSpace(input.Name) == "" || len(strings.TrimSpace(input.Name)) > 128 {
		return fmt.Errorf("%w: name is required and must be at most 128 bytes", ErrAgentAuthorizationInvalid)
	}
	if strings.TrimSpace(input.CreatedBy) == "" || len(input.CreatedBy) > 128 {
		return fmt.Errorf("%w: created_by is required", ErrAgentAuthorizationInvalid)
	}
	if !input.ExpiresAt.After(now) || input.ExpiresAt.After(now.Add(AgentAuthorizationMaxPrincipalTTL)) {
		return fmt.Errorf("%w: principal expiry must be within the next 365 days", ErrAgentAuthorizationInvalid)
	}
	if len(input.Grants) > AgentAuthorizationMaxGrants {
		return fmt.Errorf("%w: too many grants", ErrAgentAuthorizationInvalid)
	}
	seen := make(map[string]struct{}, len(input.Grants))
	for i, grant := range input.Grants {
		if !validAgentAuthorizationLabel(grant.Action) || !validAgentAuthorizationLabel(grant.ResourceType) ||
			!validAgentAuthorizationResourceID(grant.ResourceID) {
			return fmt.Errorf("%w: invalid grant %d scope", ErrAgentAuthorizationInvalid, i)
		}
		if !grant.ExpiresAt.After(now) || grant.ExpiresAt.After(input.ExpiresAt) {
			return fmt.Errorf("%w: grant %d expiry must be future and no later than the principal", ErrAgentAuthorizationInvalid, i)
		}
		if grant.QuotaMax < 1 || grant.QuotaMax > 1000000 || grant.QuotaWindowSeconds < 1 || grant.QuotaWindowSeconds > AgentAuthorizationMaxQuotaWindowSeconds {
			return fmt.Errorf("%w: grant %d quota is outside supported bounds", ErrAgentAuthorizationInvalid, i)
		}
		if err := validateAgentAuthorizationContext(grant.Conditions); err != nil {
			return fmt.Errorf("%w: invalid grant %d conditions", ErrAgentAuthorizationInvalid, i)
		}
		key := grant.Action + "\x00" + grant.ResourceType + "\x00" + grant.ResourceID
		if _, duplicate := seen[key]; duplicate {
			return fmt.Errorf("%w: duplicate action/resource grant", ErrAgentAuthorizationInvalid)
		}
		seen[key] = struct{}{}
	}
	return nil
}

func ValidateAgentAuthorizationRequest(request AgentAuthorizationRequest) error {
	if !validAgentAuthorizationLabel(request.Action) ||
		!validAgentAuthorizationLabel(request.ResourceType) ||
		!validAgentAuthorizationResourceID(request.ResourceID) {
		return fmt.Errorf("%w: invalid action or resource scope", ErrAgentAuthorizationInvalid)
	}
	if len(request.IdempotencyKey) < 16 || len(request.IdempotencyKey) > 128 {
		return fmt.Errorf("%w: idempotency_key must contain 16 to 128 characters", ErrAgentAuthorizationInvalid)
	}
	for _, ch := range request.IdempotencyKey {
		if !((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
			(ch >= '0' && ch <= '9') || ch == '-' || ch == '_' || ch == '.' || ch == ':') {
			return fmt.Errorf("%w: invalid idempotency_key", ErrAgentAuthorizationInvalid)
		}
	}
	return validateAgentAuthorizationContext(request.Context)
}

func agentAuthorizationRequestHash(request AgentAuthorizationRequest) (string, error) {
	payload := struct {
		Action       string         `json:"action"`
		ResourceType string         `json:"resource_type"`
		ResourceID   string         `json:"resource_id"`
		Context      map[string]any `json:"context,omitempty"`
	}{request.Action, request.ResourceType, request.ResourceID, request.Context}
	raw, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	hash := sha256.Sum256(raw)
	return hex.EncodeToString(hash[:]), nil
}

func agentAuthorizationConditionsMatch(required, actual map[string]any) bool {
	for key, expected := range required {
		got, exists := actual[key]
		if !exists {
			return false
		}
		wantJSON, err := json.Marshal(expected)
		if err != nil {
			return false
		}
		gotJSON, err := json.Marshal(got)
		if err != nil || string(wantJSON) != string(gotJSON) {
			return false
		}
	}
	return true
}

func (r *AgentAuthorizationRepository) RegisterPrincipal(ctx context.Context, tenantID string, input AgentAuthorizationPrincipalCreate) (*AgentAuthorizationPrincipalCreated, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return nil, fmt.Errorf("%w: authenticated tenant is required", ErrAgentAuthorizationInvalid)
	}
	if err := ValidateAgentAuthorizationPrincipalCreate(input, time.Now().UTC()); err != nil {
		return nil, err
	}
	token, tokenHash, err := NewAgentToken()
	if err != nil {
		return nil, err
	}
	principalID := uuid.NewString()
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	var databaseNow time.Time
	if err := tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&databaseNow); err != nil {
		return nil, err
	}
	if !input.ExpiresAt.After(databaseNow) || input.ExpiresAt.After(databaseNow.Add(AgentAuthorizationMaxPrincipalTTL)) {
		return nil, fmt.Errorf("%w: principal expiry is outside supported bounds", ErrAgentAuthorizationInvalid)
	}
	_, err = tx.Exec(ctx, `
		INSERT INTO agent_authorization_principals
		    (id, tenant_id, name, credential_hash, credential_prefix, status, expires_at, created_by)
		VALUES ($1, $2, $3, $4, $5, 'active', $6, $7)
	`, principalID, tenantID, strings.TrimSpace(input.Name), tokenHash, token[:8], input.ExpiresAt.UTC(), input.CreatedBy)
	if err != nil {
		return nil, err
	}
	grants := make([]AgentAuthorizationGrant, 0, len(input.Grants))
	for _, grant := range input.Grants {
		if !grant.ExpiresAt.After(databaseNow) || grant.ExpiresAt.After(input.ExpiresAt) {
			return nil, fmt.Errorf("%w: grant expiry is outside principal bounds", ErrAgentAuthorizationInvalid)
		}
		grant.ID = uuid.NewString()
		if grant.Conditions == nil {
			grant.Conditions = map[string]any{}
		}
		conditions, err := json.Marshal(grant.Conditions)
		if err != nil {
			return nil, fmt.Errorf("%w: invalid grant conditions", ErrAgentAuthorizationInvalid)
		}
		_, err = tx.Exec(ctx, `
			INSERT INTO agent_authorization_grants
			    (id, tenant_id, principal_id, action, resource_type, resource_id,
			     conditions_json, expires_at, quota_max, quota_window_seconds)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		`, grant.ID, tenantID, principalID, grant.Action, grant.ResourceType,
			grant.ResourceID, conditions, grant.ExpiresAt.UTC(), grant.QuotaMax, grant.QuotaWindowSeconds)
		if err != nil {
			return nil, err
		}
		grants = append(grants, grant)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	principal := AgentAuthorizationPrincipal{
		ID: principalID, TenantID: tenantID, Name: strings.TrimSpace(input.Name),
		TokenPrefix: token[:8], Status: "active", ExpiresAt: input.ExpiresAt.UTC(),
		CreatedBy: input.CreatedBy, CreatedAt: databaseNow, RotatedBy: []string{},
	}
	return &AgentAuthorizationPrincipalCreated{Principal: principal, Credential: token, Grants: grants}, nil
}

func (r *AgentAuthorizationRepository) ListPrincipals(ctx context.Context, tenantID string) ([]AgentAuthorizationPrincipal, error) {
	rows, err := r.db.Query(ctx, `
		SELECT id::text, tenant_id, name, credential_prefix, status, expires_at, revoked_at,
		       created_by, created_at, credential_rotated_at, rotated_by
		FROM agent_authorization_principals
		WHERE tenant_id=$1
		ORDER BY created_at DESC, id
	`, strings.TrimSpace(tenantID))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]AgentAuthorizationPrincipal, 0)
	for rows.Next() {
		var item AgentAuthorizationPrincipal
		var revokedAt, rotatedAt sql.NullTime
		if err := rows.Scan(&item.ID, &item.TenantID, &item.Name, &item.TokenPrefix, &item.Status,
			&item.ExpiresAt, &revokedAt, &item.CreatedBy, &item.CreatedAt, &rotatedAt, &item.RotatedBy); err != nil {
			return nil, err
		}
		if revokedAt.Valid {
			value := revokedAt.Time
			item.RevokedAt = &value
		}
		if rotatedAt.Valid {
			value := rotatedAt.Time
			item.CredentialRotatedAt = &value
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (r *AgentAuthorizationRepository) RevokePrincipal(ctx context.Context, tenantID, principalID string) (bool, error) {
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return false, err
	}
	defer tx.Rollback(ctx)
	tenantID = strings.TrimSpace(tenantID)
	principalID = strings.TrimSpace(principalID)
	if err := lockAgentDelegationHierarchy(ctx, tx, tenantID, principalID); err != nil {
		return false, err
	}
	result, err := tx.Exec(ctx, `
		UPDATE agent_authorization_principals
		SET status='revoked', revoked_at=COALESCE(revoked_at, clock_timestamp()), updated_at=clock_timestamp()
		WHERE tenant_id=$1 AND id=$2
	`, tenantID, principalID)
	if err != nil {
		return false, err
	}
	if result.RowsAffected() == 0 {
		return false, nil
	}
	if err := revokeDelegationSubtree(ctx, tx, tenantID, principalID); err != nil {
		return false, err
	}
	if err := tx.Commit(ctx); err != nil {
		return false, err
	}
	return true, nil
}

// RotatePrincipalCredential issues a new credential and appends actorID to rotated_by.
// Whoever rotates holds a working agent credential, so separation of duties treats every
// rotator like the creator (see agentAuthorizationRejectSelfResolution).
func (r *AgentAuthorizationRepository) RotatePrincipalCredential(ctx context.Context, tenantID, principalID, actorID string) (string, bool, error) {
	token, found, _, err := r.RotatePrincipalCredentialWithEffects(ctx, tenantID, principalID, actorID)
	return token, found, err
}

// AgentAuthorizationRotationEffects lists what a rotation invalidated in the same transaction.
type AgentAuthorizationRotationEffects struct {
	RevokedExceptionIDs []string
	RevokedApprovalIDs  []string
}

// RotatePrincipalCredentialWithEffects rotates the credential and, atomically, revokes every
// active approval exception and every approved-but-unclaimed approval of the principal (pending
// ones stay pending; their resolver is checked against the new holder set at resolve time).
// Authorization granted before the rotation must not flow to the new credential holder (G1 N1/N2).
func (r *AgentAuthorizationRepository) RotatePrincipalCredentialWithEffects(ctx context.Context, tenantID, principalID, actorID string) (string, bool, AgentAuthorizationRotationEffects, error) {
	var effects AgentAuthorizationRotationEffects
	if strings.TrimSpace(actorID) == "" || len(actorID) > 128 {
		return "", false, effects, fmt.Errorf("%w: rotating actor is required", ErrAgentAuthorizationInvalid)
	}
	token, tokenHash, err := NewAgentToken()
	if err != nil {
		return "", false, effects, err
	}
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return "", false, effects, err
	}
	defer tx.Rollback(ctx)
	tenantID, principalID = strings.TrimSpace(tenantID), strings.TrimSpace(principalID)
	var canonicalID string
	err = tx.QueryRow(ctx, `
		UPDATE agent_authorization_principals
		SET credential_hash=$1, credential_prefix=$2, credential_rotated_at=clock_timestamp(), updated_at=clock_timestamp(),
		    rotated_by=CASE WHEN $5::text = ANY(rotated_by) THEN rotated_by ELSE array_append(rotated_by, $5::text) END
		WHERE tenant_id=$3 AND id=$4 AND status='active' AND revoked_at IS NULL AND expires_at>clock_timestamp()
		RETURNING id::text
	`, tokenHash, token[:8], tenantID, principalID, actorID).Scan(&canonicalID)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", false, effects, nil
	}
	if err != nil {
		return "", false, effects, err
	}
	// Lock order principal -> exception -> approval, same as request/claim/revoke-exception.
	rows, err := tx.Query(ctx, `
		UPDATE agent_authorization_approval_exceptions
		SET revoked_by=$3, revoked_at=clock_timestamp()
		WHERE tenant_id=$1 AND principal_id=$2::uuid AND revoked_at IS NULL AND expires_at>clock_timestamp()
		RETURNING id::text
	`, tenantID, canonicalID, actorID)
	if err != nil {
		return "", false, effects, err
	}
	effects.RevokedExceptionIDs, err = pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return "", false, effects, err
	}
	rows, err = tx.Query(ctx, `
		UPDATE agentguard_confirmations
		SET status='revoked', resolved_at=clock_timestamp(), resolution_note='agent credential rotated'
		WHERE tenant_id=$1 AND source='agent_authorization' AND agent_authorization_principal_id=$2::uuid
		  AND status='approved' AND expires_at>clock_timestamp()
		  AND agent_authorization_claimed_at IS NULL
		RETURNING id::text
	`, tenantID, canonicalID)
	if err != nil {
		return "", false, effects, err
	}
	effects.RevokedApprovalIDs, err = pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return "", false, effects, err
	}
	if err := tx.Commit(ctx); err != nil {
		return "", false, effects, err
	}
	return token, true, effects, nil
}

func (r *AgentAuthorizationRepository) ResolvePrincipalCredential(ctx context.Context, credentialHash string) (*TrustedAgentPrincipal, error) {
	if len(credentialHash) != 64 {
		return nil, nil
	}
	var principal TrustedAgentPrincipal
	err := r.db.QueryRow(ctx, `
		SELECT id::text, tenant_id, credential_hash, expires_at
		FROM agent_authorization_principals
		WHERE credential_hash=$1 AND status='active' AND revoked_at IS NULL AND expires_at>clock_timestamp()
	`, credentialHash).Scan(&principal.ID, &principal.TenantID, &principal.CredentialHash, &principal.ExpiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &principal, nil
}

func (r *AgentAuthorizationRepository) Authorize(ctx context.Context, principal TrustedAgentPrincipal, request AgentAuthorizationRequest) (*AgentAuthorizationDecision, error) {
	if err := ValidateAgentAuthorizationRequest(request); err != nil {
		return nil, err
	}
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	if err := lockAgentDelegationHierarchy(ctx, tx, principal.TenantID, principal.ID); err != nil {
		return nil, err
	}

	var currentCredentialHash string
	var principalExpiresAt time.Time
	err = tx.QueryRow(ctx, `
		SELECT credential_hash, expires_at
		FROM agent_authorization_principals
		WHERE id=$1 AND tenant_id=$2 AND status='active' AND revoked_at IS NULL
		FOR UPDATE
	`, principal.ID, principal.TenantID).Scan(&currentCredentialHash, &principalExpiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrAgentAuthorizationPrincipalUnauthorized
	}
	if err != nil {
		return nil, err
	}
	if subtle.ConstantTimeCompare([]byte(currentCredentialHash), []byte(principal.CredentialHash)) != 1 {
		return nil, ErrAgentAuthorizationPrincipalUnauthorized
	}
	authorizationNow, err := agentAuthorizationDatabaseNow(ctx, tx)
	if err != nil {
		return nil, err
	}
	if !principalExpiresAt.After(authorizationNow) {
		return nil, ErrAgentAuthorizationPrincipalUnauthorized
	}
	delegationChain, err := lockAgentDelegationChain(ctx, tx, principal.TenantID, principal.ID, authorizationNow)
	if err != nil {
		return nil, err
	}
	if err := bindDelegatedRequest(delegationChain, &request); err != nil {
		return nil, err
	}
	requestHash, err := agentAuthorizationRequestHash(request)
	if err != nil {
		return nil, err
	}

	_, err = tx.Exec(ctx, `
		INSERT INTO agent_authorization_requests
		    (tenant_id, principal_id, idempotency_key, request_hash, state, created_at, expires_at)
		VALUES ($1, $2, $3, $4, 'pending', clock_timestamp(), clock_timestamp()+interval '24 hours')
		ON CONFLICT (tenant_id, principal_id, idempotency_key) DO UPDATE
		SET request_hash=EXCLUDED.request_hash, state='pending', grant_id=NULL,
		    decision_json=NULL, created_at=clock_timestamp(), expires_at=EXCLUDED.expires_at
		WHERE agent_authorization_requests.expires_at<=clock_timestamp()
	`, principal.TenantID, principal.ID, request.IdempotencyKey, requestHash)
	if err != nil {
		return nil, err
	}
	var storedHash, state string
	var priorDecision []byte
	var priorGrantID string
	err = tx.QueryRow(ctx, `
		SELECT request_hash, state, decision_json, COALESCE(grant_id::text, '')
		FROM agent_authorization_requests
		WHERE tenant_id=$1 AND principal_id=$2 AND idempotency_key=$3
		FOR UPDATE
	`, principal.TenantID, principal.ID, request.IdempotencyKey).Scan(&storedHash, &state, &priorDecision, &priorGrantID)
	if err != nil {
		return nil, err
	}
	if storedHash != requestHash {
		return nil, ErrAgentAuthorizationIdempotencyConflict
	}
	if state == "complete" {
		var decision AgentAuthorizationDecision
		if err := json.Unmarshal(priorDecision, &decision); err != nil {
			return nil, err
		}
		grantIDForCheck := ""
		if decision.Allowed {
			grantIDForCheck = priorGrantID
		}
		var principalActive, grantActive bool
		if decision.Allowed && len(delegationChain) > 0 {
			finalAuthorizationNow, err := agentAuthorizationDatabaseNow(ctx, tx)
			if err != nil {
				return nil, err
			}
			finalDelegationChain, err := lockAgentDelegationChain(ctx, tx, principal.TenantID, principal.ID, finalAuthorizationNow)
			if err != nil || !sameAgentDelegationChain(delegationChain, finalDelegationChain) {
				return nil, ErrAgentAuthorizationPrincipalUnauthorized
			}
			if _, err := ancestorGrantLimits(ctx, tx, principal.TenantID, finalDelegationChain, priorGrantID,
				request.Action, request.ResourceType, request.ResourceID, request.Context, finalAuthorizationNow); err != nil {
				return nil, ErrAgentAuthorizationPrincipalUnauthorized
			}
			principalActive, grantActive, err = agentAuthorizationDecisionActiveAt(ctx, tx, principal, priorGrantID, finalAuthorizationNow)
		} else {
			principalActive, grantActive, err = agentAuthorizationDecisionActive(ctx, tx, principal, grantIDForCheck)
		}
		if err != nil {
			return nil, err
		}
		if !principalActive {
			return nil, ErrAgentAuthorizationPrincipalUnauthorized
		}
		if decision.Allowed && (priorGrantID == "" || !grantActive) {
			decision.Allowed = false
			decision.Reason = "grant_expired"
			decision.GrantID = ""
			if err := updateAgentAuthorizationDecision(ctx, tx, principal, request, requestHash, decision, nil); err != nil {
				return nil, err
			}
		}
		if err := tx.Commit(ctx); err != nil {
			return nil, err
		}
		return &decision, nil
	}
	if state != "pending" {
		return nil, fmt.Errorf("invalid agent authorization request state")
	}

	decision := AgentAuthorizationDecision{
		PrincipalID: principal.ID, Action: request.Action,
		ResourceType: request.ResourceType, ResourceID: request.ResourceID,
		IdempotencyKey: request.IdempotencyKey,
	}
	var grantID, conditionsRaw string
	var expiresAt time.Time
	var quotaMax int64
	var quotaWindowSeconds int
	var directDelegationID any
	if len(delegationChain) > 0 {
		directDelegationID = delegationChain[0].ID
	}
	err = tx.QueryRow(ctx, `
		SELECT g.id::text, g.conditions_json::text, g.expires_at, g.quota_max, g.quota_window_seconds
		FROM agent_authorization_grants g
		WHERE g.tenant_id=$1 AND g.principal_id=$2 AND g.action=$3 AND g.resource_type=$4
		  AND g.resource_id=$5 AND g.expires_at>clock_timestamp()
		  AND ($6::uuid IS NULL OR EXISTS (
		      SELECT 1 FROM agent_delegation_grants m
		      WHERE m.tenant_id=g.tenant_id AND m.delegation_id=$6
		        AND m.child_principal_id=g.principal_id AND m.child_grant_id=g.id
		  ))
	`, principal.TenantID, principal.ID, request.Action, request.ResourceType,
		request.ResourceID, directDelegationID).Scan(&grantID, &conditionsRaw, &expiresAt, &quotaMax, &quotaWindowSeconds)
	if errors.Is(err, pgx.ErrNoRows) {
		decision.Reason = "no_matching_grant"
	} else if err != nil {
		return nil, err
	} else {
		var conditions map[string]any
		if err := json.Unmarshal([]byte(conditionsRaw), &conditions); err != nil {
			return nil, err
		}
		if !agentAuthorizationConditionsMatch(conditions, request.Context) {
			decision.Reason = "conditions_not_satisfied"
		} else if len(delegationChain) == 0 {
			var used int64
			err = tx.QueryRow(ctx, `
				INSERT INTO agent_authorization_usage
				    (tenant_id, principal_id, grant_id, window_start, used, updated_at)
				VALUES ($1, $2, $3,
				        to_timestamp(floor(extract(epoch from clock_timestamp()) / $4::double precision) * $4::double precision),
				        1, clock_timestamp())
				ON CONFLICT (tenant_id, principal_id, grant_id, window_start) DO UPDATE
				SET used=agent_authorization_usage.used+1, updated_at=clock_timestamp()
				WHERE agent_authorization_usage.used < $5
				RETURNING used
			`, principal.TenantID, principal.ID, grantID, quotaWindowSeconds, quotaMax).Scan(&used)
			if errors.Is(err, pgx.ErrNoRows) {
				decision.Reason = "quota_exceeded"
			} else if err != nil {
				return nil, err
			} else {
				decision.Allowed = true
				decision.Reason = "allowed"
				decision.GrantID = grantID
			}
		} else {
			parentQuotas, quotaErr := ancestorGrantLimits(ctx, tx, principal.TenantID, delegationChain, grantID,
				request.Action, request.ResourceType, request.ResourceID, request.Context, authorizationNow)
			if errors.Is(quotaErr, ErrAgentAuthorizationPrincipalUnauthorized) {
				decision.Reason = "delegation_parent_inactive"
			} else if errors.Is(quotaErr, ErrAgentAuthorizationInvalid) {
				decision.Reason = "delegation_scope_unavailable"
			} else if quotaErr != nil {
				return nil, quotaErr
			} else {
				if _, err := tx.Exec(ctx, "SAVEPOINT agent_delegation_quota"); err != nil {
					return nil, err
				}
				within, err := consumeDelegationQuota(ctx, tx, principal.TenantID,
					agentDelegationQuota{PrincipalID: principal.ID, GrantID: grantID, QuotaMax: quotaMax, QuotaWindowSeconds: quotaWindowSeconds}, authorizationNow)
				if err != nil {
					return nil, err
				}
				if within {
					for _, parentQuota := range parentQuotas {
						within, err = consumeDelegationQuota(ctx, tx, principal.TenantID, parentQuota, authorizationNow)
						if err != nil {
							return nil, err
						}
						if !within {
							break
						}
					}
				}
				if !within {
					if _, err := tx.Exec(ctx, "ROLLBACK TO SAVEPOINT agent_delegation_quota"); err != nil {
						return nil, err
					}
					if _, err := tx.Exec(ctx, "RELEASE SAVEPOINT agent_delegation_quota"); err != nil {
						return nil, err
					}
					decision.Reason = "quota_exceeded"
				} else {
					if _, err := tx.Exec(ctx, "RELEASE SAVEPOINT agent_delegation_quota"); err != nil {
						return nil, err
					}
					decision.Allowed = true
					decision.Reason = "allowed"
					decision.GrantID = grantID
				}
			}
		}
	}
	var decisionGrant any
	if decision.GrantID != "" {
		decisionGrant = decision.GrantID
	}
	if err := updateAgentAuthorizationDecision(ctx, tx, principal, request, requestHash, decision, decisionGrant); err != nil {
		return nil, err
	}
	if len(delegationChain) > 0 {
		if err := recordAgentDelegationCalls(ctx, tx, principal.TenantID, delegationChain, principal, request, requestHash, decision); err != nil {
			return nil, err
		}
	}
	grantIDForCheck := ""
	if decision.Allowed {
		grantIDForCheck = grantID
	}
	var principalActive, grantActive bool
	if decision.Allowed && len(delegationChain) > 0 {
		finalAuthorizationNow, err := agentAuthorizationDatabaseNow(ctx, tx)
		if err != nil {
			return nil, err
		}
		finalDelegationChain, err := lockAgentDelegationChain(ctx, tx, principal.TenantID, principal.ID, finalAuthorizationNow)
		if err != nil || !sameAgentDelegationChain(delegationChain, finalDelegationChain) {
			return nil, ErrAgentAuthorizationPrincipalUnauthorized
		}
		if _, err := ancestorGrantLimits(ctx, tx, principal.TenantID, finalDelegationChain, grantID,
			request.Action, request.ResourceType, request.ResourceID, request.Context, finalAuthorizationNow); err != nil {
			return nil, ErrAgentAuthorizationPrincipalUnauthorized
		}
		principalActive, grantActive, err = agentAuthorizationDecisionActiveAt(ctx, tx, principal, grantIDForCheck, finalAuthorizationNow)
	} else {
		principalActive, grantActive, err = agentAuthorizationDecisionActive(ctx, tx, principal, grantIDForCheck)
	}
	if err != nil {
		return nil, err
	}
	if !principalActive {
		return nil, ErrAgentAuthorizationPrincipalUnauthorized
	}
	if decision.Allowed && !grantActive {
		// Returning an error rolls back the quota increment and pending allow row.
		return nil, ErrAgentAuthorizationGrantExpired
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return &decision, nil
}

func agentAuthorizationDatabaseNow(ctx context.Context, tx pgx.Tx) (time.Time, error) {
	var databaseNow time.Time
	err := tx.QueryRow(ctx, "SELECT clock_timestamp()").Scan(&databaseNow)
	return databaseNow, err
}

// agentAuthorizationDecisionActiveAt rechecks the leaf against the same database
// timestamp used to validate a delegated decision's full ancestry and mapped grants.
func agentAuthorizationDecisionActiveAt(ctx context.Context, tx pgx.Tx, principal TrustedAgentPrincipal, grantID string, decisionAt time.Time) (bool, bool, error) {
	var grantIDArg any
	if grantID != "" {
		grantIDArg = grantID
	}
	var principalActive, grantActive bool
	err := tx.QueryRow(ctx, `
		SELECT
			EXISTS(
				SELECT 1
				FROM agent_authorization_principals p
				WHERE p.id=$1 AND p.tenant_id=$2 AND p.credential_hash=$3
				  AND p.status='active' AND p.revoked_at IS NULL
				  AND p.expires_at>$4
			) AS principal_active,
			($5::uuid IS NULL OR EXISTS(
				SELECT 1
				FROM agent_authorization_grants g
				WHERE g.id=$5 AND g.tenant_id=$2 AND g.principal_id=$1
				  AND g.expires_at>$4
			)) AS grant_active
	`, principal.ID, principal.TenantID, principal.CredentialHash, decisionAt, grantIDArg).Scan(&principalActive, &grantActive)
	return principalActive, grantActive, err
}

// agentAuthorizationDecisionActive samples one database time for both checks; any allow is tied to that decision instant.
func agentAuthorizationDecisionActive(ctx context.Context, tx pgx.Tx, principal TrustedAgentPrincipal, grantID string) (bool, bool, error) {
	var grantIDArg any
	if grantID != "" {
		grantIDArg = grantID
	}
	var principalActive, grantActive bool
	err := tx.QueryRow(ctx, `
		WITH decision_clock AS MATERIALIZED (
			SELECT clock_timestamp() AS decision_at
		)
		SELECT
			EXISTS(
				SELECT 1
				FROM agent_authorization_principals p
				CROSS JOIN decision_clock d
				WHERE p.id=$1 AND p.tenant_id=$2 AND p.credential_hash=$3
				  AND p.status='active' AND p.revoked_at IS NULL
				  AND p.expires_at>d.decision_at
			) AS principal_active,
			($4::uuid IS NULL OR EXISTS(
				SELECT 1
				FROM agent_authorization_grants g
				CROSS JOIN decision_clock d
				WHERE g.id=$4 AND g.tenant_id=$2 AND g.principal_id=$1
				  AND g.expires_at>d.decision_at
			)) AS grant_active
	`, principal.ID, principal.TenantID, principal.CredentialHash, grantIDArg).Scan(&principalActive, &grantActive)
	return principalActive, grantActive, err
}

func updateAgentAuthorizationDecision(ctx context.Context, tx pgx.Tx, principal TrustedAgentPrincipal, request AgentAuthorizationRequest, requestHash string, decision AgentAuthorizationDecision, grantID any) error {
	raw, err := json.Marshal(decision)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `
		UPDATE agent_authorization_requests
		SET state='complete', decision_json=$1, grant_id=$2, completed_at=clock_timestamp(), updated_at=clock_timestamp(),
		    expires_at=clock_timestamp()+interval '24 hours'
		WHERE tenant_id=$3 AND principal_id=$4 AND idempotency_key=$5 AND request_hash=$6
	`, raw, grantID, principal.TenantID, principal.ID, request.IdempotencyKey, requestHash)
	return err
}
