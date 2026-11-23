package repository

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

const AgentDelegationMaxDepth = 8

type AgentDelegationCreate struct {
	Name                        string                    `json:"name"`
	ProjectID                   string                    `json:"project_id"`
	ExpiresAt                   time.Time                 `json:"expires_at"`
	Grants                      []AgentAuthorizationGrant `json:"grants"`
	AuthorizationIdempotencyKey string                    `json:"authorization_idempotency_key"`
	IdempotencyKey              string                    `json:"idempotency_key"`
}

type AgentDelegation struct {
	ID                string    `json:"id"`
	TenantID          string    `json:"tenant_id"`
	ParentPrincipalID string    `json:"parent_principal_id"`
	ChildPrincipalID  string    `json:"child_principal_id"`
	ProjectID         string    `json:"project_id"`
	ExpiresAt         time.Time `json:"expires_at"`
	CreatedAt         time.Time `json:"created_at"`
	Status            string    `json:"status"`
}

type AgentDelegationCreated struct {
	Delegation AgentDelegation           `json:"delegation"`
	Credential string                    `json:"credential"`
	Grants     []AgentAuthorizationGrant `json:"grants"`
}

type AgentDelegationCall struct {
	ID                          string    `json:"id"`
	DelegationID                string    `json:"delegation_id"`
	ParentPrincipalID           string    `json:"parent_principal_id"`
	ChildPrincipalID            string    `json:"child_principal_id"`
	CallingPrincipalID          string    `json:"calling_principal_id"`
	ProjectID                   string    `json:"project_id"`
	Action                      string    `json:"action"`
	ResourceType                string    `json:"resource_type"`
	ResourceID                  string    `json:"resource_id"`
	AuthorizationIdempotencyKey string    `json:"authorization_idempotency_key"`
	RequestHash                 string    `json:"request_hash"`
	RunID                       string    `json:"run_id,omitempty"`
	InstanceID                  string    `json:"instance_id,omitempty"`
	ToolCallID                  string    `json:"tool_call_id,omitempty"`
	Allowed                     bool      `json:"allowed"`
	Reason                      string    `json:"reason"`
	CreatedAt                   time.Time `json:"created_at"`
}

type AgentDelegationRepository struct{ db agentAuthorizationDatabase }

func NewAgentDelegationRepository(db agentAuthorizationDatabase) *AgentDelegationRepository {
	return &AgentDelegationRepository{db: db}
}

type agentDelegationEdge struct {
	ID, ParentPrincipalID, ChildPrincipalID, ProjectID string
	ExpiresAt                                          time.Time
}

type agentDelegationQuota struct {
	PrincipalID, GrantID string
	QuotaMax             int64
	QuotaWindowSeconds   int
}

func validAgentIdempotencyKey(value string) bool {
	if len(value) < 16 || len(value) > 128 {
		return false
	}
	for _, ch := range value {
		if !((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
			(ch >= '0' && ch <= '9') || ch == '-' || ch == '_' || ch == '.' || ch == ':') {
			return false
		}
	}
	return true
}

func validateDelegationInput(input AgentDelegationCreate, now time.Time) error {
	if strings.TrimSpace(input.Name) == "" || len(strings.TrimSpace(input.Name)) > 128 ||
		!validAgentAuthorizationResourceID(input.ProjectID) ||
		!validAgentIdempotencyKey(input.AuthorizationIdempotencyKey) || !validAgentIdempotencyKey(input.IdempotencyKey) {
		return fmt.Errorf("%w: invalid delegation identity or project", ErrAgentAuthorizationInvalid)
	}
	if len(input.Grants) == 0 || len(input.Grants) > AgentAuthorizationMaxGrants {
		return fmt.Errorf("%w: delegated grants must be a non-empty bounded list", ErrAgentAuthorizationInvalid)
	}
	for _, grant := range input.Grants {
		if grant.ID != "" {
			return fmt.Errorf("%w: delegated grant ids are server generated", ErrAgentAuthorizationInvalid)
		}
	}
	return ValidateAgentAuthorizationPrincipalCreate(AgentAuthorizationPrincipalCreate{
		Name: input.Name, CreatedBy: "delegated", ExpiresAt: input.ExpiresAt, Grants: input.Grants,
	}, now)
}

func validateDelegatedGrantCeiling(parent, child AgentAuthorizationGrant, projectID string, delegationExpiry, now time.Time) error {
	if parent.Action != child.Action || parent.ResourceType != child.ResourceType || parent.ResourceID != child.ResourceID {
		return fmt.Errorf("%w: delegated grant exceeds parent scope", ErrAgentAuthorizationInvalid)
	}
	if !parent.ExpiresAt.After(now) || child.ExpiresAt.After(parent.ExpiresAt) || child.ExpiresAt.After(delegationExpiry) {
		return fmt.Errorf("%w: delegated grant outlives parent authority", ErrAgentAuthorizationInvalid)
	}
	if child.QuotaMax > parent.QuotaMax || child.QuotaWindowSeconds < parent.QuotaWindowSeconds {
		return fmt.Errorf("%w: delegated quota exceeds parent authority", ErrAgentAuthorizationInvalid)
	}
	if parent.Conditions["project_id"] != projectID || child.Conditions["project_id"] != projectID {
		return fmt.Errorf("%w: delegated grant must bind the exact project", ErrAgentAuthorizationInvalid)
	}
	for key, expected := range parent.Conditions {
		got, exists := child.Conditions[key]
		if !exists {
			return fmt.Errorf("%w: delegated grant removed a parent condition", ErrAgentAuthorizationInvalid)
		}
		wantJSON, err := json.Marshal(expected)
		if err != nil {
			return err
		}
		gotJSON, err := json.Marshal(got)
		if err != nil || string(wantJSON) != string(gotJSON) {
			return fmt.Errorf("%w: delegated grant changed a parent condition", ErrAgentAuthorizationInvalid)
		}
	}
	return nil
}

func bindDelegatedProject(request *AgentAuthorizationRequest, projectID string) bool {
	if request.Context == nil {
		request.Context = make(map[string]any)
	}
	if supplied, ok := request.Context["project_id"]; ok {
		return supplied == projectID
	}
	request.Context["project_id"] = projectID
	return true
}

// bindDelegatedRequest is the single project-binding rule shared by Authorize
// and T16 resolve, so both hash the same request: every edge of a delegated
// chain must name one project, which is bound into request.Context. A root
// principal (empty chain) leaves the request untouched.
func bindDelegatedRequest(chain []agentDelegationEdge, request *AgentAuthorizationRequest) error {
	if len(chain) == 0 {
		return nil
	}
	projectID := chain[0].ProjectID
	for _, edge := range chain {
		if edge.ProjectID != projectID {
			return ErrAgentAuthorizationPrincipalUnauthorized
		}
	}
	bindDelegatedProject(request, projectID)
	return ValidateAgentAuthorizationRequest(*request)
}

func stringContextField(values map[string]any, key string) string {
	value, ok := values[key].(string)
	if !ok || value == "" || len(value) > 256 || !utf8.ValidString(value) {
		return ""
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return ""
		}
	}
	return value
}

func delegationCreateHash(input AgentDelegationCreate) (string, error) {
	raw, err := json.Marshal(struct {
		Name      string                    `json:"name"`
		ProjectID string                    `json:"project_id"`
		ExpiresAt time.Time                 `json:"expires_at"`
		Grants    []AgentAuthorizationGrant `json:"grants"`
	}{strings.TrimSpace(input.Name), input.ProjectID, input.ExpiresAt.UTC(), input.Grants})
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}

func (r *AgentDelegationRepository) Create(ctx context.Context, parent TrustedAgentPrincipal, input AgentDelegationCreate) (*AgentDelegationCreated, error) {
	tenantID := strings.TrimSpace(parent.TenantID)
	if tenantID == "" || parent.ID == "" || len(parent.CredentialHash) != 64 {
		return nil, ErrAgentAuthorizationPrincipalUnauthorized
	}
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	if err := lockAgentDelegationHierarchy(ctx, tx, tenantID, parent.ID); err != nil {
		return nil, err
	}

	var currentHash, parentStatus string
	var parentExpires time.Time
	err = tx.QueryRow(ctx, "SELECT credential_hash,status,expires_at FROM agent_authorization_principals WHERE tenant_id=$1 AND id=$2 AND status='active' AND revoked_at IS NULL FOR UPDATE",
		tenantID, parent.ID).Scan(&currentHash, &parentStatus, &parentExpires)
	if errors.Is(err, pgx.ErrNoRows) || (err == nil && (parentStatus != "active" || subtle.ConstantTimeCompare([]byte(currentHash), []byte(parent.CredentialHash)) != 1)) {
		return nil, ErrAgentAuthorizationPrincipalUnauthorized
	}
	if err != nil {
		return nil, err
	}
	now, err := agentAuthorizationDatabaseNow(ctx, tx)
	if err != nil {
		return nil, err
	}
	if !parentExpires.After(now) {
		return nil, ErrAgentAuthorizationPrincipalUnauthorized
	}
	if err := validateDelegationInput(input, now); err != nil {
		return nil, err
	}
	if input.ExpiresAt.After(parentExpires) {
		return nil, fmt.Errorf("%w: delegation outlives parent principal", ErrAgentAuthorizationInvalid)
	}

	authRequest := AgentAuthorizationRequest{Action: "agents.delegate", ResourceType: "project", ResourceID: input.ProjectID,
		Context: map[string]any{"project_id": input.ProjectID}, IdempotencyKey: input.AuthorizationIdempotencyKey}
	if err := ValidateAgentAuthorizationRequest(authRequest); err != nil {
		return nil, err
	}
	authHash, err := agentAuthorizationRequestHash(authRequest)
	if err != nil {
		return nil, err
	}
	requestHash, err := delegationCreateHash(input)
	if err != nil {
		return nil, err
	}
	var rawDecision []byte
	var authGrantID, authStoredHash string
	err = tx.QueryRow(ctx, "SELECT request_hash,decision_json,COALESCE(grant_id::text,'') FROM agent_authorization_requests WHERE tenant_id=$1 AND principal_id=$2 AND idempotency_key=$3 AND state='complete' AND expires_at>$4 FOR UPDATE",
		tenantID, parent.ID, input.AuthorizationIdempotencyKey, now).Scan(&authStoredHash, &rawDecision, &authGrantID)
	if err != nil {
		return nil, ErrAgentAuthorizationInvalid
	}
	if authStoredHash != authHash {
		return nil, ErrAgentAuthorizationIdempotencyConflict
	}
	var authDecision AgentAuthorizationDecision
	if err := json.Unmarshal(rawDecision, &authDecision); err != nil {
		return nil, err
	}
	if !authDecision.Allowed || authDecision.Reason != "allowed" || authDecision.GrantID == "" || authDecision.GrantID != authGrantID ||
		authDecision.PrincipalID != parent.ID || authDecision.Action != authRequest.Action ||
		authDecision.ResourceType != authRequest.ResourceType || authDecision.ResourceID != authRequest.ResourceID ||
		authDecision.IdempotencyKey != authRequest.IdempotencyKey {
		return nil, ErrAgentAuthorizationInvalid
	}
	var parentAction, parentResourceType, parentResourceID, parentConditionsRaw string
	var parentGrantExpiry time.Time
	var parentQuotaMax int64
	var parentQuotaWindow int
	err = tx.QueryRow(ctx, "SELECT action,resource_type,resource_id,conditions_json::text,expires_at,quota_max,quota_window_seconds FROM agent_authorization_grants WHERE tenant_id=$1 AND principal_id=$2 AND id=$3 AND expires_at>$4 FOR UPDATE",
		tenantID, parent.ID, authGrantID, now).Scan(&parentAction, &parentResourceType, &parentResourceID, &parentConditionsRaw, &parentGrantExpiry, &parentQuotaMax, &parentQuotaWindow)
	if err != nil {
		return nil, err
	}
	var parentConditions map[string]any
	if err := json.Unmarshal([]byte(parentConditionsRaw), &parentConditions); err != nil {
		return nil, err
	}
	if parentAction != "agents.delegate" || parentResourceType != "project" || parentResourceID != input.ProjectID ||
		parentConditions["project_id"] != input.ProjectID || input.ExpiresAt.After(parentGrantExpiry) {
		return nil, ErrAgentAuthorizationInvalid
	}
	if err := validateDelegationChainScope(ctx, tx, tenantID, parent.ID, input.ProjectID, now); err != nil {
		return nil, err
	}

	parentByScope := make(map[string]AgentAuthorizationGrant, len(input.Grants))
	for _, child := range input.Grants {
		var parentGrant AgentAuthorizationGrant
		err := tx.QueryRow(ctx, "SELECT id::text,action,resource_type,resource_id,conditions_json::text,expires_at,quota_max,quota_window_seconds FROM agent_authorization_grants WHERE tenant_id=$1 AND principal_id=$2 AND action=$3 AND resource_type=$4 AND resource_id=$5 AND expires_at>$6 FOR UPDATE",
			tenantID, parent.ID, child.Action, child.ResourceType, child.ResourceID, now).Scan(&parentGrant.ID, &parentGrant.Action, &parentGrant.ResourceType, &parentGrant.ResourceID, &parentConditionsRaw, &parentGrant.ExpiresAt, &parentGrant.QuotaMax, &parentGrant.QuotaWindowSeconds)
		if err != nil {
			return nil, fmt.Errorf("%w: child scope is not granted to parent", ErrAgentAuthorizationInvalid)
		}
		if err := json.Unmarshal([]byte(parentConditionsRaw), &parentGrant.Conditions); err != nil {
			return nil, err
		}
		if err := validateDelegatedGrantCeiling(parentGrant, child, input.ProjectID, input.ExpiresAt, now); err != nil {
			return nil, err
		}
		parentByScope[child.Action+"\x00"+child.ResourceType+"\x00"+child.ResourceID] = parentGrant
	}

	credential, credentialHash, err := NewAgentToken()
	if err != nil {
		return nil, err
	}
	delegationID, childID := uuid.NewString(), uuid.NewString()
	_, err = tx.Exec(ctx, "INSERT INTO agent_authorization_principals (id,tenant_id,name,credential_hash,credential_prefix,status,expires_at,created_by,created_at,updated_at) VALUES ($1,$2,$3,$4,$5,'active',$6,$7,clock_timestamp(),clock_timestamp())",
		childID, tenantID, strings.TrimSpace(input.Name), credentialHash, credential[:8], input.ExpiresAt, parent.ID)
	if err != nil {
		return nil, mapDelegationInsertError(err)
	}
	_, err = tx.Exec(ctx, "INSERT INTO agent_delegations (id,tenant_id,parent_principal_id,child_principal_id,project_id,idempotency_key,authorization_idempotency_key,request_hash,expires_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)",
		delegationID, tenantID, parent.ID, childID, input.ProjectID, input.IdempotencyKey, input.AuthorizationIdempotencyKey, requestHash, input.ExpiresAt)
	if err != nil {
		return nil, mapDelegationInsertError(err)
	}
	createdGrants := make([]AgentAuthorizationGrant, 0, len(input.Grants))
	for _, grant := range input.Grants {
		grant.ID = uuid.NewString()
		conditionsRaw, err := json.Marshal(grant.Conditions)
		if err != nil {
			return nil, err
		}
		_, err = tx.Exec(ctx, "INSERT INTO agent_authorization_grants (id,tenant_id,principal_id,action,resource_type,resource_id,conditions_json,expires_at,quota_max,quota_window_seconds) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)",
			grant.ID, tenantID, childID, grant.Action, grant.ResourceType, grant.ResourceID, conditionsRaw, grant.ExpiresAt, grant.QuotaMax, grant.QuotaWindowSeconds)
		if err != nil {
			return nil, err
		}
		parentGrant := parentByScope[grant.Action+"\x00"+grant.ResourceType+"\x00"+grant.ResourceID]
		_, err = tx.Exec(ctx, "INSERT INTO agent_delegation_grants (tenant_id,delegation_id,parent_principal_id,child_principal_id,child_grant_id,parent_grant_id) VALUES ($1,$2,$3,$4,$5,$6)",
			tenantID, delegationID, parent.ID, childID, grant.ID, parentGrant.ID)
		if err != nil {
			return nil, err
		}
		createdGrants = append(createdGrants, grant)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return &AgentDelegationCreated{
		Delegation: AgentDelegation{ID: delegationID, TenantID: tenantID, ParentPrincipalID: parent.ID, ChildPrincipalID: childID, ProjectID: input.ProjectID, ExpiresAt: input.ExpiresAt, CreatedAt: now, Status: "active"},
		Credential: credential, Grants: createdGrants,
	}, nil
}

func mapDelegationInsertError(err error) error {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" {
		return ErrAgentAuthorizationIdempotencyConflict
	}
	return err
}

func validateDelegationChainScope(ctx context.Context, tx pgx.Tx, tenantID, principalID, projectID string, now time.Time) error {
	edges, err := lockAgentDelegationChain(ctx, tx, tenantID, principalID, now)
	if err != nil {
		return err
	}
	for _, edge := range edges {
		if edge.ProjectID != projectID {
			return fmt.Errorf("%w: delegated parent cannot cross projects", ErrAgentAuthorizationInvalid)
		}
	}
	return nil
}

func lockAgentDelegationChain(ctx context.Context, tx pgx.Tx, tenantID, childID string, now time.Time) ([]agentDelegationEdge, error) {
	return walkAgentDelegationChain(ctx, tx, tenantID, childID, now, " FOR UPDATE OF d,p")
}

// walkAgentDelegationChain is the single ancestry walk. Mutating paths pass the
// row-lock clause (via lockAgentDelegationChain); the read-only T16 resolve path
// passes "" so it never takes locks that could reorder Authorize's lock sequence.
func walkAgentDelegationChain(ctx context.Context, tx t13AuthorizationQuerier, tenantID, childID string, now time.Time, lockClause string) ([]agentDelegationEdge, error) {
	edges := make([]agentDelegationEdge, 0, 2)
	current := childID
	seen := map[string]bool{current: true}
	for depth := 0; depth < AgentDelegationMaxDepth; depth++ {
		var edge agentDelegationEdge
		var parentStatus string
		var parentExpires time.Time
		var parentRevoked, delegationRevoked *time.Time
		err := tx.QueryRow(ctx, "SELECT d.id::text,d.parent_principal_id::text,d.child_principal_id::text,d.project_id,d.expires_at,d.revoked_at,p.status,p.expires_at,p.revoked_at FROM agent_delegations d JOIN agent_authorization_principals p ON p.tenant_id=d.tenant_id AND p.id=d.parent_principal_id WHERE d.tenant_id=$1 AND d.child_principal_id=$2"+lockClause,
			tenantID, current).Scan(&edge.ID, &edge.ParentPrincipalID, &edge.ChildPrincipalID, &edge.ProjectID, &edge.ExpiresAt, &delegationRevoked, &parentStatus, &parentExpires, &parentRevoked)
		if errors.Is(err, pgx.ErrNoRows) {
			return edges, nil
		}
		if err != nil {
			return nil, err
		}
		if delegationRevoked != nil || seen[edge.ParentPrincipalID] || parentStatus != "active" || parentRevoked != nil || !parentExpires.After(now) || !edge.ExpiresAt.After(now) {
			return nil, ErrAgentAuthorizationPrincipalUnauthorized
		}
		edges = append(edges, edge)
		seen[edge.ParentPrincipalID] = true
		current = edge.ParentPrincipalID
	}
	var exists bool
	err := tx.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM agent_delegations WHERE tenant_id=$1 AND child_principal_id=$2)", tenantID, current).Scan(&exists)
	if err != nil {
		return nil, err
	}
	if exists {
		return nil, fmt.Errorf("%w: delegation depth exceeds limit", ErrAgentAuthorizationInvalid)
	}
	return edges, nil
}

func sameAgentDelegationChain(left, right []agentDelegationEdge) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i].ID != right[i].ID ||
			left[i].ParentPrincipalID != right[i].ParentPrincipalID ||
			left[i].ChildPrincipalID != right[i].ChildPrincipalID ||
			left[i].ProjectID != right[i].ProjectID {
			return false
		}
	}
	return true
}

func (r *AgentDelegationRepository) Revoke(ctx context.Context, tenantID, parentID, delegationID string) (bool, error) {
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return false, err
	}
	defer tx.Rollback(ctx)
	if err := lockAgentDelegationHierarchy(ctx, tx, tenantID, parentID); err != nil {
		return false, err
	}
	var childID string
	err = tx.QueryRow(ctx, "UPDATE agent_delegations SET revoked_at=COALESCE(revoked_at,clock_timestamp()) WHERE tenant_id=$1 AND parent_principal_id=$2 AND id=$3 AND revoked_at IS NULL RETURNING child_principal_id::text", tenantID, parentID, delegationID).Scan(&childID)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if err := revokeDelegationSubtree(ctx, tx, tenantID, childID); err != nil {
		return false, err
	}
	if err := tx.Commit(ctx); err != nil {
		return false, err
	}
	return true, nil
}

func revokeDelegationSubtree(ctx context.Context, tx pgx.Tx, tenantID, rootID string) error {
	_, err := tx.Exec(ctx, "WITH RECURSIVE descendants(id) AS (SELECT $2::uuid UNION SELECT d.child_principal_id FROM agent_delegations d JOIN descendants p ON d.parent_principal_id=p.id WHERE d.tenant_id=$1) UPDATE agent_delegations d SET revoked_at=COALESCE(d.revoked_at,clock_timestamp()) WHERE d.tenant_id=$1 AND (d.parent_principal_id IN (SELECT id FROM descendants) OR d.child_principal_id IN (SELECT id FROM descendants))", tenantID, rootID)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, "WITH RECURSIVE descendants(id) AS (SELECT $2::uuid UNION SELECT d.child_principal_id FROM agent_delegations d JOIN descendants p ON d.parent_principal_id=p.id WHERE d.tenant_id=$1) UPDATE agent_authorization_principals p SET status='revoked',revoked_at=COALESCE(p.revoked_at,clock_timestamp()),updated_at=clock_timestamp() WHERE p.tenant_id=$1 AND p.id IN (SELECT id FROM descendants)", tenantID, rootID)
	return err
}

func (r *AgentDelegationRepository) ListCalls(ctx context.Context, tenantID, parentPrincipalID, delegationID string, limit int) ([]AgentDelegationCall, error) {
	if limit < 1 || limit > 200 {
		return nil, fmt.Errorf("%w: invalid call limit", ErrAgentAuthorizationInvalid)
	}
	rows, err := r.db.Query(ctx, "SELECT id::text,delegation_id::text,parent_principal_id::text,child_principal_id::text,calling_principal_id::text,project_id,action,resource_type,resource_id,authorization_idempotency_key,request_hash,COALESCE(run_id,''),COALESCE(instance_id,''),COALESCE(tool_call_id,''),allowed,reason,created_at FROM agent_delegation_calls WHERE tenant_id=$1 AND parent_principal_id=$2 AND delegation_id=$3 ORDER BY created_at DESC,id LIMIT $4", tenantID, parentPrincipalID, delegationID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	calls := make([]AgentDelegationCall, 0)
	for rows.Next() {
		var call AgentDelegationCall
		if err := rows.Scan(&call.ID, &call.DelegationID, &call.ParentPrincipalID, &call.ChildPrincipalID, &call.CallingPrincipalID, &call.ProjectID, &call.Action, &call.ResourceType, &call.ResourceID, &call.AuthorizationIdempotencyKey, &call.RequestHash, &call.RunID, &call.InstanceID, &call.ToolCallID, &call.Allowed, &call.Reason, &call.CreatedAt); err != nil {
			return nil, err
		}
		calls = append(calls, call)
	}
	return calls, rows.Err()
}

func recordAgentDelegationCalls(ctx context.Context, tx pgx.Tx, tenantID string, chain []agentDelegationEdge, principal TrustedAgentPrincipal, request AgentAuthorizationRequest, requestHash string, decision AgentAuthorizationDecision) error {
	for _, edge := range chain {
		_, err := tx.Exec(ctx, "INSERT INTO agent_delegation_calls (id,tenant_id,delegation_id,parent_principal_id,child_principal_id,calling_principal_id,project_id,action,resource_type,resource_id,authorization_idempotency_key,request_hash,run_id,instance_id,tool_call_id,allowed,reason) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17) ON CONFLICT (tenant_id,delegation_id,calling_principal_id,authorization_idempotency_key,request_hash,allowed,reason) DO NOTHING",
			uuid.NewString(), tenantID, edge.ID, edge.ParentPrincipalID, edge.ChildPrincipalID, principal.ID, edge.ProjectID, request.Action, request.ResourceType, request.ResourceID, request.IdempotencyKey, requestHash, stringContextField(request.Context, "run_id"), stringContextField(request.Context, "instance_id"), stringContextField(request.Context, "tool_call_id"), decision.Allowed, decision.Reason)
		if err != nil {
			return err
		}
	}
	return nil
}

func consumeDelegationQuota(ctx context.Context, tx pgx.Tx, tenantID string, quota agentDelegationQuota, now time.Time) (bool, error) {
	var used int64
	err := tx.QueryRow(ctx, "INSERT INTO agent_authorization_usage (tenant_id,principal_id,grant_id,window_start,used,updated_at) VALUES ($1,$2,$3,to_timestamp(floor(extract(epoch from $5::timestamptz)/$4::double precision)*$4::double precision),1,clock_timestamp()) ON CONFLICT (tenant_id,principal_id,grant_id,window_start) DO UPDATE SET used=agent_authorization_usage.used+1,updated_at=clock_timestamp() WHERE agent_authorization_usage.used<$6 RETURNING used", tenantID, quota.PrincipalID, quota.GrantID, quota.QuotaWindowSeconds, now, quota.QuotaMax).Scan(&used)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	return err == nil, err
}

func ancestorGrantLimits(ctx context.Context, tx pgx.Tx, tenantID string, chain []agentDelegationEdge, childGrantID, action, resourceType, resourceID string, requestContext map[string]any, now time.Time) ([]agentDelegationQuota, error) {
	return walkAncestorGrantLimits(ctx, tx, tenantID, chain, childGrantID, action, resourceType, resourceID, requestContext, now, " FOR UPDATE OF g")
}

// walkAncestorGrantLimits is shared by Authorize/approvals (locking) and T16 resolve (lockClause "").
func walkAncestorGrantLimits(ctx context.Context, tx t13AuthorizationQuerier, tenantID string, chain []agentDelegationEdge, childGrantID, action, resourceType, resourceID string, requestContext map[string]any, now time.Time, lockClause string) ([]agentDelegationQuota, error) {
	quotas := make([]agentDelegationQuota, 0, len(chain))
	currentGrantID := childGrantID
	for _, edge := range chain {
		var parentGrantID, parentPrincipalID, parentAction, parentResourceType, parentResourceID, conditionsRaw string
		var expires time.Time
		var quotaMax int64
		var quotaWindow int
		err := tx.QueryRow(ctx, "SELECT m.parent_grant_id::text,m.parent_principal_id::text,g.action,g.resource_type,g.resource_id,g.conditions_json::text,g.expires_at,g.quota_max,g.quota_window_seconds FROM agent_delegation_grants m JOIN agent_authorization_grants g ON g.tenant_id=m.tenant_id AND g.principal_id=m.parent_principal_id AND g.id=m.parent_grant_id WHERE m.tenant_id=$1 AND m.delegation_id=$2 AND m.child_principal_id=$3 AND m.child_grant_id=$4 AND m.parent_principal_id=$5 AND g.expires_at>$6"+lockClause,
			tenantID, edge.ID, edge.ChildPrincipalID, currentGrantID, edge.ParentPrincipalID, now).Scan(&parentGrantID, &parentPrincipalID, &parentAction, &parentResourceType, &parentResourceID, &conditionsRaw, &expires, &quotaMax, &quotaWindow)
		if err != nil {
			return nil, ErrAgentAuthorizationInvalid
		}
		var conditions map[string]any
		if err := json.Unmarshal([]byte(conditionsRaw), &conditions); err != nil {
			return nil, err
		}
		if parentAction != action || parentResourceType != resourceType || parentResourceID != resourceID || !expires.After(now) || !agentAuthorizationConditionsMatch(conditions, requestContext) {
			return nil, ErrAgentAuthorizationPrincipalUnauthorized
		}
		quotas = append(quotas, agentDelegationQuota{PrincipalID: parentPrincipalID, GrantID: parentGrantID, QuotaMax: quotaMax, QuotaWindowSeconds: quotaWindow})
		currentGrantID = parentGrantID
	}
	return quotas, nil
}
