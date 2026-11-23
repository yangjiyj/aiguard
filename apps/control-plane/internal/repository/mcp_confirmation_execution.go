package repository

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

var mcpConfirmationHashPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

var (
	ErrMCPConfirmationExecutionStateNotUpdated = errors.New("mcp confirmation execution state was not updated")
	ErrMCPReplayConflict                       = errors.New("MCP invocation scope already exists with different request content")
)

type MCPConfirmationIdentity struct {
	ScopeKey             string
	CanonicalRequestHash string
	PrincipalHash        string
	ToolID               string
	SupplyChainRevision  string
	ApprovedSchemaHash   string
	ServerRouteHash      string
}

type MCPConfirmationExecution struct {
	ConfirmationID       string         `json:"confirmation_id"`
	InvocationID         string         `json:"invocation_id"`
	TenantID             string         `json:"tenant_id"`
	ConfirmationStatus   string         `json:"status"`
	ExecutionStatus      string         `json:"execution_status"`
	EvidenceStatus       string         `json:"evidence_status"`
	ExpiresAt            time.Time      `json:"expires_at"`
	AttemptID            string         `json:"-"`
	StartedAt            *time.Time     `json:"started_at,omitempty"`
	FinishedAt           *time.Time     `json:"finished_at,omitempty"`
	ResponseSummary      map[string]any `json:"response_summary,omitempty"`
	ErrorCode            string         `json:"error_code,omitempty"`
	AuditErrorCode       string         `json:"audit_error_code,omitempty"`
	ResultAvailable      bool           `json:"result_available"`
	CreatedAt            time.Time      `json:"created_at"`
	UpdatedAt            time.Time      `json:"updated_at"`
	ScopeKey             string         `json:"-"`
	CanonicalRequestHash string         `json:"-"`
	PrincipalHash        string         `json:"-"`
	ReplayCiphertext     string         `json:"-"`
	ReplayContextHash    string         `json:"-"`
	ToolID               string         `json:"-"`
	SupplyChainRevision  string         `json:"-"`
	ApprovedSchemaHash   string         `json:"-"`
	ServerRouteHash      string         `json:"-"`
	AuditRequestID       string         `json:"-"`
	ToolLogID            string         `json:"-"`
	ResultCiphertext     string         `json:"-"`
	ResultHash           string         `json:"-"`
	ResultPlaintextBytes int64          `json:"-"`
	ResultHTTPStatus     int            `json:"-"`
	ResultMediaType      string         `json:"-"`
	ResultRPCID          string         `json:"-"`
	ResultProtocol       string         `json:"-"`
	ResultSessionID      string         `json:"-"`
	ResultExpiresAt      *time.Time     `json:"-"`
}

func validMCPConfirmationIdentity(identity MCPConfirmationIdentity) bool {
	return mcpConfirmationHashPattern.MatchString(identity.ScopeKey) &&
		mcpConfirmationHashPattern.MatchString(identity.CanonicalRequestHash) &&
		mcpConfirmationHashPattern.MatchString(identity.PrincipalHash) &&
		identity.ToolID != "" && identity.SupplyChainRevision != "" &&
		mcpConfirmationHashPattern.MatchString(identity.ApprovedSchemaHash) &&
		mcpConfirmationHashPattern.MatchString(identity.ServerRouteHash)
}

func (r *AgentGuardPolicyRepository) CreateMCPConfirmationDeduplicated(
	ctx context.Context,
	c *AgentGuardConfirmation,
	identity MCPConfirmationIdentity,
	ciphertext, contextHash string,
) (*MCPConfirmationExecution, bool, error) {
	if c == nil || c.Source != "mcp" {
		return nil, false, errors.New("mcp confirmation source is required")
	}
	if !strings.HasPrefix(ciphertext, "enc:v1:") || !mcpConfirmationHashPattern.MatchString(contextHash) {
		return nil, false, errors.New("invalid encrypted MCP replay context")
	}
	if !validMCPConfirmationIdentity(identity) {
		return nil, false, errors.New("invalid MCP confirmation identity")
	}
	c.ID = "agcf_" + uuid.New().String()
	invocationID := "mcpinv_" + uuid.New().String()
	if c.Status == "" {
		c.Status = "pending"
	}
	if c.TimeoutAction == "" {
		c.TimeoutAction = AgentGuardActionBlock
	}
	if c.ExpiresAt.IsZero() {
		c.ExpiresAt = time.Now().Add(10 * time.Minute)
	}
	c.ToolCallArguments = ""
	evidenceJSON, err := json.Marshal(mapOrEmpty(c.EvidenceJSON))
	if err != nil {
		return nil, false, fmt.Errorf("marshal confirmation evidence: %w", err)
	}
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return nil, false, fmt.Errorf("begin mcp confirmation transaction: %w", err)
	}
	defer tx.Rollback(ctx)
	now := time.Now()
	if _, err = tx.Exec(ctx, `
		INSERT INTO agentguard_confirmations (
			id, tenant_id, request_id, trace_id, tool_name, raw_decision, effective_decision,
			status, timeout_action, reason, evidence_json, expires_at, created_at,
			tool_call_id, tool_call_arguments, choice_index, source
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,NULL,$15,'mcp')
	`, c.ID, c.TenantID, c.RequestID, c.TraceID, c.ToolName, c.RawDecision, c.EffectiveDecision,
		c.Status, c.TimeoutAction, c.Reason, evidenceJSON, c.ExpiresAt, now, c.ToolCallID, c.ChoiceIndex); err != nil {
		return nil, false, fmt.Errorf("create mcp confirmation: %w", err)
	}
	tag, err := tx.Exec(ctx, `
		INSERT INTO mcp_confirmation_executions (
			confirmation_id, tenant_id, invocation_id, scope_key, canonical_request_hash, principal_hash,
			replay_context_ciphertext, replay_context_hash, tool_id, supply_chain_revision,
			approved_schema_hash, server_route_hash, execution_status, evidence_status, created_at, updated_at
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,'pending','pending',$13,$13)
		ON CONFLICT (tenant_id, scope_key) DO NOTHING
	`, c.ID, c.TenantID, invocationID, identity.ScopeKey, identity.CanonicalRequestHash,
		identity.PrincipalHash, ciphertext, contextHash, identity.ToolID,
		identity.SupplyChainRevision, identity.ApprovedSchemaHash, identity.ServerRouteHash, now)
	if err != nil {
		return nil, false, fmt.Errorf("create mcp confirmation execution: %w", err)
	}
	if tag.RowsAffected() == 0 {
		if err := tx.Rollback(ctx); err != nil && !errors.Is(err, pgx.ErrTxClosed) {
			return nil, false, fmt.Errorf("rollback duplicate mcp confirmation: %w", err)
		}
		existing, getErr := r.GetMCPConfirmationExecutionByScope(ctx, c.TenantID, identity.ScopeKey)
		if getErr != nil {
			return nil, false, getErr
		}
		if existing == nil {
			return nil, false, errors.New("duplicate MCP invocation disappeared")
		}
		c.ID = existing.ConfirmationID
		if existing.CanonicalRequestHash != identity.CanonicalRequestHash {
			return existing, false, ErrMCPReplayConflict
		}
		return existing, false, nil
	}
	if err = tx.Commit(ctx); err != nil {
		return nil, false, fmt.Errorf("commit mcp confirmation: %w", err)
	}
	c.CreatedAt = now
	state, err := r.GetMCPConfirmationExecution(ctx, c.TenantID, c.ID)
	return state, true, err
}

// CreateMCPConfirmation remains as a compatibility helper for older tests.
// Production creation must use CreateMCPConfirmationDeduplicated.
func (r *AgentGuardPolicyRepository) CreateMCPConfirmation(ctx context.Context, c *AgentGuardConfirmation, ciphertext, contextHash string) error {
	seed := sha256.Sum256([]byte(uuid.New().String()))
	unique := hex.EncodeToString(seed[:])
	legacy := MCPConfirmationIdentity{
		ScopeKey: unique, CanonicalRequestHash: unique,
		PrincipalHash: unique, ToolID: "legacy-tool",
		SupplyChainRevision: "legacy", ApprovedSchemaHash: unique, ServerRouteHash: unique,
	}
	_, _, err := r.CreateMCPConfirmationDeduplicated(ctx, c, legacy, ciphertext, contextHash)
	return err
}

func (r *AgentGuardPolicyRepository) convergeStaleMCPExecutions(ctx context.Context, tenantID, confirmationID string) error {
	if tenantID == "" {
		return nil
	}
	_, err := r.db.Exec(ctx, `
		UPDATE mcp_confirmation_executions
		SET execution_status='unknown',
		    evidence_status=CASE WHEN evidence_status='complete' THEN 'complete' ELSE 'failed' END,
		    finished_at=NOW(), error_code='gateway_execution_stale',
		    audit_error_code=CASE WHEN evidence_status='complete' THEN audit_error_code ELSE 'gateway_execution_stale' END,
		    response_summary=jsonb_build_object(
		      'outcome','unknown',
		      'execution_forwarded', gateway_claimed_at IS NOT NULL
		    ),
		    updated_at=NOW()
		WHERE tenant_id=$1
		  AND ($2='' OR confirmation_id=$2)
		  AND execution_status='executing'
		  AND started_at < NOW()-INTERVAL '30 seconds'
	`, tenantID, confirmationID)
	if err != nil {
		return fmt.Errorf("converge stale mcp execution: %w", err)
	}
	return nil
}

func (r *AgentGuardPolicyRepository) GetMCPConfirmationExecution(ctx context.Context, tenantID, confirmationID string) (*MCPConfirmationExecution, error) {
	if err := r.convergeStaleMCPExecutions(ctx, tenantID, confirmationID); err != nil {
		return nil, err
	}
	return r.getMCPConfirmationExecution(ctx, `e.tenant_id = $1 AND e.confirmation_id = $2`, tenantID, confirmationID)
}

func (r *AgentGuardPolicyRepository) GetMCPConfirmationExecutionByScope(ctx context.Context, tenantID, scopeKey string) (*MCPConfirmationExecution, error) {
	if err := r.convergeStaleMCPExecutions(ctx, tenantID, ""); err != nil {
		return nil, err
	}
	return r.getMCPConfirmationExecution(ctx, `e.tenant_id = $1 AND e.scope_key = $2`, tenantID, scopeKey)
}

func (r *AgentGuardPolicyRepository) getMCPConfirmationExecution(ctx context.Context, where string, args ...any) (*MCPConfirmationExecution, error) {
	row := r.db.QueryRow(ctx, mcpConfirmationExecutionSelect+` WHERE `+where, args...)
	state, err := scanMCPConfirmationExecution(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get mcp confirmation execution: %w", err)
	}
	return state, nil
}

func (r *AgentGuardPolicyRepository) ClaimMCPConfirmationExecution(ctx context.Context, tenantID, confirmationID string) (*MCPConfirmationExecution, bool, error) {
	attemptID := "mcpexec_" + uuid.New().String()
	tag, err := r.db.Exec(ctx, `
		UPDATE mcp_confirmation_executions e
		SET execution_status = 'executing', attempt_id = $3, started_at = NOW(),
		    finished_at = NULL, error_code = NULL, response_summary = '{}'::jsonb, updated_at = NOW()
		FROM agentguard_confirmations c
		WHERE e.confirmation_id = $2 AND e.tenant_id = $1
		  AND c.id = e.confirmation_id AND c.tenant_id = e.tenant_id
		  AND c.status = 'approved' AND c.expires_at > NOW()
		  AND e.execution_status = 'pending'
	`, tenantID, confirmationID, attemptID)
	if err != nil {
		return nil, false, fmt.Errorf("claim mcp confirmation execution: %w", err)
	}
	if tag.RowsAffected() == 1 {
		state, getErr := r.GetMCPConfirmationExecution(ctx, tenantID, confirmationID)
		return state, true, getErr
	}
	// A gateway claim older than the bounded CP->GW call cannot remain
	// indefinitely executing. It converges to unknown and is never retryable.
	_, staleErr := r.db.Exec(ctx, `
		UPDATE mcp_confirmation_executions
		SET execution_status='unknown', evidence_status=CASE WHEN evidence_status='complete' THEN 'complete' ELSE 'failed' END,
		    finished_at=NOW(), error_code='gateway_execution_stale',
		    audit_error_code=CASE WHEN evidence_status='complete' THEN audit_error_code ELSE 'gateway_execution_stale' END,
		    response_summary=jsonb_build_object('outcome','unknown'), updated_at=NOW()
		WHERE tenant_id=$1 AND confirmation_id=$2 AND execution_status='executing'
		  AND gateway_claimed_at IS NOT NULL AND started_at < NOW()-INTERVAL '30 seconds'
	`, tenantID, confirmationID)
	if staleErr != nil {
		return nil, false, fmt.Errorf("converge stale mcp execution: %w", staleErr)
	}
	_, expireErr := r.db.Exec(ctx, `
		UPDATE mcp_confirmation_executions e
		SET execution_status = 'failed', evidence_status = 'failed', finished_at = NOW(),
		    error_code = 'approval_expired', audit_error_code = 'approval_expired',
		    response_summary = jsonb_build_object('outcome', 'failed'), updated_at = NOW()
		FROM agentguard_confirmations c
		WHERE e.tenant_id = $1 AND e.confirmation_id = $2
		  AND e.execution_status = 'pending'
		  AND c.id = e.confirmation_id AND c.tenant_id = e.tenant_id
		  AND c.status = 'approved' AND c.expires_at <= NOW()
	`, tenantID, confirmationID)
	if expireErr != nil {
		return nil, false, fmt.Errorf("expire mcp confirmation execution: %w", expireErr)
	}
	state, err := r.GetMCPConfirmationExecution(ctx, tenantID, confirmationID)
	return state, false, err
}

func (r *AgentGuardPolicyRepository) MarkMCPConfirmationUnknown(ctx context.Context, tenantID, confirmationID, attemptID, errorCode string) error {
	tag, err := r.db.Exec(ctx, `
		UPDATE mcp_confirmation_executions
		SET execution_status = 'unknown',
		    evidence_status = CASE WHEN evidence_status='complete' THEN 'complete' ELSE 'failed' END,
		    finished_at = NOW(), error_code = NULLIF($4, ''),
		    audit_error_code = CASE WHEN evidence_status='complete' THEN audit_error_code ELSE NULLIF($4, '') END,
		    response_summary = jsonb_build_object('outcome', 'unknown'), updated_at = NOW()
		WHERE tenant_id = $1 AND confirmation_id = $2 AND attempt_id = $3
		  AND execution_status = 'executing'
	`, tenantID, confirmationID, attemptID, errorCode)
	if err != nil {
		return fmt.Errorf("mark mcp confirmation unknown: %w", err)
	}
	if tag.RowsAffected() == 0 {
		state, getErr := r.GetMCPConfirmationExecution(ctx, tenantID, confirmationID)
		if getErr != nil {
			return getErr
		}
		if state == nil {
			return ErrMCPConfirmationExecutionStateNotUpdated
		}
	}
	return nil
}

func (r *AgentGuardPolicyRepository) ListMCPConfirmationExecutions(ctx context.Context, tenantID string, confirmationIDs []string) (map[string]*MCPConfirmationExecution, error) {
	out := make(map[string]*MCPConfirmationExecution)
	if tenantID == "" || len(confirmationIDs) == 0 {
		return out, nil
	}
	if err := r.convergeStaleMCPExecutions(ctx, tenantID, ""); err != nil {
		return nil, err
	}
	rows, err := r.db.Query(ctx, mcpConfirmationExecutionSelect+` WHERE e.tenant_id = $1 AND e.confirmation_id = ANY($2)`, tenantID, confirmationIDs)
	if err != nil {
		return nil, fmt.Errorf("list mcp confirmation executions: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		state, scanErr := scanMCPConfirmationExecution(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		out[state.ConfirmationID] = state
	}
	return out, rows.Err()
}

const mcpConfirmationExecutionSelect = `
	SELECT e.confirmation_id, e.invocation_id, e.tenant_id, c.status, e.execution_status,
	       e.evidence_status, c.expires_at, COALESCE(e.attempt_id,''), e.started_at, e.finished_at,
	       e.response_summary, COALESCE(e.error_code,''), COALESCE(e.audit_error_code,''),
	       e.created_at, e.updated_at, e.scope_key, e.canonical_request_hash, e.principal_hash,
	       e.replay_context_ciphertext, e.replay_context_hash, e.tool_id, e.supply_chain_revision,
	       e.approved_schema_hash, e.server_route_hash, COALESCE(e.audit_request_id,''),
	       COALESCE(e.tool_log_id,''), COALESCE(e.result_ciphertext,''), COALESCE(e.result_hash,''),
	       COALESCE(e.result_plaintext_bytes,0), COALESCE(e.result_http_status,0),
	       COALESCE(e.result_media_type,''), COALESCE(e.result_rpc_id,''),
	       COALESCE(e.result_protocol,''), COALESCE(e.result_session_id,''), e.result_expires_at
	FROM mcp_confirmation_executions e
	JOIN agentguard_confirmations c ON c.id=e.confirmation_id AND c.tenant_id=e.tenant_id
`

func scanMCPConfirmationExecution(row pgx.Row) (*MCPConfirmationExecution, error) {
	var state MCPConfirmationExecution
	var summaryJSON []byte
	if err := row.Scan(
		&state.ConfirmationID, &state.InvocationID, &state.TenantID, &state.ConfirmationStatus,
		&state.ExecutionStatus, &state.EvidenceStatus, &state.ExpiresAt, &state.AttemptID,
		&state.StartedAt, &state.FinishedAt, &summaryJSON, &state.ErrorCode, &state.AuditErrorCode,
		&state.CreatedAt, &state.UpdatedAt, &state.ScopeKey, &state.CanonicalRequestHash,
		&state.PrincipalHash, &state.ReplayCiphertext, &state.ReplayContextHash, &state.ToolID,
		&state.SupplyChainRevision, &state.ApprovedSchemaHash, &state.ServerRouteHash,
		&state.AuditRequestID, &state.ToolLogID, &state.ResultCiphertext, &state.ResultHash,
		&state.ResultPlaintextBytes, &state.ResultHTTPStatus, &state.ResultMediaType,
		&state.ResultRPCID, &state.ResultProtocol, &state.ResultSessionID, &state.ResultExpiresAt,
	); err != nil {
		return nil, err
	}
	_ = json.Unmarshal(summaryJSON, &state.ResponseSummary)
	state.ResultAvailable = state.ExecutionStatus == "executed" && state.ResultCiphertext != "" &&
		state.ResultExpiresAt != nil && state.ResultExpiresAt.After(time.Now())
	return &state, nil
}
