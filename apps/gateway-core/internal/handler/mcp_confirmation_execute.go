package handler

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"mime"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/yangjiyj/aiguard/packages/shared-go/protection"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/agentguard"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/auth"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
	"github.com/yangjiyj/aiguard/packages/shared-go/headeraudit"
	"github.com/yangjiyj/aiguard/packages/shared-go/mcpconfirmation"
	"github.com/yangjiyj/aiguard/packages/shared-go/retentionartifact"
	"github.com/yangjiyj/aiguard/packages/shared-go/secrets"
	"github.com/yangjiyj/aiguard/packages/shared-go/securityexit"
)

type mcpConfirmationExecutionRecord struct {
	ConfirmationID       string
	InvocationID         string
	TenantID             string
	ConfirmationState    string
	ToolCallID           string
	ExecutionStatus      string
	EvidenceStatus       string
	AttemptID            string
	ReplayCiphertext     string
	ReplayContextHash    string
	ScopeKey             string
	CanonicalRequestHash string
	PrincipalHash        string
	ToolID               string
	SupplyChainRevision  string
	ApprovedSchemaHash   string
	ServerRouteHash      string
	AuditRequestID       string
	AuditErrorCode       string
	ToolLogID            string
	ResponseSummary      map[string]any
	ErrorCode            string
	ResultCiphertext     string
	ResultHash           string
	ResultPlaintextBytes int64
	ResultHTTPStatus     int
	ResultMediaType      string
	ResultRPCID          string
	ResultProtocol       string
	ResultSessionID      string
	ResultExpiresAt      *time.Time
	ExpiresAt            time.Time
}

type mcpExecutionCompletion struct {
	Status               string
	Summary              map[string]any
	Destructive          bool
	ErrorCode            string
	EvidenceStatus       string
	AuditErrorCode       string
	ToolLogID            string
	ResultCiphertext     string
	ResultHash           string
	ResultPlaintextBytes int64
	ResultHTTPStatus     int
	ResultMediaType      string
	ResultRPCID          string
	ResultProtocol       string
	ResultSessionID      string
	ResultExpiresAt      *time.Time
}

type mcpConfirmationExecutionStore interface {
	ClaimGatewayExecution(context.Context, string, string, string) (*mcpConfirmationExecutionRecord, bool, error)
	GetGatewayExecution(context.Context, string, string) (*mcpConfirmationExecutionRecord, error)
	BeginGatewayEvidence(context.Context, string, string, string, string) error
	CompleteGatewayExecution(context.Context, string, string, string, mcpExecutionCompletion) (*mcpConfirmationExecutionRecord, error)
}

type pgMCPConfirmationExecutionStore struct{ db *pgxpool.Pool }

func newPGMCPConfirmationExecutionStore(db *pgxpool.Pool) mcpConfirmationExecutionStore {
	return &pgMCPConfirmationExecutionStore{db: db}
}

func (s *pgMCPConfirmationExecutionStore) ClaimGatewayExecution(ctx context.Context, tenantID, confirmationID, attemptID string) (*mcpConfirmationExecutionRecord, bool, error) {
	if s == nil || s.db == nil {
		return nil, false, errors.New("MCP confirmation execution store is unavailable")
	}
	tag, err := s.db.Exec(ctx, `
		UPDATE mcp_confirmation_executions e
		SET gateway_claimed_at = NOW(), updated_at = NOW()
		FROM agentguard_confirmations c
		WHERE e.tenant_id = $1 AND e.confirmation_id = $2 AND e.attempt_id = $3
		  AND e.execution_status = 'executing' AND e.gateway_claimed_at IS NULL
		  AND c.id = e.confirmation_id AND c.tenant_id = e.tenant_id
		  AND c.status = 'approved' AND c.expires_at > NOW()
	`, tenantID, confirmationID, attemptID)
	if err != nil {
		return nil, false, fmt.Errorf("claim gateway MCP execution: %w", err)
	}
	record, err := s.GetGatewayExecution(ctx, tenantID, confirmationID)
	return record, tag.RowsAffected() == 1, err
}

func (s *pgMCPConfirmationExecutionStore) GetGatewayExecution(ctx context.Context, tenantID, confirmationID string) (*mcpConfirmationExecutionRecord, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("MCP confirmation execution store is unavailable")
	}
	row := s.db.QueryRow(ctx, mcpGatewayExecutionSelect+` WHERE e.tenant_id=$1 AND e.confirmation_id=$2`, tenantID, confirmationID)
	record, err := scanGatewayMCPExecution(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get gateway MCP execution: %w", err)
	}
	return record, nil
}

func (s *pgMCPConfirmationExecutionStore) BeginGatewayEvidence(ctx context.Context, tenantID, confirmationID, attemptID, auditRequestID string) error {
	tag, err := s.db.Exec(ctx, `
		UPDATE mcp_confirmation_executions
		SET evidence_status='pending', audit_request_id=$4, audit_error_code=NULL, updated_at=NOW()
		WHERE tenant_id=$1 AND confirmation_id=$2 AND attempt_id=$3
		  AND execution_status='executing' AND gateway_claimed_at IS NOT NULL
	`, tenantID, confirmationID, attemptID, auditRequestID)
	if err != nil {
		return fmt.Errorf("persist MCP audit intent: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return errors.New("MCP audit intent state was not updated")
	}
	return nil
}

func (s *pgMCPConfirmationExecutionStore) CompleteGatewayExecution(
	ctx context.Context, tenantID, confirmationID, attemptID string, completion mcpExecutionCompletion,
) (*mcpConfirmationExecutionRecord, error) {
	if completion.Status != "executed" && completion.Status != "failed" && completion.Status != "unknown" {
		return nil, fmt.Errorf("invalid MCP execution status %q", completion.Status)
	}
	if completion.EvidenceStatus != "complete" && completion.EvidenceStatus != "failed" {
		return nil, fmt.Errorf("invalid MCP evidence status %q", completion.EvidenceStatus)
	}
	completion = sanitizeMCPExecutionCompletion(completion)
	summaryJSON, err := json.Marshal(completion.Summary)
	if err != nil {
		return nil, err
	}
	tag, err := s.db.Exec(ctx, `
		UPDATE mcp_confirmation_executions
		SET execution_status=$4, evidence_status=$5, response_summary=$6,
		    error_code=NULLIF($7,''), audit_error_code=NULLIF($8,''), tool_log_id=NULLIF($9,''),
		    result_ciphertext=NULLIF($10,''), result_hash=NULLIF($11,''),
		    result_plaintext_bytes=CASE WHEN $12::bigint=0 AND NULLIF($10,'') IS NULL THEN NULL ELSE $12 END,
		    result_http_status=CASE WHEN $13::int=0 THEN NULL ELSE $13 END,
		    result_media_type=NULLIF($14,''), result_rpc_id=NULLIF($15,''),
		    result_protocol=NULLIF($16,''), result_session_id=NULLIF($17,''),
		    result_expires_at=$18, finished_at=NOW(), updated_at=NOW()
		WHERE tenant_id=$1 AND confirmation_id=$2 AND attempt_id=$3
		  AND execution_status='executing' AND gateway_claimed_at IS NOT NULL
	`, tenantID, confirmationID, attemptID, completion.Status, completion.EvidenceStatus,
		summaryJSON, completion.ErrorCode, completion.AuditErrorCode, completion.ToolLogID,
		completion.ResultCiphertext, completion.ResultHash, completion.ResultPlaintextBytes,
		completion.ResultHTTPStatus, completion.ResultMediaType, completion.ResultRPCID,
		completion.ResultProtocol, completion.ResultSessionID, completion.ResultExpiresAt)
	if err != nil {
		return nil, fmt.Errorf("complete gateway MCP execution: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return s.GetGatewayExecution(ctx, tenantID, confirmationID)
	}
	return s.GetGatewayExecution(ctx, tenantID, confirmationID)
}

const mcpGatewayExecutionSelect = `
	SELECT e.confirmation_id, COALESCE(e.invocation_id,''), e.tenant_id, c.status,
	       COALESCE(c.tool_call_id,''), e.execution_status, e.evidence_status,
	       COALESCE(e.attempt_id,''), e.replay_context_ciphertext, e.replay_context_hash,
	       COALESCE(e.scope_key,''), COALESCE(e.canonical_request_hash,''), COALESCE(e.principal_hash,''),
	       e.tool_id, e.supply_chain_revision, e.approved_schema_hash, e.server_route_hash,
	       COALESCE(e.audit_request_id,''), COALESCE(e.audit_error_code,''), COALESCE(e.tool_log_id,''),
	       e.response_summary, COALESCE(e.error_code,''), COALESCE(e.result_ciphertext,''),
	       COALESCE(e.result_hash,''), COALESCE(e.result_plaintext_bytes,0),
	       COALESCE(e.result_http_status,0), COALESCE(e.result_media_type,''),
	       COALESCE(e.result_rpc_id,''), COALESCE(e.result_protocol,''),
	       COALESCE(e.result_session_id,''), e.result_expires_at, c.expires_at
	FROM mcp_confirmation_executions e
	JOIN agentguard_confirmations c ON c.id=e.confirmation_id AND c.tenant_id=e.tenant_id
`

func scanGatewayMCPExecution(row pgx.Row) (*mcpConfirmationExecutionRecord, error) {
	var record mcpConfirmationExecutionRecord
	var summaryJSON []byte
	if err := row.Scan(
		&record.ConfirmationID, &record.InvocationID, &record.TenantID, &record.ConfirmationState,
		&record.ToolCallID, &record.ExecutionStatus, &record.EvidenceStatus, &record.AttemptID,
		&record.ReplayCiphertext, &record.ReplayContextHash, &record.ScopeKey,
		&record.CanonicalRequestHash, &record.PrincipalHash, &record.ToolID,
		&record.SupplyChainRevision, &record.ApprovedSchemaHash, &record.ServerRouteHash,
		&record.AuditRequestID, &record.AuditErrorCode, &record.ToolLogID, &summaryJSON,
		&record.ErrorCode, &record.ResultCiphertext, &record.ResultHash,
		&record.ResultPlaintextBytes, &record.ResultHTTPStatus, &record.ResultMediaType,
		&record.ResultRPCID, &record.ResultProtocol, &record.ResultSessionID,
		&record.ResultExpiresAt, &record.ExpiresAt,
	); err != nil {
		return nil, err
	}
	_ = json.Unmarshal(summaryJSON, &record.ResponseSummary)
	return &record, nil
}

type mcpApprovedExecutionRunner interface {
	executeApprovedMCPConfirmation(context.Context, *mcpConfirmationExecutionRecord) mcpExecutionCompletion
}

type mcpConfirmationExecutionHandler struct {
	store         mcpConfirmationExecutionStore
	proxy         mcpApprovedExecutionRunner
	internalToken string
	enabled       bool
}

func NewMCPConfirmationExecutionHandler(db *pgxpool.Pool, proxy *MCPProxyHandler, internalToken string, enabled bool) http.Handler {
	return newMCPConfirmationExecutionHandler(newPGMCPConfirmationExecutionStore(db), proxy, internalToken, enabled)
}

func newMCPConfirmationExecutionHandler(store mcpConfirmationExecutionStore, proxy mcpApprovedExecutionRunner, internalToken string, enabled bool) http.Handler {
	return &mcpConfirmationExecutionHandler{store: store, proxy: proxy, internalToken: internalToken, enabled: enabled}
}

func (h *mcpConfirmationExecutionHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if h.internalToken == "" || subtle.ConstantTimeCompare([]byte(r.Header.Get(headeraudit.InternalTokenHeader)), []byte(h.internalToken)) != 1 {
		writeMCPExecutionHTTPError(w, http.StatusUnauthorized, "unauthorized", "internal authentication failed")
		return
	}
	tenantID := strings.TrimSpace(r.Header.Get("X-Tenant-ID"))
	confirmationID := chi.URLParam(r, "id")
	if tenantID == "" || confirmationID == "" {
		writeMCPExecutionHTTPError(w, http.StatusBadRequest, "invalid_identity", "tenant and confirmation are required")
		return
	}
	var request struct {
		AttemptID string `json:"attempt_id"`
	}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil || request.AttemptID == "" {
		writeMCPExecutionHTTPError(w, http.StatusBadRequest, "invalid_request", "attempt_id is required")
		return
	}

	record, claimed, err := h.store.ClaimGatewayExecution(r.Context(), tenantID, confirmationID, request.AttemptID)
	if err != nil {
		writeMCPExecutionHTTPError(w, http.StatusServiceUnavailable, "state_unavailable", "execution state is unavailable")
		return
	}
	if record == nil || record.AttemptID != request.AttemptID {
		writeMCPExecutionHTTPError(w, http.StatusNotFound, "not_found", "confirmation execution was not found")
		return
	}
	if !claimed {
		if record.ExecutionStatus == "executed" || record.ExecutionStatus == "failed" || record.ExecutionStatus == "unknown" {
			if record.ErrorCode == "approval_expired" {
				writeMCPExecutionJSON(w, http.StatusConflict, record)
				return
			}
			writeMCPExecutionJSON(w, http.StatusOK, record)
			return
		}
		writeMCPExecutionJSON(w, http.StatusAccepted, record)
		return
	}
	auditRequestID := "req_mcp_confirmation_" + uuid.New().String()
	if err := h.store.BeginGatewayEvidence(r.Context(), record.TenantID, record.ConfirmationID, record.AttemptID, auditRequestID); err != nil {
		h.completeAndWrite(w, r, record, mcpExecutionCompletion{
			Status: "failed", Summary: map[string]any{"outcome": "failed"},
			ErrorCode: "audit_intent_persist_failed", EvidenceStatus: "failed",
			AuditErrorCode: "audit_intent_persist_failed",
		})
		return
	}
	record.AuditRequestID = auditRequestID
	if !h.enabled {
		h.completeAndWrite(w, r, record, mcpExecutionCompletion{
			Status: "failed", Summary: map[string]any{"outcome": "failed"},
			ErrorCode: "mcp_gateway_disabled", EvidenceStatus: "failed", AuditErrorCode: "gateway_disabled",
		})
		return
	}
	if h.proxy == nil {
		h.completeAndWrite(w, r, record, mcpExecutionCompletion{
			Status: "failed", Summary: map[string]any{"outcome": "failed"},
			ErrorCode: "mcp_execution_runtime_unavailable", EvidenceStatus: "failed", AuditErrorCode: "runtime_unavailable",
		})
		return
	}
	completion := h.proxy.executeApprovedMCPConfirmation(r.Context(), record)
	if completion.EvidenceStatus == "" {
		completion.EvidenceStatus = "complete"
	}
	h.completeAndWrite(w, r, record, completion)
}

func (h *mcpConfirmationExecutionHandler) completeAndWrite(
	w http.ResponseWriter,
	r *http.Request,
	record *mcpConfirmationExecutionRecord,
	completion mcpExecutionCompletion,
) {
	completion = sanitizeMCPExecutionCompletion(completion)
	final, err := h.store.CompleteGatewayExecution(r.Context(), record.TenantID, record.ConfirmationID, record.AttemptID, completion)
	if err != nil || final == nil {
		writeMCPExecutionHTTPError(w, http.StatusServiceUnavailable, "state_unavailable", "terminal execution state could not be persisted")
		return
	}
	writeMCPExecutionJSON(w, http.StatusOK, final)
}

func writeMCPExecutionJSON(w http.ResponseWriter, status int, record *mcpConfirmationExecutionRecord) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	body := map[string]any{
		"confirmation_id":  record.ConfirmationID,
		"invocation_id":    record.InvocationID,
		"status":           record.ConfirmationState,
		"execution_status": record.ExecutionStatus,
		"evidence_status":  record.EvidenceStatus,
		"response_summary": record.ResponseSummary,
		"error_code":       record.ErrorCode,
		"result_available": record.ResultCiphertext != "" && record.ResultExpiresAt != nil && record.ResultExpiresAt.After(time.Now()),
	}
	if record.EvidenceStatus == "complete" {
		body["audit_request_id"] = record.AuditRequestID
		body["tool_log_id"] = record.ToolLogID
	}
	_ = json.NewEncoder(w).Encode(body)
}

func writeMCPExecutionHTTPError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]string{"code": code, "message": message}})
}

func (h *MCPProxyHandler) executeApprovedMCPConfirmation(
	ctx context.Context,
	record *mcpConfirmationExecutionRecord,
) mcpExecutionCompletion {
	fail := func(code string) mcpExecutionCompletion {
		return mcpExecutionCompletion{
			Status: "failed", Summary: map[string]any{"outcome": "failed"},
			ErrorCode: code, EvidenceStatus: "failed",
			AuditErrorCode: "preflight_not_audited",
		}
	}
	if h == nil || record == nil || !strings.HasPrefix(record.ReplayCiphertext, "enc:v1:") {
		return fail("invalid_encrypted_context")
	}
	plaintext, err := secrets.DecryptProviderSecret(record.ReplayCiphertext)
	if err != nil {
		return fail("context_decryption_failed")
	}
	digest := sha256.Sum256([]byte(plaintext))
	if subtle.ConstantTimeCompare([]byte(hex.EncodeToString(digest[:])), []byte(record.ReplayContextHash)) != 1 {
		return fail("context_integrity_failed")
	}
	var replay mcpconfirmation.ReplayContext
	if err := json.Unmarshal([]byte(plaintext), &replay); err != nil {
		return fail("context_decode_failed")
	}
	if replay.Version != mcpconfirmation.ReplayContextVersion || replay.TenantID != record.TenantID ||
		replay.ServerID == "" || replay.ToolName == "" || replay.ToolCallID == "" ||
		replay.ToolCallID != record.ToolCallID || len(replay.RequestBody) == 0 ||
		len(replay.RequestBody) > maxMCPRequestBodyBytes {
		return fail("context_identity_mismatch")
	}
	if h.toolRiskClient == nil {
		return fail("policy_runtime_unavailable")
	}
	scopeKey, scopeErr := mcpconfirmation.ScopeKey(h.toolRiskClient.mcpConfirmationSecret(), replay)
	requestHash, requestHashErr := mcpconfirmation.CanonicalRequestHash(replay)
	principalHash, principalErr := mcpconfirmation.PrincipalFingerprint(h.toolRiskClient.mcpConfirmationSecret(), replay)
	if scopeErr != nil || requestHashErr != nil || principalErr != nil ||
		subtle.ConstantTimeCompare([]byte(scopeKey), []byte(record.ScopeKey)) != 1 ||
		subtle.ConstantTimeCompare([]byte(requestHash), []byte(record.CanonicalRequestHash)) != 1 ||
		subtle.ConstantTimeCompare([]byte(principalHash), []byte(record.PrincipalHash)) != 1 ||
		replay.ToolID != record.ToolID || replay.SupplyChainRevision != record.SupplyChainRevision ||
		replay.ApprovedSchemaHash != record.ApprovedSchemaHash || replay.ServerRouteHash != record.ServerRouteHash {
		return fail("context_identity_mismatch")
	}
	effectiveEnvironmentScope := retentionartifact.ResolveEnvironmentScope(replay.EnvironmentScope, h.environmentScope)
	messages, batch, err := parseMCPRPCMessages(replay.RequestBody)
	if err != nil || batch || len(messages) != 1 || messages[0].JSONRPC != "2.0" ||
		messages[0].Method != "tools/call" || strings.TrimSpace(messages[0].Params.Name) != replay.ToolName {
		return fail("invalid_tools_call")
	}
	callID := mcpToolCallID(messages[0].ID)
	if callID == "" || callID != replay.ToolCallID {
		return fail("tool_call_id_mismatch")
	}

	inbound, err := http.NewRequestWithContext(ctx, http.MethodPost, "/mcp/"+replay.ServerID, bytes.NewReader(replay.RequestBody))
	if err != nil {
		return fail("request_build_failed")
	}
	inbound.Header.Set("Content-Type", "application/json")
	inbound.Header.Set("MCP-Protocol-Version", replay.ProtocolVersion)
	if replay.MCPSessionID != "" {
		// 仅保留给审计 / 操作标识使用。旧 SSE 上游的桥接在重放时忽略它：下游会话不能复用，
		// 一律走临时上游会话（见 withMCPReplayPrincipal）。Streamable 上游沿用原有透传行为。
		inbound.Header.Set("Mcp-Session-Id", replay.MCPSessionID)
	}
	if err := validateMCPProtocolRequest(inbound, messages); err != nil {
		return fail("protocol_context_invalid")
	}
	if replay.SourceIP != "" {
		inbound.RemoteAddr = net.JoinHostPort(replay.SourceIP, "0")
	}

	server, err := h.lookupMCPServerForApprovedExecution(ctx, replay.TenantID, replay.ServerID)
	if err != nil || server == nil || !mcpServerUsable(server.Status) {
		return fail("mcp_server_unavailable")
	}
	auditRequestID := record.AuditRequestID
	if auditRequestID == "" {
		auditRequestID = "req_mcp_confirmation_" + uuid.New().String()
	}
	if replay.OperationID == "" {
		replay.OperationID = operationID(destructiveOperationIdentity{
			TenantID: replay.TenantID, Protocol: "mcp", SessionID: replay.MCPSessionID, RequestID: auditRequestID,
			OutputItemID: "mcp:" + replay.ServerID, ToolCallID: replay.ToolCallID, ToolName: replay.ToolName,
		})
	}
	envelope := &modelrouter.RequestEnvelope{
		RequestID: auditRequestID,
		TenantID:  replay.TenantID, ProjectID: replay.ProjectID, UserID: replay.UserID,
		ClientID: replay.ClientID, KeyPrefix: replay.KeyPrefix, AgentType: replay.AgentType,
		SessionID: replay.AgentSessionID, TraceID: replay.TraceID, SourceIP: replay.SourceIP,
		EndpointType:     "proxy",
		EnvironmentScope: effectiveEnvironmentScope,
	}
	destructivePolicy, policyErr := h.toolRiskClient.GetAgentGuardPolicy(ctx, envelope)
	tenant := newMCPTenantContext(server.Name, destructivePolicy)
	policy, replayArgChain, err := h.toolRiskClient.fetchMCPToolPolicyWithArgChain(ctx, envelope, server.ID, replay.ToolName)
	policyRuntimeUnavailable := false
	replayItem, _ := protection.Lookup(protection.KeyMCPReplayChanged)
	unavailableAction, _ := mcpFallbackAction(replayItem, "policy_runtime_unavailable", tenant, replay.ToolName)
	if (err != nil || policy == nil) && unavailableAction != protection.ActionBlock {
		// 重放时策略拉不到按 mcp.replay_changed 处置：默认告警放行，按默认策略继续判定。
		log.Printf("MCP 重放时策略不可用，按 mcp.replay_changed 继续: server=%s tool=%s err=%v", server.ID, replay.ToolName, err)
		policy, replayArgChain, err, policyRuntimeUnavailable = mcpDefaultEffectivePolicy(), nil, nil, true
	}
	if err != nil || policy == nil {
		decision := agentguard.Decision{
			RawDecision: agentguard.DecisionBlock, EffectiveDecision: agentguard.DecisionBlock,
			Mode: agentguard.ModeStrict, Reason: "policy_runtime_unavailable",
			EffectiveReason: "policy_runtime_unavailable", RiskLevel: "critical", ConfiguredEnforcement: true,
			OperationID: replay.OperationID,
			TraceID:     replay.TraceID,
			// 走到这里只有 mcp.replay_changed 配成阻断（没有例外）：结论归因到该项。
			ProtectionItem: protection.KeyMCPReplayChanged, ProtectionAction: string(protection.ActionBlock),
		}
		toolDecision := mcpToolCallDecision{
			Message: messages[0], ToolName: replay.ToolName, Qualified: server.Name + "__" + replay.ToolName,
			ArgsJSON: string(messages[0].Params.Arguments), Decision: decision,
			MCPServerID: server.ID, MCPToolID: replay.ToolID, OutcomeStatus: "blocked",
		}
		return h.auditMCPConfirmationPreflightFailure(ctx, replay, server, inbound, envelope, toolDecision, "policy_runtime_unavailable")
	}
	policy = enforceMCPGatewayRouteBinding(policy, server.RouteHash)
	replayArgs := string(messages[0].Params.Arguments)
	// 重放与首判同口径：参数条件按重放的原参数求值（W1 1.12）。
	policy = applyMCPArgChain(policy, replayArgChain, replayArgs)
	var replayRedlineActions map[string]string
	if len(matchMCPRedlines(replayArgs)) > 0 {
		replayRedlineActions = h.mcpRedlineActions(ctx, envelope.TenantID)
	}
	decision := synthesizeMCPDecisionForTenant(policy, replay.ToolName, replayArgs, agentguard.ModeStrict, true, replayRedlineActions, tenant)
	decision.OperationID = replay.OperationID
	decision.TraceID = replay.TraceID
	{
		var arguments map[string]interface{}
		argumentsErr := json.Unmarshal(messages[0].Params.Arguments, &arguments)
		if arguments == nil {
			argumentsErr = fmt.Errorf("tools/call arguments must be an object")
			arguments = map[string]interface{}{}
		}
		decision = h.evaluateMCPAgentGuardToolCall(ctx, envelope, server.Name+"__"+replay.ToolName, structuredToolCallInput{
			RequestID: envelope.RequestID, OutputItemID: "mcp:" + server.ID,
			ToolCallID: replay.ToolCallID, ToolName: replay.ToolName,
			ToolType: inferToolTypeFromName(replay.ToolName), Arguments: arguments,
			RawArguments:           replayArgs,
			ArgumentsParseRejected: argumentsErr != nil, Policy: destructivePolicy,
			Protocol: "mcp", Mode: agentguard.ModeStrict, ConfirmSupported: true, BaseDecision: decision,
			ExceptionScope: mcpExceptionTarget(server.Name, replay.ToolName),
		}, decision, policyErr)
		decision.OperationID = replay.OperationID
	}
	toolDecision := mcpToolCallDecision{
		Message: messages[0], ToolName: replay.ToolName, Qualified: server.Name + "__" + replay.ToolName,
		ArgsJSON: string(messages[0].Params.Arguments), PolicyID: policy.PolicyID, Decision: decision,
		MCPServerID: server.ID, MCPToolID: policy.ToolID,
		SupplyChainRevision: policy.SupplyChainRevision, ApprovedSchemaHash: policy.ApprovedSchemaHash,
		ServerRouteHash: policy.RouteHash, OutcomeStatus: "proposed",
	}
	drifted := server.RouteHash != replay.ServerRouteHash ||
		policy.ToolID != replay.ToolID || policy.SupplyChainRevision != replay.SupplyChainRevision ||
		policy.RouteHash != replay.ServerRouteHash || policy.ApprovedSchemaHash != replay.ApprovedSchemaHash ||
		policy.StructuralBlock
	if policyRuntimeUnavailable {
		decision, _ = mcpProtectionFallback(decision, "policy_runtime_unavailable", tenant, replay.ToolName, false)
		toolDecision.Decision = decision
		drifted = false
	}
	if drifted && mcpReplayDriftTolerable(policy, decision) {
		// 批准后重放时环境变化按 mcp.replay_changed 处置：默认告警放行（仍受其余结论约束），设为阻断才拦。
		downgraded, enforce := mcpProtectionFallback(decision, "approval_context_drift", tenant, replay.ToolName, false)
		// 设为阻断时结论归因到 mcp.replay_changed（拦截记录写下该项）。
		decision = downgraded
		toolDecision.Decision = decision
		if !enforce {
			log.Printf("MCP 重放时审批上下文变化，按 mcp.replay_changed 继续: server=%s tool=%s action=%s", server.ID, replay.ToolName, downgraded.ProtectionAction)
			drifted = false
		}
	}
	if drifted {
		decision.RawDecision = agentguard.DecisionBlock
		decision.EffectiveDecision = agentguard.DecisionBlock
		decision.Mode = agentguard.ModeStrict
		decision.ConfiguredEnforcement = true
		decision.RiskLevel = "critical"
		decision.Reason = "approval_context_drift"
		decision.EffectiveReason = "approval_context_drift"
		decision.Evidence = append(decision.Evidence, agentguard.Evidence{
			RuleID: "mcp_approval_context_drift", Category: "mcp_supply_chain",
			Hash: policy.SupplyChainRevision,
		})
		toolDecision.Decision = decision
		toolDecision.OutcomeStatus = "blocked"
		return h.auditMCPConfirmationPreflightFailure(ctx, replay, server, inbound, envelope, toolDecision, "approval_context_drift")
	}
	if securityexit.Blocks(string(decision.EffectiveDecision)) {
		outcome := securityexit.Decide(securityexit.ModeFromAuditOnly(h.securityAuditOnly(ctx)), string(decision.EffectiveDecision), securityexit.ToolPolicy)
		if outcome.Enforce {
			toolDecision.OutcomeStatus = "blocked"
			return h.auditMCPConfirmationPreflightFailure(ctx, replay, server, inbound, envelope, toolDecision, "current_policy_blocked")
		}
		decision.EffectiveDecision = agentguard.DecisionAudit
		decision.EffectiveReason = "mcp_confirmation_policy_recorded"
		if decision.FinalAction != "" {
			decision.FinalAction = agentguard.DestructiveActionRecord
		}
		toolDecision.Decision = decision
	}
	// A current confirm decision may be overridden exactly once by this claimed,
	// approved execution. No other policy action is weakened.
	if decision.EffectiveDecision == agentguard.DecisionConfirm {
		decision.EffectiveDecision = agentguard.DecisionAllow
		decision.EffectiveReason = "human_confirmation_approved_once"
		toolDecision.Decision = decision
	}

	preflightInfo := replayMCPAuthInfo(replay, envelope.RequestID, effectiveEnvironmentScope)
	preflightAudit := h.newMCPAuditRecord(
		preflightInfo, server, inbound, int64(len(replay.RequestBody)), 0, "pending", 0, 0,
	)
	preflightToolLogID, auditErr := h.writeMCPProxyAudit(
		context.WithoutCancel(ctx), envelope, preflightAudit, []mcpToolCallDecision{toolDecision}, false,
	)
	if auditErr != nil || preflightToolLogID == "" {
		return mcpExecutionCompletion{
			Status: "failed", Summary: map[string]any{"outcome": "failed"},
			ErrorCode: "preflight_audit_failed", EvidenceStatus: "failed",
			AuditErrorCode: "preflight_audit_failed",
		}
	}

	startedAt := time.Now()
	// 重放的额度主体取自 replay 记录里的真实调用主体（租户 + key + 用户 + 项目），
	// 而不是空主体——否则所有租户的重放会共用同一个 "\x1f\x1f" 额度桶。
	forwardCtx := withMCPReplayPrincipal(ctx, mcpBridgePrincipalKey(replay.TenantID, replay.ClientID, replay.UserID, replay.ProjectID))
	resp, _, err := h.forwardMCPUpstream(forwardCtx, server, inbound, replay.RequestBody)
	if err == nil && mcpResponseNotForwarded(resp) {
		// 桥接合成的 404/503/405：请求没有到达上游。审批单不能被消耗为 executed，审计如实记录。
		_ = resp.Body.Close()
		err = errors.New("MCP 请求未转发到上游")
		resp = nil
	}
	if err != nil {
		toolDecision.OutcomeStatus = "unknown"
		info := replayMCPAuthInfo(replay, envelope.RequestID, effectiveEnvironmentScope)
		recordAudit := h.newMCPAuditRecord(info, server, inbound, int64(len(replay.RequestBody)), 0, "unknown", 0, time.Since(startedAt))
		toolLogID, auditErr := h.writeMCPProxyOutcomeAudit(
			context.WithoutCancel(ctx), envelope, recordAudit, []mcpToolCallDecision{toolDecision},
		)
		completion := mcpExecutionCompletion{
			Status: "unknown", Summary: map[string]any{"outcome": "unknown", "result_observed": false},
			ErrorCode: "upstream_outcome_unknown", EvidenceStatus: "complete", ToolLogID: toolLogID,
		}
		if auditErr != nil || toolLogID == "" {
			completion.EvidenceStatus = "failed"
			completion.AuditErrorCode = "terminal_audit_failed"
			completion.ToolLogID = ""
		}
		return completion
	}
	defer resp.Body.Close()

	contentType, _, _ := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	limit := int64(maxMCPNonStreamingResponseBytes)
	if strings.EqualFold(contentType, "text/event-stream") {
		limit = int64(maxMCPSSECumulativeBytes)
	}
	responseBody, readErr := readMCPBoundedBody(resp.Body, limit)
	validResponse := readErr == nil
	if strings.EqualFold(contentType, "application/json") {
		validResponse = validResponse && validateMCPJSONResponse(responseBody) == nil
	} else if !strings.EqualFold(contentType, "text/event-stream") {
		validResponse = validResponse && (resp.StatusCode == http.StatusAccepted || resp.StatusCode == http.StatusNoContent)
	}

	toolDecision.ExecutionForwarded = true
	toolDecision.OutcomeStatus = "success"
	if validResponse {
		// observeMCPToolResults mutates its slice; use a stable one below.
		decisions := []mcpToolCallDecision{toolDecision}
		isSSE := strings.EqualFold(contentType, "text/event-stream")
		// W1 1.7：审批后重放的工具返回与直连路径同口径检测，拦截时缓存的是替换后的错误。
		if guard := h.prepareMCPToolResultGuard(ctx, envelope, server, decisions, h.securityAuditOnly(ctx)); guard != nil {
			if isSSE {
				responseBody = mcpRewriteSSEBody(responseBody, guard.rewritePayload)
			} else {
				responseBody = guard.rewritePayload(responseBody)
			}
		}
		observeMCPToolResults(decisions, responseBody, isSSE)
		toolDecision = decisions[0]
	}
	summary, destructive := buildMCPExecutionResponseSummary(toolDecision, resp.StatusCode)
	errorCode := ""
	if !validResponse {
		errorCode = "upstream_response_invalid"
		toolDecision.OutcomeStatus = "failed"
	}
	info := replayMCPAuthInfo(replay, envelope.RequestID, effectiveEnvironmentScope)
	recordAudit := h.newMCPAuditRecord(info, server, inbound, int64(len(replay.RequestBody)), int64(len(responseBody)), toolDecision.OutcomeStatus, resp.StatusCode, time.Since(startedAt))
	toolLogID, auditErr := h.writeMCPProxyOutcomeAudit(
		context.WithoutCancel(ctx), envelope, recordAudit, []mcpToolCallDecision{toolDecision},
	)
	completion := mcpExecutionCompletion{
		Status: "executed", Summary: summary, ErrorCode: errorCode,
		Destructive: destructive, EvidenceStatus: "complete", ToolLogID: toolLogID,
	}
	if auditErr != nil || toolLogID == "" {
		completion.EvidenceStatus = "failed"
		completion.AuditErrorCode = "terminal_audit_failed"
		completion.ToolLogID = ""
	}
	if validResponse {
		terminal, unique := uniqueMCPConfirmationResponse(messages[0].ID, responseBody, strings.EqualFold(contentType, "text/event-stream"))
		if unique && len(terminal) <= maxMCPNonStreamingResponseBytes {
			responseDigest := sha256.Sum256(terminal)
			completion.ResultHash = hex.EncodeToString(responseDigest[:])
			aad, aadErr := mcpconfirmation.ResponseAAD(
				h.toolRiskClient.mcpConfirmationSecret(), replay, record.InvocationID, record.ConfirmationID,
				record.CanonicalRequestHash, completion.ResultHash,
			)
			if aadErr == nil {
				completion.ResultCiphertext, aadErr = secrets.EncryptMCPResult(terminal, aad)
			}
			if aadErr == nil {
				completion.ResultPlaintextBytes = int64(len(terminal))
				completion.ResultHTTPStatus = resp.StatusCode
				completion.ResultMediaType = "application/json"
				completion.ResultRPCID = replay.ToolCallID
				completion.ResultProtocol = replay.ProtocolVersion
				completion.ResultSessionID = replay.MCPSessionID
				expires := time.Now().Add(10 * time.Minute)
				completion.ResultExpiresAt = &expires
			} else {
				completion.ErrorCode = "result_cache_encryption_failed"
			}
		}
	}
	return completion
}

func (h *MCPProxyHandler) auditMCPConfirmationPreflightFailure(
	ctx context.Context,
	replay mcpconfirmation.ReplayContext,
	server *mcpServerRoute,
	inbound *http.Request,
	envelope *modelrouter.RequestEnvelope,
	decision mcpToolCallDecision,
	errorCode string,
) mcpExecutionCompletion {
	info := replayMCPAuthInfo(replay, envelope.RequestID, envelope.EnvironmentScope)
	recordAudit := h.newMCPAuditRecord(
		info, server, inbound, int64(len(replay.RequestBody)), 0, "blocked", 0, 0,
	)
	toolLogID, auditErr := h.writeMCPProxyAudit(
		context.WithoutCancel(ctx), envelope, recordAudit, []mcpToolCallDecision{decision}, false,
	)
	completion := mcpExecutionCompletion{
		Status: "failed", Summary: map[string]any{"outcome": "failed", "execution_forwarded": false},
		ErrorCode: errorCode, EvidenceStatus: "complete", ToolLogID: toolLogID,
	}
	if auditErr != nil || toolLogID == "" {
		completion.EvidenceStatus = "failed"
		completion.AuditErrorCode = "preflight_audit_failed"
		completion.ToolLogID = ""
	}
	return completion
}

func uniqueMCPConfirmationResponse(id json.RawMessage, body []byte, sse bool) ([]byte, bool) {
	wanted, ok := mcpRPCIDKey(id)
	if !ok {
		return nil, false
	}
	var observations []mcpRPCResponseObservation
	if sse {
		for _, payload := range parseMCPSSEDataPayloads(body) {
			observations = append(observations, parseMCPJSONRPCResponseItems(payload)...)
		}
	} else {
		observations = parseMCPJSONRPCResponseItems(body)
	}
	var found json.RawMessage
	count := 0
	for _, observation := range observations {
		if observation.idKey == wanted {
			found = observation.raw
			count++
		}
	}
	if count != 1 || len(found) == 0 {
		return nil, false
	}
	return append([]byte(nil), found...), true
}

func replayMCPAuthInfo(replay mcpconfirmation.ReplayContext, requestID, environmentScope string) *auth.AuthInfo {
	return &auth.AuthInfo{
		TenantID: replay.TenantID, ProjectID: replay.ProjectID, UserID: replay.UserID,
		KeyID: replay.ClientID, KeyPrefix: replay.KeyPrefix, AgentType: replay.AgentType,
		SessionID: replay.AgentSessionID, RequestID: requestID, TraceID: replay.TraceID,
		ClientIP:         replay.SourceIP,
		EnvironmentScope: environmentScope,
	}
}

func (h *MCPProxyHandler) lookupMCPServerForApprovedExecution(ctx context.Context, tenantID, serverID string) (*mcpServerRoute, error) {
	if h.db == nil {
		return h.lookupServer(ctx, tenantID, serverID)
	}
	route, err := scanMCPServerRoute(h.db.QueryRow(ctx, mcpServerRouteSelect, serverID, tenantID))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return route, nil
}

func sanitizeMCPExecutionCompletion(completion mcpExecutionCompletion) mcpExecutionCompletion {
	if !completion.Destructive {
		return completion
	}
	safe := make(map[string]any)
	for _, key := range []string{
		"outcome",
		"execution_forwarded",
		"result_observed",
		"http_status",
		"result_hash",
		"result_plaintext_bytes",
		"result_media_type",
		"result_rpc_id",
		"result_protocol",
	} {
		if value, ok := completion.Summary[key]; ok {
			safe[key] = value
		}
	}
	if completion.ResultHash != "" {
		safe["result_hash"] = completion.ResultHash
	}
	if completion.ResultPlaintextBytes > 0 {
		safe["result_plaintext_bytes"] = completion.ResultPlaintextBytes
	}
	if completion.ResultMediaType != "" {
		safe["result_media_type"] = completion.ResultMediaType
	}
	if completion.ResultRPCID != "" {
		safe["result_rpc_id"] = completion.ResultRPCID
	}
	if completion.ResultProtocol != "" {
		safe["result_protocol"] = completion.ResultProtocol
	}
	completion.Summary = safe
	return completion
}

func buildMCPExecutionResponseSummary(decision mcpToolCallDecision, httpStatus int) (map[string]any, bool) {
	destructive := decision.Decision.RiskCategory == agentguard.DestructiveRiskCategory ||
		isDestructiveGateDecision(decision.Decision)
	summary := map[string]any{
		"outcome": "executed", "execution_forwarded": decision.ExecutionForwarded, "http_status": httpStatus,
		"result_observed": decision.ResultObserved,
	}
	if decision.ResultExcerpt != "" && !destructive {
		summary["result_excerpt"] = decision.ResultExcerpt
	}
	return summary, destructive
}
