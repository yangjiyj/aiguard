package handler

import (
	"context"
	"errors"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/roles"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

type agentAuthorizationApprovalRepository interface {
	Authorize(context.Context, repository.TrustedAgentPrincipal, repository.AgentAuthorizationRequest) (*repository.AgentAuthorizationDecision, error)
	CreateAgentAuthorizationApproval(context.Context, repository.TrustedAgentPrincipal, string, repository.AgentAuthorizationApprovalInput) (*repository.AgentAuthorizationApproval, bool, error)
	ClaimAgentAuthorizationApproval(context.Context, repository.TrustedAgentPrincipal, string, string, repository.AgentAuthorizationApprovalClaimInput) (*repository.AgentAuthorizationApprovalClaim, error)
	ListAgentAuthorizationApprovals(context.Context, string, string, int) ([]*repository.AgentAuthorizationApproval, error)
	ResolveAgentAuthorizationApproval(context.Context, string, string, string, string, string) (*repository.AgentAuthorizationApproval, bool, error)
	RevokeAgentAuthorizationApproval(context.Context, string, string, string, string) (*repository.AgentAuthorizationApproval, bool, error)
	CreateAgentAuthorizationApprovalException(context.Context, string, string, repository.AgentAuthorizationApprovalExceptionInput) (*repository.AgentAuthorizationApprovalException, bool, error)
	ListAgentAuthorizationApprovalExceptions(context.Context, string, int) ([]*repository.AgentAuthorizationApprovalException, error)
	RevokeAgentAuthorizationApprovalException(context.Context, string, string, string) (*repository.AgentAuthorizationApprovalException, bool, error)
}

type AgentAuthorizationApprovalAPI struct {
	Repo agentAuthorizationApprovalRepository
	Deps *Dependencies
}

func NewAgentAuthorizationApprovalAPI(repo agentAuthorizationApprovalRepository, deps *Dependencies) *AgentAuthorizationApprovalAPI {
	return &AgentAuthorizationApprovalAPI{Repo: repo, Deps: deps}
}

type agentAuthorizationApprovalRequest struct {
	Action                      string `json:"action"`
	ResourceType                string `json:"resource_type"`
	ResourceID                  string `json:"resource_id"`
	ArgumentsSHA256             string `json:"arguments_sha256"`
	AuthorizationIdempotencyKey string `json:"authorization_idempotency_key"`
	ApprovalIdempotencyKey      string `json:"approval_idempotency_key"`
	RunID                       string `json:"run_id,omitempty"`
	InstanceID                  string `json:"instance_id,omitempty"`
	ToolCallID                  string `json:"tool_call_id,omitempty"`
}

func (req agentAuthorizationApprovalRequest) input() repository.AgentAuthorizationApprovalInput {
	return repository.AgentAuthorizationApprovalInput{Action: req.Action, ResourceType: req.ResourceType, ResourceID: req.ResourceID,
		ArgumentsSHA256: req.ArgumentsSHA256, AuthorizationIdempotencyKey: req.AuthorizationIdempotencyKey,
		ApprovalIdempotencyKey: req.ApprovalIdempotencyKey}
}

func (req agentAuthorizationApprovalRequest) authorizationContext() map[string]any {
	if req.RunID == "" {
		return nil
	}
	return map[string]any{"run_id": req.RunID, "instance_id": req.InstanceID, "tool_call_id": req.ToolCallID}
}

func (req agentAuthorizationApprovalRequest) validAuthorizationContext() bool {
	return validAgentAuthorizationApprovalContext(req.RunID, req.InstanceID, req.ToolCallID)
}

func (req agentAuthorizationApprovalRequest) authorizationRequest() repository.AgentAuthorizationRequest {
	return repository.AgentAuthorizationRequest{Action: req.Action, ResourceType: req.ResourceType, ResourceID: req.ResourceID,
		Context: req.authorizationContext(), IdempotencyKey: req.AuthorizationIdempotencyKey}
}

func validAgentAuthorizationApprovalContext(runID, instanceID, toolCallID string) bool {
	if runID == "" && instanceID == "" && toolCallID == "" {
		return true
	}
	for _, value := range []string{runID, instanceID, toolCallID} {
		if value == "" || len(value) > 512 || strings.TrimSpace(value) != value {
			return false
		}
		for _, r := range value {
			if r < 0x20 || r == 0x7f {
				return false
			}
		}
	}
	return true
}

func agentAuthorizationApprovalNoStore(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store,max-age=0")
	w.Header().Set("Pragma", "no-cache")
}

func (h *AgentAuthorizationApprovalAPI) RequestApproval(w http.ResponseWriter, r *http.Request) {
	agentAuthorizationApprovalNoStore(w)
	principal := trustedAgentAuthorizationPrincipal(r)
	if principal == nil {
		writeUnauthorized(w, "agent credential required")
		return
	}
	var req agentAuthorizationApprovalRequest
	if err := decodeStrictJSON(http.MaxBytesReader(w, r.Body, agentAuthorizationBodyLimit), &req); err != nil || !req.validAuthorizationContext() {
		writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "invalid approval request")
		return
	}
	decision, err := h.Repo.Authorize(r.Context(), *principal, req.authorizationRequest())
	if err != nil {
		switch {
		case errors.Is(err, repository.ErrAgentAuthorizationInvalid):
			writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "invalid approval request")
		case errors.Is(err, repository.ErrAgentAuthorizationPrincipalUnauthorized):
			writeUnauthorized(w, "agent credential is no longer active")
		case errors.Is(err, repository.ErrAgentAuthorizationIdempotencyConflict):
			writeErrorWithStatus(w, http.StatusConflict, "idempotency_conflict", "authorization key belongs to another scope")
		default:
			writeErrorWithStatus(w, http.StatusServiceUnavailable, "authorization_unavailable", "T13 authorization is unavailable")
		}
		return
	}
	if decision == nil || !decision.Allowed || decision.GrantID == "" {
		writeErrorWithStatus(w, http.StatusForbidden, "authorization_denied", "T13 authorization denied the exact request")
		return
	}
	approval, created, err := h.Repo.CreateAgentAuthorizationApproval(r.Context(), *principal, decision.GrantID, req.input())
	if err != nil {
		writeAgentAuthorizationApprovalRepoError(w, err)
		return
	}
	if approval == nil {
		writeErrorWithStatus(w, http.StatusServiceUnavailable, "approval_unavailable", "approval state is unavailable")
		return
	}
	status := http.StatusAccepted
	if created {
		status = http.StatusCreated
	}
	writeAgentAdminJSON(w, status, map[string]any{"approval_id": approval.ID, "status": approval.Status, "expires_at": approval.ExpiresAt, "created": created})
}

type agentAuthorizationApprovalClaimRequest struct {
	ApprovalID                  string `json:"approval_id"`
	Action                      string `json:"action"`
	ResourceType                string `json:"resource_type"`
	ResourceID                  string `json:"resource_id"`
	ArgumentsSHA256             string `json:"arguments_sha256"`
	AuthorizationIdempotencyKey string `json:"authorization_idempotency_key"`
	ClaimIdempotencyKey         string `json:"claim_idempotency_key"`
	RunID                       string `json:"run_id,omitempty"`
	InstanceID                  string `json:"instance_id,omitempty"`
	ToolCallID                  string `json:"tool_call_id,omitempty"`
}

func (req agentAuthorizationApprovalClaimRequest) input() repository.AgentAuthorizationApprovalClaimInput {
	return repository.AgentAuthorizationApprovalClaimInput{Action: req.Action, ResourceType: req.ResourceType, ResourceID: req.ResourceID,
		ArgumentsSHA256: req.ArgumentsSHA256, AuthorizationIdempotencyKey: req.AuthorizationIdempotencyKey,
		ClaimIdempotencyKey: req.ClaimIdempotencyKey}
}

func (req agentAuthorizationApprovalClaimRequest) authorizationContext() map[string]any {
	if req.RunID == "" {
		return nil
	}
	return map[string]any{"run_id": req.RunID, "instance_id": req.InstanceID, "tool_call_id": req.ToolCallID}
}

func (req agentAuthorizationApprovalClaimRequest) validAuthorizationContext() bool {
	return validAgentAuthorizationApprovalContext(req.RunID, req.InstanceID, req.ToolCallID)
}

func (req agentAuthorizationApprovalClaimRequest) authorizationRequest() repository.AgentAuthorizationRequest {
	return repository.AgentAuthorizationRequest{Action: req.Action, ResourceType: req.ResourceType, ResourceID: req.ResourceID,
		Context: req.authorizationContext(), IdempotencyKey: req.AuthorizationIdempotencyKey}
}

func (h *AgentAuthorizationApprovalAPI) ClaimApproval(w http.ResponseWriter, r *http.Request) {
	agentAuthorizationApprovalNoStore(w)
	principal := trustedAgentAuthorizationPrincipal(r)
	if principal == nil {
		writeUnauthorized(w, "agent credential required")
		return
	}
	var req agentAuthorizationApprovalClaimRequest
	if err := decodeStrictJSON(http.MaxBytesReader(w, r.Body, agentAuthorizationBodyLimit), &req); err != nil || !req.validAuthorizationContext() {
		writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "invalid approval claim")
		return
	}
	decision, err := h.Repo.Authorize(r.Context(), *principal, req.authorizationRequest())
	if err != nil {
		switch {
		case errors.Is(err, repository.ErrAgentAuthorizationInvalid):
			writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "invalid approval claim")
		case errors.Is(err, repository.ErrAgentAuthorizationPrincipalUnauthorized):
			writeUnauthorized(w, "agent credential is no longer active")
		case errors.Is(err, repository.ErrAgentAuthorizationIdempotencyConflict):
			writeErrorWithStatus(w, http.StatusConflict, "idempotency_conflict", "authorization key belongs to another scope")
		default:
			writeErrorWithStatus(w, http.StatusServiceUnavailable, "authorization_unavailable", "T13 authorization is unavailable")
		}
		return
	}
	if decision == nil || !decision.Allowed || decision.GrantID == "" {
		writeErrorWithStatus(w, http.StatusForbidden, "authorization_denied", "T13 authorization denied the exact request")
		return
	}
	claim, err := h.Repo.ClaimAgentAuthorizationApproval(r.Context(), *principal, decision.GrantID, req.ApprovalID, req.input())
	if err != nil {
		writeAgentAuthorizationApprovalRepoError(w, err)
		return
	}
	status := http.StatusForbidden
	if claim != nil && claim.Allowed {
		status = http.StatusOK
	}
	writeAgentAdminJSON(w, status, claim)
}

// agentAuthorizationSoDDenialReason names a separation-of-duties refusal for the audit log.
func agentAuthorizationSoDDenialReason(err error) string {
	switch {
	case errors.Is(err, repository.ErrAgentAuthorizationApprovalSelfResolution):
		return "self_resolution"
	case errors.Is(err, repository.ErrAgentAuthorizationApprovalHolderUnknown):
		return "credential_holder_unknown"
	}
	return ""
}

func writeAgentAuthorizationApprovalRepoError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, repository.ErrAgentAuthorizationApprovalInvalid), errors.Is(err, repository.ErrAgentAuthorizationInvalid):
		writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "invalid approval binding")
	case errors.Is(err, repository.ErrAgentAuthorizationPrincipalNotFound):
		writeErrorWithStatus(w, http.StatusNotFound, "not_found", "agent principal not found")
	case errors.Is(err, repository.ErrAgentAuthorizationPrincipalUnauthorized):
		writeUnauthorized(w, "agent credential is no longer active")
	case errors.Is(err, repository.ErrAgentAuthorizationGrantExpired), errors.Is(err, repository.ErrAgentAuthorizationApprovalExpired):
		writeErrorWithStatus(w, http.StatusConflict, "approval_expired", "approval or T13 grant is no longer active")
	case errors.Is(err, repository.ErrAgentAuthorizationApprovalConflict), errors.Is(err, repository.ErrAgentAuthorizationIdempotencyConflict):
		writeErrorWithStatus(w, http.StatusConflict, "idempotency_conflict", "idempotency key belongs to another exact request")
	case errors.Is(err, repository.ErrAgentAuthorizationApprovalSelfResolution):
		writeErrorWithStatus(w, http.StatusForbidden, "approval_self_resolution_forbidden",
			"the creator of an agent principal or its grants, or anyone who rotated its credential, cannot resolve its approvals or create its exceptions")
	case errors.Is(err, repository.ErrAgentAuthorizationApprovalHolderUnknown):
		writeErrorWithStatus(w, http.StatusForbidden, "approval_separation_unverifiable",
			"the agent principal's credential holders cannot be established; rotate its credential before resolving approvals")
	case errors.Is(err, repository.ErrAgentAuthorizationApprovalStateConflict):
		writeErrorWithStatus(w, http.StatusConflict, "approval_state_conflict", "approval state cannot be changed")
	default:
		writeErrorWithStatus(w, http.StatusServiceUnavailable, "approval_unavailable", "approval state is unavailable")
	}
}

func agentAuthorizationApprovalAdminUser(w http.ResponseWriter, r *http.Request) (*repository.User, bool) {
	agentAuthorizationApprovalNoStore(w)
	user, ok := agentAdminUser(w, r)
	if !ok {
		return nil, false
	}
	if !canManageAgentGuard(user.Role) {
		writeErrorWithStatus(w, http.StatusForbidden, "forbidden", "only tenant or platform admins can manage agent approvals")
		return nil, false
	}
	if strings.TrimSpace(user.TenantID) == "" || strings.TrimSpace(user.ID) == "" {
		writeUnauthorized(w, "admin tenant context not found")
		return nil, false
	}
	return user, true
}

// agentAuthorizationApprovalReaderUser 用于只读的审批记录查询：SoD 把 GET agent/approvals 归 security_record_read，
// 审计员可读；写操作与例外管理仍走 agentAuthorizationApprovalAdminUser。
func agentAuthorizationApprovalReaderUser(w http.ResponseWriter, r *http.Request) (*repository.User, bool) {
	agentAuthorizationApprovalNoStore(w)
	user, ok := agentAdminUser(w, r)
	if !ok {
		return nil, false
	}
	if !canManageAgentGuard(user.Role) && !roles.IsAuditor(user.Role) {
		writeErrorWithStatus(w, http.StatusForbidden, "forbidden", "only tenant admins, security officers or auditors can read agent approvals")
		return nil, false
	}
	if strings.TrimSpace(user.TenantID) == "" || strings.TrimSpace(user.ID) == "" {
		writeUnauthorized(w, "admin tenant context not found")
		return nil, false
	}
	return user, true
}

func (h *AgentAuthorizationApprovalAPI) ListApprovals(w http.ResponseWriter, r *http.Request) {
	user, ok := agentAuthorizationApprovalReaderUser(w, r)
	if !ok {
		return
	}
	status := strings.TrimSpace(r.URL.Query().Get("status"))
	switch status {
	case "", "pending", "approved", "rejected", "expired", "revoked":
	default:
		writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "invalid approval status")
		return
	}
	limit := 50
	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		value, err := strconv.Atoi(raw)
		if err != nil || value < 1 || value > 200 {
			writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "limit must be between 1 and 200")
			return
		}
		limit = value
	}
	items, err := h.Repo.ListAgentAuthorizationApprovals(r.Context(), user.TenantID, status, limit)
	if err != nil {
		writeErrorWithStatus(w, http.StatusServiceUnavailable, "approval_unavailable", "approval queue is unavailable")
		return
	}
	writeAgentAdminJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (h *AgentAuthorizationApprovalAPI) ResolveApproval(w http.ResponseWriter, r *http.Request) {
	user, ok := agentAuthorizationApprovalAdminUser(w, r)
	if !ok {
		return
	}
	var req struct {
		Status string `json:"status"`
		Note   string `json:"note"`
	}
	if err := decodeStrictJSON(http.MaxBytesReader(w, r.Body, 2048), &req); err != nil ||
		(req.Status != "approved" && req.Status != "rejected") || len(req.Note) > 512 {
		writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "invalid approval resolution")
		return
	}
	approvalID := chi.URLParam(r, "id")
	approval, changed, err := h.Repo.ResolveAgentAuthorizationApproval(r.Context(), user.TenantID, approvalID, req.Status, user.ID, req.Note)
	if reason := agentAuthorizationSoDDenialReason(err); reason != "" {
		logAudit(r, h.Deps, "agent_authorization_approval.resolve_denied", map[string]any{
			"approval_id": approvalID, "requested_status": req.Status, "reason": reason,
		}, "agent_authorization_approval", approvalID)
	}
	if err != nil {
		writeAgentAuthorizationApprovalRepoError(w, err)
		return
	}
	if approval == nil {
		writeErrorWithStatus(w, http.StatusNotFound, "not_found", "approval not found")
		return
	}
	if changed {
		logAudit(r, h.Deps, "agent_authorization_approval.resolve", map[string]any{"approval_id": approval.ID, "status": approval.Status, "resolution_note": req.Note},
			"agent_authorization_approval", approval.ID)
	}
	writeAgentAdminJSON(w, http.StatusOK, map[string]any{"approval": approval, "changed": changed})
}

func (h *AgentAuthorizationApprovalAPI) RevokeApproval(w http.ResponseWriter, r *http.Request) {
	user, ok := agentAuthorizationApprovalAdminUser(w, r)
	if !ok {
		return
	}
	var req struct {
		Note string `json:"note"`
	}
	if err := decodeStrictJSON(http.MaxBytesReader(w, r.Body, 2048), &req); err != nil || len(req.Note) > 512 {
		writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "invalid approval revocation")
		return
	}
	approval, changed, err := h.Repo.RevokeAgentAuthorizationApproval(r.Context(), user.TenantID, chi.URLParam(r, "id"), user.ID, req.Note)
	if err != nil {
		writeAgentAuthorizationApprovalRepoError(w, err)
		return
	}
	if approval == nil {
		writeErrorWithStatus(w, http.StatusNotFound, "not_found", "approval not found")
		return
	}
	if changed {
		logAudit(r, h.Deps, "agent_authorization_approval.revoke", map[string]any{"approval_id": approval.ID, "revocation_note": req.Note}, "agent_authorization_approval", approval.ID)
	}
	writeAgentAdminJSON(w, http.StatusOK, map[string]any{"approval": approval, "changed": changed})
}

func (h *AgentAuthorizationApprovalAPI) CreateException(w http.ResponseWriter, r *http.Request) {
	user, ok := agentAuthorizationApprovalAdminUser(w, r)
	if !ok {
		return
	}
	var req struct {
		PrincipalID     string `json:"principal_id"`
		GrantID         string `json:"grant_id"`
		Action          string `json:"action"`
		ResourceType    string `json:"resource_type"`
		ResourceID      string `json:"resource_id"`
		ArgumentsSHA256 string `json:"arguments_sha256"`
		Reason          string `json:"reason"`
		TTLSeconds      int    `json:"ttl_seconds"`
		IdempotencyKey  string `json:"idempotency_key"`
	}
	if err := decodeStrictJSON(http.MaxBytesReader(w, r.Body, 4096), &req); err != nil {
		writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "invalid approval exception")
		return
	}
	item, created, err := h.Repo.CreateAgentAuthorizationApprovalException(r.Context(), user.TenantID, user.ID,
		repository.AgentAuthorizationApprovalExceptionInput{PrincipalID: strings.TrimSpace(req.PrincipalID), GrantID: strings.TrimSpace(req.GrantID),
			Action: req.Action, ResourceType: req.ResourceType, ResourceID: req.ResourceID,
			ArgumentsSHA256: req.ArgumentsSHA256, Reason: req.Reason, TTLSeconds: req.TTLSeconds, IdempotencyKey: req.IdempotencyKey})
	if reason := agentAuthorizationSoDDenialReason(err); reason != "" {
		logAudit(r, h.Deps, "agent_authorization_approval_exception.create_denied", map[string]any{
			"principal_id": req.PrincipalID, "grant_id": req.GrantID, "reason": reason,
		}, "agent_authorization_principal", req.PrincipalID)
	}
	if err != nil {
		writeAgentAuthorizationApprovalRepoError(w, err)
		return
	}
	if created {
		logAudit(r, h.Deps, "agent_authorization_approval_exception.create", map[string]any{
			"exception_id": item.ID, "principal_id": item.PrincipalID, "grant_id": item.GrantID,
			"action": item.Action, "resource_type": item.ResourceType, "resource_id": item.ResourceID,
			"arguments_sha256": item.ArgumentsSHA256, "expires_at": item.ExpiresAt, "reason": item.Reason,
		}, "agent_authorization_approval_exception", item.ID)
	}
	status := http.StatusOK
	if created {
		status = http.StatusCreated
	}
	writeAgentAdminJSON(w, status, map[string]any{"exception": item, "created": created})
}

func (h *AgentAuthorizationApprovalAPI) ListExceptions(w http.ResponseWriter, r *http.Request) {
	user, ok := agentAuthorizationApprovalAdminUser(w, r)
	if !ok {
		return
	}
	limit := 50
	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		value, err := strconv.Atoi(raw)
		if err != nil || value < 1 || value > 200 {
			writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "limit must be between 1 and 200")
			return
		}
		limit = value
	}
	items, err := h.Repo.ListAgentAuthorizationApprovalExceptions(r.Context(), user.TenantID, limit)
	if err != nil {
		writeErrorWithStatus(w, http.StatusServiceUnavailable, "approval_unavailable", "approval exceptions are unavailable")
		return
	}
	writeAgentAdminJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (h *AgentAuthorizationApprovalAPI) RevokeException(w http.ResponseWriter, r *http.Request) {
	user, ok := agentAuthorizationApprovalAdminUser(w, r)
	if !ok {
		return
	}
	item, changed, err := h.Repo.RevokeAgentAuthorizationApprovalException(r.Context(), user.TenantID, chi.URLParam(r, "id"), user.ID)
	if err != nil {
		writeAgentAuthorizationApprovalRepoError(w, err)
		return
	}
	if item == nil {
		writeErrorWithStatus(w, http.StatusNotFound, "not_found", "approval exception not found")
		return
	}
	if changed {
		logAudit(r, h.Deps, "agent_authorization_approval_exception.revoke", map[string]any{"exception_id": item.ID}, "agent_authorization_approval_exception", item.ID)
	}
	writeAgentAdminJSON(w, http.StatusOK, map[string]any{"exception": item, "changed": changed})
}
