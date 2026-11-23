package handler

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
	"github.com/go-chi/chi/v5"
)

type agentDelegationAuthorizer interface {
	Authorize(context.Context, repository.TrustedAgentPrincipal, repository.AgentAuthorizationRequest) (*repository.AgentAuthorizationDecision, error)
}

type agentDelegationStore interface {
	Create(context.Context, repository.TrustedAgentPrincipal, repository.AgentDelegationCreate) (*repository.AgentDelegationCreated, error)
	Revoke(context.Context, string, string, string) (bool, error)
	ListCalls(context.Context, string, string, string, int) ([]repository.AgentDelegationCall, error)
}

type AgentDelegationAPI struct {
	Authorizer agentDelegationAuthorizer
	Repo       agentDelegationStore
}

func NewAgentDelegationAPI(authorizer agentDelegationAuthorizer, repo agentDelegationStore) *AgentDelegationAPI {
	return &AgentDelegationAPI{Authorizer: authorizer, Repo: repo}
}

// Create is behind AgentAuthorizationAPI.Authenticate; identity and tenant come from that bearer.
func (h *AgentDelegationAPI) Create(w http.ResponseWriter, r *http.Request) {
	parent := trustedAgentAuthorizationPrincipal(r)
	if parent == nil {
		writeUnauthorized(w, "agent credential required")
		return
	}
	var input repository.AgentDelegationCreate
	if err := decodeStrictJSON(http.MaxBytesReader(w, r.Body, agentAuthorizationBodyLimit), &input); err != nil {
		writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "invalid delegation request")
		return
	}
	request := repository.AgentAuthorizationRequest{
		Action: "agents.delegate", ResourceType: "project", ResourceID: input.ProjectID,
		Context: map[string]any{"project_id": input.ProjectID}, IdempotencyKey: input.AuthorizationIdempotencyKey,
	}
	decision, err := h.Authorizer.Authorize(r.Context(), *parent, request)
	if err != nil {
		switch {
		case errors.Is(err, repository.ErrAgentAuthorizationInvalid):
			writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "invalid delegation authorization")
		case errors.Is(err, repository.ErrAgentAuthorizationPrincipalUnauthorized):
			writeUnauthorized(w, "agent credential is no longer active")
		default:
			writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", "delegation authorization unavailable")
		}
		return
	}
	if decision == nil || !decision.Allowed || decision.Reason != "allowed" {
		writeAgentAdminJSON(w, http.StatusForbidden, map[string]any{"decision": decision})
		return
	}
	created, err := h.Repo.Create(r.Context(), *parent, input)
	if err != nil {
		switch {
		case errors.Is(err, repository.ErrAgentAuthorizationInvalid):
			writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "delegation exceeds its parent scope")
		case errors.Is(err, repository.ErrAgentAuthorizationPrincipalUnauthorized):
			writeUnauthorized(w, "parent delegation authority is no longer active")
		case errors.Is(err, repository.ErrAgentAuthorizationIdempotencyConflict):
			writeErrorWithStatus(w, http.StatusConflict, "idempotency_conflict", "delegation idempotency key was already used")
		default:
			writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", "delegation could not be created")
		}
		return
	}
	writeAgentAdminSecretJSON(w, http.StatusCreated, created)
}

func (h *AgentDelegationAPI) Revoke(w http.ResponseWriter, r *http.Request) {
	parent := trustedAgentAuthorizationPrincipal(r)
	if parent == nil {
		writeUnauthorized(w, "agent credential required")
		return
	}
	found, err := h.Repo.Revoke(r.Context(), parent.TenantID, parent.ID, strings.TrimSpace(chi.URLParam(r, "id")))
	if err != nil {
		writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", "delegation revocation failed")
		return
	}
	if !found {
		writeErrorWithStatus(w, http.StatusNotFound, "not_found", "active child delegation not found")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *AgentDelegationAPI) ListCalls(w http.ResponseWriter, r *http.Request) {
	parent := trustedAgentAuthorizationPrincipal(r)
	if parent == nil {
		writeUnauthorized(w, "agent credential required")
		return
	}
	limit := 100
	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 1 || parsed > 200 {
			writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "limit must be between 1 and 200")
			return
		}
		limit = parsed
	}
	items, err := h.Repo.ListCalls(r.Context(), parent.TenantID, parent.ID, strings.TrimSpace(chi.URLParam(r, "id")), limit)
	if err != nil {
		if errors.Is(err, repository.ErrAgentAuthorizationInvalid) {
			writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "invalid delegation call query")
			return
		}
		writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", "delegation calls unavailable")
		return
	}
	writeAgentAdminJSON(w, http.StatusOK, map[string]any{"items": items})
}
