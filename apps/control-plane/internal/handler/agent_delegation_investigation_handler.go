package handler

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

type agentDelegationInvestigator interface {
	InvestigateTree(context.Context, string, string, int) (*repository.AgentDelegationInvestigation, error)
}

// AgentDelegationInvestigationAPI serves the tenant-admin view of a delegation
// tree. It sits behind the session auth + permission middleware; the tenant is
// always the authenticated admin's tenant, never a request parameter.
type AgentDelegationInvestigationAPI struct {
	Repo agentDelegationInvestigator
}

func NewAgentDelegationInvestigationAPI(repo agentDelegationInvestigator) *AgentDelegationInvestigationAPI {
	return &AgentDelegationInvestigationAPI{Repo: repo}
}

func (h *AgentDelegationInvestigationAPI) Tree(w http.ResponseWriter, r *http.Request) {
	user, ok := agentAdminUser(w, r)
	if !ok {
		return
	}
	limit := 100
	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 1 || parsed > 500 {
			writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "limit must be between 1 and 500")
			return
		}
		limit = parsed
	}
	result, err := h.Repo.InvestigateTree(r.Context(), user.TenantID, strings.TrimSpace(chi.URLParam(r, "id")), limit)
	if err != nil {
		switch {
		case errors.Is(err, repository.ErrAgentAuthorizationInvalid):
			writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "invalid delegation investigation query")
		case errors.Is(err, repository.ErrAgentDelegationRootNotFound):
			writeErrorWithStatus(w, http.StatusNotFound, "not_found", "agent principal not found")
		default:
			writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", "delegation investigation unavailable")
		}
		return
	}
	writeAgentAdminJSON(w, http.StatusOK, result)
}
