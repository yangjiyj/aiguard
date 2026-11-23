package handler

import (
	"context"
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

type intentTaskAdminRepository interface {
	CreateIntentTask(context.Context, string, string, repository.AgentIntentTaskCreate) (*repository.AgentIntentTask, error)
	GetIntentTask(context.Context, string, string) (*repository.AgentIntentTask, error)
	RevokeIntentTask(context.Context, string, string, string) (bool, error)
}

func canApproveAgentIntentTask(user *repository.User) bool {
	if user == nil || user.DepartmentAssignmentMode == "emergency" {
		return false
	}
	switch user.Role {
	case "platform_admin", "tenant_owner", "tenant_admin":
		return true
	default:
		return false
	}
}

// CreateIntentTask is an explicit tenant-admin approval operation. Tenant and
// actor come from the authenticated session; endpoint/principal/grant locators
// are resolved against server records by the repository.
func (h *AgentAuthorizationAPI) CreateIntentTask(w http.ResponseWriter, r *http.Request) {
	user, ok := agentAdminUser(w, r)
	if !ok {
		return
	}
	if !canApproveAgentIntentTask(user) {
		writeErrorWithStatus(w, http.StatusForbidden, "forbidden", "agent intent task approval requires a tenant administrator")
		return
	}
	repo, ok := h.Repo.(intentTaskAdminRepository)
	if !ok {
		writeErrorWithStatus(w, http.StatusServiceUnavailable, "unavailable", "agent intent task service unavailable")
		return
	}
	var request repository.AgentIntentTaskCreate
	if err := decodeStrictJSON(http.MaxBytesReader(w, r.Body, agentAuthorizationBodyLimit), &request); err != nil {
		writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "invalid approved intent task")
		return
	}
	created, err := repo.CreateIntentTask(r.Context(), user.TenantID, user.ID, request)
	if err != nil {
		if errors.Is(err, repository.ErrAgentIntentTaskInvalid) {
			writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "invalid approved intent task")
			return
		}
		writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", "failed to approve intent task")
		return
	}
	writeAgentAdminSecretJSON(w, http.StatusCreated, created)
}

func (h *AgentAuthorizationAPI) GetIntentTask(w http.ResponseWriter, r *http.Request) {
	user, ok := agentAdminUser(w, r)
	if !ok {
		return
	}
	if !canApproveAgentIntentTask(user) {
		writeErrorWithStatus(w, http.StatusForbidden, "forbidden", "agent intent task approval requires a tenant administrator")
		return
	}
	repo, ok := h.Repo.(intentTaskAdminRepository)
	if !ok {
		writeErrorWithStatus(w, http.StatusServiceUnavailable, "unavailable", "agent intent task service unavailable")
		return
	}
	task, err := repo.GetIntentTask(r.Context(), user.TenantID, chi.URLParam(r, "id"))
	if err != nil {
		writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", "failed to read intent task")
		return
	}
	if task == nil {
		writeErrorWithStatus(w, http.StatusNotFound, "not_found", "intent task not found")
		return
	}
	writeAgentAdminJSON(w, http.StatusOK, task)
}

func (h *AgentAuthorizationAPI) RevokeIntentTask(w http.ResponseWriter, r *http.Request) {
	user, ok := agentAdminUser(w, r)
	if !ok {
		return
	}
	if !canApproveAgentIntentTask(user) {
		writeErrorWithStatus(w, http.StatusForbidden, "forbidden", "agent intent task approval requires a tenant administrator")
		return
	}
	repo, ok := h.Repo.(intentTaskAdminRepository)
	if !ok {
		writeErrorWithStatus(w, http.StatusServiceUnavailable, "unavailable", "agent intent task service unavailable")
		return
	}
	found, err := repo.RevokeIntentTask(r.Context(), user.TenantID, user.ID, chi.URLParam(r, "id"))
	if err != nil {
		if errors.Is(err, repository.ErrAgentIntentTaskInvalid) {
			writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "invalid intent task ID")
			return
		}
		writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", "failed to revoke intent task")
		return
	}
	if !found {
		writeErrorWithStatus(w, http.StatusNotFound, "not_found", "active intent task not found")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
