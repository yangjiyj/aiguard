package handler

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
	"github.com/go-chi/chi/v5"
)

// AgentDestinationApprovalRepo is the subset of
// *repository.AgentDestinationApprovalRepository this handler needs, so tests
// can substitute a fake.
type AgentDestinationApprovalRepo interface {
	List(context.Context, string, repository.DestinationApprovalRuleFilter) (*repository.DestinationApprovalRulePage, error)
	Create(context.Context, string, repository.DestinationApprovalRuleCreate) (*repository.DestinationApprovalRule, error)
	Deactivate(context.Context, string, string, string) (bool, error)
}

// AgentDestinationApprovalAPI is the T08 admin management surface for the
// server-side approval-destination catalog that T07's server-side
// verification (repository.verifyDestinationApprovalTx) checks every
// aiprobe-reported destination against. It never deletes a rule: Deactivate
// only flips enabled=false, preserving history for audit.
type AgentDestinationApprovalAPI struct {
	Repo AgentDestinationApprovalRepo
	Deps *Dependencies
}

func NewAgentDestinationApprovalAPI(repo AgentDestinationApprovalRepo, deps *Dependencies) *AgentDestinationApprovalAPI {
	return &AgentDestinationApprovalAPI{Repo: repo, Deps: deps}
}

func (h *AgentDestinationApprovalAPI) ready(w http.ResponseWriter) bool {
	if h == nil || h.Repo == nil {
		writeErrorWithStatus(w, http.StatusServiceUnavailable, "service_unavailable", "destination approval service is not configured")
		return false
	}
	return true
}

func (h *AgentDestinationApprovalAPI) List(w http.ResponseWriter, r *http.Request) {
	user, ok := agentAdminUser(w, r)
	if !ok || !h.ready(w) {
		return
	}
	page, size, valid := agentAdminPageOrError(w, r)
	if !valid {
		return
	}
	q := r.URL.Query()
	enabled, ok := optionalBool(q.Get("enabled"))
	if !ok {
		writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "enabled must be true or false")
		return
	}
	filter := repository.DestinationApprovalRuleFilter{Category: strings.TrimSpace(q.Get("category")), Enabled: enabled, Page: page, PageSize: size}
	if filter.Category != "" && !validUnifiedAssetText(filter.Category, 32, false) {
		writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "invalid category")
		return
	}
	value, err := h.Repo.List(r.Context(), user.TenantID, filter)
	if err != nil {
		writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", "failed to list destination approval rules")
		return
	}
	writeAgentAdminJSON(w, http.StatusOK, value)
}

func (h *AgentDestinationApprovalAPI) Create(w http.ResponseWriter, r *http.Request) {
	user, ok := agentAdminUser(w, r)
	if !ok || !h.ready(w) {
		return
	}
	var body struct {
		RuleID      *string `json:"rule_id"`
		MatchType   *string `json:"match_type"`
		MatchValue  *string `json:"match_value"`
		Category    *string `json:"category"`
		Description *string `json:"description"`
	}
	if !decodeAgentAssetBody(w, r, &body) {
		return
	}
	if body.RuleID == nil || body.MatchType == nil || body.MatchValue == nil || body.Category == nil {
		writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "rule_id, match_type, match_value, and category are required")
		return
	}
	description := ""
	if body.Description != nil {
		description = strings.TrimSpace(*body.Description)
	}
	if !validUnifiedAssetText(description, 1024, true) {
		writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "invalid description")
		return
	}
	input := repository.DestinationApprovalRuleCreate{
		RuleID: strings.TrimSpace(*body.RuleID), MatchType: strings.TrimSpace(*body.MatchType),
		MatchValue: strings.TrimSpace(*body.MatchValue), Category: strings.TrimSpace(*body.Category),
		Description: description, CreatedBy: user.ID,
	}
	created, err := h.Repo.Create(r.Context(), user.TenantID, input)
	switch {
	case errors.Is(err, repository.ErrDestinationApprovalRuleInvalid):
		writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "invalid destination approval rule")
		return
	case errors.Is(err, repository.ErrDestinationApprovalRuleConflict):
		writeErrorWithStatus(w, http.StatusConflict, "conflict", "an enabled rule already matches this value")
		return
	case err != nil:
		writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", "failed to create destination approval rule")
		return
	}
	logAudit(r, h.Deps, "agent.destination_approval.rule.create", map[string]interface{}{"rule_id": created.RuleID, "match_type": created.MatchType, "category": created.Category}, "agent_destination_approval_rule", created.ID)
	writeAgentAdminJSON(w, http.StatusCreated, created)
}

func (h *AgentDestinationApprovalAPI) Deactivate(w http.ResponseWriter, r *http.Request) {
	user, ok := agentAdminUser(w, r)
	if !ok || !h.ready(w) {
		return
	}
	id := strings.TrimSpace(chi.URLParam(r, "id"))
	if !validUnifiedAssetText(id, 128, false) {
		writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "invalid rule id")
		return
	}
	ok2, err := h.Repo.Deactivate(r.Context(), user.TenantID, id, user.ID)
	switch {
	case errors.Is(err, repository.ErrDestinationApprovalRuleNotFound):
		writeErrorWithStatus(w, http.StatusNotFound, "not_found", "destination approval rule not found")
		return
	case err != nil:
		writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", "failed to deactivate destination approval rule")
		return
	}
	if !ok2 {
		writeErrorWithStatus(w, http.StatusNotFound, "not_found", "destination approval rule not found")
		return
	}
	logAudit(r, h.Deps, "agent.destination_approval.rule.deactivate", map[string]interface{}{"rule_id": id}, "agent_destination_approval_rule", id)
	writeAgentAdminJSON(w, http.StatusOK, map[string]bool{"deactivated": true})
}
