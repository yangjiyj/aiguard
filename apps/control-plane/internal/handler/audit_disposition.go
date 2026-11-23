package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/types"
)

var allowedDispositionSubjectTypes = map[string]struct{}{
	"request":        {},
	"session":        {},
	"security_event": {},
	"alert_case":     {},
	"tool_call":      {},
}

var allowedDispositionStatuses = map[string]struct{}{
	"open":           {},
	"resolved":       {},
	"false_positive": {},
	"accepted":       {},
	"escalated":      {},
}

var allowedDispositionActions = map[string]struct{}{
	"revoke_key": {},
	"ban_user":   {},
}

type auditDispositionAuthorizedWriter interface {
	UpsertAuthorized(context.Context, *repository.AuditDisposition, []string, string, string) (*repository.AuditDisposition, error)
}

func ListAuditDispositions(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user, ok := authenticatedContentEvidenceUser(w, r)
		if !ok {
			return
		}
		if !canReadFullTenantContentEvidence(user) {
			writeErrorWithStatus(w, http.StatusNotFound, "not_found", "audit dispositions not found")
			return
		}
		if deps.AuditDispositionRepo == nil {
			writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", "audit disposition repository is not configured")
			return
		}

		limit := parseIntParam(r.URL.Query().Get("limit"), 500)
		offset := parseIntParam(r.URL.Query().Get("offset"), 0)
		items, total, err := deps.AuditDispositionRepo.List(
			r.Context(),
			user.TenantID,
			r.URL.Query().Get("subject_type"),
			r.URL.Query().Get("subject_id"),
			limit,
			offset,
		)
		if err != nil {
			writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", "failed to list audit dispositions")
			return
		}

		data := make([]types.AuditDispositionInfo, len(items))
		for i, item := range items {
			data[i] = mapAuditDispositionToInfo(item)
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(types.AuditDispositionListResponse{Data: data, Total: total})
	}
}

func UpsertAuditDisposition(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user, ok := authenticatedContentEvidenceUser(w, r)
		if !ok {
			return
		}
		if !canMutateAuditDisposition(user) {
			writeErrorWithStatus(w, http.StatusForbidden, "forbidden", "insufficient permissions")
			return
		}
		if deps.AuditDispositionRepo == nil {
			writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", "audit disposition repository is not configured")
			return
		}

		var req types.UpsertAuditDispositionRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "invalid JSON format")
			return
		}
		if _, ok := allowedDispositionSubjectTypes[req.SubjectType]; !ok {
			writeErrorWithStatus(w, http.StatusBadRequest, "invalid_subject_type", "unsupported disposition subject type")
			return
		}
		if req.SubjectID == "" {
			writeErrorWithStatus(w, http.StatusBadRequest, "invalid_subject_id", "subject_id is required")
			return
		}
		if _, ok := allowedDispositionStatuses[req.Status]; !ok {
			writeErrorWithStatus(w, http.StatusBadRequest, "invalid_status", "unsupported disposition status")
			return
		}
		var seenThrough *time.Time
		if req.SubjectType == "alert_case" {
			parsed, e := time.Parse(time.RFC3339Nano, req.CaseSeenThrough)
			if e != nil || parsed.After(time.Now()) {
				writeErrorWithStatus(w, http.StatusBadRequest, "invalid_case_snapshot", "case_seen_through must be the observed detection timestamp")
				return
			}
			seenThrough = &parsed
			if req.Action != "" {
				writeErrorWithStatus(w, http.StatusBadRequest, "invalid_action", "case review does not revoke credentials or ban users")
				return
			}
		}
		if req.Action != "" {
			if _, ok := allowedDispositionActions[req.Action]; !ok {
				writeErrorWithStatus(w, http.StatusBadRequest, "invalid_action", "unsupported disposition action")
				return
			}
			if req.ActionTarget == "" {
				writeErrorWithStatus(w, http.StatusBadRequest, "invalid_action_target", "action_target is required when action is set")
				return
			}
			if deps.DispositionEnforcer == nil {
				writeErrorWithStatus(w, http.StatusServiceUnavailable, "enforcer_unavailable", "disposition enforcer is not configured")
				return
			}
		}

		writer, ok := deps.AuditDispositionRepo.(auditDispositionAuthorizedWriter)
		if !ok {
			writeErrorWithStatus(w, http.StatusServiceUnavailable, "service_unavailable", "disposition subject authorization is unavailable")
			return
		}
		var projectIDs []string
		if !isFullTenantRole(user.Role) {
			scope, scopeOK := resolveUsageScope(r, deps)
			if !scopeOK || len(scope.ProjectIDs) == 0 {
				writeErrorWithStatus(w, http.StatusNotFound, "not_found", "disposition subject not found")
				return
			}
			projectIDs = scope.ProjectIDs
		}
		item, err := writer.UpsertAuthorized(r.Context(), &repository.AuditDisposition{
			CaseSeenThrough: seenThrough,
			TenantID:        user.TenantID,
			SubjectType:     req.SubjectType,
			SubjectID:       req.SubjectID,
			Status:          req.Status,
			Note:            req.Note,
			OperatorID:      user.ID,
			OperatorName:    user.Username,
		}, projectIDs, req.Action, req.ActionTarget)
		if errors.Is(err, repository.ErrStaleCaseSnapshot) {
			writeErrorWithStatus(w, http.StatusConflict, "case_changed", "case has new evidence; refresh before reviewing")
			return
		}
		if errors.Is(err, repository.ErrNotFound) {
			writeErrorWithStatus(w, http.StatusNotFound, "not_found", "disposition subject not found")
			return
		}
		if err != nil {
			writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", "failed to save audit disposition")
			return
		}

		auditDetail := map[string]interface{}{
			"subject_type": req.SubjectType,
			"subject_id":   req.SubjectID,
			"status":       req.Status,
		}
		if req.Action != "" {
			if err := deps.DispositionEnforcer.Enforce(r.Context(), DispositionAction{
				TenantID: user.TenantID,
				Action:   req.Action,
				Target:   req.ActionTarget,
				Operator: user.ID,
				Reason:   req.Note,
			}); err != nil {
				writeErrorWithStatus(w, http.StatusInternalServerError, "enforcement_failed", "failed to enforce disposition action")
				return
			}
			auditDetail["action"] = req.Action
			auditDetail["action_target"] = req.ActionTarget
		}

		logAudit(r, deps, "audit_disposition.upsert", auditDetail, req.SubjectType, req.SubjectID)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(mapAuditDispositionToInfo(item))
	}
}

func mapAuditDispositionToInfo(item *repository.AuditDisposition) types.AuditDispositionInfo {
	return types.AuditDispositionInfo{
		ID:           item.ID,
		SubjectType:  item.SubjectType,
		SubjectID:    item.SubjectID,
		Status:       item.Status,
		Note:         item.Note,
		OperatorID:   item.OperatorID,
		OperatorName: item.OperatorName,
		CreatedAt:    item.CreatedAt.Format(time.RFC3339),
		UpdatedAt:    item.UpdatedAt.Format(time.RFC3339),
	}
}
