package handler

import (
	"context"
	"errors"
	"net/http"

	"github.com/yangjiyj/aiguard/packages/shared-go/headeraudit"
	"github.com/yangjiyj/aiguard/packages/shared-go/headercompat"
)

const (
	jjdguardTenantHeader = "X-JJDGuard-Tenant-Id"
	legacyTenantHeader   = "X-NewAPI-Tenant-Id"
)

var errHeaderConflictAuditUnavailable = errors.New("header conflict audit unavailable")

type headerContractSystemWriter interface {
	CreateHeaderContractConflictOnce(ctx context.Context, eventID string, payload map[string]any) error
}

func persistHeaderConflict(ctx context.Context, deps *Dependencies, event headeraudit.Event) error {
	if deps == nil || deps.SystemRepo == nil || deps.AuditAppender == nil {
		return errHeaderConflictAuditUnavailable
	}
	system, ok := deps.SystemRepo.(headerContractSystemWriter)
	if !ok {
		return errHeaderConflictAuditUnavailable
	}
	eventID := "header-contract-conflict:" + event.OccurrenceID
	payload := event.Payload()
	if err := system.CreateHeaderContractConflictOnce(ctx, eventID, payload); err != nil {
		return errors.Join(errHeaderConflictAuditUnavailable, err)
	}
	if err := deps.AuditAppender.AppendCritical(ctx, "", eventID, payload); err != nil {
		return errors.Join(errHeaderConflictAuditUnavailable, err)
	}
	return nil
}

// criticalHeaderValue is the only compatibility read at control-plane product boundaries.
func criticalHeaderValue(w http.ResponseWriter, r *http.Request, deps *Dependencies, service, kind, newName, legacyName string) (string, bool) {
	value, _, err := headercompat.Resolve(r.Header, newName, legacyName)
	if err == nil {
		return value, true
	}
	event, eventErr := headeraudit.NewEvent(service, kind, r.Header, r.RemoteAddr)
	if eventErr != nil || persistHeaderConflict(r.Context(), deps, event) != nil {
		writeErrorWithStatus(w, http.StatusServiceUnavailable, "header_conflict_audit_unavailable", "security audit unavailable")
		return "", false
	}
	if kind == "internal_token" {
		writeErrorWithStatus(w, http.StatusUnauthorized, "internal_token_header_conflict", "conflicting credential metadata")
	} else {
		writeErrorWithStatus(w, http.StatusBadRequest, "header_value_conflict", "conflicting request metadata")
	}
	return "", false
}
