package handler

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
	"github.com/go-chi/chi/v5"
)

// ListAlertInbox handles GET /admin/v1/alerts/inbox
// Query params: unread=true&limit=20
func ListAlertInbox(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "no user")
			return
		}
		if deps.AlertInboxRepo == nil {
			writeErrorWithStatus(w, http.StatusServiceUnavailable, "service_unavailable", "alert inbox not configured")
			return
		}

		unreadOnly := r.URL.Query().Get("unread") == "true"
		limit := 20
		if l := r.URL.Query().Get("limit"); l != "" {
			if n, err := strconv.Atoi(l); err == nil && n > 0 {
				limit = n
			}
		}

		var items []*repository.AlertInboxItem
		var err error
		if unreadOnly {
			items, err = deps.AlertInboxRepo.ListUnread(r.Context(), user.TenantID, limit)
		} else {
			items, err = deps.AlertInboxRepo.List(r.Context(), user.TenantID, limit)
		}
		if err != nil {
			writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", err.Error())
			return
		}
		if items == nil {
			items = []*repository.AlertInboxItem{}
		}

		inboxItemsForViewer(items, canReadFullTenantContentEvidence(user))
		unreadCount, _ := deps.AlertInboxRepo.CountUnread(r.Context(), user.TenantID)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"items":        items,
			"unread_count": unreadCount,
		})
	}
}

// MarkAlertRead handles POST /admin/v1/alerts/{id}/read
func MarkAlertRead(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "no user")
			return
		}
		if deps.AlertInboxRepo == nil {
			writeErrorWithStatus(w, http.StatusServiceUnavailable, "service_unavailable", "alert inbox not configured")
			return
		}

		id := chi.URLParam(r, "id")
		if id == "" {
			writeError(w, "invalid_request", "id required")
			return
		}

		// 越权修复：按当前用户租户过滤，拿到别家 alert id 也只是 no-op。
		if err := deps.AlertInboxRepo.MarkRead(r.Context(), user.TenantID, id); err != nil {
			writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", err.Error())
			return
		}

		logAudit(r, deps, "alert.read", map[string]interface{}{"alert_id": id}, "alert", id)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"ok": true})
	}
}
