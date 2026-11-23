package handler

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"unicode/utf8"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

type contentAuditUserCursor struct {
	Name string `json:"n"`
	ID   string `json:"i"`
}

func encodeContentAuditUserCursor(item repository.ContentAuditUserOption) string {
	raw, _ := json.Marshal(contentAuditUserCursor{Name: strings.ToLower(item.Username), ID: item.ID})
	return base64.RawURLEncoding.EncodeToString(raw)
}

func decodeContentAuditUserCursor(value string) (contentAuditUserCursor, error) {
	var cursor contentAuditUserCursor
	raw, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return cursor, err
	}
	err = json.Unmarshal(raw, &cursor)
	return cursor, err
}

func writeEmptyContentAuditUsers(w http.ResponseWriter, limit, offset int) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"data": []repository.ContentAuditUserOption{}, "limit": limit, "offset": offset,
		"has_more": false, "next_cursor": "",
	})
}

func ListContentAuditUsers(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user, ok := authenticatedContentEvidenceUser(w, r)
		if !ok {
			return
		}
		if deps.ContentAuditSelector.Users == nil {
			writeErrorWithStatus(w, http.StatusServiceUnavailable, "service_unavailable", "content audit user selector is unavailable")
			return
		}
		query := strings.TrimSpace(r.URL.Query().Get("q"))
		if utf8.RuneCountInString(query) > 128 {
			writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "q exceeds 128 characters")
			return
		}
		limit := parseIntParam(r.URL.Query().Get("limit"), 50)
		if limit <= 0 {
			limit = 50
		}
		if limit > 100 {
			limit = 100
		}
		offset := parseIntParam(r.URL.Query().Get("offset"), 0)
		if offset < 0 {
			offset = 0
		}
		filter := repository.ContentAuditUserSelectorFilter{
			TenantID: user.TenantID, Query: query, Limit: limit, Offset: offset,
		}
		if rawCursor := strings.TrimSpace(r.URL.Query().Get("cursor")); rawCursor != "" {
			cursor, err := decodeContentAuditUserCursor(rawCursor)
			if err != nil || cursor.ID == "" {
				writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "invalid cursor")
				return
			}
			filter.CursorName, filter.CursorID, filter.Offset = cursor.Name, cursor.ID, 0
			offset = 0
		}
		if !canReadFullTenantContentEvidence(user) {
			scopeRepo := deps.ContentAuditSelector.Departments
			if scopeRepo == nil && deps.TeamMemberRepo != nil {
				scopeRepo = deps.TeamMemberRepo
			}
			if scopeRepo == nil {
				writeEmptyContentAuditUsers(w, limit, offset)
				return
			}
			ids, err := scopeRepo.ListTeamSubtreeIDsByUser(r.Context(), user.TenantID, user.ID)
			if err != nil || len(ids) == 0 {
				writeEmptyContentAuditUsers(w, limit, offset)
				return
			}
			filter.DepartmentIDs = ids
		}
		items, hasMore, err := deps.ContentAuditSelector.Users.ListContentAuditUsers(r.Context(), filter)
		if err != nil {
			writeError(w, "internal_error", "failed to list content audit users")
			return
		}
		nextCursor := ""
		if hasMore && len(items) > 0 {
			nextCursor = encodeContentAuditUserCursor(items[len(items)-1])
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"data": items, "limit": limit, "offset": offset,
			"has_more": hasMore, "next_cursor": nextCursor,
		})
	}
}
