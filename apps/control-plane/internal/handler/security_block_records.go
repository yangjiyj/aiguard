package handler

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

// ListSecurityBlockRecords serves 阻断记录: every request a data plane actually
// blocked, with the configured rule, the matched detail, and every number an
// agent-side notice can show (block, operation, request, trace).
//
// GET /admin/v1/security/block-records?q=&layer=&from=&to=&limit=&offset=
func ListSecurityBlockRecords(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "authentication required")
			return
		}
		if deps == nil || deps.SecurityEventRepo == nil {
			writeErrorWithStatus(w, http.StatusServiceUnavailable, "service_unavailable", "block records are unavailable")
			return
		}
		query := r.URL.Query()
		filter := repository.SecurityBlockRecordFilter{
			Query:  strings.TrimSpace(query.Get("q")),
			Layer:  strings.TrimSpace(query.Get("layer")),
			Limit:  parseIntParam(query.Get("limit"), 50),
			Offset: parseIntParam(query.Get("offset"), 0),
		}
		if len(filter.Query) > 256 {
			writeError(w, "invalid_request", "q must be at most 256 characters")
			return
		}
		for key, target := range map[string]*time.Time{"from": &filter.From, "to": &filter.To} {
			raw := strings.TrimSpace(query.Get(key))
			if raw == "" {
				continue
			}
			parsed, err := time.Parse(time.RFC3339, raw)
			if err != nil {
				writeError(w, "invalid_request", key+" must be RFC3339")
				return
			}
			*target = parsed
		}
		// Department managers only see their own projects (same rule as the
		// security event list); an empty project set is an empty result.
		if scope, ok := resolveUsageScope(r, deps); ok && !scope.FullTenant {
			if len(scope.ProjectIDs) == 0 {
				writeJSON(w, map[string]any{"items": []repository.SecurityBlockRecord{}, "total": 0, "limit": filter.Limit, "offset": filter.Offset})
				return
			}
			filter.ProjectIDs = scope.ProjectIDs
		}
		records, total, err := deps.SecurityEventRepo.ListBlockRecords(r.Context(), user.TenantID, filter)
		if err != nil {
			log.Printf("ListSecurityBlockRecords error: tenant=%s err=%v", user.TenantID, err)
			writeError(w, "internal_error", "failed to list block records")
			return
		}
		// 列表不带命中原文和前后文，减小列表响应；有内容证据权限的角色在详情、溯源里看。
		for i := range records {
			stripBlockRecordEvidence(&records[i])
		}
		writeJSON(w, map[string]any{"items": records, "total": total, "limit": filter.Limit, "offset": filter.Offset})
	}
}

// GetSecurityBlockRecord returns one block by its block number.
//
// GET /admin/v1/security/block-records/{block_id}
func GetSecurityBlockRecord(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "authentication required")
			return
		}
		if deps == nil || deps.SecurityEventRepo == nil {
			writeErrorWithStatus(w, http.StatusServiceUnavailable, "service_unavailable", "block records are unavailable")
			return
		}
		blockID := strings.TrimSpace(chi.URLParam(r, "block_id"))
		if blockID == "" || len(blockID) > 128 {
			writeError(w, "invalid_request", "invalid block id")
			return
		}
		record, err := deps.SecurityEventRepo.GetBlockRecord(r.Context(), user.TenantID, blockID)
		if errors.Is(err, pgx.ErrNoRows) {
			writeErrorWithStatus(w, http.StatusNotFound, "not_found", "block record not found")
			return
		}
		if err != nil {
			log.Printf("GetSecurityBlockRecord error: tenant=%s err=%v", user.TenantID, err)
			writeError(w, "internal_error", "failed to read block record")
			return
		}
		if scope, ok := resolveUsageScope(r, deps); ok && !scope.FullTenant && !containsString(scope.ProjectIDs, record.ProjectID) {
			writeErrorWithStatus(w, http.StatusNotFound, "not_found", "block record not found")
			return
		}
		blockRecordForViewer(record, canReadFullTenantContentEvidence(user))
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(record)
	}
}
