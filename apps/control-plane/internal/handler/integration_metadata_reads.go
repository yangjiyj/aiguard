package handler

import (
	"context"
	"net/http"
	"strconv"
	"time"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
	ai "github.com/yangjiyj/aiguard/packages/shared-go/agentintegration"
)

// 独立的只读接口，避免让既有凭据写入仓储获得额外权限或依赖。
type integrationMetadataReader interface {
	CredentialHits(context.Context, string, repository.CredentialHitsQuery) (*repository.CredentialHitsPage, error)
	CredentialRetentionStatus(context.Context, string, string, time.Time) (*repository.CredentialRetentionStatus, error)
}

func ListIntegrationCredentialHits(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user, ok := integrationActor(w, r, deps)
		if !ok {
			return
		}
		params := r.URL.Query()
		for _, field := range []string{"key_id", "since", "until", "cursor", "limit"} {
			if values, present := params[field]; present && (len(values) != 1 || values[0] == "" && field != "cursor") {
				integrationError(w, ai.ErrInvalid)
				return
			}
		}
		q := repository.CredentialHitsQuery{KeyID: params.Get("key_id"), Cursor: params.Get("cursor")}
		for name, target := range map[string]*time.Time{"since": &q.Since, "until": &q.Until} {
			if value := params.Get(name); value != "" {
				parsed, err := time.Parse(time.RFC3339Nano, value)
				if err != nil {
					integrationError(w, ai.ErrInvalid)
					return
				}
				*target = parsed
			}
		}
		if value := params.Get("limit"); value != "" {
			limit, err := strconv.Atoi(value)
			if err != nil || limit < 1 || limit > 200 {
				integrationError(w, ai.ErrInvalid)
				return
			}
			q.Limit = limit
		}
		q, err := repository.NormalizeCredentialHitsQuery(user.TenantID, q, time.Now())
		if err != nil {
			integrationError(w, err)
			return
		}
		reader, ok := deps.IntegrationRepo.(integrationMetadataReader)
		if !ok {
			writeErrorWithStatus(w, 503, "integration_unavailable", "集成查询暂时不可用")
			return
		}
		page, err := reader.CredentialHits(r.Context(), user.TenantID, q)
		if err != nil {
			integrationError(w, err)
			return
		}
		integrationWriteJSON(w, http.StatusOK, page)
	}
}

func GetIntegrationRetentionStatus(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user, ok := integrationActor(w, r, deps)
		if !ok {
			return
		}
		keys := r.URL.Query()["key_id"]
		if len(keys) != 1 || !ai.ValidID(keys[0]) {
			integrationError(w, ai.ErrInvalid)
			return
		}
		reader, ok := deps.IntegrationRepo.(integrationMetadataReader)
		if !ok {
			writeErrorWithStatus(w, 503, "integration_unavailable", "集成查询暂时不可用")
			return
		}
		status, err := reader.CredentialRetentionStatus(r.Context(), user.TenantID, keys[0], time.Now().UTC())
		if err != nil {
			integrationError(w, err)
			return
		}
		integrationWriteJSON(w, http.StatusOK, status)
	}
}
