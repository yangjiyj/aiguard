package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/roles"
)

var errKeyNotFound = repository.ErrKeyNotFound

// keyTrafficClassWriter 是 SetKeyTrafficClass 依赖的最小写接口，便于在不连库的情况下验证权限与校验。
type keyTrafficClassWriter interface {
	SetTrafficClass(ctx context.Context, tenantID, keyID, class string) error
}

// SetKeyTrafficClass 设置接入凭据的流量类别（PUT /admin/v1/keys/{id}/traffic-class）。
// 告警页的「测评流量 / 观察」车道只信这个由管理员打的标记，所以只有控制台管理员能改，
// 且只能改自己租户内的密钥。取值仅限 ""（普通）、"evaluation"（测评）、"coding"（编程助手）。
func SetKeyTrafficClass(repo keyTrafficClassWriter) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "user not found")
			return
		}
		if !roles.IsConsoleAdministrator(user.Role) {
			writeErrorWithStatus(w, http.StatusForbidden, "forbidden", "insufficient permissions")
			return
		}
		var req struct {
			TrafficClass *string `json:"traffic_class"`
		}
		dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&req); err != nil || req.TrafficClass == nil {
			writeError(w, "invalid_request", "traffic_class is required")
			return
		}
		switch *req.TrafficClass {
		case "", "evaluation", "coding":
		default:
			writeError(w, "invalid_request", "traffic_class must be one of: \"\", evaluation, coding")
			return
		}
		keyID := chi.URLParam(r, "id")
		if err := repo.SetTrafficClass(r.Context(), user.TenantID, keyID, *req.TrafficClass); err != nil {
			if errors.Is(err, repository.ErrKeyNotFound) {
				writeErrorWithStatus(w, http.StatusNotFound, "not_found", "key not found")
				return
			}
			writeError(w, "internal_error", "failed to update key traffic class")
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}
