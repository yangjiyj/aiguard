package handler

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/notify"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// ListNotifyChannels handles GET /admin/v1/notify-channels
func ListNotifyChannels(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "no user")
			return
		}
		if deps.NotifyChannelsRepo == nil {
			writeErrorWithStatus(w, http.StatusServiceUnavailable, "service_unavailable", "notify channels not configured")
			return
		}

		chs, err := deps.NotifyChannelsRepo.ListByTenant(r.Context(), user.TenantID)
		if err != nil {
			writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", err.Error())
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"channels": chs})
	}
}

// CreateNotifyChannel handles POST /admin/v1/notify-channels
// Body: {type, name, config_json}
func CreateNotifyChannel(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "no user")
			return
		}
		if deps.NotifyChannelsRepo == nil {
			writeErrorWithStatus(w, http.StatusServiceUnavailable, "service_unavailable", "notify channels not configured")
			return
		}

		var req struct {
			Type       string         `json:"type"`
			Name       string         `json:"name"`
			ConfigJSON map[string]any `json:"config_json"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, "invalid_request", "invalid JSON")
			return
		}
		if req.Type == "" || req.Name == "" {
			writeError(w, "invalid_request", "type and name are required")
			return
		}

		if notifyPrivateTargetForbidden(user, nil, req.ConfigJSON) {
			writeErrorWithStatus(w, http.StatusForbidden, "egress_override_requires_platform_role", egressLooseningForbiddenMessage)
			return
		}
		ch := &repository.NotifyChannel{
			ID:         "nc_" + uuid.New().String()[:8],
			TenantID:   user.TenantID,
			Type:       req.Type,
			Name:       req.Name,
			ConfigJSON: req.ConfigJSON,
			Enabled:    true,
		}
		if err := deps.NotifyChannelsRepo.Create(r.Context(), ch); err != nil {
			writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", err.Error())
			return
		}

		logAudit(r, deps, "notify_channel.create", map[string]interface{}{
			"channel_id": ch.ID, "type": ch.Type, "name": ch.Name,
			"allow_private_target": notifyChannelAllowsPrivateTarget(ch.ConfigJSON),
		}, "notify_channel", ch.ID)
		auditNotifyChannelPrivateTarget(r, deps, ch.ID, nil, ch.ConfigJSON)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(ch)
	}
}

// UpdateNotifyChannel handles PUT /admin/v1/notify-channels/{id}
// Body: {name, config_json, enabled}
func UpdateNotifyChannel(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "no user")
			return
		}
		if deps.NotifyChannelsRepo == nil {
			writeErrorWithStatus(w, http.StatusServiceUnavailable, "service_unavailable", "notify channels not configured")
			return
		}

		id := chi.URLParam(r, "id")
		if id == "" {
			writeError(w, "invalid_request", "id required")
			return
		}

		var req struct {
			Name       string         `json:"name"`
			ConfigJSON map[string]any `json:"config_json"`
			Enabled    bool           `json:"enabled"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, "invalid_request", "invalid JSON")
			return
		}

		var previousConfig map[string]any
		if previous, err := deps.NotifyChannelsRepo.GetForTenant(r.Context(), user.TenantID, id); err == nil && previous != nil {
			previousConfig = previous.ConfigJSON
		}
		if notifyPrivateTargetForbidden(user, previousConfig, req.ConfigJSON) {
			writeErrorWithStatus(w, http.StatusForbidden, "egress_override_requires_platform_role", egressLooseningForbiddenMessage)
			return
		}
		if err := deps.NotifyChannelsRepo.Update(r.Context(), user.TenantID, id, req.Name, req.ConfigJSON, req.Enabled); err != nil {
			writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", err.Error())
			return
		}

		logAudit(r, deps, "notify_channel.update", map[string]interface{}{
			"channel_id": id, "name": req.Name, "enabled": req.Enabled,
			"allow_private_target": notifyChannelAllowsPrivateTarget(req.ConfigJSON),
		}, "notify_channel", id)
		auditNotifyChannelPrivateTarget(r, deps, id, previousConfig, req.ConfigJSON)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"ok": true})
	}
}

// DeleteNotifyChannel handles DELETE /admin/v1/notify-channels/{id}
func DeleteNotifyChannel(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "no user")
			return
		}
		if deps.NotifyChannelsRepo == nil {
			writeErrorWithStatus(w, http.StatusServiceUnavailable, "service_unavailable", "notify channels not configured")
			return
		}

		id := chi.URLParam(r, "id")
		if id == "" {
			writeError(w, "invalid_request", "id required")
			return
		}

		if err := deps.NotifyChannelsRepo.Delete(r.Context(), user.TenantID, id); err != nil {
			writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", err.Error())
			return
		}

		logAudit(r, deps, "notify_channel.delete", map[string]interface{}{"channel_id": id}, "notify_channel", id)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"ok": true})
	}
}

// TestNotifyChannel handles POST /admin/v1/notify-channels/{id}/test
// 向本租户的指定渠道发送一条中文测试消息；失败返回中文原因。渠道只按 (tenant_id, id) 查找。
func TestNotifyChannel(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "no user")
			return
		}
		if deps.NotifyDispatcher == nil {
			writeErrorWithStatus(w, http.StatusServiceUnavailable, "service_unavailable", "告警通知服务未启用")
			return
		}
		id := chi.URLParam(r, "id")
		if id == "" {
			writeError(w, "invalid_request", "缺少渠道编号")
			return
		}

		err := deps.NotifyDispatcher.SendTestMessage(r.Context(), user.TenantID, id)
		if errors.Is(err, pgx.ErrNoRows) {
			writeErrorWithStatus(w, http.StatusNotFound, "not_found", "通知渠道不存在")
			return
		}
		reason := notify.FriendlyError(err)
		logAudit(r, deps, "notify_channel.test", map[string]interface{}{
			"channel_id": id, "success": err == nil, "reason": reason,
		}, "notify_channel", id)
		if err != nil {
			writeErrorWithStatus(w, http.StatusBadGateway, "notify_test_failed", "测试消息发送失败："+reason)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"ok": true, "message": "测试消息已发送"})
	}
}
