package handler

// W1 1.11：内置 MCP 红线处置配置端点。
//
//	GET  /admin/v1/mcp-redline-settings                    管理台查看（任意登录成员可读）
//	PUT  /admin/v1/mcp-redline-settings                    管理员修改 {actions:{rule:alert|block}}
//	GET  /admin/v1/internal/mcp/redline-settings           gateway-core 拉取（内部密钥，X-Tenant-ID）
//
// 默认（未配置）全部 alert，行为与基线一致。仓库经构造参数注入，不改共享的 Dependencies；
// 路由需在 cmd/server/main.go 接线：store := repository.NewMCPRedlineSettingsRepository(db)。

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

// mcpRedlineSettingsStore 是红线处置配置的最小仓库面（真实实现 *repository.MCPRedlineSettingsRepository）。
type mcpRedlineSettingsStore interface {
	List(ctx context.Context, tenantID string) ([]repository.MCPRedlineSetting, error)
	Actions(ctx context.Context, tenantID string) (map[string]string, error)
	Upsert(ctx context.Context, tenantID, actor string, actions map[string]string) (map[string]string, error)
}

type mcpRedlineSettingsUpdate struct {
	Actions map[string]string `json:"actions"`
}

func mcpRedlineStoreReady(w http.ResponseWriter, store mcpRedlineSettingsStore) bool {
	if store == nil {
		writeErrorWithStatus(w, http.StatusServiceUnavailable, "service_unavailable", "mcp redline settings not configured")
		return false
	}
	return true
}

// GetMCPRedlineSettings handles GET /admin/v1/mcp-redline-settings
func GetMCPRedlineSettings(deps *Dependencies, store mcpRedlineSettingsStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "no user")
			return
		}
		if !mcpRedlineStoreReady(w, store) {
			return
		}
		items, err := store.List(r.Context(), user.TenantID)
		if err != nil {
			writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", "failed to load mcp redline settings")
			return
		}
		writeJSON(w, map[string]interface{}{"items": items})
	}
}

// UpdateMCPRedlineSettings handles PUT /admin/v1/mcp-redline-settings
func UpdateMCPRedlineSettings(deps *Dependencies, store mcpRedlineSettingsStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "no user")
			return
		}
		if !canManageAgentGuard(user.Role) {
			writeErrorWithStatus(w, http.StatusForbidden, "forbidden", "only admins can manage MCP redline settings")
			return
		}
		if !mcpRedlineStoreReady(w, store) {
			return
		}
		var req mcpRedlineSettingsUpdate
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&req); err != nil {
			writeError(w, "invalid_request", "invalid JSON format")
			return
		}
		actions, err := repository.NormalizeMCPRedlineUpdates(req.Actions)
		if err != nil {
			writeError(w, "invalid_request", err.Error())
			return
		}
		before, err := store.Upsert(r.Context(), user.TenantID, user.ID, actions)
		if err != nil {
			writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", "failed to save mcp redline settings")
			return
		}
		logAudit(r, deps, "mcp_redline_settings.update", map[string]interface{}{
			"before": before, "after": actions,
		}, "mcp_redline_settings", user.TenantID)
		items, err := store.List(r.Context(), user.TenantID)
		if err != nil {
			writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", "failed to load mcp redline settings")
			return
		}
		writeJSON(w, map[string]interface{}{"items": items})
	}
}

// GetInternalMCPRedlineSettings handles GET /admin/v1/internal/mcp/redline-settings
// 响应 {actions:{rule:action}}，网关据此决定红线命中是否阻断。
func GetInternalMCPRedlineSettings(store mcpRedlineSettingsStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tenantID := resolveInternalTenantID(r)
		if tenantID == "" {
			writeUnauthorized(w, "tenant context not found")
			return
		}
		if !mcpRedlineStoreReady(w, store) {
			return
		}
		actions, err := store.Actions(r.Context(), tenantID)
		if err != nil {
			writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", "failed to load mcp redline settings")
			return
		}
		writeJSON(w, map[string]interface{}{"actions": actions})
	}
}
