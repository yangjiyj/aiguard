package handler

// W1 1.6（D2）：可选"只允许勾选的工具"模板的管理端点。
//
//	GET    /admin/v1/mcp-servers/{id}/allowlist-template   查看当前是否套用、勾选了哪些工具
//	POST   /admin/v1/mcp-servers/{id}/allowlist-template   套用/替换 {tools:[...], enabled?:bool, dry_run?:bool}
//	DELETE /admin/v1/mcp-servers/{id}/allowlist-template   撤销（只删模板生成的策略）
//
// 默认行为不变：不调用这些端点就不会产生任何模板策略。路由需在 cmd/server/main.go 接线。

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"sort"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

// mcpAllowlistTemplateStore 是模板落库需要的最小仓库面（真实实现为 *repository.MCPPoliciesRepository）。
type mcpAllowlistTemplateStore interface {
	ReplaceMCPAllowlistTemplate(ctx context.Context, policies []*repository.MCPPolicy) error
	RemoveMCPAllowlistTemplate(ctx context.Context, tenantID, serverID string) (int64, error)
}

type mcpAllowlistTemplateRequest struct {
	Tools   []string `json:"tools"`
	Enabled *bool    `json:"enabled"`
	DryRun  bool     `json:"dry_run"`
}

type mcpAllowlistTemplateView struct {
	ServerID     string                  `json:"server_id"`
	Applied      bool                    `json:"applied"`
	Enabled      bool                    `json:"enabled"`
	AllowedTools []string                `json:"allowed_tools"`
	UnknownTools []string                `json:"unknown_tools,omitempty"`
	Policies     []*repository.MCPPolicy `json:"policies"`
	DryRun       bool                    `json:"dry_run,omitempty"`
}

// summarizeMCPAllowlistTemplate 从策略列表中提取某 server 的模板状态（纯函数）。
func summarizeMCPAllowlistTemplate(serverID string, policies []*repository.MCPPolicy) mcpAllowlistTemplateView {
	view := mcpAllowlistTemplateView{ServerID: serverID, AllowedTools: []string{}, Policies: []*repository.MCPPolicy{}}
	note := repository.MCPAllowlistTemplateNote(serverID)
	for _, p := range policies {
		if p == nil || p.ServerID != serverID || p.Note != note {
			continue
		}
		view.Applied = true
		view.Policies = append(view.Policies, p)
		if p.ToolPattern == "*" {
			view.Enabled = p.Enabled
			continue
		}
		view.AllowedTools = append(view.AllowedTools, p.ToolPattern)
	}
	sort.Strings(view.AllowedTools)
	return view
}

func mcpAllowlistTemplateStoreFrom(deps *Dependencies) mcpAllowlistTemplateStore {
	if deps == nil || deps.MCPPolicyRepo == nil {
		return nil
	}
	store, _ := deps.MCPPolicyRepo.(mcpAllowlistTemplateStore)
	return store
}

// mcpAllowlistTemplateServer 校验调用者与 server 归属，失败时已写响应并返回 nil。
func mcpAllowlistTemplateServer(w http.ResponseWriter, r *http.Request, deps *Dependencies, write bool) (*repository.User, string) {
	user := auth.GetUser(r.Context())
	if user == nil {
		writeUnauthorized(w, "no user")
		return nil, ""
	}
	if write && !canManageAgentGuard(user.Role) {
		writeErrorWithStatus(w, http.StatusForbidden, "forbidden", "only admins can manage MCP policies")
		return nil, ""
	}
	if deps.MCPPolicyRepo == nil || deps.MCPServerRepo == nil {
		writeErrorWithStatus(w, http.StatusServiceUnavailable, "service_unavailable", "mcp policies not configured")
		return nil, ""
	}
	id := chi.URLParam(r, "id")
	if id == "" {
		writeError(w, "invalid_request", "id required")
		return nil, ""
	}
	if _, err := deps.MCPServerRepo.Get(r.Context(), user.TenantID, id); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			writeErrorWithStatus(w, http.StatusNotFound, "not_found", "mcp server not found")
			return nil, ""
		}
		writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", err.Error())
		return nil, ""
	}
	return user, id
}

// GetMCPAllowlistTemplate handles GET /admin/v1/mcp-servers/{id}/allowlist-template
func GetMCPAllowlistTemplate(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user, serverID := mcpAllowlistTemplateServer(w, r, deps, false)
		if user == nil {
			return
		}
		policies, err := deps.MCPPolicyRepo.ListByTenant(r.Context(), user.TenantID, serverID)
		if err != nil {
			writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", err.Error())
			return
		}
		writeJSON(w, summarizeMCPAllowlistTemplate(serverID, policies))
	}
}

// ApplyMCPAllowlistTemplate handles POST /admin/v1/mcp-servers/{id}/allowlist-template
func ApplyMCPAllowlistTemplate(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user, serverID := mcpAllowlistTemplateServer(w, r, deps, true)
		if user == nil {
			return
		}
		var req mcpAllowlistTemplateRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, "invalid_request", "invalid JSON format")
			return
		}
		enabled := true
		if req.Enabled != nil {
			enabled = *req.Enabled
		}
		policies, err := repository.BuildMCPAllowlistTemplatePolicies(user.TenantID, serverID, user.ID, req.Tools, enabled)
		if err != nil {
			writeError(w, "invalid_request", err.Error())
			return
		}
		view := summarizeMCPAllowlistTemplate(serverID, policies)
		view.UnknownTools = mcpAllowlistUnknownTools(r.Context(), deps, user.TenantID, serverID, view.AllowedTools)
		if req.DryRun {
			view.DryRun = true
			writeJSON(w, view)
			return
		}
		store := mcpAllowlistTemplateStoreFrom(deps)
		if store == nil {
			writeErrorWithStatus(w, http.StatusServiceUnavailable, "service_unavailable", "mcp allowlist template not supported")
			return
		}
		if err := store.ReplaceMCPAllowlistTemplate(r.Context(), policies); err != nil {
			writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", err.Error())
			return
		}
		logAudit(r, deps, "mcp_policy.allowlist_template.apply", map[string]interface{}{
			"server_id": serverID, "allowed_tools": view.AllowedTools, "enabled": enabled,
			"unknown_tools": view.UnknownTools,
		}, "mcp_server", serverID)
		writeJSON(w, view)
	}
}

// RemoveMCPAllowlistTemplate handles DELETE /admin/v1/mcp-servers/{id}/allowlist-template
func RemoveMCPAllowlistTemplate(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user, serverID := mcpAllowlistTemplateServer(w, r, deps, true)
		if user == nil {
			return
		}
		store := mcpAllowlistTemplateStoreFrom(deps)
		if store == nil {
			writeErrorWithStatus(w, http.StatusServiceUnavailable, "service_unavailable", "mcp allowlist template not supported")
			return
		}
		removed, err := store.RemoveMCPAllowlistTemplate(r.Context(), user.TenantID, serverID)
		if err != nil {
			writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", err.Error())
			return
		}
		logAudit(r, deps, "mcp_policy.allowlist_template.remove", map[string]interface{}{
			"server_id": serverID, "removed": removed,
		}, "mcp_server", serverID)
		writeJSON(w, map[string]interface{}{"server_id": serverID, "removed": removed})
	}
}

// mcpAllowlistUnknownTools 返回勾选了但当前不在册（未同步或已移除）的工具名，仅作提示，不阻止套用。
func mcpAllowlistUnknownTools(ctx context.Context, deps *Dependencies, tenantID, serverID string, names []string) []string {
	if deps == nil || deps.MCPToolRepo == nil {
		return nil
	}
	tools, err := deps.MCPToolRepo.ListByServer(ctx, tenantID, serverID)
	if err != nil {
		return nil
	}
	live := map[string]bool{}
	for _, t := range tools {
		if t != nil && !t.Removed {
			live[t.ToolName] = true
		}
	}
	var unknown []string
	for _, n := range names {
		if !live[n] {
			unknown = append(unknown, n)
		}
	}
	return unknown
}
