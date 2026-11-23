package permission

import (
	"context"
	"crypto/sha256"
	"fmt"
	"log"

	"github.com/jackc/pgx/v5/pgxpool"
)

// permissionMatrix defines the RBAC permission matrix for builtin roles
// format: role_name -> []{"resource:action", ...}
var permissionMatrix = map[string][]string{
	// 旧版管理员只读取系统币种设置；切换系统币种仅平台管理员（影响全部钱包与价格，等同资金调账）。
	"admin": {"billing_settings:read"},
	"platform_connector": {
		"agent_credentials:read", "agent_credentials:write",
		"agent_enforcement_policies:read", "agent_enforcement_policies:write",
		"gateway_enforcement_status:read", "integration_events:read", "integration_upstreams:read", "security_events:read",
		"integration_projects:read",
		// Connector middleware enforces a closed route contract; no audit resource.
		"gateway_security_policies:read", "gateway_security_policies:write",
		"agentguard_policies:read", "agentguard_policies:write",
		"mcp_policies:read", "mcp_policies:write",
	},
	"platform_admin": {
		"billing_currency:write", "billing_settings:read",
		// All resources × all actions (handled via special check in checker)
		// Still seed explicit entries for completeness
		"users:read", "users:write", "users:delete", "users:approve", "users:export",
		"users.grants:read", "users.grants:write", "users.grants:delete",
		"teams:read", "teams:write", "teams:delete",
		"teams.members:read", "teams.members:write", "teams.members:delete",
		"projects:read", "projects:write", "projects:delete",
		"project_users:read", "project_users:write", "project_users:delete",
		"quota_policies:read", "quota_policies:write", "quota_policies:delete", "quota_policies:approve",
		"api_keys:read", "api_keys:write", "api_keys:delete",
		"models:read", "models:write", "models:delete",
		"providers:read", "providers:write", "providers:delete",
		"routing_policies:read", "routing_policies:write", "routing_policies:delete",
		"audit_chain:read", "audit_chain:export",
		"security_events:read", "security_events:export",
		"saving_metrics:read", "saving_metrics:export",
		"billing:read", "billing:write",
		"fx_rates:read", "fx_rates:write",
		"pricing:read", "pricing:write",
		"forecast_jobs:read", "forecast_jobs:write",
		"notify_channels:read", "notify_channels:write", "notify_channels:delete",
		"proxy_access_keys:read", "proxy_access_keys:write", "proxy_access_keys:delete",
		"mcp_servers:read", "mcp_servers:write", "mcp_servers:delete",
		"mcp_policies:read", "mcp_policies:write", "mcp_policies:delete",
		"alert_inbox:read", "alert_inbox:write",
		"alert_groups:read", "alert_groups:write",
		"agentguard_policies:read", "agentguard_policies:write",
		"agent_operation_policy:read", "agent_operation_policy:write",
		"agent_operation_event:read",
		"agent_endpoints:read", "agent_endpoints:write", "agent_sessions:read", "agent_enrollment:admin",
		"agent_principals:read", "agent_principals:admin", "agent_authorization:check",
		"agent_intent_tasks:read", "agent_intent_tasks:admin",

		"skill_assets:read", "skill_assets:write",
		"system_license:read", "system_license:write",
		"identity_sources:read", "identity_sources:write", "identity_sources:delete", "identity_sources:manage",
		"directory_sources:read", "directory_sources:write", "directory_sources:manage",
		"diagnostics:read", "diagnostics:write",
	},
	"tenant_owner": {
		"billing_settings:read",
		"users:read", "users:write", "users:delete",
		"users.grants:read", "users.grants:write", "users.grants:delete",
		"teams:read", "teams:write", "teams:delete",
		"teams.members:read", "teams.members:write", "teams.members:delete",
		"projects:read", "projects:write", "projects:delete",
		"project_users:read", "project_users:write", "project_users:delete",
		"quota_policies:read", "quota_policies:write", "quota_policies:approve",
		"api_keys:read", "api_keys:write", "api_keys:delete",
		"models:read", "models:write",
		"providers:read", "providers:write",
		"routing_policies:read", "routing_policies:write",
		"audit_chain:read", "audit_chain:export",
		"security_events:read", "security_events:export",
		"audit_dispositions:write",
		"saving_metrics:read",
		"fx_rates:read", "fx_rates:write",
		"pricing:read",
		"forecast_jobs:read", "forecast_jobs:write",
		"notify_channels:read", "notify_channels:write",
		"proxy_access_keys:read", "proxy_access_keys:write",
		"mcp_servers:read", "mcp_servers:write",
		"mcp_policies:read", "mcp_policies:write", "mcp_policies:delete",
		"alert_inbox:read", "alert_inbox:write",
		"alert_groups:read", "alert_groups:write",
		"agentguard_policies:read", "agentguard_policies:write",
		"agent_operation_policy:read", "agent_operation_policy:write",
		"agent_operation_event:read",
		"agent_endpoints:read", "agent_endpoints:write", "agent_sessions:read", "agent_enrollment:admin",
		"agent_principals:read", "agent_principals:admin", "agent_authorization:check",
		"agent_intent_tasks:read", "agent_intent_tasks:admin",

		"identity_sources:read", "identity_sources:write", "identity_sources:delete", "identity_sources:manage",
		"directory_sources:read", "directory_sources:write", "directory_sources:manage",
		"diagnostics:read", "diagnostics:write",
	},
	// tenant_admin 是租户级管理员（handler 层 canManageAgentGuard/org_admin/usage 已把它
	// 当作与 tenant_owner 同级的特权角色）。此前 permissionMatrix 无此档 → enforce 模式下
	// 所有 RBAC 受控路由对 tenant_admin 一律 403（仅 dryRun 靠 handler 门禁兜底）。这里补齐
	// MCP 安全网关相关授权（与 tenant_owner 的 MCP 授权对齐），使其可管理 MCP 服务与策略；
	// 同时允许只读本租户团队列表。团队写删及 users 权限仍不授予，避免非预期提权。
	"tenant_admin": {
		"billing_settings:read",
		"teams:read",
		"quota_policies:read", "quota_policies:write",
		"security_events:read", "security_events:export",
		"audit_dispositions:write",
		"mcp_servers:read", "mcp_servers:write",
		"mcp_policies:read", "mcp_policies:write", "mcp_policies:delete",
		"agent_operation_policy:read", "agent_operation_policy:write",
		"agent_operation_event:read",
		"agent_endpoints:read", "agent_endpoints:write", "agent_sessions:read", "agent_enrollment:admin",
		"agent_principals:read", "agent_principals:admin", "agent_authorization:check",
		"agent_intent_tasks:read", "agent_intent_tasks:admin",

		"identity_sources:read", "identity_sources:write", "identity_sources:delete", "identity_sources:manage",
		"directory_sources:read", "directory_sources:write", "directory_sources:manage",
		"diagnostics:read", "diagnostics:write",
	},
	// auditor: read-only audit data. Since W4 it no longer gets business config reads
	// (models/providers/routing_policies/quota/pricing/fx/notify/api_keys ...);
	// see docs/design/ws4-rbac-matrix.md. Route-level enforcement lives in sod.go (always-on).
	"auditor": {
		"users:read",
		"audit_chain:read", "audit_chain:export",
		"security_events:read", "security_events:export",
		"alert_groups:read",
		"agent_operation_event:read",
		"agent_endpoints:read", "agent_sessions:read",
		"diagnostics:read",
	},
	// security_officer: security policies and alert handling; no user management, no system
	// config, no audit reads. sod.go allows its routes directly; this entry keeps
	// UAG_RBAC_ENFORCE=true and /me/permissions consistent with it.
	"security_officer": {
		"teams:read", "projects:read", "models:read", "api_keys:read",
		"security_events:read", "security_events:export",
		"audit_dispositions:write",
		"alert_groups:read", "alert_groups:write",
		"mcp_policies:read", "mcp_policies:write", "mcp_policies:delete",
		"mcp_servers:read",
		"agentguard_policies:read", "agentguard_policies:write",
		"agent_operation_policy:read", "agent_operation_policy:write",
		"agent_operation_event:read",
		"skill_assets:read", "skill_assets:write",
		"diagnostics:read",
	},
	"team_owner": {
		"teams:read", "teams:write",
		"teams.members:read", "teams.members:write", "teams.members:delete",
		"projects:read",
		"project_users:read",
		"users:read",
		"api_keys:read", "api_keys:write",
		"quota_policies:read", "quota_policies:write",
		"models:read",
		"saving_metrics:read",
		"diagnostics:read",
	},
	"team_member": {
		"teams:read",
		"teams.members:read",
		"projects:read",
		"api_keys:read",
		"models:read",
		"quota_policies:read",
		"diagnostics:read",
	},
	"project_owner": {
		"projects:read", "projects:write",
		"project_users:read", "project_users:write", "project_users:delete",
		"quota_policies:read", "quota_policies:write",
		"api_keys:read", "api_keys:write", "api_keys:delete",
		"models:read",
		"saving_metrics:read",
		"routing_policies:read",
		"diagnostics:read",
	},
	"project_developer": {
		"projects:read",
		"project_users:read",
		"quota_policies:read",
		"api_keys:read", "api_keys:write",
		"models:read",
		"diagnostics:read",
	},
	"project_viewer": {
		"projects:read",
		"project_users:read",
		"quota_policies:read",
		"api_keys:read",
		"models:read",
		"diagnostics:read",
	},
	// dept_manager（部门主管）：只读，且只看本部门。定位见
	// docs/specs/2026-07-06-rbac-blast-radius-audit.md（路线乙）。
	// 分两层：本矩阵(layer A，permission_grants.role) 决定"能读哪些 resource"（纯 read，无 write/delete/export）；
	// 真正把数据收窄到"本部门"靠 handler 层(layer B，users.role='dept_manager')——resolveUsageScope 天然按 team 收窄用量，
	// 团队详情类读接口(members/projects/models/effective/usage)由 callerMayAccessTeam 做成员校验。
	// 刻意不给：api_keys(防 reveal/铸key)、providers、audit_chain、mcp_*、agentguard_*、
	//   notify/proxy/fx/pricing、content 留证原文(不看对话原文，用户明确选"只看聚合+告警元信息")、
	//   一切 *:write/*:delete/*:export。
	// security_events/alert_groups 已按 project 收窄（handler 层），故放开给"看本部门告警元信息"。
	"dept_manager": {
		"saving_metrics:read",  // 用量/统计（resolveUsageScope 已按 team 收窄）
		"teams:read",           // teams 列表 + teams/{id}/effective
		"teams.members:read",   // teams/{id}/members（本部门成员）
		"projects:read",        // projects 列表 + teams/{id}/projects（本部门应用）
		"project_users:read",   // projects/{id}/users（按 project 成员校验）
		"models:read",          // teams/{id}/models（模型白名单）+ policies/model（按 project 校验）
		"users:read",           // 员工 AI 权限 tab：users/{id}/detail（同部门校验）
		"users.grants:read",    // 员工 AI 权限 tab：users/{id}/grants
		"quota_policies:read",  // 本部门预算只读（按 project/team 校验）
		"security_events:read", // 本部门安全告警(元信息)——ListSecurityEvents 按 project 收窄
		"alert_groups:read",    // 本部门告警分组(元信息)——alert_group_handler 按 project 收窄
		"diagnostics:read",
	},
	// developer / viewer 是控制台里的员工业务角色，矩阵里此前没有条目；enforce 模式下它们没有任何 RBAC 授权。
	// 这里只授予诊断助手的只读权限，不授予任何其他资源。
	"developer": {"diagnostics:read"},
	"viewer":    {"diagnostics:read"},
}

const maxBuiltinPermissionIDLength = 50

func builtinPermissionID(roleName, resource, action string) string {
	raw := fmt.Sprintf("sysperm_%s_%s_%s", roleName, resource, action)
	if len(raw) <= maxBuiltinPermissionIDLength {
		return raw
	}
	checksum := fmt.Sprintf("%x", sha256.Sum256([]byte(raw)))[:16]
	prefixLength := maxBuiltinPermissionIDLength - len(checksum) - 1
	return raw[:prefixLength] + "_" + checksum
}

// SeedBuiltinRoles ensures all 8 builtin roles and their permission matrices
// are present in system_permissions. Idempotent via ON CONFLICT DO NOTHING.
func SeedBuiltinRoles(ctx context.Context, db *pgxpool.Pool) error {
	total := 0
	for roleName, perms := range permissionMatrix {
		for _, perm := range perms {
			resource, action, ok := splitResourceAction(perm)
			if !ok {
				continue
			}

			id := builtinPermissionID(roleName, resource, action)
			codeName := fmt.Sprintf("%s.%s.%s", roleName, resource, action)

			_, err := db.Exec(ctx, `
				INSERT INTO system_permissions (id, name, code, role_name, resource, action, is_system)
				VALUES ($1, $2, $3, $4, $5, $6, TRUE)
				ON CONFLICT (code) DO UPDATE SET
					role_name = EXCLUDED.role_name,
					resource = EXCLUDED.resource,
					action = EXCLUDED.action
			`, id, codeName, codeName, roleName, resource, action)
			if err != nil {
				return fmt.Errorf("seed permission %s: %w", codeName, err)
			}
			total++
		}
	}
	// 收回已下线的内置授权：币种切换只属于 platform_admin（其权限由 checker 直接放行，不依赖这些行）。
	// 此前版本曾把 billing_currency:write 种给 admin/tenant_owner/tenant_admin，已 seed 过的库里这些行
	// 不会因为矩阵变化自动消失，所以在这里幂等删除，只动内置（is_system）行。
	revoked, err := db.Exec(ctx, `
		DELETE FROM system_permissions
		WHERE is_system = TRUE AND resource = 'billing_currency' AND action = 'write'
		  AND role_name IS DISTINCT FROM 'platform_admin'`)
	if err != nil {
		return fmt.Errorf("revoke superseded billing_currency grants: %w", err)
	}
	if n := revoked.RowsAffected(); n > 0 {
		log.Printf("[permission] revoked %d superseded billing_currency:write grants", n)
	}
	log.Printf("[permission] seeded %d builtin role permissions", total)
	return nil
}

func splitResourceAction(s string) (resource, action string, ok bool) {
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == ':' {
			return s[:i], s[i+1:], true
		}
	}
	return "", "", false
}
