// W4 three-officer separation of duties: single source of truth for which
// console role may open which page. App.tsx route guards and Layout.tsx menu
// filtering both read from here, so menus never show a page the route guard
// would bounce. The backend SoD guard (control-plane permission/sod.go) is the
// real enforcement; this is the presentation layer.
// See docs/design/ws4-rbac-matrix.md.

export const SYSTEM_ADMIN_ROLES = ["platform_admin", "admin"] as const
export const TENANT_ADMIN_ROLES = ["tenant_owner", "tenant_admin"] as const

// 谁能查看告警/会话的证据内容。与后端 handler.canReadFullTenantContentEvidence 保持一致
// （platform_admin、tenant_owner、tenant_admin、auditor、security_officer）；三员分立下 evidence 类对安全员与审计员都是 Allow
// （docs/design/ws4-rbac-matrix.md）。其余角色只看告警元数据。后端才是真正的闸门，这里只决定页面是否展示入口。
export function canReadContentEvidence(role?: string): boolean {
  return role === "platform_admin" || role === "admin" || role === "tenant_owner" || role === "tenant_admin" ||
    role === "auditor" || role === "security_officer"
}

// 谁能查看脱敏原文留证：只有系统管理员与安全保密员（与后端 roles.CanViewRawEvidence 一致）。
// 审计员、租户管理员等只看脱敏版本；后端 SoD 才是真正的闸门，这里只决定是否展示入口。
// 旧 admin 角色值不放行（与后端、现有内容留证一致）。
export function canViewRawEvidenceRole(role?: string): boolean {
  return role === "platform_admin" || role === "security_officer"
}

// 脱敏原文留证开关对全平台生效，只有系统管理员能改（与后端 UpdateRawEvidenceSettings 一致）。
export function canToggleRawEvidenceRole(role?: string): boolean {
  return role === "platform_admin"
}

// 谁能写 /system/settings：与后端 UpdateSystemSettings 一致，只认平台管理员（旧 admin 不算）。
export function canWriteSystemSettings(role?: string): boolean {
  return role === "platform_admin"
}

// 谁能做 Skill 版本审核（批准、隔离、撤销、提交扫描）。
export function canManageSkillAdmission(role?: string): boolean {
  return ["platform_admin", "admin", "tenant_owner", "tenant_admin", "security_officer"].includes(role ?? "")
}

// 谁能改安全设置（防护项、智能体行为、例外、MCP 调用策略等）：与后端 roles.CanManageSecurityPolicy 一致，
// 系统管理员与安全保密员；审计员、租户管理员只读。
export function canManageSecurityPolicy(role?: string): boolean {
  return role === "platform_admin" || role === "security_officer"
}

// 平台级角色：系统管理员，或属于平台租户（tenant_default / tenant_system）的安全员；与后端 isPlatformLevel 一致。
// 防跳板出站的对象级放行（反向代理、MCP 服务的高级出站，通知渠道的允许内网地址）只有平台级角色能打开。
export const PLATFORM_TENANT_IDS: readonly string[] = ["tenant_default", "tenant_system"]
export function isPlatformLevelRole(role?: string, tenantId?: string): boolean {
  if (role === "platform_admin" || role === "admin") return true
  return role === "security_officer" && PLATFORM_TENANT_IDS.includes(tenantId ?? "")
}

// 平台级安全设置（system_settings 里全平台共享的安全键）的可写判断：能改安全设置且是平台级角色。
// 租户级安全员只读（后端对租户级账号返回 global_config_requires_platform_level）。
export function canManagePlatformSecuritySettings(role?: string, tenantId?: string): boolean {
  return canManageSecurityPolicy(role) && isPlatformLevelRole(role, tenantId)
}

export function isSystemAdminRole(role?: string): boolean {
  return role === "platform_admin" || role === "admin"
}

// 控制台管理员：与后端 roles.IsConsoleAdministrator 对齐（platform_admin / admin / tenant_owner / tenant_admin）。
// security_officer、auditor、viewer 等不在其中。消息中心「批量标为已读」入口只对管理员展示；后端才是真正的闸门。
export function isConsoleAdministratorRole(role?: string): boolean {
  return role === "platform_admin" || role === "admin" || role === "tenant_owner" || role === "tenant_admin"
}

// Access groups. A page lists the groups (or single roles) that may open it.
const SYS = [...SYSTEM_ADMIN_ROLES]
const TENANT = [...TENANT_ADMIN_ROLES]
const SO = ["security_officer"]
const AUD = ["auditor"]
const DEPT = ["dept_manager"]
const MEMBERS = ["team_owner", "team_member", "project_owner", "project_developer", "project_viewer", "developer", "viewer"]

// Path -> roles allowed. Paths not listed are open to every authenticated user.
export const PAGE_ACCESS: Record<string, readonly string[]> = {
  // Security operations (security officer's duty; system admin keeps policy
  // ownership per decision 2026-09-30; tenant admins keep tenant scope).
  "/security/policies": [...SYS, ...SO],
  "/security/tool-config": [...SYS, ...SO],
  "/security/agents": [...SYS, ...SO, ...TENANT],
  "/security/agents/advanced": [...SYS, ...SO, ...TENANT],
  "/security/agentguard": [...SYS, ...SO, ...TENANT],
  "/security/agent-operation-protection/advanced": [...SYS, ...SO],
  "/security/skills": [...SYS, ...SO, ...TENANT],
  // 训练语料扫描：上传、下载脱敏副本是安全写操作（SoDSecurityWrite），只给系统管理员与安全保密员。
  "/security/corpus-scan": [...SYS, ...SO],
  "/security/alerts": [...SYS, ...SO, ...AUD, ...TENANT, ...DEPT],
  "/security/blocks": [...SYS, ...SO, ...AUD, ...TENANT, ...DEPT],
  "/security/agent-tools": [...SYS, ...SO, ...AUD],
  "/mcp-gateway/servers": [...SYS, ...SO],
  "/mcp-gateway/policies": [...SYS, ...SO],
  "/mcp-gateway/approvals": [...SYS, ...SO],
  "/mcp-gateway/audit": [...SYS, ...SO, ...AUD],

  "/agent/sessions": [...SYS, ...TENANT, ...AUD],

  // Audit & compliance (auditor's duty). Decision 2026-10-01: the system
  // administrator also has full read access, matching the backend SoD change.
  "/compliance/overview": [...SYS, ...AUD, ...SO],
  "/audit/access-retention": [...SYS, ...AUD, ...SO],
  "/system/audit-operations": [...SYS, ...AUD],
  "/system/service-health": ["platform_admin"],
  "/audit/login-history": [...SYS, ...AUD],

  // Resources & billing (system administrator's duty).
  "/organizations": [...SYS, ...TENANT, ...DEPT],
  "/users": [...SYS],
  "/apps": [...SYS, ...TENANT],
  "/keys": [...SYS],
  "/identity-sources": [...SYS, ...TENANT],
  "/identity-sources/login": [...SYS, ...TENANT],
  "/identity-sources/directory": [...SYS, ...TENANT],
  "/providers": [...SYS, ...TENANT],
  "/models": [...SYS, ...TENANT],
  "/model-operations": [...SYS, ...TENANT],
  "/model-routing": [...SYS, "tenant_owner", "project_owner"],
  // P1 资源与计费重组：价格与成本、账单与对账继承原“计费中心”的角色；预算与额度继承原“配额与限流”。
  // 旧路径保留同样的权限，供跳转路由守卫使用。
  "/cost/customer-billing": [...SYS],
  "/cost/pricing": [...SYS],
  "/cost/statements": [...SYS],
  "/cost/quota-policies": [...SYS, ...TENANT, ...DEPT, ...MEMBERS],
  "/cost/budgets": [...SYS, ...TENANT, ...DEPT, ...MEMBERS],

  // System management.
  "/system/settings": [...SYS],
  "/system/retention-storage": [...SYS],
  "/system/license": [...SYS],
  "/system/notify-channels": [...SYS],
  "/connect/channels": [...SYS],
  "/connect/network": [...SYS],
  "/cost/alerts": [...SYS, ...SO, ...AUD],
}

// Sub-pages without their own menu entry are guarded like their parent.
PAGE_ACCESS["/security"] = PAGE_ACCESS["/security/policies"]

// Business pages open to every authenticated role except the two officers:
// the security officer and the auditor must not browse business/billing data.
// Kept as a deny-list so legacy or unknown roles keep their pre-W4 access and
// can never bounce in a redirect loop off their own home page.
export const OFFICER_EXCLUDED_PATHS = new Set<string>(["/dashboard", "/usage", "/cost/records"])

export function isOfficerRole(role?: string): boolean {
  return role === "security_officer" || role === "auditor"
}

// 平台级安全员可以进入的系统页，页面里只显示与防护相关的区块
// （系统设置的“故障处理”“检测执行”，网络与证书的“出站限制”）。租户级安全员仍不能进。
const PLATFORM_SECURITY_OFFICER_PATHS = new Set<string>(["/system/settings", "/connect/network"])

export function canAccessPath(role: string | undefined, path: string, tenantId?: string): boolean {
  if (role === "chat_user") return path === "/chat"
  if (OFFICER_EXCLUDED_PATHS.has(path)) return !isOfficerRole(role)
  if (role === "security_officer" && PLATFORM_SECURITY_OFFICER_PATHS.has(path)) return isPlatformLevelRole(role, tenantId)
  const allow = PAGE_ACCESS[path]
  if (!allow) return true
  return !!role && allow.includes(role)
}

// Menu-only narrowing: pages that stay reachable by URL for more roles than
// see them in the side menu (pre-W4 behaviour kept on purpose).
export const MENU_ACCESS: Record<string, readonly string[]> = {
  "/cost/quota-policies": [...SYS, ...TENANT],
  "/cost/budgets": [...SYS, ...TENANT],
}
const MENU_HIDDEN: Record<string, readonly string[]> = {
  "/dashboard": [...DEPT],
}

export function canSeeMenuItem(role: string | undefined, path: string, tenantId?: string): boolean {
  if (!canAccessPath(role, path, tenantId)) return false
  if (role && MENU_HIDDEN[path]?.includes(role)) return false
  const allow = MENU_ACCESS[path]
  return !allow || (!!role && allow.includes(role))
}

// Landing page per role: each officer lands on their own duty.
export function roleHome(role: string): string {
  switch (role) {
    case "chat_user":
      return "/chat"
    case "auditor":
      return "/system/audit-operations"
    case "security_officer":
      return "/security/alerts"
    case "dept_manager":
      return "/cost/records"
    default:
      return "/dashboard"
  }
}

// Use a same-origin fragment so the one-use proof is absent from HTTP URLs,
// referrers and reverse-proxy access logs. The Portal removes it immediately.
export function openAuthenticatedChat(ticket: string): void {
  if (!/^[A-Za-z0-9_-]{43}$/.test(ticket)) throw new Error("登录交接已失效，请重新登录")
  window.location.replace("/chat/login#chat_ticket=" + ticket)
}
