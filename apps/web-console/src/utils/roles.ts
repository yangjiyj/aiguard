// 平台/系统角色的中文展示与取值收口。
//
// 四套角色务必区分，切勿混用：
//   1) users.role        —— 全局平台角色，权威域 = platform_admin/security_officer/auditor/tenant_admin/dept_manager/developer/viewer/chat_user
//                          （与后端 handler 白名单 isValidUserPlatformRole、session_test.go 一致）
//   2) team_members.role —— 部门内角色（owner/member），见 utils/risk.ts teamRoleLabel
//   3) project_users.role—— 应用内角色（owner/developer/viewer）
//   4) system_roles      —— permission_grants 的 scoped RBAC 角色，GET /admin/v1/roles 返回
//
// 本文件只负责 (1) 平台角色 与 (4) system_roles 的展示，二者互不通用。

// ── (1) 平台角色 users.role ─────────────────────────────────────────────

// 创建/编辑用户时角色下拉的权威取值域（硬编码，不从 /roles 拉，避免与 scoped RBAC 混淆）。
export const PLATFORM_ROLE_OPTIONS: { value: string; label: string }[] = [
  { value: 'platform_admin', label: '平台管理员（账号、资源与系统管理）' },
  { value: 'security_officer', label: '安全保密管理员（安全策略与告警处置）' },
  { value: 'auditor', label: '审计员（审计查看与导出）' },
  { value: 'tenant_admin', label: '租户管理员（本租户业务管理）' },
  { value: 'dept_manager', label: '部门主管（本部门业务查看）' },
  { value: 'developer', label: '开发者（后台业务角色）' },
  { value: 'viewer', label: '只读（后台业务查看）' },
  { value: 'chat_user', label: '普通用户（仅 Chat）' },
]

// 创建用户时的默认角色。
export const DEFAULT_PLATFORM_ROLE = 'chat_user'

const PLATFORM_ROLE_META: Record<string, { label: string; color: string }> = {
  platform_admin: { label: '平台管理员', color: 'red' },
  security_officer: { label: '安全保密管理员', color: 'purple' },
  auditor: { label: '审计员', color: 'cyan' },
  tenant_admin: { label: '租户管理员', color: 'volcano' },
  dept_manager: { label: '部门主管（只读）', color: 'geekblue' },
  developer: { label: '开发者', color: 'blue' },
  viewer: { label: '只读', color: 'default' },
  chat_user: { label: '普通用户（仅 Chat）', color: 'green' },
  // 历史遗留取值：仅用于存量数据回显，创建/编辑下拉不再提供。
  // 保留中文映射是为了避免列表/详情直接露出原始英文枚举（用户红线）。
  admin: { label: '管理员（历史）', color: 'gold' },
  operator: { label: '操作员（历史）', color: 'gold' },
  tenant_owner: { label: '租户管理员（历史）', color: 'gold' },
}

export function platformRoleMeta(role?: string): { label: string; color: string } {
  if (!role) return { label: '未设置', color: 'default' }
  return PLATFORM_ROLE_META[role] || { label: '未知角色', color: 'default' }
}

export function platformRoleLabel(role?: string): string {
  return platformRoleMeta(role).label
}

// ── (4) system_roles（scoped RBAC 角色）─────────────────────────────────

// 内置系统角色的中文兜底名，与 deploy/migrations/045_rbac_seed.sql 的 description 对齐。
// 当 /roles 接口暂不可用或某条历史授权的 role 不在返回集合中时，用它兜底避免露英文。
const SYSTEM_ROLE_LABELS: Record<string, string> = {
  platform_admin: '平台超级管理员',
  tenant_owner: '租户管理员',
  auditor: '审计员',
  team_owner: '部门管理员',
  team_member: '部门成员',
  project_owner: '应用管理员',
  project_developer: '应用开发者',
  project_viewer: '应用观察者',
  chat_user: '普通用户（仅 Chat）',
}

// GET /admin/v1/roles 返回的 system_roles 行。后端 Go 结构体没有 json tag，
// 序列化后是首字母大写键（Code/Name/Description）；这里同时兼容大小写，避免空白。
export interface RawSystemRole {
  code?: string
  Code?: string
  name?: string
  Name?: string
  description?: string
  Description?: string
}

export function normalizeSystemRole(raw: RawSystemRole): { code: string; label: string } {
  const code = raw.code ?? raw.Code ?? raw.name ?? raw.Name ?? ''
  const desc = raw.description ?? raw.Description ?? ''
  const label = desc || SYSTEM_ROLE_LABELS[code] || code || '未知角色'
  return { code, label }
}

// 展示某条授权的 role：优先动态映射（由 /roles 现拉的 code→中文），其次内置中文，最后才是 code。
export function systemRoleLabel(code?: string, dynamic?: Record<string, string>): string {
  if (!code) return '-'
  return (dynamic && dynamic[code]) || SYSTEM_ROLE_LABELS[code] || code
}
