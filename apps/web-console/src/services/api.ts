import axios, { type AxiosResponse } from 'axios'
import { useCurrencyStore } from '../stores/currency'
import { useAuthStore } from '../stores/auth'

const api = axios.create({
  baseURL: '/admin/v1',
  timeout: 30000,
  headers: {
    'Content-Type': 'application/json',
  },
})

// 普通管理 API 的默认预算保持 30 秒。模型目录同步会串行验证所选模型，
// 三个生图模型的单次探测预算各为 120 秒，现场生图请求也达到 93～105 秒。
// 同步单独使用 10 分钟，并与 control-plane 保持一致，为目录请求和回写留余量。
// 否则浏览器可能先报「同步失败」，而后台仍在验证或提交。
export const MODEL_SYNC_TIMEOUT_MS = 10 * 60 * 1000

// 导出实例仅供测试断言请求级配置；业务代码请使用下方各 *Api 对象。
export const apiClient = api

// 请求拦截器：添加 token
api.interceptors.request.use(
  (config) => {
    const token = useAuthStore.getState().token
    if (token) {
      config.headers.Authorization = `Bearer ${token}`
    }
    return config
  },
  (error) => Promise.reject(error)
)

// 响应拦截器：处理错误
api.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401 || (error.response?.status === 403 && error.response?.data?.error?.code === 'console_role_required')) {
      useAuthStore.getState().logout()
    }
    if (error.response?.status === 403 && error.response?.data?.error?.code === 'password_change_required') {
      const state = useAuthStore.getState()
      if (state.user) {
        state.setUser({ ...state.user, password_change_required: true })
      }
    }
    return Promise.reject(error)
  }
)

// Auth API
export const authApi = {
  captcha: () => api.get<{ captcha_id: string; image: string; expires_in: number }>('/captcha'),
  login: (username: string, password: string, captchaId: string, captchaCode: string) =>
    api.post('/login', {
      username, password, captcha_id: captchaId, captcha_code: captchaCode,
    }),
  logout: () => api.post('/logout'),
  me: () => api.get('/me'),
  chatLogin: () => api.post<{ chat_ticket: string; expires_in: number }>('/me/chat-login'),
  changePassword: (currentPassword: string, newPassword: string) =>
    api.post('/me/change-password', { current_password: currentPassword, new_password: newPassword }),
}

// Tenant API
export const tenantApi = {
  list: () => api.get('/tenants'),
  create: (data: { name: string; edition: string }) =>
    api.post('/tenants', data),
  get: (id: string) => api.get(`/tenants/${id}`),
  update: (id: string, data: { name?: string; edition?: string; status?: string }) =>
    api.patch(`/tenants/${id}`, data),
  delete: (id: string) => api.delete(`/tenants/${id}`),
  listTeams:    (id: string) => api.get(`/tenants/${id}/teams`),
  listUsers:    (id: string) => api.get(`/tenants/${id}/users`),
  listProjects: (id: string) => api.get(`/tenants/${id}/projects`),
  deleteProject: (id: string, projectId: string) => api.delete(`/tenants/${id}/projects/${projectId}`),
  listKeys:     (id: string) => api.get(`/tenants/${id}/keys`),
}

export interface ProductInfo {
  product_profile: 'gateway' | 'agent-platform'
  product_name: string
  product_version: string
  engine_version: string
  engine_commit: string
}

export const productApi = {
  get: () => api.get<ProductInfo>('/system/product'),
}

// 系统设置（system_settings）：读对所有控制台角色开放，写入按后端权限。
export const systemSettingsApi = {
  get: () => api.get<Record<string, unknown>>('/system/settings'),
  update: (patch: Record<string, unknown>) => api.put('/system/settings', patch),
}

// 平台级安全键（安全员也能写）：PUT /security/system-settings，键值形式与 /system/settings 相同，
// 服务端按白名单校验，名单外的键一律 400。读取仍走 GET /system/settings。
export const securitySystemSettingsApi = {
  update: (patch: Record<string, unknown>) => api.put('/security/system-settings', patch),
}

// Settings API
export const settingsApi = {
  getOrgLabels: () => api.get('/settings/org-labels'),
  setOrgLabels: (data: { org_tier1_label: string; org_tier2_label: string }) =>
    api.put('/settings/org-labels', data),
}

export interface LicensePayload {
  license_id: string
  customer: string
  license_type: string
  edition: string
  issued_at: string
  not_before: string
  expires_at: string
  max_users: number
  features: string[]
}

export interface LicensePayloadV2 {
  schemaVersion: string
  licenseId: string
  customer: {
    id: string
    displayName: string
  }
  subject?: {
    displayName: string
    products: string[]
  }
  edition: string
  issuedAt: string
  notBefore: string
  expiresAt: string
  maxUsers: number
  features: string[]
}

export interface LicenseStatus {
  status: 'active' | 'trial' | 'grace' | 'missing' | 'expired' | 'pending' | 'invalid'
  valid: boolean
  reason?: string
  days_left?: number
  trial_days?: number
  public_key_set: boolean
  imported_at?: string
  version?: string
  key_id?: string
  features?: string[]
  payload?: LicensePayload
  payload_v2?: LicensePayloadV2
}

export const licenseApi = {
  status: () => api.get<LicenseStatus>('/system/license'),
  import: (license: string) => api.post<LicenseStatus>('/system/license/import', { license }),
  hostInfo: () => api.get<Record<string, unknown>>('/system/license/host-info'),
}

type UserPlatformRole = 'platform_admin' | 'tenant_admin' | 'dept_manager' | 'developer' | 'viewer'

type CreateUserBase = {
  username: string
  password: string
  email?: string
  phone?: string
  tenant_id?: string
}

type CreateUserInput = CreateUserBase & (
  | { role: 'platform_admin'; department_id?: never }
  | { role: Exclude<UserPlatformRole, 'platform_admin'>; department_id: string }
)

type UpdateUserInput = {
  username?: string
  email?: string
  phone?: string
  role?: string
  department_id?: string
}

// User API
export const userApi = {
  list: () => api.get('/users'),
  create: (data: CreateUserInput) =>
    api.post('/users', data),
  update: (id: string, data: UpdateUserInput) =>
    api.patch(`/users/${id}`, data),
  delete: (id: string) => api.delete(`/users/${id}`),
  resetPassword: (id: string, password: string) =>
    api.post(`/users/${id}/reset-password`, { password }),
  // RBAC enhancements
  toggleStatus: (id: string, status: 'active' | 'disabled') =>
    api.patch(`/users/${id}/status`, { status }),
  listGrants: (id: string) => api.get(`/users/${id}/grants`),
  listKeys: (id: string) => api.get(`/users/${id}/keys`),
  createGrant: (id: string, data: { scope_type: string; scope_id: string; role: string }) =>
    api.post(`/users/${id}/grants`, data),
  deleteGrant: (id: string, grantId: string) =>
    api.delete(`/users/${id}/grants/${grantId}`),
  getLoginHistory: (id: string, limit = 20) =>
    api.get(`/users/${id}/login-history`, { params: { limit } }),
  getDetail: (id: string) => api.get(`/users/${id}/detail`),
  // 个人用量看板（管理员下钻）
  usage: {
    summary: (id: string, params?: UsageRangeParams) =>
      api.get(`/users/${id}/usage/summary`, { params }),
    trend: (id: string, params?: UsageRangeParams) =>
      api.get(`/users/${id}/usage/trend`, { params }),
    byModel: (id: string, params?: UsageRangeParams) =>
      api.get(`/users/${id}/usage/by-model`, { params }),
    records: (id: string, params?: UsageRecordsParams) =>
      api.get<{ records: UsageRecord[]; total: number }>(`/users/${id}/usage/records`, { params }),
  },
}

// Role API
export const roleApi = {
  list: () => api.get('/roles'),
  getPermissions: (name: string) => api.get(`/roles/${name}/permissions`),
  listResources: () => api.get('/permissions/resources'),
  listActions: () => api.get('/permissions/actions'),
}

// Me API (current user context)
export const meApi = {
  getPermissions: (scopeType?: string, scopeId?: string) =>
    api.get('/me/permissions', { params: { scope_type: scopeType, scope_id: scopeId } }),
}

// Project API
export const projectApi = {
  list: () => api.get('/projects'),
  create: (data: { name: string; code?: string; environment?: string }) =>
    api.post('/projects', data),
  get: (id: string) => api.get(`/projects/${id}`),
  update: (id: string, data: { name?: string; code?: string; environment?: string; status?: string }) =>
    api.patch(`/projects/${id}`, data),
  delete: (id: string) => api.delete(`/projects/${id}`),
  // User management
  listUsers: (id: string) => api.get(`/projects/${id}/users`),
  bindUser: (id: string, userId: string, role: string = 'developer') =>
    api.post(`/projects/${id}/users`, { user_id: userId, role }),
  unbindUser: (id: string, userId: string) =>
    api.delete(`/projects/${id}/users/${userId}`),
  // Model config
  updateModelConfig: (id: string, whitelist: string[], quotaLimits: Record<string, any>) =>
    api.patch(`/projects/${id}/model-config`, {
      model_whitelist: JSON.stringify(whitelist),
      quota_limits: JSON.stringify(quotaLimits),
    }),
}

// Key API
export const keyApi = {
  list: (project_id?: string) => api.get('/keys', { params: { project_id } }),
  create: (data: { project_id: string; user_id: string; name?: string; scopes?: string[] }) =>
    api.post('/keys', data),
  // 更新备注/名称（仅 name，走后端受保护 PATCH，租户隔离 + 限长校验）
  update: (id: string, data: { name: string }) => api.patch(`/keys/${id}`, data),
  // 设置流量类别（''普通 / evaluation 测评 / coding 编程助手）。告警页车道只信这个管理员标记；仅控制台管理员可调。
  setTrafficClass: (id: string, trafficClass: '' | 'evaluation' | 'coding') => api.put(`/keys/${id}/traffic-class`, { traffic_class: trafficClass }),
  revoke: (id: string) => api.post(`/keys/${id}/revoke`),
  delete: (id: string) => api.delete(`/keys/${id}`),
  // 后台按需揭示完整密钥（受保护端点，命中且有密文才返 full_key；老 key 返 reason 引导重置）
  reveal: (id: string) => api.get(`/keys/${id}/reveal`),
}

// Provider API
export const providerApi = {
  list: () => api.get('/providers'),
  metrics: () => api.get('/providers/metrics'),
  deleted: () => api.get('/providers/deleted'),
  create: (data: { name: string; provider_type: string; base_url: string; api_key?: string; auth_mode?: string; model_id?: string }) =>
    api.post('/providers', data),
  update: (id: string, data: { name?: string; base_url?: string; api_key?: string; status?: string }) =>
    api.patch(`/providers/${id}`, data),
  history: (id: string) => api.get(`/providers/${id}/credentials/history`),
  restore: (id: string) => api.post(`/providers/${id}/restore`),
  delete: (id: string) => api.delete(`/providers/${id}`),
}

export interface AzureModelSyncCandidate {
  catalog_model_id: string
  display_name: string
  deployment_name: string
  current_status?: string
}

export interface AzureModelSyncPreview {
  provider_id: string
  candidates: AzureModelSyncCandidate[]
  catalog_unavailable: boolean
  catalog_truncated: boolean
  current_active: number
}

export interface AzureModelSyncVerifyItem {
  catalog_model_id: string
  deployment_name: string
  protocols?: string[]
}

export type AzureModelSyncErrorKind =
  | 'unauthorized'
  | 'not_deployed'
  | 'rate_limited'
  | 'timeout'
  | 'cancelled'
  | 'invalid_request'
  | 'upstream_error'
  | 'skipped_after_unauthorized'

export interface AzureModelSyncVerification {
  catalog_model_id: string
  deployment_name: string
  protocols?: string[]
  status: 'success' | 'failed' | 'skipped'
  error_kind?: AzureModelSyncErrorKind
  message?: string
  proof_token?: string
  expires_at?: string
}

export interface AzureModelSyncVerifyResponse {
  provider_id: string
  results: AzureModelSyncVerification[]
}

export interface AzureModelSyncCommitResponse {
  provider_id: string
  created: number
  updated: number
  reactivated: number
  deactivated: number
}

// 通用模型目录同步：先从上游拉目录让管理员勾选，再只同步勾选的条目。
export interface ModelCatalogSyncCandidate {
  catalog_model_id: string
  display_name: string
  deployment_name?: string
  current_status?: string
}

export interface ModelCatalogSyncPreview {
  provider_id: string
  candidates: ModelCatalogSyncCandidate[]
  catalog_unavailable: boolean
  catalog_truncated: boolean
  current_active: number
  max_selection: number
}

export interface ModelCatalogSyncResult {
  provider_id: string
  total_seen: number
  created: number
  updated: number
  deactivated: number
  skipped: number
  verified?: number
  verification_failed?: number
  verification_failures?: Array<{ model_id: string; upstream_model_id: string; reason: string }>
  pending?: number
  reused?: number
  reappeared?: number
  synced_at?: string
  selection_applied?: boolean
  selected_matched?: number
  not_found_model_ids?: string[]
}

// Model API
export const modelApi = {
  list: (params?: { available_only?: boolean }) => params ? api.get('/models', { params }) : api.get('/models'),
  create: (data: { provider_id: string; model_name: string; model_label?: string; upstream_model_id?: string; protocols?: string[]; status?: string }) =>
    api.post('/models', data),
  evalStatus: () => api.get('/models/eval-status'),
  // 每次使用完整目录清理已移除来源；勾选项仅表示管理员纳入并探测的新模型。
  sync: (providerId: string, catalogModelIds?: string[]) =>
    api.post<ModelCatalogSyncResult>(
      '/models/sync',
      catalogModelIds && catalogModelIds.length > 0
        ? { provider_id: providerId, catalog_model_ids: catalogModelIds }
        : { provider_id: providerId },
      { timeout: MODEL_SYNC_TIMEOUT_MS }
    ),
  catalogSyncState: (providerId: string) => api.get(`/models/sync/state`, { params: { provider_id: providerId } }),
  setCatalogSyncInterval: (providerId: string, intervalSeconds: number) => api.put(`/models/sync/state`, { interval_seconds: intervalSeconds }, { params: { provider_id: providerId } }),
  previewCatalogSync: (providerId: string) =>
    api.post<ModelCatalogSyncPreview>(
      '/models/sync/candidates',
      { provider_id: providerId },
      { timeout: MODEL_SYNC_TIMEOUT_MS }
    ),
  previewVerifiedSync: (providerId: string) =>
    api.post<AzureModelSyncPreview>('/models/sync/preview', { provider_id: providerId }),
  verifySyncCandidates: (providerId: string, items: AzureModelSyncVerifyItem[]) =>
    api.post<AzureModelSyncVerifyResponse>('/models/sync/verify', { provider_id: providerId, items }),
  commitVerifiedSync: (providerId: string, proofTokens: string[]) =>
    api.post<AzureModelSyncCommitResponse>('/models/sync/commit', {
      provider_id: providerId,
      proof_tokens: proofTokens,
    }),
  updateRouting: (id: string, fallbackProviderId: string) =>
    api.patch(`/models/${id}/routing`, { fallback_provider_id: fallbackProviderId }),
  updateStatus: (id: string, status: string) =>
    api.patch(`/models/${id}/status`, { status }),
  batchDelete: (modelIds: string[]) => api.post('/models/batch-delete', { model_ids: modelIds }),
  delete: (id: string) => api.delete(`/models/${id}`),
}

// Policy API
export const policyApi = {
  getModel: () => api.get('/policies/model'),
  setModel: (data: { tenant_id: string; project_id: string; allow_list: string[]; deny_list: string[] }) =>
    api.put('/policies/model', data),
  getQuota: (params?: { project_id?: string; scope_type?: string; scope_id?: string }) =>
    api.get('/policies/quota', { params }),
  setQuota: (data: {
    tenant_id?: string
    project_id?: string
    scope_type?: string
    scope_id?: string
    daily_token_limit: number | null
    daily_token_blocked: boolean
    monthly_token_limit: number | null
    monthly_token_blocked: boolean
    daily_budget_micros: number | null
    daily_budget_blocked: boolean
    monthly_budget_micros: number | null
    monthly_budget_blocked: boolean
    rpm_limit: number | null
    rpm_blocked: boolean
    tpm_limit: number | null
    tpm_blocked: boolean
    concurrency_limit: number | null
    concurrency_blocked: boolean
    overage_action?: 'notify' | 'rate_limit'
    enforcement_mode?: 'soft' | 'enforce' | 'bypass'
    quota_timezone?: string
  }) =>
    api.put('/policies/quota', data),
}

// ===== 身份与访问 — 登录与单点登录 (identity-access-frontdoor) =====

export interface IdentitySource {
  id: string
  display_name: string
  protocol: string
  issuer_url: string
  client_id: string
  client_secret_set: boolean
  scopes: string
  subject_claim: string
  username_claim: string
  name_claim: string
  email_claim: string
  phone_claim: string
  dept_code_claim: string
  dept_name_claim: string
  groups_claim: string
  // id_token 验签方式 jwks（默认）/ none；首次登录不弹资料页
  signature_mode?: 'jwks' | 'none'
  skip_profile_review?: boolean
  status: string
  is_default: boolean
  version: number
  published_by?: string
  published_at?: string
  last_tested_at?: string
  last_test_result?: IdentityTestResult
  callback_url: string
}

export interface IdentityTestStage {
  name: string
  status: string
  message: string
}

export interface IdentityTestResult {
  success: boolean
  stages: IdentityTestStage[]
  error?: string
  tested_at?: string
  hints?: string[]
}

export interface IdentityStatus {
  has_active: boolean
  has_draft: boolean
  active_display_name?: string
  last_tested_at?: string
  emergency_admin_available: boolean
  callback_url: string
  publish_status: 'not_published' | 'publishing' | 'active' | 'error' | 'drifted' | 'disabled'
  applied_version?: number
  drift: boolean
  runtime_available: boolean
  runtime_message?: string
  drift_fields?: Array<'signature_mode' | 'username_claim' | 'skip_profile_review'>
  adopt_recommended?: boolean
}

export interface IdentityDraft {
  display_name: string
  issuer_url: string
  client_id: string
  client_secret?: string
  scopes?: string
  subject_claim?: string
  username_claim?: string
  name_claim?: string
  email_claim?: string
  phone_claim?: string
  dept_code_claim?: string
  dept_name_claim?: string
  groups_claim?: string
  signature_mode?: 'jwks' | 'none'
  skip_profile_review?: boolean
}

export interface IdentityDeptMapping {
  id: string
  match_value: string
  mapped_team_id?: string
  mapped_project_id?: string
  priority: number
  enabled: boolean
}


// 任务 12：企业身份源总览权威状态。后端聚合 login/directory 两路独立状态 + 待对账计数。
// 安全：本契约只承载客户可理解的状态/计数/时间，绝不承载 secret/Bind DN 密码/管理 URL。
export interface IdentityOverviewDirectorySummary {
  created: number
  updated: number
  disabled: number
  conflicts: number
  unassigned: number
}

export interface IdentityOverviewLogin {
  state: string // unconfigured|draft|tested|active|abnormal
  last_tested_at?: string
  last_published_at?: string
  runtime_healthy: boolean
  runtime_message?: string
}

export interface IdentityOverviewDirectory {
  state: string // unconfigured|draft|tested|active|abnormal
  last_preview_at?: string
  last_sync_at?: string
  last_sync_summary?: IdentityOverviewDirectorySummary
  runtime_healthy: boolean
  runtime_message?: string
}

export interface IdentityOverview {
  login: IdentityOverviewLogin
  directory: IdentityOverviewDirectory
  reconciliation_required: number
}

export const identityApi = {
  getSources: () => api.get('/identity/sources'),
  saveDraft: (data: IdentityDraft) => api.put('/identity/sources/draft', data),
  testConnection: () => api.post('/identity/sources/test'),
  activate: () => api.post('/identity/sources/activate'),
  disable: (confirm: boolean) => api.post('/identity/sources/disable', { confirm }),
  reconcile: () => api.post('/identity/sources/reconcile'),
  // 管理员触发：只读读取运行态并反推验签方式/用户名取值/首登资料页写回配置，不改动运行态
  adoptRuntime: (sourceId: string) => api.post('/identity/sources/adopt-runtime', { source_id: sourceId }),
  getStatus: () => api.get('/identity/status'),
  getOverview: () => api.get<IdentityOverview>('/identity/overview'),
  getDeptMappings: () => api.get('/identity/dept-mappings'),
  createDeptMapping: (data: Partial<IdentityDeptMapping>) => api.post('/identity/dept-mappings', data),
  updateDeptMapping: (id: string, data: Partial<IdentityDeptMapping>) => api.patch(`/identity/dept-mappings/${id}`, data),
  deleteDeptMapping: (id: string) => api.delete(`/identity/dept-mappings/${id}`),
}

export interface DirectorySourceSummary {
  id: string
  kind: "ad" | "ldap"
  display_name: string
  bind_password_set: boolean
  ca_cert_set: boolean
  stable_id_attribute: string
  username_attribute: string
  email_attribute: string
  name_attribute: string
  status: string
  version: number
}

export interface DirectoryDraftInput {
  kind: "ad" | "ldap"
  display_name: string
  connection_url?: string
  bind_dn?: string
  bind_password?: string
  ca_cert_pem?: string
  base_dn?: string
  users_dn?: string
  user_filter?: string
  stable_id_attribute?: string
  username_attribute?: string
  email_attribute?: string
  name_attribute?: string
  version?: number
}

// 任务 5 目录预览—激活流程返回体。响应只暴露计数与 ID，绝不暴露脱敏字段以外的内容。
export interface DirectoryPreview {
  preview_id: string
  source_id: string
  status: string
  scanned: number
  created: number
  updated: number
  disabled: number
  conflict: number
  unassigned: number
  error_code?: string
  expires_at?: string
}

export interface DirectoryActivation {
  run_id: string
  preview_id: string
  scanned: number
  created: number
  updated: number
  disabled: number
  conflict: number
  unassigned: number
  restored: number
}

export interface DirectorySyncRun {
  id: string
  source_id: string
  source_version: number
  kind: string
  status: string
  started_at: string
  finished_at?: string
  scanned: number
  created: number
  updated: number
  restored: number
  disabled: number
  conflict: number
  skipped: number
  actor_user_id?: string
  error_code?: string
}

export const directoryApi = {
  getDraft: () => api.get('/directory/sources/draft'),
  saveDraft: (data: DirectoryDraftInput) => api.put('/directory/sources/draft', data),
  testConnection: () => api.post('/directory/sources/test'),
  // 任务 5 预览—激活—历史
  previewDirectory: () => api.post<DirectoryPreview>('/directory/sources/preview'),
  getPreview: (previewId: string) => api.get<DirectoryPreview>(`/directory/sources/previews/${previewId}`),
  // 激活是破坏性操作：后端要求显式确认。漏传 body 时后端 json.Decode
  // 会读到 io.EOF，现场表现为误导性的「请求格式错误」。
  activatePreview: (previewId: string) =>
    api.post<DirectoryActivation>(`/directory/sources/previews/${previewId}/activate`, { confirm: true }),
  listSyncRuns: () => api.get<{ data: DirectorySyncRun[] } | DirectorySyncRun[]>('/directory/sync-runs'),
  getSyncRun: (runId: string) => api.get<DirectorySyncRun>(`/directory/sync-runs/${runId}`),
}


// Security API
export const securityApi = {
  listRuleSets: () => api.get('/rule-sets'),
  createRuleSet: (data: { name: string }) => api.post('/rule-sets', data),
  publishRuleSet: (id: string) => api.post(`/rule-sets/${id}/publish`),
  test: (data: { text: string; project_id?: string; model?: string }) =>
    api.post('/security/test', data),
}

// Rule API
export const ruleApi = {
  list: (ruleSetId?: string) => ruleSetId
    ? api.get('/rules', { params: { rule_set_id: ruleSetId } })
    : api.get('/rules'),
  create: (data: { rule_set_id: string; rule_type: string; name: string; action?: string; severity?: string; priority?: number; match_config_json?: object }) =>
    api.post('/rules', data),
  update: (id: string, data: { name?: string; action?: string; severity?: string; priority?: number; enabled?: boolean; match_config_json?: object }) =>
    api.patch(`/rules/${id}`, data),
  delete: (id: string) => api.delete(`/rules/${id}`),
  toggle: (id: string) => api.post(`/rules/${id}/toggle`),
  batchUpdate: (data: { rule_type: string; enabled?: boolean; action?: string; reply_message?: string }) =>
    api.post('/detectors/batch-update', data),
}

export type RuleRuntimeRule = {
  rule_id: string
  rule_name: string
  rule_type: string
  category: string
  severity: string
  action: string
}

export type RuleRuntimePendingRule = {
  rule_id: string
  rule_name: string
  rule_type: string
  reason: string
}

export type RuleRuntimeStatus = {
  desired_version?: string
  catalog_count: number
  compiled_count: number
  compiled_rule_ids: string[]
  skipped_count: number
  reasons?: Record<string, number>
  skip_reasons?: Record<string, number>
  runtime_verified: boolean
  active_runtime_count: number | null
  actual_skipped_count: number | null
  fresh_count: number
  fresh_converged_count: number
  compiled_rules: RuleRuntimeRule[]
  stale_count: number
  pending_count: number
  pending_rules: RuleRuntimePendingRule[]
  all_converged?: boolean
  status: string
  last_error?: string
  warnings?: string[]
  degraded?: boolean
}

export const ruleRuntimeApi = {
  getStatus: () => api.get<{ runtime: RuleRuntimeStatus }>('/system/version'),
}

// Detector API
export const detectorApi = {
  init: () => api.post('/detectors/init'),
  batchUpdate: (data: { rule_type: string; enabled?: boolean; action?: string; reply_message?: string }) =>
    api.post('/detectors/batch-update', data),
}

export type SecurityReplyTemplates = {
  default: string
  prompt_injection: string
  content_safety: string
  data_leak: string
}

export type SecurityReplyPolicy = {
  schema_version: number
  enabled: boolean
  templates: SecurityReplyTemplates
  security_audit_only?: boolean
}

export const securityReplyApi = {
  get: () => api.get<SecurityReplyPolicy>('/security/reply-policy'),
  update: (data: { enabled: boolean; templates: SecurityReplyTemplates }) =>
    api.put<SecurityReplyPolicy>('/security/reply-policy', data),
}
export type ContentFilePolicy = {

  allowed_types?: string[]
  blocked_types?: string[]
  review_types?: string[]
  max_file_mb?: number
  max_zip_ratio?: number
  max_attachments?: number
  // 文件内容 DLP（数据外发防护）：开启后对文本类附件(docx/pptx/xlsx/pdf/txt/csv/json)
  // 提取正文做敏感数据检测。需同时开启部署级 SECURITY_FILE_CONTENT_DLP_ENABLED 总开关才生效。
  content_dlp_enabled?: boolean
  // 2.9.22：可执行、伪装可执行、脚本、未知类型、压缩炸弹各自的动作，缺省告警放行。
  executable_action?: FileRiskAction
  disguised_executable_action?: FileRiskAction
  script_action?: FileRiskAction
  unknown_action?: FileRiskAction
  zip_bomb_action?: FileRiskAction
  max_zip_entries?: number
  max_zip_uncompressed_mb?: number
  max_zip_nested?: number
  unverified_file_reference_action?: FileRiskAction
  file_reference_lookup_failure_action?: FileRiskAction
}

export type FileRiskAction = 'allow' | 'alert_allow' | 'block'

export const contentSecurityApi = {
  listRules: () => api.get('/content-security/rules'),
  createSensitiveRule: (data: { name: string; regex?: string; category?: string; severity?: string; action?: string; keywords?: string[]; field_names?: string[] }) =>
    api.post('/content-security/rules', data),
  listExceptions: () => api.get('/content-security/exceptions'),
  createException: (data: { scope_type?: string; scope_ref?: string; rule_id?: string; rule_ref?: string; decision?: 'allow' | 'audit'; reason: string; expires_at?: string }) =>
    api.post('/content-security/exceptions', data),
  deleteException: (id: string) => api.delete(`/content-security/exceptions/${id}`),
  getFilePolicy: () => api.get<ContentFilePolicy>('/content-security/file-policy'),
  updateFilePolicy: (data: ContentFilePolicy) => api.put('/content-security/file-policy', data),
  getIndustry: () => api.get<IndustryPackResponse>('/content-security/industry'),
  setIndustry: (industry: string) => api.put<IndustryPackResponse>('/content-security/industry', { industry }),
}

// 行业当前生效的内置数据安全预置包——与引擎实际编译下发的规则同源（单一事实源）
export type DataSecurityPackItem = {
  rule_id: string
  name: string
  category: string
  rule_type: string
  data_level: string // L1–L4
  severity: string
  action: string
}

export type IndustryPackResponse = {
  industry: string
  packs: DataSecurityPackItem[]
}

// Audit request detail response types (mirror control-plane types.go AuditRequestDetailResponse)
export type AuditSecurityEventInfo = {
  id: string
  request_id: string
  event_type: string
  severity: string
  rule_id?: string
  rule_name?: string
  rule_type?: string
  action_taken: string
  matched_summary?: Record<string, unknown>
  evidence_ref?: string
  created_at: string
}

export type AuditContentLogInfo = {
  id: string
  request_id: string
  role: string
  content: string
  tokens: number
  message_index?: number
  created_at: string
}

export type AuditToolCallLogInfo = {
  id: string
  request_id: string
  tool_name: string
  tool_type: string
  risk_level: string
  matched_policy_id?: string
  matched_policy_name?: string
  matched_action?: string
  match_reason?: string
  status: string
  event_kind: string
  execution_observed: boolean
  result_observed: boolean
  tool_call_id?: string
  created_at: string
}

export type AuditContentEvidenceInfo = {
  status: 'available' | 'not_collected' | 'expired' | 'unavailable' | string
  reason_code: string
  summary: string
  can_view: boolean
}

export type AuditDetectionIssueInfo = {
  component: string
  reason_code: string
  summary: string
  next_action: string
}

export type AuditEvidenceInfo = { label: string; value: string; severity?: string }

export type AuditToolSummaryInfo = {
  total: number
  unique_tools: number
  high_risk: number
  definition_exposed: number
  invocation_proposed: number
  execution_forwarded: number
  result_observed: number
  types: string[]
  top_tools: string[]
  summary: string
}

export type AuditDecisionInfo = {
  stage: 'informational' | 'needs_review' | 'confirmed_attempt' | 'confirmed_impact' | string
  semantic_status: 'completed' | 'incomplete' | 'not_run' | 'not_recorded' | string
  what_happened: string
  why_risky: string
  impact: string
  next_action: string
}

export type AuditSummaryInfo = {
  title: string
  intent: string
  outcome: string
  business_summary: string
  risk_level: string
  risk_score: number
  risk_reasons: string[]
  recommended_action: string
  tags: string[]
  primary_user_message: string
  assistant_summary: string
  system_prompt_count: number
  raw_content_count: number
  hidden_noise_count: number
  decision: AuditDecisionInfo
  evidence: AuditEvidenceInfo[]
  tools: AuditToolSummaryInfo
  generated_by: string
  extra?: Record<string, unknown>
}

export type AuditRequestDetailResponse = {
  request_id: string
  audit_summary: AuditSummaryInfo
  security_events: AuditSecurityEventInfo[]
  content_logs: AuditContentLogInfo[]
  tool_call_logs: AuditToolCallLogInfo[]
  content_evidence: AuditContentEvidenceInfo
  detection_issues: AuditDetectionIssueInfo[]
  content_audit_enabled: boolean
  tool_audit_enabled: boolean
}

export const boundedTimeWindowParams = (hours = 24) => {
  const end = new Date()
  const start = new Date(end.getTime() - hours * 60 * 60 * 1000)
  return { from: start.toISOString(), to: end.toISOString() }
}

// Audit API
export const auditApi = {
  listRequests: (params?: { tenant_id?: string; project_id?: string; model?: string; from?: string; to?: string; skip_total?: boolean }) =>
    api.get('/audit/requests', { params }),
  getRequestDetail: (requestId: string, params?: { events_only?: boolean; from?: string; to?: string; signal?: AbortSignal }) => {
    const { signal, ...query } = params || {}
    return api.get<AuditRequestDetailResponse>(`/audit/requests/${requestId}`, { params: query, signal })
  },
  listEvents: (params?: { tenant_id?: string; project_id?: string; event_type?: string; severity?: string }) =>
    api.get('/audit/events', { params }),
}

export type AuditDispositionStatus = 'open' | 'resolved' | 'false_positive' | 'accepted' | 'escalated'

export const auditDispositionApi = {
  list: (params?: { subject_type?: string; subject_id?: string; limit?: number; offset?: number }) =>
    api.get('/audit/dispositions', { params }),
  upsert: (data: { subject_type: string; subject_id: string; status: AuditDispositionStatus; note?: string; case_seen_through?: string }) =>
    api.put('/audit/dispositions', data),
}

export type AccessRetentionRecord = {
  request_id: string
  tenant_id?: string
  user_id?: string
  username?: string
  client_id?: string
  client_name?: string
  identity_kind?: 'key_owner' | 'api_key' | 'unknown' | string
  key_owner?: string
  created_at: string
  source_ip?: string
  target_host: string
  target_path?: string
  method?: string
  provider?: string
  provider_cn?: string
  product?: string
  product_cn?: string
  access_type: 'llm' | 'ai_ide' | 'normal_public' | 'unknown_ai_candidate'
  endpoint_kind?: string
  path_template?: string
  status: string
  status_code: number
  response_bytes: number
  // 上行字节；不解密隧道为整条隧道上行总量。
  request_bytes?: number
  // 不解密隧道持续时长（毫秒），其他记录为 0 或缺省。
  tunnel_duration_ms?: number
  tls_inspected: boolean
  retention_level: 'summary' | 'content' | string
  content_retained: boolean
  risk_state: 'normal' | 'risk' | 'blocked'
  risk_reasons?: string[]
  action_taken: string
  security_event_count: number
  disposition_status: string
  access_direction?: string
  agent_type?: string
  agent_label?: string
  // 会话聚合：member_count 为模型物理调用次数，turn_count 为用户对话轮次。
  member_count?: number
  turn_count?: number
  member_request_ids?: string[]
}

export type AccessRetentionSummary = {
  total: number
  normal_count: number
  risk_count: number
  blocked_count: number
  llm_count: number
  ai_ide_count: number
  normal_public_count: number
  retained_content_count: number
  undetected_count: number
  forward_count: number
  reverse_count: number
  device_count: number
  agent_request_count: number
  identified_agent_count: number
  unidentified_agent_count: number
  unique_model_count: number
  evidence_quality: {
    complete_count: number
    request_only_count: number
    response_only_count: number
    metadata_only_count: number
  }
  timeline: Array<{
    bucket: string
    total_count: number
    normal_count: number
    risk_count: number
    blocked_count: number
  }>
  top_risk_categories: Array<{ name: string; count: number }>
  top_providers: Array<{ name: string; count: number; risk_count: number }>
  top_targets: Array<{ name: string; count: number; risk_count: number }>
  top_agents: Array<{ name: string; label: string; count: number; risk_count: number }>
  data_fresh_until?: string
}

export type AccessRetentionParams = { access_type?: string; risk_state?: string; provider?: string; target_host?: string; source_ip?: string; user_id?: string; disposition?: string; keyword?: string; keyword_scope?: 'all' | 'request' | 'response'; agent_type?: string; request_id?: string; from?: string; to?: string; limit?: number; offset?: number; direction?: string; content_only?: boolean; skip_summary?: boolean; skip_total?: boolean; summary_only?: boolean; summary_detail?: 'counts' }
export type AccessRetentionListResponse = { data: AccessRetentionRecord[]; total: number; has_more?: boolean; total_known?: boolean; summary: AccessRetentionSummary; summary_error?: 'summary_unavailable' | string }
export type AccessRetentionWindow = { from: string; to: string }
type AbortableAccessRetentionParams = AccessRetentionParams & { signal?: AbortSignal }
type AbortableAccessRetentionWindow = AccessRetentionWindow & { signal?: AbortSignal }
type AbortableAccessRetentionRawWindow = AbortableAccessRetentionWindow & { members?: string[] }

export type EvidenceRunRecord = {
  run_id: string
  kind: 'agent_task' | 'ai_conversation' | string
  task_class?: string
  correlation_source: string
  correlation_confidence: 'exact' | 'unlinked' | string
  representative_request_id: string
  member_request_ids: string[]
  title: string
  started_at: string
  ended_at: string
  duration_ms: number
  agent_type?: string
  agent_label?: string
  agent_runtime?: string
  agent_detection_source?: string
  agent_detection_confidence?: number
  username?: string
  client_name?: string
  source_ip?: string
  models: string[]
  access_directions: string[]
  request_count: number
  evidence_status: 'complete' | 'partial' | 'metadata_only' | string
  risk_state: 'normal' | 'risk' | 'blocked'
}

export type EvidenceTimelineEvent = {
  id: string
  request_id?: string
  type: 'model_call' | 'model_calls' | 'tool_action' | 'artifact' | string
  title: string
  detail?: string
  status?: string
  event_kind?: string
  fact_label?: string
  timestamp: string
  count?: number
}

export const accessRetentionApi = {
  list: (params?: AbortableAccessRetentionParams) => {
    const { signal, ...query } = params || {}
    return api.get<AccessRetentionListResponse>('/audit/access-retention', { params: query, signal })
  },
  getSummary: (params?: AbortableAccessRetentionParams) => {
    const { signal, ...query } = params || {}
    return api.get<AccessRetentionListResponse>('/audit/access-retention', { params: { ...query, summary_only: true }, signal })
  },
  export: (params?: AccessRetentionParams) =>
    api.get<Blob>('/audit/access-retention/export', { params, responseType: 'blob' }),
  listRuns: (params?: AbortableAccessRetentionParams & { view: 'agent_tasks' | 'ai_conversations' }) => {
    const { signal, ...query } = params || {}
    return api.get<{ data: EvidenceRunRecord[]; total: number; total_known?: boolean; has_more?: boolean }>('/audit/access-retention/runs', { params: query, signal })
  },
  getTimeline: (requestId: string, members?: string[], window?: AbortableAccessRetentionWindow) => {
    const { signal, ...query } = window || {}
    const config = { params: query, ...(signal ? { signal } : {}) }
    return (
    members && members.length > 1
      ? window
        ? api.post<{ data: EvidenceTimelineEvent[] }>(`/audit/access-retention/${requestId}/timeline`, { members }, config)
        : api.post<{ data: EvidenceTimelineEvent[] }>(`/audit/access-retention/${requestId}/timeline`, { members })
      : api.get<{ data: EvidenceTimelineEvent[] }>(`/audit/access-retention/${requestId}/timeline`, window ? config : { params: undefined })
    )
  },
  // members 传入同一 turn 的全部成员 request_id 时，后端把多条物理记录合并进同一份四栏详情；
  // 不传则为单请求详情（行为不变，保留逐 request_id 下钻）。
  getContent: (requestId: string, members?: string[], window?: AbortableAccessRetentionWindow & { view?: 'turns'; keyword?: string; keyword_scope?: 'all' | 'request' | 'response' }) => {
    const { signal, ...query } = window || {}
    const config = { params: query, ...(signal ? { signal } : {}) }
    return (
    members && members.length > 1
      ? window
        ? api.post<AccessRetentionContent>(`/audit/access-retention/${requestId}/content`, { members }, config)
        : api.post<AccessRetentionContent>(`/audit/access-retention/${requestId}/content`, { members })
      : api.get<AccessRetentionContent>(`/audit/access-retention/${requestId}/content`, window ? config : { params: undefined })
    )
  },
  // view=raw：全部原文。返回按 direction/role 切分的分段正文、工具调用元数据，
  // 以及正文未留存时的安全事件留证回退（未脱敏，仅 FullTenant 证据权限可见）。
  getRawContent: (requestId: string, window?: AbortableAccessRetentionRawWindow) => {
    const { signal, members, ...query } = window || {}
    const config = { params: { ...query, view: 'raw' }, ...(signal ? { signal } : {}) }
    return members && members.length > 1
      ? api.post<AccessRetentionRawContent>(`/audit/access-retention/${requestId}/content`, { members }, config)
      : api.get<AccessRetentionRawContent>(`/audit/access-retention/${requestId}/content`, config)
  },
  getTurnProcess: (requestId: string, members: string[], turnId: string, offset: number, window: AbortableAccessRetentionWindow) => {
    const { signal, ...query } = window
    const config = { params: { ...query, view: 'turn_process', turn_id: turnId, offset, limit: 50 }, signal }
    return members.length > 1
      ? api.post<{ data: AccessRetentionMessage[]; total: number; offset: number; limit: number; has_more: boolean }>(`/audit/access-retention/${requestId}/content`, { members }, config)
      : api.get<{ data: AccessRetentionMessage[]; total: number; offset: number; limit: number; has_more: boolean }>(`/audit/access-retention/${requestId}/content`, config)
  },
  getArtifact: (requestId: string, artifactId: string, variant: 'preview' | 'original', window?: AbortableAccessRetentionWindow) => {
    const { signal, ...query } = window || {}
    return api.get<Blob>(
      `/audit/access-retention/${encodeURIComponent(requestId)}/artifacts/${encodeURIComponent(artifactId)}/${variant}`,
      window ? { params: query, responseType: 'blob', ...(signal ? { signal } : {}) } : { responseType: 'blob' },
    )
  },
}

export type AccessRetentionMessage = {
  id: string
  request_id: string
  sequence: number
  role: 'user' | 'assistant' | string
  kind: 'user_input' | 'model_output' | string
  content: string
  created_at?: string
}

export type AccessRetentionTurn = {
  tools?: {id: string; name: string; kind: string; request_id: string}[]
  id: string
  index: number
  user_input: string
  answer?: AccessRetentionMessage
  request_ids: string[]
  // 该回合里输入被阻断且有原文留证的请求编号（顺序同 request_ids）；没有或无权限时不返回。
  blocked_input_evidence_request_ids?: string[]
  request_count: number
  process_count: number
  status: 'unconfirmed' | 'response_unavailable' | 'completed' | 'interrupted' | 'request_failed' | 'blocked'
  finality_source: string
  correlation_source: string
  evidence_status: string
  started_at?: string
  last_observed_at?: string
  observed_duration_ms: number
}

export type AccessRetentionSearchHit = {
 request_id: string
 turn_id?: string
 kind: 'user_input' | 'model_output' | 'process' | 'request_context' | 'retained_text' | 'file'
 role: string
 snippet: string
 message_index?: number
}

export type AccessRetentionContent = {
 search_hits?: AccessRetentionSearchHit[]
 search_hits_truncated?: boolean
  turn_view_version?: number
  turns?: AccessRetentionTurn[]
  request_id: string
  request_content: string
  response_content: string
  user_input: string
  model_output: string
  evidence_status: 'complete' | 'evidence_gap' | string
  artifacts: AccessRetentionArtifact[]
  messages?: AccessRetentionMessage[]
  retention_until?: string
  file_metadata: Array<{
    source?: string
    stage?: string
    field_name?: string
    file_name?: string
    reference_id?: string
    content_type?: string
    size?: number
    sha256?: string
    text_preview?: string
    retained_text?: string
    data_base64?: string
    download_url?: string
    findings?: Array<{ category?: string; rule_name?: string; action?: string }>
  }>
}

export type AccessRetentionArtifact = {
  id: string
  request_id?: string
  direction: 'input' | 'output' | string
  kind: 'image' | 'file' | string
  display_name: string
  media_type: string
  byte_size: number
  sha256: string
  retention_status: 'retained' | 'reference_only' | 'failed' | 'oversize_unretained' | string
  failure_code?: string
  has_preview: boolean
  reference_count?: number
}

export type AccessRetentionRawSection = {
  direction: 'request' | 'response' | string
  role: 'user' | 'assistant' | 'system' | 'tool' | 'other' | string
  content: string
  request_id?: string
}

export type AccessRetentionRawToolCall = {
  id?: string
  name?: string
  kind: 'invocation_proposed' | 'result_observed' | string
  stage: 'request' | 'response' | string
  arguments_preview?: string
  result_preview?: string
}

export type AccessRetentionRawEvidence = {
  event_id?: string
  rule_name?: string
  category?: string
  severity?: string
  content_source?: string
  message_role?: string
  message_index?: number
  raw_evidence?: string
  evidence_context?: string
}

export type AccessRetentionRawContent = {
  request_id: string
  retention_until?: string
  decoder_version?: string
  sections: AccessRetentionRawSection[]
  tool_calls: AccessRetentionRawToolCall[]
  evidence_fallback: AccessRetentionRawEvidence[]
}

export type LLMProviderCatalogEntry = {
  id: string
  provider: string
  provider_cn: string
  product: string
  product_cn: string
  category: string
  domains: string[]
  retain_level: string
}

export const llmProviderCatalogApi = {
  list: () => api.get<{ data: LLMProviderCatalogEntry[]; providers: Array<{ value: string; label: string; count: number }> }>('/llm-provider-catalog'),
}

// Operation Audit API
export const operationAuditApi = {
  list: (params?: { limit?: number; offset?: number; user_id?: string }) =>
    api.get('/system/audit-operations', { params }),
}

// Usage API
export type UsageRangeParams = { start_date?: string; end_date?: string; currency?: 'USD' | 'CNY' }

export interface RequestTiming {
  input_security_ms?: number | null
  output_security_ms?: number | null
  pre_upstream_ms?: number | null
  generation_ms?: number | null
  upstream_ttft_ms?: number | null
  latency_ms?: number | null
  output_tokens_per_sec?: number | null
}

export interface UsageRecord {
  timing?: RequestTiming | null
  source_ip?: string
  raw_status?: string
  error_message?: string
  error_hint?: string
  upstream_error_code?: string
  id: string
  request_id: string
  session_id: string
  created_at: string
  user_name: string
  key_prefix: string
  key_name: string
  project_name: string
  provider_name: string
  model_name: string
  request_status: string
  upstream_status_code: number
  input_tokens: number
  output_tokens: number
  total_tokens: number
  billing_amount_micros: number | null
  billing_currency: string
  billing_state: 'settled' | 'reserved' | 'released' | 'unpriced' | 'failed' | 'exception' | 'not_billed'
  billing_mode: 'metering' | 'prepaid' | ''
  latency_ms: number
  upstream_ttft_ms?: number | null
  fallback_used?: boolean
  planned_route_name?: string
  actual_route_name?: string
  failure_category?: string
  attempts?: UsageRouteAttempt[] | null
}

export interface UsageRouteAttempt {
  route?: { provider_name?: string; route_ref?: string }
  result?: string
  status_code_category?: string
  latency_ms?: number
  failure_category?: string
}

// 失败原因类别 → 中文标签（与后端 deriveUsageFailureCategory 枚举对齐）
export const FAILURE_CATEGORY_LABELS: Record<string, string> = {
  security_rejected: '内容安全拦截',
  timeout: '请求超时',
  rate_limited: '触发限流',
  upstream_5xx: '上游服务异常',
  temporary_network: '网络不可达',
  auth_failed: '鉴权失败',
  quota_exceeded: '配额不足',
  client_canceled: '客户端取消',
  stream_aborted: '流式响应中断',
  model_not_found: '模型不存在',
  unknown: '其他原因',
}

export interface UsageRecordsSummary {
  requests: number
  users: number
  apps: number
  keys: number
  input_tokens: number
  output_tokens: number
  total_tokens: number
  billing_amount_micros: number
  settled_requests: number
  reserved_requests: number
  released_requests: number
  exception_requests: number
  not_billed_requests: number
  success_requests: number
  failed_requests: number
}

export type UsageRecordsParams = Record<string, string | number | undefined>

export interface RiskLevelCount {
  risk_level: string
  count: number
}

export interface ToolCount {
  tool_name: string
  count: number
}

export interface PolicyCount {
  policy_id: string
  policy_name: string
  mode: string
  count: number
}

export interface ObjectCount {
  id: string
  name: string
  count: number
}

export interface AgentRiskOverview {
  /** 兼容旧客户端：与 tool_call_attempts 同口径。 */
  total_tool_calls: number
  /** 以下生命周期、双决策与运行态字段由新版本后端提供，滚动升级期间可能缺失。 */
  tool_call_attempts?: number
  definition_exposed_count?: number
  invocation_proposed_count?: number
  execution_forwarded_count?: number
  result_observed_count?: number
  confirmation_replay_count?: number
  unknown_event_count?: number
  raw_decisions?: Record<string, number>
  effective_decisions?: Record<string, number>
  high_risk_calls: number
  /** 兼容字段；权威处置分布见 effective_decisions。 */
  blocked_calls: number
  audit_calls: number
  confirm_calls: number
  pending_confirm: number
  effective_mode?: string
  effective_mode_source?: string
  audit_ceiling?: boolean | null
  runtime_mode_verified?: boolean
  configured_mode?: string
  configured_mode_source?: string
  configured_audit_ceiling?: boolean | null
  confirmation_pending?: number
  confirmation_approved?: number
  confirmation_rejected?: number
  confirmation_expired?: number
  confirmation_executed?: number
  confirmation_executing?: number
  confirmation_failed?: number
  confirmation_unknown?: number
  confirmation_evidence_failed?: number
  by_risk_level: RiskLevelCount[]
  top_tools: ToolCount[]
  by_policy: PolicyCount[]
  top_users: ObjectCount[]
  top_apps: ObjectCount[]
  top_keys: ObjectCount[]
  top_sessions: ObjectCount[]
  top_agents: ObjectCount[]
}

export const getUsageRecords = (params: UsageRecordsParams) =>
  api.get<{ records: UsageRecord[]; total: number }>('/usage/records', { params })

export const getUsageRecordsSummary = (params: UsageRecordsParams) =>
  api.get<UsageRecordsSummary>('/usage/records/summary', { params })

export const getAgentRiskOverview = (params: { start: string; end: string }) =>
  api.get<AgentRiskOverview>('/agentguard/risk-overview', { params })

export const usageApi = {
  summary: (params?: UsageRangeParams) =>
    api.get('/usage/summary', { params }),
  byProject: (params?: UsageRangeParams) =>
    api.get('/usage/by-project', { params }),
  costCoverage: (params?: UsageRangeParams) =>
    api.get('/usage/cost-coverage', { params }),
  byModel: (params?: UsageRangeParams) =>
    api.get('/usage/by-model', { params }),
  byUser: (params?: UsageRangeParams) =>
    api.get('/usage/by-user', { params }),
  byKey: (params?: UsageRangeParams) =>
    api.get('/usage/by-key', { params }),
  byProvider: (params?: UsageRangeParams) =>
    api.get('/usage/by-provider', { params }),
  trend: (params?: UsageRangeParams) =>
    api.get('/usage/trend', { params }),
  records: getUsageRecords,
  recordsSummary: getUsageRecordsSummary,
  recommendations: (params?: UsageRangeParams) =>
    api.get('/usage/recommendations', { params }),
}

export type BillingAnalyticsParams = UsageRangeParams & {
  tenant_id?: string
  granularity?: 'hour' | 'day'
  timezone?: string
  interval_minutes?: 15 | 30 | 60
  limit?: number
  department_ids?: string
  project_ids?: string
  user_ids?: string
  model_ids?: string
  provider_ids?: string
  agent_types?: string
}

// 保持旧页面读取 response.data 数组的约定，同时保留新接口的币种边界信息。
function normalizeBillingAnalyticsRows(response: AxiosResponse<any>, requestedCurrency?: string): AxiosResponse<any[]> & { currency: string; other_currencies: string[] } {
  const body = response.data
  const currency: string = body?.currency || requestedCurrency || useCurrencyStore.getState().tenantCurrency
  const otherCurrencies: string[] = Array.isArray(body?.other_currencies) ? body.other_currencies : []
  const rows: Record<string, any>[] = Array.isArray(body) ? body : Array.isArray(body?.data) ? body.data : []
  return {
    ...response,
    currency,
    other_currencies: otherCurrencies,
    data: rows.map(row => ({ ...row, currency: row.currency || currency, other_currencies: row.other_currencies || otherCurrencies })),
  }
}

export const billingAnalyticsApi = {
  summary: (params?: BillingAnalyticsParams) => api.get('/billing/analytics/summary', { params }),
  breakdown: (dimension: 'department' | 'provider' | 'model' | 'project' | 'user' | 'agent' | 'tariff_band', params?: BillingAnalyticsParams) =>
    api.get('/billing/analytics/breakdown', { params: { ...params, dimension } }).then(response => normalizeBillingAnalyticsRows(response, params?.currency)),
  series: (params?: BillingAnalyticsParams) => api.get('/billing/analytics/series', { params }).then(response => normalizeBillingAnalyticsRows(response, params?.currency)),
  timeProfile: (params?: BillingAnalyticsParams) => api.get('/billing/analytics/time-profile', { params }).then(response => normalizeBillingAnalyticsRows(response, params?.currency)),
  departmentProviderMatrix: (params?: BillingAnalyticsParams) => api.get('/billing/analytics/department-provider-matrix', { params }).then(response => normalizeBillingAnalyticsRows(response, params?.currency)),
  report: (params?: BillingAnalyticsParams) => api.get<Blob>('/billing/analytics/report', { params, responseType: 'blob' }),
}

// Gateway session audit uses agent_audit; endpoint sessions use agentEndpointApi.
export interface GatewayAgentSession {
  session_id: string
  agent_type: string
  workspace_id: string
  risk_score: number
  request_count: number
  first_request: string
  last_request: string
}

export const agentApi = {
  list: (params?: { tenant_scope?: 'all' | 'tenant'; tenant_id?: string; agent_type?: string; limit?: number; offset?: number }) =>
    api.get<{ data: GatewayAgentSession[]; total: number }>('/agent-sessions', { params }),
  get: (sessionId: string) => api.get(`/agent-sessions/${sessionId}`),
}

// Stats API
export type StatsRangeParams = { start?: string; end?: string; from?: string; to?: string }

export const statsApi = {
  getOverview: () => api.get('/stats/overview'),
  getUserStats: (by: 'tokens' | 'requests' = 'tokens', limit = 10, params?: StatsRangeParams) =>
    api.get('/stats/users', { params: { by, limit, ...params } }),
  getAppStats: (limit = 10) => api.get(`/stats/apps?limit=${limit}`),
  getModelStats: (limit = 10, params?: StatsRangeParams) => api.get('/stats/models', { params: { limit, ...params } }),
  getAgentStats: () => api.get('/stats/agents'),
  getOrgStats: () => api.get('/stats/org'),
}

// Agent Stats API (extended)
export const agentStatsApi = {
  getStats: (params?: StatsRangeParams) =>
    params ? api.get('/stats/agents', { params }) : api.get('/stats/agents'),
  getDistribution: (params?: StatsRangeParams) =>
    params ? api.get('/stats/agents/distribution', { params }) : api.get('/stats/agents/distribution'),
  getUserDetail: (userId: string, params?: StatsRangeParams) =>
    params ? api.get(`/audit/agents/user/${userId}`, { params }) : api.get(`/audit/agents/user/${userId}`),
  listSessions: (agentType?: string, userId?: string, limit?: number, offset?: number) =>
    api.get('/audit/agents/sessions', { params: { agent_type: agentType, user_id: userId, limit, offset } }),
}

// Content Audit API
export type ContentAuditListParams = {
  user_id?: string
  session_id?: string
  keyword?: string
  category?: string | string[]
  severity?: string
  disposition?: string
  limit?: number
  offset?: number
  from?: string
  to?: string
  start_time?: string
  end_time?: string
  skip_total?: boolean
  alert_only?: boolean
  signal?: AbortSignal
}

// 安全运营总览聚合：一次请求返回会话级告警总数与各维度分布，
// 口径与 /audit/content?alert_only=true（安全告警页）一致。
// 不含人工作业状态（audit_dispositions / alert_groups.status）——那份数据只有内容留证页和
// 工具审计页能写，安全告警页与本总览页都没有处置入口，放在这里只会误导（见页面内注释）。
export type ContentSecurityOverviewBucket = {
  key: string
  count: number
}

export type ContentSecurityOverview = {
  total: number
  subjects: number
  // 命中风险类型的精确去重数（已剔除 agent_* 智能体行为类）。
  // 不要用 categories.length 代替：categories 带 LIMIT 24，在真实数据上正好会被截断。
  category_count: number
  severity: ContentSecurityOverviewBucket[]
  categories: ContentSecurityOverviewBucket[]
}

export type ContentAuditUserOption = {
  id: string
  username: string
  identity_kind: 'key_owner'
  department_id?: string
  department_name?: string
}

export type ContentAuditUserSelectorResponse = {
  data: ContentAuditUserOption[]
  limit: number
  offset: number
  has_more: boolean
  next_cursor?: string
}

export const contentAuditApi = {
  list: (params: ContentAuditListParams) => {
    const { signal, ...query } = params
    return api.get('/audit/content', { params: query, signal })
  },
  listUsers: (params: { q?: string; limit?: number; cursor?: string; offset?: number; signal?: AbortSignal } = {}) => {
    const { signal, ...query } = params
    return api.get<ContentAuditUserSelectorResponse>('/audit/content/users', { params: query, signal })
  },
  getSession: (sessionId: string, params?: {
    view?: 'manager' | 'all'
    limit?: number
    offset?: number
    from?: string
    to?: string
    signal?: AbortSignal
  }) => {
    const { signal, ...query } = params || {}
    return params
      ? api.get(`/audit/content/${sessionId}`, { params: query, signal })
      : api.get(`/audit/content/${sessionId}`)
  },
  getSessionEvents: (sessionId: string, params?: { from?: string; to?: string; limit?: number; offset?: number; signal?: AbortSignal }) => {
    const { signal, ...query } = params || {}
    return api.get(`/audit/content/${sessionId}/events`, { params: query, signal })
  },
  export: (sessionId: string, format: 'json' | 'text' = 'json', window?: AccessRetentionWindow) =>
    api.get(`/audit/content/${sessionId}/export`, { params: { format, ...window }, responseType: 'blob' }),
  // 安全运营总览专用聚合端点：单次查询返回总数 + 涉及主体数 + 严重级别 / 风险分类分布。
  // 不要退回用 list({limit:1}) 去数总数——alert_only 走服务端快速路径，那条路径的 total
  // 是渐进式分页值（handler 用 offset+len+hasMore 拼出来），不是精确计数。
  securityOverview: (params: { from?: string; to?: string; signal?: AbortSignal } = {}) => {
    const { signal, ...query } = params
    return api.get<{ data: ContentSecurityOverview; total: number; type: string }>(
      '/audit/content/security-overview',
      { params: query, signal },
    )
  },
}

// Tool Audit API (Skills/MCP Risk Audit)
export type ToolAuditListParams = {
  limit?: number
  offset?: number
  start?: string
  end?: string
  user_id?: string
  client_id?: string
  project_id?: string
  session_id?: string
  request_id?: string
  mode?: string
  risk_level?: string
  tool_name?: string
  tool_type?: string
  agent_type?: string
  policy_id?: string
  // MCP 审计服务端过滤增强：原始判定/实际动作双决策维度 + 按 MCP 服务名过滤（tool_name 的 '__' 前缀）
  raw_decision?: string
  effective_decision?: string
  server?: string
  keyword?: string
  disposition_status?: string
  attention_only?: boolean
  from?: string
  to?: string
  skip_total?: boolean
  signal?: AbortSignal
}

export const toolAuditApi = {
  getStats: () => api.get('/audit/tools/stats'),
  listHighRisk: (params: ToolAuditListParams = {}) => {
    const { signal, ...query } = params
    return api.get('/audit/tools/high-risk', { params: query, signal })
  },
  getSessionToolCalls: (sessionId: string, params: { limit?: number; signal?: AbortSignal } = {}) => {
    const { signal, ...query } = params
    return api.get(`/audit/tools/session/${sessionId}`, { params: query, signal })
  },
  getUserToolCalls: (userId: string, params?: { limit?: number; offset?: number }) =>
    api.get(`/audit/tools/user/${userId}`, { params }),
  getRiskTrend: (days?: number) => api.get('/audit/tools/trend', { params: { days } }),
}

// Tool Risk Config API
export interface ObservedTool {
  tool_name: string
  tool_types: string[]
  runtime_tool_type?: string
  runtime_type_source?: string
  definition_exposed_count: number
  invocation_proposed_count: number
  execution_forwarded_count: number
  result_observed_count: number
  unknown_event_count: number
  event_count: number
  last_seen: string
}
export const toolRiskConfigApi = {
  list: (params?: { observed?: boolean }) => api.get('/tools/config', { params }),
  create: (data: { tool_name: string; tool_type: string; risk_level: string; action: string; description?: string }) =>
    api.post('/tools/config', data),
  update: (id: string, data: { tool_type?: string; risk_level?: string; action?: string; description?: string }) =>
    api.put(`/tools/config/${id}`, data),
  delete: (id: string) => api.delete(`/tools/config/${id}`),
  batchUpsert: (configs: Array<{
    tool_name: string;
    tool_type: string;
    risk_level: string;
    action: string;
    description?: string;
  }>, preserveExisting = false) => api.post('/tools/config/batch', { configs, preserve_existing: preserveExisting }),
}

// 对象级出站放行：反向代理路由与 MCP 服务各自保存，默认全部关闭。
// trusted_ca_pem、insecure_skip_verify、allow_same_host_redirect 只对 MCP 服务有效。
export interface EgressOverrides {
  allow_loopback?: boolean
  allow_link_local?: boolean
  allow_metadata?: boolean
  allow_internal_hostnames?: boolean
  trusted_ca_pem?: string
  insecure_skip_verify?: boolean
  allow_same_host_redirect?: boolean
}

// Proxy Whitelist API
export interface ProxyWhitelist {
  id: string
  tenant_id: string
  host_pattern: string
  port: number
  audit_enabled: boolean
  description: string
  created_at: string
}

export interface ProxyWhitelistCreate {
  host_pattern: string
  port?: number
  audit_enabled?: boolean
  description?: string
}

export interface ProxyWhitelistUpdate {
  host_pattern?: string
  port?: number
  audit_enabled?: boolean
  description?: string
}

export const proxyApi = {
  getWhitelist: () => api.get('/proxy/whitelist'),
  createWhitelist: (entry: ProxyWhitelistCreate) =>
    api.post<ProxyWhitelist>('/proxy/whitelist', entry),
  updateWhitelist: (id: string, entry: ProxyWhitelistUpdate) =>
    api.put(`/proxy/whitelist/${id}`, entry),
  deleteWhitelist: (id: string) =>
    api.delete(`/proxy/whitelist/${id}`),
}

// 正向代理访问密钥（P1-10, task 1.7）：签发/管理写 proxy_access_keys；明文仅签发时回显一次
export interface ProxyAccessKey {
  id: string
  tenant_id: string
  proxy_key_prefix: string
  model_ids: string[]
  rpm_limit: number
  daily_cap: number
  expires_at?: string | null
  last_used_at?: string | null
  status: string
  created_at: string
}

export interface ProxyAccessKeyCreate {
  model_ids?: string[]
  rpm_limit?: number
  daily_cap?: number
}

export interface ProxyAccessKeyCreateResult extends ProxyAccessKey {
  full_key: string
}

export interface ProxyAccessKeyUpdate {
  model_ids?: string[]
  rpm_limit?: number
  daily_cap?: number
  status?: string
}

export const proxyKeyApi = {
  list: () => api.get('/proxy-access-keys'),
  create: (entry: ProxyAccessKeyCreate) =>
    api.post<ProxyAccessKeyCreateResult>('/proxy-access-keys', entry),
  update: (id: string, entry: ProxyAccessKeyUpdate) =>
    api.put(`/proxy-access-keys/${id}`, entry),
  delete: (id: string) =>
    api.delete(`/proxy-access-keys/${id}`),
}

// MCP 安全网关：受管 MCP 服务（迁移 099 扩列 transport/manifest_hash/allow_private_egress 等）
export interface McpServer {
  id: string
  tenant_id: string
  name: string
  server_url: string
  owner: string
  trust_level: string
  transport?: string
  manifest_hash?: string
  allow_private_egress?: boolean
  egress_overrides?: EgressOverrides
  last_synced_at?: string | null
  last_manifest_changed_at?: string | null
  tool_count?: number
  admission_status?: McpAdmissionStatus
  observed_manifest_snapshot?: unknown
  approved_manifest_hash?: string
  approved_manifest_snapshot?: unknown
  quarantine_reason?: string
  quarantined_at?: string | null
  admission_reviewed_by?: string
  admission_reviewed_at?: string | null
  observed_route_hash?: string
  approved_route_hash?: string
  admission_revision?: number
  updated_at?: string
  auth_configured?: boolean
  capabilities: Record<string, unknown>
  // 后端汇总的上游连接配置与协商结果（不含密钥）
  upstream?: McpUpstreamSummary
  status: string
  created_at: string
}

export interface McpUpstreamSummary {
  transport: string
  detected_transport?: string
  effective_transport: string
  auth_location: string
  auth_name: string
  auth_template: string
  extra_headers?: Record<string, string>
  protocol_version?: string
  protocol_version_raw?: string
  url_has_plaintext_secret?: boolean
  config_error?: string
}

export interface McpServerCreate {
  name: string
  server_url?: string
  owner?: string
  trust_level?: string
  transport?: string
  // 鉴权令牌明文只写不读：编辑时传空字符串 = 保持不变
  auth_token?: string
  allow_private_egress?: boolean
  egress_overrides?: EgressOverrides
  capabilities?: Record<string, unknown>
  status?: string
}

export type McpServerUpdate = Partial<McpServerCreate>

export type McpAdmissionStatus = 'unverified' | 'approved' | 'quarantined' | 'revoked'

export interface McpAdmissionRequest {
  status: Exclude<McpAdmissionStatus, 'unverified'>
  expected_hash: string
  expected_route_hash?: string
  reason?: string
}

// 同步能力（initialize + tools/list）的结果：manifest 内容哈希比对用于 rug-pull 检测
export interface McpTool {
  id: string
  tool_name: string
  description: string
  input_schema?: Record<string, unknown> | null
  risk_tags?: string[] | null
  schema_hash?: string
  admission_status?: McpAdmissionStatus
  approved_schema_hash?: string
  approved_schema_snapshot?: unknown
  quarantine_reason?: string
  quarantined_at?: string | null
  admission_reviewed_by?: string
  admission_reviewed_at?: string | null
  admission_revision?: number
  first_seen_at?: string
  last_seen_at?: string
  removed?: boolean
  // 同步时完整扫描工具描述；非空表示命中投毒模式，并由供应链准入事务自动隔离。
  // 例如 instruction_override（指令覆盖）/exfil_induce（数据外传诱导）。
  poison_flags?: string[] | null
}

// 同名工具告警：schema 不一致时同步事务自动隔离，schema 完全一致时只保留风险提示。
// 恶意/被攻陷的 server 可能提供同名工具诱导 agent 误调用；字段对齐 control-plane
// repository.MCPShadowToolWarning / MCPShadowToolServer。
export interface McpShadowToolServer {
  server_id: string
  server_name: string
  schema_hash: string
  risk_tags?: string[] | null
}

export interface McpShadowToolWarning {
  tool_name: string
  servers: McpShadowToolServer[]
  schema_diverges: boolean // 同名但指纹不一致=定义不同，更可能是冒充
  reason: string
}

export interface McpSyncResult {
  manifest_hash: string
  changed: boolean
  previous_hash: string
  tool_count: number
  tools?: McpTool[]
  // 以下计数为可选增强字段：后端若未提供则前端按 tools 列表回退展示
  added_count?: number
  updated_count?: number
  removed_count?: number
  description_scan_complete?: boolean
  supply_chain?: {
    server_status: McpAdmissionStatus
    server_reason?: string
    approved_tool_count: number
    quarantined_tool_count: number
    revoked_tool_count: number
    removed_tool_count: number
    reasons: string[]
    description_scan_complete: boolean
  }
}

// 测试连接：仅探测可达性与握手（initialize），返回结构化错误分类而非只给一句“同步失败”
export interface McpTestConnectionResult {
  ok: boolean
  error_kind?: string
  message?: string
  server_info?: Record<string, unknown>
}

export const mcpServerApi = {
  list: () => api.get('/mcp-servers'),
  create: (entry: McpServerCreate) => api.post<McpServer>('/mcp-servers', entry),
  update: (id: string, entry: McpServerUpdate) =>
    api.put(`/mcp-servers/${id}`, entry),
  delete: (id: string) => api.delete(`/mcp-servers/${id}`),
  sync: (id: string) => api.post<McpSyncResult>(`/mcp-servers/${id}/sync`),
  listTools: (id: string) => api.get(`/mcp-servers/${id}/tools`),
  testConnection: (id: string) =>
    api.post<McpTestConnectionResult>(`/mcp-servers/${id}/test-connection`),
  setAdmission: (id: string, entry: McpAdmissionRequest) =>
    api.post(`/mcp-servers/${id}/admission`, entry),
}

// 影子工具自检列出租户内同名跨服务告警；异构定义由同步事务隔离，
// 同构重复保留人工核验，口径同 control-plane DetectShadowTools。
export const mcpToolApi = {
  shadowCheck: () =>
    api.get<{ warnings: McpShadowToolWarning[] }>('/mcp-tools/shadow-check'),
  setAdmission: (id: string, entry: McpAdmissionRequest) =>
    api.post(`/mcp-tools/${id}/admission`, entry),
}

// MCP 权限策略（六元组作用域 × 服务 × 工具模式）
export type McpPolicyMode = 'observe' | 'audit' | 'strict'
export type McpPolicyAction = 'allow' | 'audit' | 'confirm' | 'block'

export interface McpPolicy {
  id: string
  tenant_id: string
  scope_type: string
  scope_ref: string
  server_id: string
  tool_pattern: string
  mode: McpPolicyMode
  default_action: McpPolicyAction
  priority: number
  enabled: boolean
  note: string
  created_at: string
  updated_at: string
}

export interface McpPolicyPayload {
  scope_type: string
  scope_ref?: string
  server_id?: string
  tool_pattern?: string
  mode: McpPolicyMode
  default_action: McpPolicyAction
  priority?: number
  enabled?: boolean
  note?: string
}

// 策略预演入参：六元组作用域上下文 + 目标服务/工具，交后端用运行时同源 ResolveMCPPolicy 求解
export interface McpPolicySimulatePayload {
  scope_type: string
  scope_ref: string
  server_id: string
  tool_name: string
  project_id?: string
  user_id?: string
  key_prefix?: string
  agent_id?: string
  session_id?: string
}

// 预演结果：胜出策略 + 全部命中候选（按与运行时一致的排序），null 表示无策略命中走默认
export interface McpSimulateResult {
  winning: McpPolicy | null
  candidates: McpPolicy[]
}

// 遮蔽告警：更宽松、优先级更高的 allow 把精确 block 顶掉，导致 block 永不生效
export interface McpShadowWarning {
  shadowed_block_id: string
  winning_allow_id: string
  scope: string
  reason: string
}

export const mcpPolicyApi = {
  list: (params?: { server_id?: string }) => api.get('/mcp-policies', { params }),
  create: (data: McpPolicyPayload) => api.post<McpPolicy>('/mcp-policies', data),
  update: (id: string, data: Partial<McpPolicyPayload>) =>
    api.put(`/mcp-policies/${id}`, data),
  delete: (id: string) => api.delete(`/mcp-policies/${id}`),
  // 保存前预演：返回胜出策略与候选切片；口径以后端为准，前端只展示不自算
  simulate: (data: McpPolicySimulatePayload) =>
    api.post<McpSimulateResult>('/mcp-policies/simulate', data),
  // 遮蔽自检：列出被更宽松 allow 顶掉的 block 策略
  shadowCheck: () => api.get<{ warnings: McpShadowWarning[] }>('/mcp-policies/shadow-check'),
}

// MCP 调用审计：复用 tool_call_logs 明细端点（053 双决策列），按 tool_type='mcp' 过滤；
// 该端点 risk_level 缺省只出 high+，审计页要全量明细所以强制 risk_level='all'。
export const mcpAuditApi = {
  list: (params?: ToolAuditListParams) =>
    api.get('/audit/tools/high-risk', {
      params: { risk_level: 'all', tool_type: 'mcp', ...params },
    }),
}

// MCP 审批与例外：复用 agentguard confirmations 端点，按 source=mcp 只取 MCP 建的确认单。
// 双决策（原始判定 raw_decision / 实际动作 effective_decision）字段与 AgentGuard 一致。
export interface McpConfirmationExecution {
  confirmation_id: string
  execution_status: 'pending' | 'executing' | 'executed' | 'failed' | 'unknown'
  evidence_status?: 'pending' | 'complete' | 'failed'
  error_code?: string
  audit_error_code?: string
  audit_request_id?: string
  tool_log_id?: string
  result_available?: boolean
  started_at?: string
  finished_at?: string
  response_summary?: Record<string, unknown>
}

export interface McpConfirmation {
  id: string
  request_id: string
  trace_id: string
  tool_name: string
  raw_decision: string
  effective_decision: string
  status: string
  timeout_action: string
  reason: string
  source?: string
  expires_at: string
  created_at: string
  mcp_execution?: McpConfirmationExecution
}

export const mcpApprovalApi = {
  // status: pending/approved/rejected...; source 默认 mcp，仅取 MCP 网关建的确认单
  list: (params?: { status?: string; source?: string }) =>
    api.get<{ data: McpConfirmation[] }>('/agentguard/confirmations', {
      params: { source: 'mcp', ...params },
    }),
  resolve: (id: string, data: { status: 'approved' | 'rejected'; note?: string }) =>
    api.post<McpConfirmation>(`/agentguard/confirmations/${id}/resolve`, data),
}

export interface ProviderPriceSnapshot {
  snapshot_date: string
  provider_id: string
  model_id: string
  input_price: number
  output_price: number
  currency: string
}

// 供应商价格快照（只读历史，P2-2 task 1.9）。
export const providerPriceApi = {
  list: (date?: string) =>
    api.get('/provider-price-snapshots', { params: date ? { date } : {} }),
}

export interface ReverseProxyRoute {
  id: string
  tenant_id: string
  name: string
  path_prefix: string
  target_url: string
  target_path_prefix: string
  allow_private_egress: boolean
  private_egress_cidrs: string[]
  egress_overrides?: EgressOverrides
  security_enabled: boolean
  stats_enabled: boolean
  status: string
  description: string
  created_at: string
  updated_at: string
}

export interface ReverseProxyRouteCreate {
  name: string
  path_prefix: string
  target_url: string
  target_path_prefix?: string
  allow_private_egress?: boolean
  private_egress_cidrs?: string[]
  egress_overrides?: EgressOverrides
  security_enabled?: boolean
  stats_enabled?: boolean
  status?: string
  description?: string
}

export interface ReverseProxyRouteUpdate {
  name?: string
  path_prefix?: string
  target_url?: string
  target_path_prefix?: string
  allow_private_egress?: boolean
  private_egress_cidrs?: string[]
  egress_overrides?: EgressOverrides
  security_enabled?: boolean
  stats_enabled?: boolean
  status?: string
  description?: string
}

export const reverseProxyApi = {
  list: () => api.get('/reverse-proxy/routes'),
  create: (entry: ReverseProxyRouteCreate) =>
    api.post<ReverseProxyRoute>('/reverse-proxy/routes', entry),
  update: (id: string, entry: ReverseProxyRouteUpdate) =>
    api.put<ReverseProxyRoute>(`/reverse-proxy/routes/${id}`, entry),
  delete: (id: string) =>
    api.delete(`/reverse-proxy/routes/${id}`),
}

// CA Certificate API
export interface CACertificate {
  id: string
  tenant_id: string
  ca_type: string
  certificate_pem: string
  status: 'pending' | 'active' | 'deprecated' | 'expired'
  fingerprint_sha256?: string
  created_at: string
  expires_at: string
}

export const caApi = {
  generate: (validityDays?: number) =>
    api.post<CACertificate>('/ca/generate', null, { params: { validity_days: validityDays || 3650 } }),
  get: () => api.get<CACertificate>('/ca/certificate'),
  list: () => api.get<{ data: CACertificate[]; total: number }>('/ca/list'),
  download: (id?: string) => api.get(id ? `/ca/${id}/download` : '/ca/download', { responseType: 'blob' }),
  activate: (id: string) => api.post<CACertificate>(`/ca/${id}/activate`),
  delete: (id: string) => api.delete(`/ca/${id}`),
}

// Org API
export const orgApi = {
  listTeams:      () => api.get('/teams'),
  createTeam:     (data: { name: string; parent_team_id?: string; create_app?: boolean }) => api.post('/teams', data),
  deleteTeam:     (id: string) => api.delete(`/teams/${id}`),
  listMembers:    (teamId: string) => api.get(`/teams/${teamId}/members`),
  addMember:      (teamId: string, data: { user_id: string; role?: string }) =>
                    api.post(`/teams/${teamId}/members`, data),
  removeMember:   (teamId: string, userId: string) =>
                    api.delete(`/teams/${teamId}/members/${userId}`),
  // IAM enterprise additions (D1)
  batchAddMembers:(teamId: string, data: { user_ids: string[]; role: string }) =>
                    api.post(`/teams/${teamId}/members/batch`, data),
  updateBudget:   (teamId: string, data: { monthly_budget_cny: number; daily_budget_cny: number }) =>
                    api.put(`/teams/${teamId}/budget`, data),
  listModels:     (teamId: string) => api.get(`/teams/${teamId}/models`),
  updateModels:   (teamId: string, data: { mode?: 'all_active'|'allowlist'|'deny_all'; models: Array<{ model_id: string; allowed: boolean; daily_token_limit?: number | null }> }) =>
                    api.put(`/teams/${teamId}/models`, data),
  deleteModel:    (teamId: string, modelId: string) => api.delete(`/teams/${teamId}/models/${modelId}`),
  getEffective:   (teamId: string) => api.get(`/teams/${teamId}/effective`),
  listProjects:   (teamId: string) => api.get(`/teams/${teamId}/projects`),
  getUsage:       (teamId: string, range = '30d') => api.get(`/teams/${teamId}/usage`, { params: { range } }),
  patchProjectTeam:(projectId: string, teamId: string) => api.patch(`/projects/${projectId}/team`, { team_id: teamId }),
  patchPersonalBudget:(userId: string, amount: number | null) => api.patch(`/users/${userId}/personal-budget`, { personal_monthly_budget_cny: amount }),
}

// Budget API
export const budgetApi = {
  snapshot:  (params: { scope_type: string; scope_id?: string }) =>
               api.get('/budgets/snapshot', { params }),
  pauseKey:  (keyPrefix: string, reason: string) =>
               api.post(`/budgets/keys/${keyPrefix}/pause`, { reason }),
  unpauseKey:(keyPrefix: string) =>
               api.post(`/budgets/keys/${keyPrefix}/unpause`),
  pauseLog:  () => api.get('/budgets/pause-log'),
  // 密钥预算核查读模型：只回真实证据（确认用量/生效配额/窗口/owner 级在途），
  // key 维度在途金额因 billing_reservations 无 key 归属而显式不可用
  keyReadModel: (keyId: string) => api.get(`/budgets/keys/${keyId}/readmodel`),
}

// 服务健康读模型：平台管理员专用，全部组件基于真实 DB/探针证据，
// 无证据来源的组件如实上报 unknown，绝不按满分兜底
export const serviceHealthApi = {
  readModel: () => api.get('/service-health/readmodel'),
}

// Saving API
export const savingApi = {
  summary: (params: { range?: string; scope_type?: string; scope_id?: string }) =>
             api.get('/savings/summary', { params }),
  trend:   (params: { range?: string; groupBy?: 'source'|'team'|'project'|'user' }) =>
             api.get('/savings/trend', { params }),
}

// FX API
export const fxApi = {
  current: () => api.get('/fx/current'),
  set:     (data: { rate: number; effective_at: string }) => api.put('/fx', data),
  history: () => api.get('/fx/history'),
}

// Alert API
export const alertApi = {
  inbox:    (unread?: boolean) => api.get('/alerts/inbox', { params: { unread } }),
  markRead: (id: string) => api.post(`/alerts/${id}/read`),
}

// 告警组（alert_groups）列表与批量处置：只处置显式勾选的 id，服务端单次上限 500。
export type AlertGroupBatchStatus = 'acknowledged' | 'resolved' | 'false_positive'
export interface AlertGroupItem {
  id: string
  severity: string
  effective_severity?: string
  status: string
  type: string
  title: string
  rule_name?: string
  occurrence_count: number
  first_seen_at: string
  last_seen_at: string
}
export interface AlertGroupListParams {
  status?: string
  type?: string
  rule?: string
  from?: string
  to?: string
  limit?: number
  offset?: number
}
export interface AlertGroupBatchResult {
  requested: number
  updated: number
  updated_ids?: string[]
  failed: { id: string; reason: string }[]
}
export const alertGroupApi = {
  list: (params: AlertGroupListParams) =>
    api.get<{ items: AlertGroupItem[]; total: number; limit: number; offset: number }>('/alert-groups', { params }),
  batchStatus: (body: {
    ids: string[]
    status: AlertGroupBatchStatus
    note?: string
    filters?: { status?: string; type?: string; rule?: string; from?: string; to?: string }
  }) => api.post<AlertGroupBatchResult>('/alert-groups/batch-status', body),
}

// Notify Channel API
export const notifyApi = {
  list:   () => api.get('/notify-channels'),
  create: (data: { type: string; name: string; config_json: Record<string, any> }) =>
            api.post('/notify-channels', data),
  update: (id: string, data: any) => api.put(`/notify-channels/${id}`, data),
  delete: (id: string) => api.delete(`/notify-channels/${id}`),
  test:   (id: string) => api.post<{ ok: boolean; message: string }>(`/notify-channels/${id}/test`),
}

export type AgentOperationMode = 'audit' | 'light' | 'strict'
export type AgentOperationAction = 'record' | 'alert_allow' | 'confirm' | 'block'
export type AgentOperationScope = 'tenant' | 'application' | 'agent'
export type AgentOperationTenantScope = 'all' | 'tenant'

export interface AgentOperationChannel {
  id: string
  name: string
  type: string
  enabled: boolean
}

export interface AgentOperationPolicy {
  tenant_scope: AgentOperationTenantScope
  tenant_id?: string
  scope_type: AgentOperationScope
  scope_ref: string
  mode: AgentOperationMode
  action: AgentOperationAction
  protocol: '' | 'mcp'
  mode_default_action: AgentOperationAction
  current_action: AgentOperationAction
  config_source: string
  /** false 表示这个范围还没保存过策略，下面是系统默认值；旧后端不返回该字段。 */
  configured?: boolean
  /** false 表示这个范围有一条已保存但被停用的策略（configured 仍为 true）；旧后端不返回该字段，视为启用。 */
  enabled?: boolean
  discardable_paths: string[]
  notify_channel_ids: string[]
  channels: AgentOperationChannel[]
  version: number
  updated_at: string
}

export interface AgentOperationEvent {
  public_event_id: string
  operation_id: string
  request_id?: string
  trace_id?: string
  model?: string
  tool_call_id?: string
  category_code?: string
  category_label?: string
  subcategory_code?: string
  basis_code?: string
  fact_code?: string
  fact_message?: string
  application_id?: string
  agent_type?: string
  protocol: string
  tool_name: string
  target_summary: string
  confidence: number
  status_code: string
  status_label: string
  current_action: AgentOperationAction
  notification_code: string
  created_at: string
}

export const agentOperationProtectionApi = {
  getPolicy: (params?: { tenant_scope?: AgentOperationTenantScope; tenant_id?: string; scope_type?: AgentOperationScope; scope_ref?: string }) =>
    api.get<AgentOperationPolicy>('/agent-operation-protection', { params }),
  updatePolicy: (data: Pick<AgentOperationPolicy, 'tenant_scope' | 'tenant_id' | 'scope_type' | 'scope_ref' | 'mode' | 'action' | 'protocol' | 'discardable_paths' | 'notify_channel_ids' | 'version'>) =>
    api.put<AgentOperationPolicy>('/agent-operation-protection', data),
  listEvents: (params?: { limit?: number; offset?: number }) =>
    api.get<{ items: AgentOperationEvent[]; total: number; limit: number; offset: number }>('/agent-operation-events', { params }),
}


// Audit Chain API
export interface AuditChainIntegrity {
  hmac_default_key: boolean
  verified: boolean
  ok?: boolean
  last_verified_at?: string
  first_break_at_seq?: number
  detail?: string
}

export const auditChainApi = {
  verify: (params?: { from_seq?: number; to_seq?: number }) =>
    api.post('/audit-chain/verify', null, { params }),
  stats: () => api.get('/audit-chain/stats'),
  // 签名密钥状态与最近一次完整性校验结果（只读）。
  integrity: () => api.get<AuditChainIntegrity>('/audit-chain/integrity'),
  exportUrl: (from: number, to: number) =>
    `/admin/v1/audit-chain/export?from=${from}&to=${to}&format=zip`,
}

// Savings Config API
export const savingsConfigApi = {
  get: () => api.get('/savings/config'),
  set: (data: { self_research_saving_monthly?: number; labor_hourly_rate?: number; labor_hours_per_op?: number }) =>
    api.put('/savings/config', data),
}

// Anomaly API
export const anomalyApi = {
  list: (params?: { range?: string; dimension?: string }) => api.get('/anomalies', { params }),
  ack: (id: string) => api.post(`/anomalies/${id}/ack`),
}

// Forecast API
export const forecastApi = {
  create: (data: { range_days: number; quota_params: Record<string, any> }) => api.post('/forecast/jobs', data),
  list: () => api.get('/forecast/jobs'),
  get: (id: string) => api.get(`/forecast/jobs/${id}`),
}


export interface RoutingRouteView {
  provider_name?: string
  route_ref?: string
}

export interface RoutingCandidateView extends RoutingRouteView {
  sample_state?: string
  normalized_scores?: Record<string, number>
  dimension_state?: Record<string, string>
  exclusion_reason?: string
}

export interface RoutingAttemptView {
  route: RoutingRouteView
  result: string
  status_code_category?: string
  latency_ms: number
  failure_category?: string
}

// Customer-safe routing record list item. Internal tenant/provider/policy IDs and
// raw decision JSON are intentionally absent from this contract.
export interface RoutingDecisionRow {
  request_id: string
  model_name: string
  endpoint_type: string
  result: string
  status_code_category?: string
  created_at: string
  planned_route: RoutingRouteView
  actual_route: RoutingRouteView
  fallback_used: boolean
  fallback_reason?: string
  explanation_status: 'parsed' | 'legacy' | 'unparseable' | string
  latency_ms?: number | null
}

export interface RoutingDecisionDetail extends RoutingDecisionRow {
  policy_source?: string
  policy_version?: number
  strategy?: string
  candidates?: RoutingCandidateView[]
  attempts?: RoutingAttemptView[]
}

export interface RoutingDecisionQuery {
  limit?: number
  offset?: number
  from?: string
  to?: string
  model?: string
  provider?: string
  result?: string
  fallback?: boolean
}

// Routing Policy API
export const routingApi = {
  decisions: async (params: RoutingDecisionQuery = {}, signal?: AbortSignal): Promise<{ data: RoutingDecisionRow[]; total: number }> => {
    const res = await api.get('/routing-decisions', { params, signal })
    return res.data
  },
  decisionDetail: async (requestID: string, signal?: AbortSignal): Promise<RoutingDecisionDetail> => {
    const res = await api.get(`/routing-decisions/${encodeURIComponent(requestID)}`, { signal })
    return res.data
  },
  list: (params?: { scope_type?: string; scope_ref?: string }) => api.get('/routing-policies', { params }),
  upsert: (data: { id?: string; scope_type: string; scope_ref?: string; layer: string; strategy: string; config_json: Record<string, any>; enabled: boolean }) => api.put('/routing-policies', data),
  delete: (id: string) => api.delete(`/routing-policies/${id}`),
  test: (data: { prompt_tokens?: number; text?: string; strategy: string; config: Record<string, any> }) => api.post('/routing-policies/test', data),
}

export type ModelRoutingStrategy = 'priority' | 'weighted' | 'smart' | 'fixed'
export type ModelRoutingObjective = 'stability' | 'latency' | 'cost' | 'balanced' | 'custom'
export type ModelRoutingCostBasis = 'none' | 'relative' | 'actual'
export type ModelRoutingCostLevel = 'low' | 'medium' | 'high'

export interface ModelRoutingProviderRule {
	route_ref: string
	display_name: string
  enabled: boolean
  priority: number
  weight: number
  relative_cost?: ModelRoutingCostLevel
  actual_cost?: { currency: string; input_per_million: number; output_per_million: number }
}

export interface ModelRoutingConfig {
  strategy: ModelRoutingStrategy
  objective?: ModelRoutingObjective
  custom_order?: ModelRoutingObjective[]
  cost_basis: ModelRoutingCostBasis
	fixed_route_ref?: string
  providers: ModelRoutingProviderRule[]
}

export interface ModelRoutingRule {
  config: ModelRoutingConfig
  config_version: number
  enabled: boolean
  invalid?: boolean
  invalid_reason?: 'configured_route_removed' | string
}

export interface ModelRoutingException extends ModelRoutingRule {
  model_name: string
  invalid?: boolean
  invalid_reason?: 'configured_route_removed' | string
}

export interface ModelRoutingOverview {
  default_rule: ModelRoutingRule | null
  model_exceptions: ModelRoutingException[]
  multi_route_model_count: number
  today_fallback_count?: number
  unhealthy_route_count?: number
  outbound_route_available: boolean
  legacy_report: Array<{ model_name?: string; strategy: string; convertible: boolean; reason: string }>
}

// 模型路由页主体：按模型分组的线路状态（GET /model-routing/status）
export interface ModelRouteLineStatus {
  route_ref: string
  provider_name: string
  avg_ttft_ms: number | null
  samples_30m: number
  failures_30m: number
  input_per_million?: number
  output_per_million?: number
	capability_state?: 'supported' | 'unsupported' | 'unknown' | 'expired'
	health_state?: 'healthy' | 'unhealthy' | 'unknown' | 'stale'
}

export type ModelRoutingState = 'single' | 'pending' | 'configured' | 'unavailable'

export interface ModelRoutingStatusItem {
  model_name: string
  state: ModelRoutingState
  route_count: number
	configured_candidate_count?: number
	eligible_candidate_count?: number
	endpoint_type?: 'chat' | 'responses' | 'messages' | 'images' | 'embeddings' | 'files'
  config_version: number
  routes: ModelRouteLineStatus[]
}

export interface ModelRoutingModelOption {
  model_name: string
  route_count: number
  provider_names?: string[]
}

export interface ModelRoutingValidationResult {
  valid: boolean
  scope: 'default' | 'override'
  model_name: string
  provider_count: number
  provider_names: string[]
  warnings: string[]
}

export interface ModelRoutingProviderOption {
	route_ref: string
  display_name: string
}

export const modelRoutingApi = {
  overview: async (): Promise<ModelRoutingOverview> => (await api.get<ModelRoutingOverview>('/model-routing')).data,
  providers: async (): Promise<{ providers: ModelRoutingProviderOption[] }> => {
	const response = await api.get<{ routes: ModelRoutingProviderOption[] }>('/model-routing/routes')
	return { providers: response.data.routes }
  },
  searchModels: async (query: string, limit = 20, signal?: AbortSignal): Promise<{ models: ModelRoutingModelOption[] }> =>
    (await api.get<{ models: ModelRoutingModelOption[] }>('/model-routing/models', { params: { q: query, limit }, signal })).data,
  status: async (params?: { q?: string; state?: string; provider?: string; endpoint?: string; cursor?: string; route_count?: number; min_route_count?: number; limit?: number }): Promise<{ models: ModelRoutingStatusItem[]; next_cursor: string }> =>
    (await api.get<{ models: ModelRoutingStatusItem[]; next_cursor: string }>('/model-routing/status', { params })).data,
  validate: async (modelName: string | undefined, config: ModelRoutingConfig, signal?: AbortSignal): Promise<ModelRoutingValidationResult> =>
    (await api.post<ModelRoutingValidationResult>('/model-routing/validate', { model_name: modelName, config }, { signal })).data,
  saveDefault: async (expectedVersion: number, config: ModelRoutingConfig): Promise<ModelRoutingRule> =>
    (await api.put<ModelRoutingRule>('/model-routing/default', { expected_version: expectedVersion, config })).data,
  saveOverride: async (modelName: string, expectedVersion: number, config: ModelRoutingConfig): Promise<ModelRoutingException> =>
    (await api.put<ModelRoutingException>(`/model-routing/models/${encodeURIComponent(modelName)}`, { expected_version: expectedVersion, config })).data,
  deleteOverride: async (modelName: string): Promise<{ deleted: boolean; model_name: string }> =>
    (await api.delete<{ deleted: boolean; model_name: string }>(`/model-routing/models/${encodeURIComponent(modelName)}`)).data,
  deleteDefault: async (): Promise<{ deleted: boolean }> =>
    (await api.delete<{ deleted: boolean }>('/model-routing/default')).data,
}


// AgentGuard Policy Governance API
export type AgentGuardDecision = 'allow' | 'audit' | 'confirm' | 'block'
export type AgentGuardMode = 'observe' | 'audit' | 'strict'

export interface AgentGuardPolicyPayload {
  id?: string
  name: string
  scope_type: string
  scope_ref?: string
  mode: AgentGuardMode
  default_action: AgentGuardDecision
  fail_policy: 'fail_open' | 'fail_closed'
  priority?: number
  enabled?: boolean
  template_id?: string
  rules_json?: Record<string, any>
  behavior_json?: Record<string, any>
  dlp_json?: Record<string, any>
}

export interface AgentGuardExceptionPayload {
  id?: string
  scope_type: string
  scope_ref?: string
  rule_id?: string
  target_pattern?: string
  decision: 'allow' | 'audit'
  reason: string
  expires_at: string
  enabled?: boolean
}

// 例外“长期”有效：后端按这个时间当作不过期。
export const LONG_TERM_EXCEPTION_EXPIRY = '9999-12-31T00:00:00Z'

// 2.9.22 防护项设置：原先产品内置的拦截全部改成可配置的防护项，默认告警放行。
export type ProtectionAction = 'record' | 'alert_allow' | 'confirm' | 'block'
export type ProtectionGroup = 'agent_target' | 'agent_fallback' | 'skill' | 'mcp' | 'endpoint'

export interface ProtectionParamSpec {
  key: string
  label: string
  kind: 'int' | 'string_list' | string
  default?: unknown
  min?: number
  max?: number
}

export interface ProtectionSettingItem {
  key: string
  group: ProtectionGroup | string
  label: string
  actions: ProtectionAction[]
  default_action: ProtectionAction
  action: ProtectionAction
  configured: boolean
  params: Record<string, unknown>
  param_specs: ProtectionParamSpec[]
  // legacy：值由旧配置折算而来，页面照常显示动作，不额外标注。
  source?: string
  updated_by?: string
  updated_at?: string | null
}

export type ProtectionSettingInput = { action: ProtectionAction; params?: Record<string, unknown> }

export const protectionSettingsApi = {
  list: () => api.get<{ items: ProtectionSettingItem[] }>('/protection-settings'),
  update: (items: Record<string, ProtectionSettingInput>) =>
    api.put<{ items: ProtectionSettingItem[] }>('/protection-settings', { items }),
}

export interface AgentGuardRolloutPayload {
  policy_id: string
  scope_type: string
  scope_ref?: string
  rollout_mode: AgentGuardMode
  traffic_percent: number
  status?: 'active' | 'paused' | 'completed'
  expires_at: string
}

export interface AgentGuardConfirmation {
  id: string
  request_id?: string
  trace_id?: string
  tool_name: string
  raw_decision: string
  effective_decision: string
  status: string
  timeout_action: string
  reason: string
  source?: string
  expires_at: string
  created_at?: string
  mcp_execution?: McpConfirmationExecution
}

export const agentGuardApi = {
  listPolicies: () => api.get('/agentguard/policies'),
  upsertPolicy: ({ id, ...data }: AgentGuardPolicyPayload) =>
    id ? api.put(`/agentguard/policies/${id}`, data) : api.post('/agentguard/policies', data),
  listTemplates: () => api.get('/agentguard/templates'),
  getGovernanceStats: (days = 7) => api.get('/agentguard/governance/stats', { params: { days } }),
  simulatePolicy: (data: { policy_id?: string; policy?: AgentGuardPolicyPayload; days?: number; limit?: number }) =>
    api.post('/agentguard/policies/simulate', data),
  listVersions: (policyId: string) => api.get(`/agentguard/policies/${policyId}/versions`),
  rollbackPolicy: (policyId: string, versionId: string) =>
    api.post(`/agentguard/policies/${policyId}/rollback`, { version_id: versionId }),
  listExceptions: () => api.get('/agentguard/exceptions'),
  createException: (data: AgentGuardExceptionPayload) => api.post('/agentguard/exceptions', data),
  deleteException: (id: string) => api.delete(`/agentguard/exceptions/${id}`),
  suggestException: (data: { tool_call_id: string; reason: string }) => api.post('/agentguard/exceptions/suggest', data),
  // General AgentGuard approvals only authorize the originating client to retry
  // its local action. MCP approvals execute a server-side MCP call, so they are
  // deliberately isolated in the MCP approval console.
  listConfirmations: (status?: string, source = 'agentguard') =>
    api.get<{ data: AgentGuardConfirmation[] }>('/agentguard/confirmations', { params: { status, source } }),
  resolveConfirmation: (id: string, data: { status: 'approved' | 'rejected'; note?: string }) =>
    api.post<AgentGuardConfirmation>(`/agentguard/confirmations/${id}/resolve`, data),
  getBehaviorBaseline: (days = 7) => api.get('/agentguard/behavior/baseline', { params: { days } }),
  listRollouts: (status?: string) => api.get('/agentguard/rollouts', { params: { status } }),
  createRollout: (data: AgentGuardRolloutPayload) => api.post('/agentguard/rollouts', data),
}


export interface SkillAsset {
  id: string
  canonical_name: string
  display_name: string
  source_type: 'uploaded' | 'observed' | string
  source_uri?: string
  publisher?: string
  admission_status: 'approved' | 'unverified' | 'quarantined' | 'revoked' | string
  first_seen_at?: string
  last_seen_at?: string
}

export interface SkillFindingSummary {
  file?: string
  line?: number
  evidence_preview?: string
  type?: string
  code?: string
  severity?: string
  category?: string
  field?: string
  content_hash?: string
}

export interface SkillAssetVersion {
  id: string
  asset_id: string
  declared_version: string
  source_commit?: string
  bundle_hash: string
  tree_hash: string
  signature_status: string
  signer_identity?: string
  manifest?: Record<string, unknown> | unknown[]
  findings?: SkillFindingSummary[]
  risk_level: string
  decision: string
  scan_status: string
  scan_error_code?: string
  admission_status: string
  approved_at?: string
  approved_by?: string
  review_reason?: string
  reviewed_by?: string
  reviewed_at?: string
  observed_at?: string
}

export interface SkillInvocationObservation {
  id: string
  asset_id?: string
  asset_version_id?: string
  request_id?: string
  session_id?: string
  tool_call_id?: string
  canonical_name: string
  declared_version?: string
  status: string
  raw_decision: string
  effective_decision: string
  result_status?: string
  result_findings?: SkillFindingSummary[]
  attribution_mode: string
  attribution_confidence: number
  proposed_at?: string
  forwarded_at?: string
  result_observed_at?: string
}

export interface SkillInventorySummary {
  uploaded_assets: number
  observed_assets: number
  pending_versions: number
  approved_versions: number
  quarantined_versions: number
  revoked_versions: number
  failed_scans: number
  invocations: number
}

export const skillSecurityApi = {
  listAssets: (params?: { limit?: number; offset?: number; query?: string; source_type?: string; admission_status?: string }) =>
    api.get<{ items: SkillAsset[]; total: number; limit: number; offset: number; summary: SkillInventorySummary; inventory_scope: string; endpoint_inventory: boolean }>('/skills/assets', { params }),
  listVersions: (assetId: string) =>
    api.get<{ items: SkillAssetVersion[]; total: number; endpoint_execution_observed: boolean }>(`/skills/assets/${assetId}/versions`),
  listInvocations: (params?: { limit?: number; offset?: number; asset_id?: string; version_id?: string; canonical_name?: string; status?: string; effective_decision?: string }) =>
    api.get<{ items: SkillInvocationObservation[]; total: number; limit: number; offset: number; observation_scope: string; endpoint_execution_proof: boolean }>('/skills/invocations', { params }),
  scanArchive: (data: FormData) =>
    api.post('/skills/scan', data, { headers: { 'Content-Type': 'multipart/form-data' } }),
  // override_reason：扫描判为阻断或扫描失败的版本强制批准时必填。
  setAdmission: (versionId: string, status: 'approved' | 'quarantined' | 'revoked' | string, review: { reason: string; expected_status: string; expected_bundle_hash: string; override_reason?: string }) =>
    api.post(`/skills/versions/${versionId}/admission`, { status, ...review }),
}

export interface PolicyLink {
  kind: 'policy' | 'agent_behavior' | 'agent_exception' | 'mcp_tool' | 'skill' | 'protection_item' | 'protection_group' | 'deleted' | 'none'
  path?: string
  label?: string
  // protection_item：防护项键；protection_group：防护项分组。
  item_key?: string
  group?: string
}

// 阻断记录：数据面真实阻断的每一次请求（命中规则、命中内容、阻断/操作编号）。
export interface SecurityBlockRecord {
  block_id: string
  created_at: string
  request_id: string
  trace_id?: string
  operation_id?: string
  project_id?: string
  project_name?: string
  user_id?: string
  user_name?: string
  model?: string
  agent_type?: string
  endpoint_type?: string
  source_ip?: string
  source: string
  event_type: string
  action_taken: string
  severity: string
  stage?: string
  layer: string
  reason: string
  rule_id?: string
  rule_name?: string
  category?: string
  detail?: string
  // 命中原文与不打码前后文，只有有内容证据权限的角色才有
  raw_evidence?: string
  evidence_context?: string
  raw_evidence_truncated?: boolean
  // 原文因单个事件的总量上限没有随事件保存（哈希照存），要到内容留存里看
  raw_evidence_omitted?: boolean
  basis: string
  // 这次调用为什么危险；只有网关记录了可靠的风险原因时才有值
  explanation?: string
  summary?: string
  request_status?: string
  http_status?: number
  policy_link?: PolicyLink
}

export interface SecurityBlockTrace {
  block: SecurityBlockRecord
  alerts: import('./alertOccurrences').AlertOccurrencePage | null
  alerts_status: 'available' | 'unavailable'
  audit: {
    request_id: string
    status: 'available' | 'unavailable' | 'not_found'
    content_count: number
    tool_count: number
    request: {
      record_id: string
      request_id: string
      created_at: string
      project_id?: string
      session_id?: string
      conversation_id?: string
      trace_id?: string
      status?: string
      http_status?: number
      input_tokens?: number
      output_tokens?: number
      latency_ms?: number
    } | null
    security_events: AuditSecurityEventInfo[]
    content_records: { id: string; role: string; tokens: number; created_at: string }[]
    tool_records: { id: string; tool_name: string; tool_type: string; event_type: string; status: string; operation_id?: string; created_at: string }[]
    content_evidence: AuditContentEvidenceInfo
    detail_url: string
    retention_url: string
  }
}

export type BlockResponseMode = 'error' | 'message'

export const blockRecordsApi = {
  list: (params: { q?: string; layer?: string; from?: string; to?: string; limit?: number; offset?: number }) =>
    api.get<{ items: SecurityBlockRecord[]; total: number; limit: number; offset: number }>('/security/block-records', { params }),
  get: (blockId: string) => api.get<SecurityBlockRecord>(`/security/block-records/${encodeURIComponent(blockId)}`),
  trace: (blockId: string, signal?: AbortSignal) => api.get<SecurityBlockTrace>(`/security/block-records/${encodeURIComponent(blockId)}/trace`, { signal }),
  getNoticeSettings: () => api.get<Record<string, unknown>>('/system/settings').then((response) => response.data),
  saveNoticeSettings: (input: { mode: BlockResponseMode; template: string }) =>
    api.put('/system/settings', {
      security_block_response_mode: input.mode,
      security_block_notice_template: input.template,
    }),
}

export default api

export interface RetentionStorageConfig {
  backend: string
  local_path: string
  s3_endpoint: string
  s3_bucket: string
  s3_access_key: string
  s3_region: string
  s3_prefix: string
  s3_use_ssl: boolean
  has_secret: boolean
  updated_at?: string
  updated_by?: string
}

export const retentionStorageApi = {
  get: () => api.get<RetentionStorageConfig>('/retention/storage-config'),
  update: (data: Record<string, unknown>) => api.put('/retention/storage-config', data),
  test: (data: Record<string, unknown>) =>
    api.post<{ ok: boolean; message: string }>('/retention/storage-config/test', data),
}

// Billing operations: system-admin console only.
export const billingAdminApi = {
  runtime: () => api.get('/billing/runtime'),
  // 月度分账单：按部门汇总、展开到员工×模型；format=xlsx 下载 Excel（部门汇总/员工明细/计费口径说明）
  monthlyStatement: (tenantId: string, month: string) => api.get('/billing/statements/monthly', { params: { tenant_id: tenantId, month } }),
  monthlyStatementXlsx: (tenantId: string, month: string) => api.get<Blob>('/billing/statements/monthly', { params: { tenant_id: tenantId, month, format: 'xlsx' }, responseType: 'blob' }),
  models: (tenantId: string) => api.get('/billing/models', { params: { tenant_id: tenantId } }),
  // 客户列表走 keyset 游标分页：cursor 为上一页末行 (username, user_id) 的
  // 不透明令牌；响应含 data/meta.has_more/meta.next_cursor
  customers: (tenantId: string, cursor?: string, limit?: number) =>
    api.get('/billing/customers', { params: { tenant_id: tenantId, ...(cursor !== undefined ? { cursor } : {}), ...(limit ? { limit } : {}) } }),
  customerGroups: (tenantId: string) => api.get('/billing/customer-groups', { params: { tenant_id: tenantId } }),
  createCustomerGroup: (data: Record<string, unknown>) => api.post('/billing/customer-groups', data),
  updateCustomerGroup: (id: string, data: Record<string, unknown>) => api.patch(`/billing/customer-groups/${id}`, data),
  assignCustomerGroup: (userId: string, data: Record<string, unknown>) =>
    api.put(`/billing/customers/${userId}/group`, data),
  credit: (data: Record<string, unknown>) => api.post('/billing/wallets/credit', data),
  adjust: (data: Record<string, unknown>) => api.post('/billing/wallets/adjustments', data),
  // 账本同样走 keyset 游标分页（created_at, id 倒序）
  ledger: (tenantId: string, cursor?: string, walletId?: string, limit?: number) =>
    api.get('/billing/ledger', { params: { tenant_id: tenantId, ...(cursor !== undefined ? { cursor } : {}), ...(walletId ? { wallet_id: walletId } : {}), ...(limit ? { limit } : {}) } }),
  // params 可带 limit、scope=effective（只取当前生效版本）、model_name；不带时与原来完全一致
  prices: (tenantId: string, params: Record<string, unknown> = {}) => api.get('/billing/prices', { params: { tenant_id: tenantId, ...params } }),
  createPrice: (data: Record<string, unknown>) => api.post('/billing/prices', data),
  createRatioPrice: (data: Record<string, unknown>) => api.post('/billing/prices/newapi-ratio', data),
  redemptions: (tenantId: string, filters: Record<string, unknown> = {}) => api.get('/billing/redemptions', { params: { tenant_id: tenantId,...filters } }),
  bulkDisableRedemptions: (tenantId:string,ids:string[]) => api.post('/billing/redemptions/batch-disable',{tenant_id:tenantId,ids}),
  revealRedemption: (tenantId:string,id:string) => api.post(`/billing/redemptions/${encodeURIComponent(id)}/reveal`,null,{params:{tenant_id:tenantId}}),
  redemptionDetails: (tenantId:string,id:string) => api.get(`/billing/redemptions/${encodeURIComponent(id)}`,{params:{tenant_id:tenantId}}),
  exportRedemptionHints: (tenantId:string,batch:string) => api.get('/billing/redemptions/export',{params:{tenant_id:tenantId,batch},responseType:'blob'}),
  createRedemptions: (data: Record<string, unknown>) => api.post('/billing/redemptions', data),
  deleteRedemption: (tenantId: string, id: string) => api.delete(`/billing/redemptions/${encodeURIComponent(id)}`, { params: { tenant_id: tenantId } }),
  updateRedemption: (id: string, data: Record<string, unknown>) => api.patch(`/billing/redemptions/${id}`, data),
  tariffs: (tenantId: string) => api.get('/billing/tariffs', { params: { tenant_id: tenantId } }),
  createTariff: (tenantId: string, data: Record<string, unknown>) => api.post('/billing/tariffs', data, { params: { tenant_id: tenantId } }),
  updateTariff: (tenantId: string, id: string, data: Record<string, unknown>) => api.put(`/billing/tariffs/${id}`, data, { params: { tenant_id: tenantId } }),
  publishTariff: (tenantId: string, id: string) => api.post(`/billing/tariffs/${id}/publish`, null, { params: { tenant_id: tenantId } }),
  retireTariff: (tenantId: string, id: string) => api.post(`/billing/tariffs/${id}/retire`, {}, { params: { tenant_id: tenantId } }),
  deleteTariff: (tenantId: string, id: string) => api.delete(`/billing/tariffs/${id}`, { params: { tenant_id: tenantId } }),
  previewTariff: (tenantId: string, modelName: string, at?: string) => api.get('/billing/tariffs/preview', { params: { tenant_id: tenantId, model_name: modelName, ...(at ? { at } : {}) } }),
}

// ===== W1 MCP 网关追加（请勿在此块外修改；集成时整块保留） =====

// W1 1.11：内置红线处置配置
export type McpRedlineAction = 'off' | 'record' | 'alert' | 'block'
export interface McpRedlineSetting {
  rule_name: string
  action: McpRedlineAction
  updated_by?: string
  updated_at?: string
}
export const mcpRedlineApi = {
  list: () => api.get<{ items: McpRedlineSetting[] }>('/mcp-redline-settings'),
  update: (actions: Record<string, McpRedlineAction>) =>
    api.put<{ items: McpRedlineSetting[] }>('/mcp-redline-settings', { actions }),
}
// W1 1.12：参数条件 + 部门档位（在不改原接口的前提下扩展策略类型）
export type McpArgConditionOp =
  | 'eq' | 'ne' | 'in' | 'not_in' | 'contains' | 'prefix' | 'suffix' | 'regex'
  | 'gt' | 'gte' | 'lt' | 'lte' | 'exists' | 'not_exists'
export interface McpArgCondition {
  path: string
  op: McpArgConditionOp
  value?: unknown
}
// 控制台表单行：value 为输入框原文，提交前由 toArgConditions 转成带类型的值
export interface McpArgConditionFormRow {
  path?: string
  op?: McpArgConditionOp
  value?: string
}
export type McpPolicyWithConditions = McpPolicy & { target_kind?: string; arg_conditions?: McpArgCondition[] }
export type McpPolicyPayloadWithConditions = McpPolicyPayload & { target_kind?: string; arg_conditions?: McpArgCondition[] }
export type McpPolicySimulatePayloadWithConditions = McpPolicySimulatePayload & {
  department_id?: string
  arguments?: Record<string, unknown>
}
// W1 1.13：MCP 调用审计服务端全量导出（CSV / XLSX），服务端写 mcp_audit.export 留痕
export type McpAuditExportFormat = 'csv' | 'xlsx'
const mcpAuditExportTimeoutMs = 5 * 60 * 1000
export const mcpAuditExportApi = {
  export: (format: McpAuditExportFormat, params?: Record<string, unknown>) =>
    api.get<Blob>('/mcp-audit/export', {
      params: { ...params, format },
      responseType: 'blob',
      timeout: mcpAuditExportTimeoutMs,
    }),
}
// ===== W1 MCP 网关追加结束 =====

// ==== W3 console login security (MLPS level 3) ====
export interface ConsoleLoginSecuritySettings {
  lockout_threshold: number
  lockout_minutes: number
  password_min_length: number
  password_min_classes: number
  password_history_count: number
  password_max_age_days: number
  session_idle_minutes: number
  session_absolute_hours: number
  session_max_concurrent: number
  admin_totp_required: boolean
  admin_ip_allowlist: string
}

export interface PortalLoginBaselineItem {
  key: string
  current: unknown
  target: unknown
  compliant: boolean
}

export interface PortalLoginBaselineReport {
  status: 'compliant' | 'not_compliant' | 'unavailable'
  items?: PortalLoginBaselineItem[]
  checked_at: string
  message?: string
  apply_hint?: string
}


const bearerOverride = (token?: string) => (token ? { headers: { Authorization: `Bearer ${token}` } } : undefined)

export const consoleLoginSecurityApi = {
  loginWithTOTP: (username: string, password: string, captchaId: string, captchaCode: string, totpCode: string) =>
    api.post('/login', {
      username, password, captcha_id: captchaId, captcha_code: captchaCode, totp_code: totpCode,
    }),
  totpStatus: () => api.get<{ enabled: boolean; required: boolean }>('/me/totp'),
  // token: enrollment-only session issued by login before it is stored (see pages/login-security/TotpEnroll).
  setupTOTP: (token?: string) =>
    api.post<{ secret: string; otpauth_uri: string }>('/me/totp/setup', undefined, bearerOverride(token)),
  enableTOTP: (code: string, token?: string) =>
    api.post<{ enabled: boolean }>('/me/totp/enable', { code }, bearerOverride(token)),
  unlockUserLogin: (userId: string) => api.post(`/users/${encodeURIComponent(userId)}/unlock-login`),
  resetUserTOTP: (userId: string) => api.post(`/users/${encodeURIComponent(userId)}/reset-totp`),
  getSettings: () => api.get<ConsoleLoginSecuritySettings>('/system/login-security'),
  updateSettings: (data: ConsoleLoginSecuritySettings) =>
    api.put<ConsoleLoginSecuritySettings>('/system/login-security', data),
  portalBaseline: () => api.get<PortalLoginBaselineReport>('/system/portal-login-baseline'),
}

// ── W4: three-officer separation of duties ─────────────────────────────
export interface LoginHistoryAuditEntry {
  id: number
  user_id: string
  username: string
  tenant_id: string
  logged_at: string
  ip: string
  user_agent: string
  success: boolean
  failure_reason?: string
}

export const loginHistoryAuditApi = {
  list: (params?: { user_id?: string; since?: string; until?: string; limit?: number; offset?: number }) =>
    api.get<{ data: LoginHistoryAuditEntry[]; total: number }>('/audit/login-history', { params }),
}


// W7: XLSX variant of the billing detail report (same figures as the CSV).
export const billingReportXlsxApi = {
  report: (params?: BillingAnalyticsParams) =>
    api.get<Blob>('/billing/analytics/report', { params: { ...params, format: 'xlsx' }, responseType: 'blob' }),
}

// ---- W8: statistics definitions, audit filters and server-side exports ----
// Appended block owned by workstream W8. Existing signatures above are untouched.

export type ReportExportFormat = 'csv' | 'xlsx'

export interface StatsExecutionModeView {
  configured_mode?: string
  effective_mode?: string
  locked?: boolean
  source?: string
}

export interface UserStatsTotals {
  total_tokens: number
  total_requests: number
}

export type AuditOperationFilterParams = {
  from?: string
  to?: string
  user_id?: string
  action_type?: string
  target_type?: string
  limit?: number
  offset?: number
}

export type BlockRecordExportParams = { q?: string; layer?: string; from?: string; to?: string }

export type AlertInboxFilterParams = {
  unread?: boolean
  severity?: string
  type?: string
  from?: string
  to?: string
  limit?: number
  offset?: number
}

// 服务端全量导出（上限 10 万行）比普通列表慢，单独放宽到 5 分钟，不动全局默认。
export const REPORT_EXPORT_TIMEOUT_MS = 5 * 60 * 1000

const ws8Blob = (url: string, params: Record<string, unknown>) =>
  api.get<Blob>(url, { params, responseType: 'blob', timeout: REPORT_EXPORT_TIMEOUT_MS })

export const ws8StatsApi = {
  getUserStatsWithTotals: (by: 'tokens' | 'requests' = 'tokens', limit = 10, params?: StatsRangeParams) =>
    api.get<{ data: unknown[]; totals: UserStatsTotals }>('/stats/users', {
      params: { by, limit, with_totals: true, ...params },
    }),
}

export const ws8AuditApi = {
  listOperations: (params: AuditOperationFilterParams) =>
    api.get<{ data: unknown[]; total: number; limit: number; offset: number; timezone?: string }>(
      '/system/audit-operations',
      { params },
    ),
  exportOperations: (format: ReportExportFormat, params: Omit<AuditOperationFilterParams, 'limit' | 'offset'>) =>
    ws8Blob('/system/audit-operations/export', { ...params, format }),
}

export const ws8BlockRecordsApi = {
  export: (format: ReportExportFormat, params: BlockRecordExportParams) =>
    ws8Blob('/security/block-records/export', { ...params, format }),
}

// ---- 消息中心：同类消息折叠视图 + 管理员批量已读（契约 A-E）----
export type AlertInboxFoldedParams = AlertInboxFilterParams & { limit: number; offset: number }

export interface AlertInboxFoldedGroup {
  key: string
  type: string
  severity: string
  day: string
  day_start: string
  day_end: string
  count: number
  unread_count: number
  first_at: string
  last_at: string
  // 该组最新一条完整记录，字段与普通 inbox item 相同。
  sample: Record<string, any>
}

export interface AlertInboxFoldedResponse {
  groups: AlertInboxFoldedGroup[]
  total_groups: number
  total_items: number
  unread_count: number
  timezone?: string
}

export type AlertInboxFoldedItemsParams = {
  key: string
  type: string
  severity: string
  day_start: string
  day_end: string
  unread?: boolean
  limit: number
  offset: number
}

export interface AlertInboxTypeSummaryItem {
  type: string
  unread: number
  total: number
  first_at?: string
  last_at?: string
  bulk_read_allowed: boolean
}

export type AlertInboxBulkReadScope = { type: string; from: string; to: string }

export interface AlertInboxBulkReadPreview extends AlertInboxBulkReadScope {
  matched_unread: number
  first_at?: string
  last_at?: string
  timezone?: string
}

export interface AlertInboxBulkReadResult extends AlertInboxBulkReadScope {
  ok: boolean
  marked_read: number
}

export const ws8AlertInboxApi = {
  list: (params: AlertInboxFilterParams) =>
    api.get<{ items: unknown[]; unread_count: number; total?: number; timezone?: string }>('/alerts/inbox', { params }),
  export: (format: ReportExportFormat, params: Omit<AlertInboxFilterParams, 'limit' | 'offset'>) =>
    ws8Blob('/alerts/inbox/export', { ...params, format }),
  // A：按「同 type + 同严重度 + 同标题 + 同天 + 同关键字段」折叠，服务端按组分页。
  folded: (params: AlertInboxFoldedParams) =>
    api.get<AlertInboxFoldedResponse>('/alerts/inbox/folded', { params }),
  // B：展开某一组，取该组全部原始明细（参数均取自 group 原值）。
  foldedItems: (params: AlertInboxFoldedItemsParams) =>
    api.get<{ items: unknown[]; total: number }>('/alerts/inbox/folded/items', { params }),
  // C/D/E：管理员「把某一类历史通知标为已读」。只改消息中心已读状态，不关闭告警、不删数据。
  typeSummary: () =>
    api.get<{ types: AlertInboxTypeSummaryItem[] }>('/alerts/inbox/type-summary'),
  bulkReadPreview: (params: AlertInboxBulkReadScope) =>
    api.get<AlertInboxBulkReadPreview>('/alerts/inbox/bulk-read/preview', { params }),
  bulkRead: (body: AlertInboxBulkReadScope & { expected_count: number; confirm: true }) =>
    api.post<AlertInboxBulkReadResult>('/alerts/inbox/bulk-read', body),
}
// ---- end W8 ----

// ---- W9 9.2 多身份源并存（仅追加）----
// 身份源以服务端派生的 source_alias 为稳定标识：历史默认身份源为 'enterprise'，其余为 'jjd-…'。
// 不带 source 的 identityApi 调用继续作用于默认身份源；以下接口显式指定身份源。
// 新建身份源用 saveDraft('new', …)，响应中的 source_alias 即新身份源标识。
export const DEFAULT_IDENTITY_SOURCE_ALIAS = 'enterprise'
export const NEW_IDENTITY_SOURCE = 'new'

export type IdentitySourceWithAlias = IdentitySource & { source_alias?: string }

export const identitySourcesApi = {
  saveDraft: (source: string, data: IdentityDraft) =>
    api.put<IdentitySourceWithAlias>('/identity/sources/draft', data, { params: { source } }),
  testConnection: (source: string) => api.post('/identity/sources/test', null, { params: { source } }),
  activate: (source: string) => api.post('/identity/sources/activate', null, { params: { source } }),
  disable: (source: string, confirm: boolean) =>
    api.post('/identity/sources/disable', { confirm }, { params: { source } }),
  reconcile: (source: string) => api.post('/identity/sources/reconcile', null, { params: { source } }),
  getStatus: (source: string) => api.get<IdentityStatus>('/identity/status', { params: { source } }),
}

export const billingEmployeeApi = {
  switchCurrency: (tenant_id: string, data: { currency: string; preview: boolean; confirm_token?: string; confirm_unpriced?: boolean }) => api.post('/billing/currency-switch', data, { params: { tenant_id } }),
  settings: (tenant_id: string) => api.get('/billing/employee-settings', { params: { tenant_id } }),
  saveSettings: (tenant_id: string, data: any) => api.put('/billing/employee-settings', data, { params: { tenant_id } }),
  list: (tenant_id: string) => api.get('/billing/employee-allowances', { params: { tenant_id } }),
  // 预算树（只读）：组织总预算 → 部门预算 → 员工月额度，含本月已用、剩余与状态
  budgetTree: (tenant_id: string) => api.get('/billing/budget-tree', { params: { tenant_id } }),
  saveAllowances: (tenant_id: string, user_ids: string[], monthly_micros: number | null) => api.put('/billing/employee-allowances', { user_ids, monthly_micros }, { params: { tenant_id } }),
  upstreamModels: (tenant_id: string) => api.get('/billing/upstream-models', { params: { tenant_id } }),
  upstreamRates: (tenant_id: string) => api.get('/billing/upstream-rates', { params: { tenant_id } }),
  deleteUpstreamRate: (tenant_id: string, provider_id: string, model_name: string) => api.delete('/billing/upstream-rates', { params: { tenant_id, provider_id, model_name } }),
  fixedCosts: (tenant_id: string) => api.get('/billing/channel-fixed-costs', { params: { tenant_id } }),
  saveFixedCost: (tenant_id: string, data: any) => api.put('/billing/channel-fixed-costs', data, { params: { tenant_id } }),
  deleteFixedCost: (tenant_id: string, id: string) => api.delete('/billing/channel-fixed-costs', { params: { tenant_id, id } }),
  saveUpstreamRate: (tenant_id: string, data: any) => api.put('/billing/upstream-rates', data, { params: { tenant_id } }),
}

// 运维诊断契约：docs/superpowers/plans/2026-10-24-ops-diagnosis-bot.md §2.1、§2.3。
export type DiagnosisLevel = 'confirmed' | 'suspected' | 'unknown'
export type DiagnosisTier = 'L1' | 'L2' | 'L3'
export type DiagnosisSeverity = 'ok' | 'warn' | 'error'
export interface DiagnosisEvidence { kind: string; ref: string; summary: string; raw?: string }
export interface DiagnosisAdvice { text: string; link?: string }
export interface DiagnosisFinding {
  check_id: string
  severity: DiagnosisSeverity
  level: DiagnosisLevel
  title: string
  impact: string
  advice: DiagnosisAdvice[]
  excluded: string[]
  evidence: DiagnosisEvidence[]
}
export interface DiagnosisStep { tool: string; args: unknown; summary: string; error?: string }
export interface DiagnosisReport {
  id: string
  tier: DiagnosisTier
  degraded?: string
  findings: DiagnosisFinding[]
  ok_count: number
  steps: DiagnosisStep[]
  model?: string
  started_at: string
  finished_at: string
}
export interface DiagnosisInput {
  kind: 'request' | 'user' | 'model' | 'provider' | 'health' | 'question'
  text: string
  ref: string
  window_hours: number
}
export interface DiagnosisSession {
  status: 'running' | 'done' | 'failed'
  steps: Pick<DiagnosisStep, 'tool' | 'summary'>[]
  report?: DiagnosisReport
}
// 最近会话的行结构未在 §2.3 展开；只读取标识、输入、状态及时间。
export interface DiagnosisSessionSummary {
  id: string
  input?: DiagnosisInput
  status: DiagnosisSession['status']
  created_at?: string
}
export interface DiagnosisSettingsData {
  ai_enabled: boolean
  model_id: string | null
  model_name: string
  effective_model_name?: string
  models: { id: string; name: string }[]
  selfcheck: { passed: boolean; score: number; model_name?: string; tested_at: string } | null
  agent_installed: boolean
  agent_last_seen: string | null
}
export type DiagnosisSettingsInput = Pick<DiagnosisSettingsData, 'ai_enabled' | 'model_id'>
export const diagnosticsApi = {
  createSession: (input: DiagnosisInput) => api.post<{ session_id: string }>('/diagnostics/sessions', { input }),
  getSession: (id: string) => api.get<DiagnosisSession>(`/diagnostics/sessions/${encodeURIComponent(id)}`),
  sendMessage: (id: string, text: string) => api.post<{ session_id: string }>(`/diagnostics/sessions/${encodeURIComponent(id)}/messages`, { text }),
  listSessions: (all?: boolean) => api.get<DiagnosisSessionSummary[]>('/diagnostics/sessions', { params: all ? { all: 1 } : undefined }),
  downloadBundle: (id: string) => api.get<Blob>(`/diagnostics/sessions/${encodeURIComponent(id)}/bundle`, { responseType: 'blob' }),
  getSettings: () => api.get<DiagnosisSettingsData>('/diagnostics/settings'),
  putSettings: (body: DiagnosisSettingsInput) => api.put('/diagnostics/settings', body),
  getBadge: () => api.get<{ has_issue: boolean }>('/diagnostics/badge'),
}
