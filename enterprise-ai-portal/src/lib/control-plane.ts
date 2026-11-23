// 控制面机器通道客户端：门户用已验证 OIDC token 调 /admin/v1/portal-integration/users
// 拿到稳定身份绑定；请求时授权上下文再提供部门 ID/名称、Chat 门禁和模型调用名。
// 这些控制面字段才是门户的授权与展示依据，而非 OIDC sub 或原始部门声明。
// 所有身份字段来自服务端已验证 token，浏览器 body 的任何覆盖都被忽略。
import { loadGatewayEnv, type GatewayEnv } from './gateway-env';

// 默认租户：当前单租户门户阶段，所有员工进入 tenant_default。
// 多租户化时由 OIDC claims 租户选择器注入，门户侧绝不接受浏览器 header 覆盖。
export const PORTAL_DEFAULT_TENANT_ID = 'tenant_default';

// 已验证 OIDC token 提取出的稳定身份声明——门户把这些作为机器通道 body 注入控制面。
// 浏览器提交的 iss/sub/departments/groups/preferred_username/email 一律忽略。
export interface StableIdentityClaims {
  issuer: string;
  subject: string;
  username: string;
  email: string;
  /** OIDC department claim normalized to a list; absent is valid for unassigned users. */
  departments?: string[];
  groups: string[];
}

// 控制面 EnsurePortalUser 返回的授权依据。
export interface PortalUserResolution {
  userId: string;
  departmentId: string;
  projectId?: string;
  chatAllowed: boolean;
  /** Personal portal access is independent of business model permission. */
  portalAllowed?: boolean;
  resolution: string;
  created: boolean;
  /**
   * users.department_version 的单调授权 revision。
   * 门户在敏感操作前与控制面校验；revision 变化必须刷新，零值按未授权处理。
   */
  departmentVersion: number;
}

export interface EnsurePortalUserOptions {
  externalSubject?: string;
  loginMode?: 'local'|'oidc';
  localCredentialVersion?: number;
  /** 默认走 process.env，测试可注入 in-memory env。 */
  env?: NodeJS.ProcessEnv;
  /** 默认全局 fetch，测试可注入 mock。 */
  fetchImpl?: typeof fetch;
  /** 默认走 loadGatewayEnv(process.env)，测试可注入。 */
  gateway?: GatewayEnv;
}

export type ModelAccessSource = 'department' | 'personal_extra' | 'personal_narrowed';
export interface PortalModelExtraGrant {
 id:string; model:string; reason:string; expires_at:string|null;
 created_by:string; created_at:string; revoked_at:string|null;
}
export interface PortalAuthorizationContext {
 historyUserIds?:string[];
 projectId?: string;
 modelAccessMode?: 'inherit'|'allowlist';
 departmentModels?: string[];
 personalAllowlist?: string[];
 extraGrants?: PortalModelExtraGrant[];
 modelSources?: Record<string,ModelAccessSource>;
 staleModels?: string[];
  userId: string;
  departmentId: string;
  departmentName: string;
  departmentVersion: number;
  chatAllowed: boolean;
  portalAllowed?: boolean;
  modelIds: string[];
  modelAccessVersion?: number;
  localLoginAllowed?: boolean;
  localCredentialVersion?: number;
  localExternalSubject?: string;
}

export interface PortalCallRecord {
  requestId: string;
  createdAt: string;
  model: string;
  status: string;
  inputTokens: number;
  cachedInputTokens: number;
  cacheWriteInputTokens: number;
  outputTokens: number;
  totalTokens: number;
  latencyMs: number;
  agentType: string;
  endpointType: string;
	billingAmountMicros: number | null;
	billingCurrency: string;
	billingState: PortalBillingState;
}

export type PortalBillingState =
	| 'settled'
	| 'reserved'
	| 'released'
	| 'exception'
	| 'not_billed'
	| 'unpriced'
	| 'failed';

export interface PortalCallRecordSummary {
  requests: number;
  averageLatencyMs: number | null;
  successRate: number | null;
}

export interface PortalCallRecordPage {
  summary?: PortalCallRecordSummary;
  records: PortalCallRecord[];
  total: number;
  nextCursor: string;
}

export const PORTAL_REQUEST_ID_PATTERN = /^(?:req_)?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

export interface PortalCallRecordQuery {
  limit?: number;
  cursor?: string;
  days?: number;
  requestId?: string;
}

// 控制面机器通道错误。message 仅暴露分类 + 状态码，绝不泄露 DSN/secret/完整 claims。
export class ControlPlaneError extends Error {
  readonly code: string;
  readonly status: number;
  constructor(code: string, status: number, message: string) {
    super(message);
    this.name = 'ControlPlaneError';
    this.code = code;
    this.status = status;
  }
}

function bound(value: unknown, label: string): string {
  if (typeof value !== 'string') {
    throw new ControlPlaneError('invalid_identity', 0, `${label} must be a string`);
  }
  const trimmed = value.trim();
  if (!trimmed) {
    throw new ControlPlaneError('invalid_identity', 0, `${label} is required`);
  }
  return trimmed;
}

// 调控制面 EnsurePortalUser。失败时抛 ControlPlaneError，调用方决定是否阻断登录。
// 红线：iss/sub/username 任一缺失直接拒（控制面也会 400，但前置一道省一次往返）；
// 错误信息不含 DSN/secret/原始 token/完整 claims。
export async function ensurePortalUser(
  tenantId: string,
  identity: StableIdentityClaims,
  options: EnsurePortalUserOptions = {},
): Promise<PortalUserResolution> {
  const tid = (tenantId ?? '').trim() || PORTAL_DEFAULT_TENANT_ID;
  const issuer = bound(identity?.issuer, 'issuer');
  const subject = bound(identity?.subject, 'subject');
  const username = bound(identity?.username, 'username');
  const email = typeof identity?.email === 'string' ? identity.email.trim() : '';
  const departmentsRaw = Array.isArray(identity?.departments) ? identity.departments : [];
  const departments = departmentsRaw
    .filter((department): department is string => typeof department === 'string' && department.trim().length > 0)
    .map((department) => department.trim());
  const groupsRaw = Array.isArray(identity?.groups) ? identity.groups : [];
  const groups = groupsRaw.filter((g): g is string => typeof g === 'string' && g.trim().length > 0);

  const gateway = options.gateway ?? loadGatewayEnv(options.env ?? process.env);
  const fetchImpl = options.fetchImpl ?? fetch;

  const url = `${gateway.baseUrl}/admin/v1/portal-integration/users`;
  let response: Response;
  try {
    response = await fetchImpl(url, {
      method: 'POST',
      headers: {
        authorization: `Bearer ${gateway.portalSecret}`,
        'content-type': 'application/json',
        'X-JJDGuard-Tenant-Id': tid,
      },
      body: JSON.stringify({
        issuer,
        source_type: 'oidc',
        external_subject: subject,
        username,
        email,
        departments,
        groups,
      }),
      cache: 'no-store',
    });
  } catch {
    // 不暴露原始网络错误细节（可能含主机/中间件签名）。
    throw new ControlPlaneError('control_plane_unreachable', 0, '控制面机器通道不可达');
  }

  if (!response.ok) {
    // 控制面返回的错误码是稳定的分类标识；message 不含敏感字段。
    const code = await safeErrorCode(response);
    throw new ControlPlaneError(code, response.status, `控制面拒绝身份绑定 (${response.status})`);
  }

  // 控制面返回 snake_case JSON；用 raw 接口接收，再映射到 camelCase PortalUserResolution。
  const data = (await response.json().catch(() => null)) as {
    user_id?: unknown;
    department_id?: unknown;
    project_id?: unknown;
    chat_allowed?: unknown;
    portal_allowed?: unknown;
    resolution?: unknown;
    created?: unknown;
    department_version?: unknown;
  } | null;
  if (!data || typeof data.user_id !== 'string' || !data.user_id) {
    throw new ControlPlaneError('invalid_identity_response', response.status, '控制面返回缺 user_id');
  }
  if (
    (data.portal_allowed !== undefined && typeof data.portal_allowed !== 'boolean') ||
    typeof data.department_version !== 'number' ||
    !Number.isSafeInteger(data.department_version) ||
    data.department_version <= 0
  ) {
    throw new ControlPlaneError('invalid_identity_response', response.status, 'Control plane returned an invalid authorization revision');
  }
  return {
    userId: data.user_id,
    departmentId: typeof data.department_id === 'string' ? data.department_id : '',
    projectId: typeof data.project_id === 'string' ? data.project_id : '',
    chatAllowed: data.chat_allowed === true,
    ...(typeof data.portal_allowed === 'boolean' ? { portalAllowed: data.portal_allowed } : {}),
    resolution: typeof data.resolution === 'string' ? data.resolution : '',
    created: data.created === true,
    departmentVersion: data.department_version,
  };
}

export async function getCurrentPortalAuthorization(
  tenantId: string,
  userId: string,
  options: EnsurePortalUserOptions = {},
): Promise<PortalAuthorizationContext> {
  const tid = (tenantId ?? '').trim() || PORTAL_DEFAULT_TENANT_ID;
  const uid = bound(userId, 'user_id');
  const gateway = options.gateway ?? loadGatewayEnv(options.env ?? process.env);
  const fetchImpl = options.fetchImpl ?? fetch;

  const query=new URLSearchParams();
  if(options.externalSubject!==undefined) query.set('external_subject',bound(options.externalSubject,'external_subject'));
  if(options.loginMode) query.set('login_mode',options.loginMode);
  if(options.localCredentialVersion!==undefined) query.set('local_credential_version',String(options.localCredentialVersion));
  const suffix=query.size?'?'+query.toString():'';
  let response: Response;
  try {
    response = await fetchImpl(
      `${gateway.baseUrl}/admin/v1/portal-integration/users/${encodeURIComponent(uid)}/authorization-context${suffix}`,
      {
        method: 'GET',
        headers: {
          authorization: `Bearer ${gateway.portalSecret}`,
          'X-JJDGuard-Tenant-Id': tid,
        },
        cache: 'no-store',
      },
    );
  } catch {
    throw new ControlPlaneError(
      'control_plane_unreachable',
      0,
      '控制面授权上下文不可达',
    );
  }

  if (!response.ok) {
    const code = await safeErrorCode(response);
    throw new ControlPlaneError(code, response.status, `控制面拒绝授权上下文 (${response.status})`);
  }

  const payload = (await response.json().catch(() => null)) as {
    data?: {
      user_id?: unknown;
      department_id?: unknown;
      department_name?: unknown;
      department_version?: unknown;
      chat_allowed?: unknown;
      portal_allowed?: unknown;
      model_ids?: unknown;
      model_access_version?: unknown;
      project_id?: unknown;
      model_access_mode?: unknown;
      department_models?: unknown;
      personal_allowlist?: unknown;
      extra_grants?: unknown;
      model_sources?: unknown;
      stale_models?: unknown;
      local_login_allowed?: unknown;
      local_credential_version?: unknown;
      local_external_subject?: unknown;
      history_user_ids?:unknown;
    };
  } | null;
  const data = payload?.data;
  if (
    !data ||
    data.user_id !== uid ||
    typeof data.department_id !== 'string' ||
    typeof data.department_name !== 'string' ||
    typeof data.department_version !== 'number' ||
    !Number.isSafeInteger(data.department_version) ||
    data.department_version <= 0 ||
    typeof data.chat_allowed !== 'boolean' ||
    (data.portal_allowed !== undefined && typeof data.portal_allowed !== 'boolean') ||
    !Array.isArray(data.model_ids) ||
    !data.model_ids.every((id): id is string => typeof id === 'string' && id.trim().length > 0)
  ) {
    throw new ControlPlaneError(
      'invalid_authorization_response',
      response.status,
      '控制面返回无效授权上下文',
    );
  }
  if (!(typeof data.portal_allowed === 'boolean' ? data.portal_allowed : data.chat_allowed)) {
    throw new ControlPlaneError('authorization_denied', 403, '当前用户禁止使用聊天能力');
  }
  const modelDetails = parseModelAccessDetails(data);
  const history=data.history_user_ids;
  if(history!==undefined&&(!Array.isArray(history)||history.length>1024||!history.includes(uid)||!history.every(id=>typeof id==='string'&&id.length>0&&id.length<=128))) {
    throw new ControlPlaneError('invalid_authorization_response',response.status,'控制面返回无效历史归属');
  }
  return {
    ...modelDetails,
    ...(Array.isArray(history)?{historyUserIds:[...new Set(history as string[])]}:{}),
    ...(typeof data.project_id === 'string' ? {projectId:data.project_id} : {}),
    userId: data.user_id,
    departmentId: data.department_id,
    departmentName: data.department_name,
    departmentVersion: data.department_version,
    chatAllowed: data.chat_allowed,
    ...(typeof data.portal_allowed === 'boolean' ? { portalAllowed: data.portal_allowed } : {}),
    modelIds: data.chat_allowed ? [...new Set(data.model_ids)] : [],
    ...(typeof data.model_access_version === 'number' && Number.isSafeInteger(data.model_access_version) && data.model_access_version > 0 ? { modelAccessVersion: data.model_access_version } : {}),
    ...(typeof data.local_login_allowed === 'boolean' ? { localLoginAllowed: data.local_login_allowed } : {}),
    ...(typeof data.local_credential_version === 'number' && Number.isSafeInteger(data.local_credential_version) && data.local_credential_version > 0 ? {localCredentialVersion:data.local_credential_version} : {}),
    ...(typeof data.local_external_subject === 'string' ? { localExternalSubject: data.local_external_subject } : {}),
  };
}

function boundedInteger(value: number | undefined, fallback: number, minimum: number, maximum: number): number {
  if (!Number.isSafeInteger(value)) return fallback;
  return Math.min(Math.max(value as number, minimum), maximum);
}

const portalCallRecordCursorPattern = /^[A-Za-z0-9_-]+$/;

function normalizePortalCallRecordCursor(value: string | undefined): string {
  if (value === undefined || value === '') return '';
  if (
    value.length > 512 ||
    value.trim() !== value ||
    !portalCallRecordCursorPattern.test(value)
  ) {
    throw new ControlPlaneError(
      'invalid_call_records_cursor',
      400,
      '调用留痕分页参数无效',
    );
  }
  return value;
}

function isBoundedString(value: unknown, maximum: number, allowEmpty = true): value is string {
  return (
    typeof value === 'string' &&
    value.length <= maximum &&
    (allowEmpty || value.trim().length > 0) &&
    !/[\u0000-\u001f\u007f]/.test(value)
  );
}

function isNonNegativeSafeInteger(value: unknown): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0;
}

const portalBillingStates = new Set<PortalBillingState>([
	'settled',
	'reserved',
	'released',
	'exception',
	'not_billed',
	'unpriced',
	'failed',
]);

function parsePortalCallRecord(value: unknown): PortalCallRecord | null {
  if (!value || typeof value !== 'object') return null;
  const raw = value as Record<string, unknown>;
  if (
    !isBoundedString(raw.request_id, 128, false) ||
    !isBoundedString(raw.created_at, 64, false) ||
    !Number.isFinite(Date.parse(raw.created_at)) ||
    !isBoundedString(raw.model, 512, false) ||
    !isBoundedString(raw.status, 64, false) ||
    !isNonNegativeSafeInteger(raw.input_tokens) ||
    (raw.cached_input_tokens !== undefined && !isNonNegativeSafeInteger(raw.cached_input_tokens)) ||
    (raw.cache_write_input_tokens !== undefined && !isNonNegativeSafeInteger(raw.cache_write_input_tokens)) ||
    !isNonNegativeSafeInteger(raw.output_tokens) ||
    !isNonNegativeSafeInteger(raw.total_tokens) ||
    raw.total_tokens !== raw.input_tokens + raw.output_tokens ||
    !Number.isSafeInteger(raw.input_tokens + raw.output_tokens) ||
    !isNonNegativeSafeInteger(raw.latency_ms) ||
    !isBoundedString(raw.agent_type, 128) ||
    !isBoundedString(raw.endpoint_type, 64) ||
		!isBoundedString(raw.billing_state, 32, false) ||
		!portalBillingStates.has(raw.billing_state as PortalBillingState) ||
		!(raw.billing_amount_micros === null || isNonNegativeSafeInteger(raw.billing_amount_micros)) ||
		!isBoundedString(raw.billing_currency, 3) ||
		!(raw.billing_currency === '' || /^[A-Z]{3}$/.test(raw.billing_currency)) ||
		(raw.billing_state === 'settled'
			? raw.billing_amount_micros === null
				? raw.billing_currency !== ''
				: !/^[A-Z]{3}$/.test(raw.billing_currency)
			: raw.billing_amount_micros !== null)
  ) {
    return null;
  }
  return {
    requestId: raw.request_id,
    createdAt: raw.created_at,
    model: raw.model,
    status: raw.status,
    inputTokens: raw.input_tokens,
    cachedInputTokens: raw.cached_input_tokens === undefined ? 0 : raw.cached_input_tokens as number,
    cacheWriteInputTokens: raw.cache_write_input_tokens === undefined ? 0 : raw.cache_write_input_tokens as number,
    outputTokens: raw.output_tokens,
    totalTokens: raw.total_tokens,
    latencyMs: raw.latency_ms,
    agentType: raw.agent_type,
    endpointType: raw.endpoint_type,
		billingAmountMicros: raw.billing_amount_micros,
		billingCurrency: raw.billing_currency,
		billingState: raw.billing_state as PortalBillingState,
  };
}

export async function listPortalCallRecords(
  tenantId: string,
  userId: string,
  query: PortalCallRecordQuery = {},
  options: EnsurePortalUserOptions = {},
): Promise<PortalCallRecordPage> {
  const tid = (tenantId ?? '').trim() || PORTAL_DEFAULT_TENANT_ID;
  const uid = bound(userId, 'user_id');
  const gateway = options.gateway ?? loadGatewayEnv(options.env ?? process.env);
  const fetchImpl = options.fetchImpl ?? fetch;
  const params = new URLSearchParams();
  params.set('limit', String(boundedInteger(query.limit, 50, 1, 200)));
  const cursor = normalizePortalCallRecordCursor(query.cursor);
  if (cursor) params.set('cursor', cursor);
  params.set('days', String(boundedInteger(query.days, 30, 1, 90)));
  if (query.requestId) {
    if (!PORTAL_REQUEST_ID_PATTERN.test(query.requestId)) {
      throw new ControlPlaneError('invalid_request_id', 400, '调用编号格式无效');
    }
    params.set('request_id', query.requestId);
  }

  let response: Response;
  try {
    response = await fetchImpl(
      gateway.baseUrl +
        '/admin/v1/portal-integration/users/' +
        encodeURIComponent(uid) +
        '/call-records?' +
        params.toString(),
      {
        method: 'GET',
        headers: {
          authorization: 'Bearer ' + gateway.portalSecret,
          'X-JJDGuard-Tenant-Id': tid,
        },
        cache: 'no-store',
      },
    );
  } catch {
    throw new ControlPlaneError(
      'control_plane_unreachable',
      0,
      '控制面调用留痕不可达',
    );
  }

  if (!response.ok) {
    const code = await safeErrorCode(response);
    throw new ControlPlaneError(code, response.status, '控制面拒绝调用留痕 (' + response.status + ')');
  }

  const payload = (await response.json().catch(() => null)) as {
    data?: unknown;
    total?: unknown;
    next_cursor?: unknown;
    summary?: unknown;
  } | null;
  if (
    !payload ||
    !Array.isArray(payload.data) ||
    !isNonNegativeSafeInteger(payload.total) ||
    !isBoundedString(payload.next_cursor, 512) ||
    (payload.next_cursor !== '' && !portalCallRecordCursorPattern.test(payload.next_cursor))
  ) {
    throw new ControlPlaneError(
      'invalid_call_records_response',
      response.status,
      '控制面返回无效调用留痕',
    );
  }
  const records = payload.data.map(parsePortalCallRecord);
  if (records.some((record) => record === null) || payload.total < records.length) {
    throw new ControlPlaneError(
      'invalid_call_records_response',
      response.status,
      '控制面返回无效调用留痕',
    );
  }
  // 汇总按整个筛选范围计算，严格白名单，避免透传额外字段。
  let summary: PortalCallRecordSummary | undefined;
  if (payload.summary !== undefined) {
    const raw = payload.summary as Record<string, unknown> | null;
    if (!raw || !isNonNegativeSafeInteger(raw.requests) ||
      !(raw.average_latency_ms === null || (typeof raw.average_latency_ms === 'number' && Number.isFinite(raw.average_latency_ms) && raw.average_latency_ms >= 0)) ||
      !(raw.success_rate === null || (typeof raw.success_rate === 'number' && Number.isFinite(raw.success_rate) && raw.success_rate >= 0 && raw.success_rate <= 1))) {
      throw new ControlPlaneError('invalid_call_records_response', response.status, '控制面返回无效调用汇总');
    }
    summary = { requests: raw.requests, averageLatencyMs: raw.average_latency_ms as number | null, successRate: raw.success_rate as number | null };
  }
  return {
    ...(summary ? { summary } : {}),
    records: records as PortalCallRecord[],
    total: payload.total,
    nextCursor: payload.next_cursor,
  };
}

async function safeErrorCode(response: Response): Promise<string> {
  try {
    const body = (await response.json().catch(() => null)) as { error?: unknown } | null;
    const code = body?.error;
    return typeof code === 'string' && /^[a-z_]+$/.test(code) ? code : `http_${response.status}`;
  } catch {
    return `http_${response.status}`;
  }
}

/** Server-verified local identity returned by a one-use login ticket. */
export interface ChatLoginIdentity extends PortalUserResolution {
  localCredentialVersion: number;
  tenantId: string;
  username: string;
  email: string;
  externalSubject: string;
  departmentName: string;
}

export async function redeemChatLoginTicket(
  ticket: string,
  options: EnsurePortalUserOptions = {},
): Promise<ChatLoginIdentity> {
  if (typeof ticket !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(ticket)) {
    throw new ControlPlaneError('invalid_chat_ticket', 400, '登录交接已失效，请重新登录');
  }
  const gateway = options.gateway ?? loadGatewayEnv(options.env ?? process.env);
  let response: Response;
  try {
    response = await (options.fetchImpl ?? fetch)(
      gateway.baseUrl + '/admin/v1/portal-integration/chat-login/redeem',
      {
        method: 'POST',
        headers: {
          authorization: 'Bearer ' + gateway.portalSecret,
          'content-type': 'application/json',
          // The portal currently serves exactly one business tenant. Never
          // silently reinterpret a ticket issued by a different tenant.
          'X-JJDGuard-Tenant-Id': PORTAL_DEFAULT_TENANT_ID,
        },
        body: JSON.stringify({ ticket }),
        cache: 'no-store',
      },
    );
  } catch {
    throw new ControlPlaneError('control_plane_unreachable', 0, '登录交接服务暂不可用');
  }
  if (!response.ok) {
    throw new ControlPlaneError(await safeErrorCode(response), response.status, '登录交接已失效或账号授权已变更');
  }
  const data = await response.json().catch(() => null) as Record<string, unknown> | null;
  if (
    !data || data.tenant_id !== PORTAL_DEFAULT_TENANT_ID ||
    typeof data.local_credential_version !== 'number' || !Number.isSafeInteger(data.local_credential_version) || data.local_credential_version <= 0 ||
    typeof data.user_id !== 'string' || !data.user_id.trim() ||
    typeof data.external_subject !== 'string' || !data.external_subject.trim() ||
    typeof data.username !== 'string' || !data.username.trim() ||
    typeof data.email !== 'string' ||
    typeof data.department_id !== 'string' || (data.chat_allowed === true && !data.department_id.trim()) ||
    typeof data.department_name !== 'string' ||
    typeof data.department_version !== 'number' ||
    !Number.isSafeInteger(data.department_version) || data.department_version <= 0 ||
    typeof data.chat_allowed !== 'boolean' ||
    (data.portal_allowed !== undefined && typeof data.portal_allowed !== 'boolean') ||
    !(typeof data.portal_allowed === 'boolean' ? data.portal_allowed : data.chat_allowed)
  ) {
    throw new ControlPlaneError('invalid_chat_identity', 403, '登录交接身份无效，请联系管理员');
  }
  return {
    userId: data.user_id,
    tenantId: PORTAL_DEFAULT_TENANT_ID,
    localCredentialVersion:data.local_credential_version,
    username: data.username,
    email: data.email,
    externalSubject: data.external_subject,
    departmentId: data.department_id,
    departmentName: data.department_name,
    departmentVersion: data.department_version,
    chatAllowed: data.chat_allowed,
    ...(typeof data.portal_allowed === 'boolean' ? { portalAllowed: data.portal_allowed } : {}),
    resolution: 'manual',
    created: false,
  };
}

function parseModelAccessDetails(data: Record<string,unknown>): Partial<PortalAuthorizationContext> {
 if (data.model_access_mode === undefined) return {};
 const list = (value:unknown):value is string[]=>Array.isArray(value)&&value.every(item=>typeof item==='string'&&item.trim().length>0&&item.length<=256);
 const date = (value:unknown)=>value===null||(typeof value==='string'&&Number.isFinite(Date.parse(value)));
 const grant = (value:unknown):value is PortalModelExtraGrant=>{
  if(!value||typeof value!=='object')return false;
  const g=value as Record<string,unknown>;
  return typeof g.id==='string'&&typeof g.model==='string'&&typeof g.reason==='string'&&typeof g.created_by==='string'&&typeof g.created_at==='string'&&Number.isFinite(Date.parse(g.created_at))&&date(g.expires_at)&&date(g.revoked_at);
 };
 const sources=data.model_sources;
 if((data.model_access_mode!=='inherit'&&data.model_access_mode!=='allowlist')||!list(data.department_models)||!list(data.personal_allowlist)||!list(data.stale_models)||!Array.isArray(data.extra_grants)||!data.extra_grants.every(grant)||!sources||typeof sources!=='object'||Array.isArray(sources)||!Object.values(sources).every(source=>source==='department'||source==='personal_extra'||source==='personal_narrowed')) {
  throw new ControlPlaneError('invalid_authorization_response',502,'控制面返回无效模型授权来源');
 }
 return {modelAccessMode:data.model_access_mode,departmentModels:data.department_models,personalAllowlist:data.personal_allowlist,staleModels:data.stale_models,extraGrants:data.extra_grants,modelSources:sources as Record<string,ModelAccessSource>};
}
