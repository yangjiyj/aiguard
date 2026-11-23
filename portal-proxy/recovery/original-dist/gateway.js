// 员工 key scope：chat（/v1/chat/completions）+ models（/v1/models 对账）
// + responses（/v1/responses）+ embeddings（/v1/embeddings 记忆提取）。
// 缺 responses/embeddings 时网关对这两端点回 401 insufficient_scope（有路由无回复）。
const KEY_SCOPES = ['chat', 'models', 'responses', 'embeddings'];
// scope 版本（Phase4 B6 漂移治本）：KEY_SCOPES 每次扩容都 +1。
// v1=[chat,models]（Phase1 遗留）；v2=[chat,models,responses,embeddings]（A 线补全）。
// settleEmployeeKey 惰性检测 stored.scopeVersion<SCOPE_VERSION → 重签自愈（存量 key 旧 scope 不再 401）。
export const SCOPE_VERSION = 2;
function portalHeaders(cfg) {
    return {
        'content-type': 'application/json',
        'X-NewAPI-Internal-Token': cfg.portalApiSecret,
        'X-NewAPI-Tenant-Id': cfg.tenantId,
    };
}
/**
 * 签发员工专属 key 到指定 project（换组/首签都走此，project 由评估决定）。
 * Phase4 B2：可选 userId——用户打通开关 ON 时把 key 绑到网关 user（网关后台「用户管理」原生可见）；
 * 未打通（开关关 / 建 user 降级）则不带 user_id，网关落 key.UserID 为空，向后兼容现状。
 */
export async function createPortalKey(cfg, input) {
    const res = await fetch(`${cfg.gatewayCpUrl}/admin/v1/portal-integration/keys`, {
        method: 'POST',
        headers: portalHeaders(cfg),
        body: JSON.stringify({
            project_id: input.projectId,
            scopes: KEY_SCOPES,
            name: input.name,
            expires_at: input.expiresAt,
            ...(input.userId ? { user_id: input.userId } : {}),
        }),
    });
    const text = await res.text();
    if (!res.ok) {
        // 注意：错误文本可能含网关内部信息但不含 key，截断后可安全上抛
        throw new Error(`portal-integration keys API ${res.status}: ${text.slice(0, 300)}`);
    }
    const parsed = JSON.parse(text);
    const record = (typeof parsed === 'object' && parsed !== null && 'data' in parsed ? parsed.data : parsed);
    const fullKey = record?.full_key;
    const keyPrefix = record?.key_prefix;
    const id = record?.id;
    if (typeof fullKey !== 'string' || typeof keyPrefix !== 'string' || typeof id !== 'string') {
        throw new Error('portal-integration 响应缺少 full_key/key_prefix/id');
    }
    return { id, keyPrefix, fullKey };
}
/** 吊销旧 key（换组时）。204 无内容即成功；404 视作已不存在，同样当成功。 */
export async function revokePortalKey(cfg, keyId) {
    const res = await fetch(`${cfg.gatewayCpUrl}/admin/v1/portal-integration/keys/${encodeURIComponent(keyId)}/revoke`, {
        method: 'POST',
        headers: portalHeaders(cfg),
    });
    if (res.ok || res.status === 404)
        return;
    const text = await res.text();
    throw new Error(`portal-integration revoke API ${res.status}: ${text.slice(0, 300)}`);
}
// ===== Phase4 阶段B：门户员工↔网关 user/team 打通客户端（开关 ON 时惰性调用，全程 best-effort）=====
/** 用户打通失败分类：license_quota(402 配额满) / username_conflict(409 邮箱撞名) / gateway_error(其余)。
 *  jit 据 reason 分级降级日志——绝不升级为断 chat。 */
export class PortalUserSyncError extends Error {
    reason;
    status;
    constructor(reason, status, message) {
        super(message);
        this.reason = reason;
        this.status = status;
        this.name = 'PortalUserSyncError';
    }
}
/** 网关错误信封 {error:{code}} 取 code（解析失败返空串）。 */
function errorCode(text) {
    try {
        const p = JSON.parse(text);
        return typeof p.error?.code === 'string' ? p.error.code : '';
    }
    catch {
        return '';
    }
}
/**
 * 幂等建/查网关 user（键 = tenant + external_subject，命中不过配额闸）。
 * 阶段A 契约：200 {user_id,created}；402 license_max_users_exceeded；409 username_conflict。
 * 失败一律抛 PortalUserSyncError（带 reason），调用方 try/catch 降级不断链。
 */
export async function ensurePortalUser(cfg, input) {
    const res = await fetch(`${cfg.gatewayCpUrl}/admin/v1/portal-integration/users`, {
        method: 'POST',
        headers: portalHeaders(cfg),
        body: JSON.stringify({ external_subject: input.externalSubject, email: input.email }),
    });
    const text = await res.text();
    if (!res.ok) {
        const code = errorCode(text);
        const reason = res.status === 402 || code === 'license_max_users_exceeded'
            ? 'license_quota'
            : res.status === 409 || code === 'username_conflict'
                ? 'username_conflict'
                : 'gateway_error';
        throw new PortalUserSyncError(reason, res.status, `portal-integration users API ${res.status}: ${text.slice(0, 200)}`);
    }
    const parsed = JSON.parse(text);
    if (typeof parsed.user_id !== 'string') {
        throw new PortalUserSyncError('gateway_error', res.status, 'portal-integration users 响应缺少 user_id');
    }
    return { userId: parsed.user_id, created: parsed.created === true };
}
/**
 * 建网关 team（部门）。复用阶段A CreatePortalTeam（POST /teams），返回新建 team 的 id。
 * 注意：网关侧按 name 不做幂等——「只建一次」靠门户把 teamId 惰性回填进 GroupMappingRule.gatewayTeamId。
 * 失败抛 PortalUserSyncError（reason=gateway_error），调用方 best-effort 降级（team 挂载可选）。
 */
export async function ensurePortalTeam(cfg, input) {
    const res = await fetch(`${cfg.gatewayCpUrl}/admin/v1/portal-integration/teams`, {
        method: 'POST',
        headers: portalHeaders(cfg),
        body: JSON.stringify({ name: input.name }),
    });
    const text = await res.text();
    if (!res.ok) {
        throw new PortalUserSyncError('gateway_error', res.status, `portal-integration teams API ${res.status}: ${text.slice(0, 200)}`);
    }
    const parsed = JSON.parse(text);
    if (typeof parsed.id !== 'string') {
        throw new PortalUserSyncError('gateway_error', res.status, 'portal-integration teams 响应缺少 id');
    }
    return { teamId: parsed.id };
}
/**
 * 把 user 挂到 team（部门成员，让网关「团队管理」看到部门归属）。阶段A EnsureTeamMember（ON CONFLICT 幂等）。
 * 跨租户/team 不存在返 404。失败抛 PortalUserSyncError，调用方 best-effort 降级（不影响 user/key 打通）。
 */
export async function ensureTeamMember(cfg, teamId, userId) {
    const res = await fetch(`${cfg.gatewayCpUrl}/admin/v1/portal-integration/teams/${encodeURIComponent(teamId)}/members`, {
        method: 'POST',
        headers: portalHeaders(cfg),
        body: JSON.stringify({ user_id: userId }),
    });
    if (res.ok)
        return;
    const text = await res.text();
    throw new PortalUserSyncError('gateway_error', res.status, `portal-integration team members API ${res.status}: ${text.slice(0, 200)}`);
}
/** 查某 project 的模型策略 allow/deny（S3.4 ai_models 对账据 allowList 决定「只看到」）。 */
export async function getModelPolicy(cfg, projectId) {
    const res = await fetch(`${cfg.gatewayCpUrl}/admin/v1/portal-integration/policies/model?project_id=${encodeURIComponent(projectId)}`, { method: 'GET', headers: portalHeaders(cfg) });
    const text = await res.text();
    if (!res.ok) {
        throw new Error(`portal-integration policies/model API ${res.status}: ${text.slice(0, 300)}`);
    }
    const parsed = JSON.parse(text);
    const toStrArr = (v) => (Array.isArray(v) ? v.filter((x) => typeof x === 'string') : []);
    return { allowList: toStrArr(parsed.allow_list), denyList: toStrArr(parsed.deny_list) };
}
// B：读网关分组映射规则（GroupMappingRule 迁入网关后的读侧；priority 升序）。防腐 snake→camel。
// 失败抛错，由 RuleStore.list 兜底 SQLite。
export async function fetchGroupMappingRules(cfg) {
    const res = await fetch(`${cfg.gatewayCpUrl}/admin/v1/portal-integration/group-mapping-rules`, {
        method: 'GET',
        headers: portalHeaders(cfg),
    });
    const text = await res.text();
    if (!res.ok) {
        throw new Error(`portal-integration group-mapping-rules API ${res.status}: ${text.slice(0, 300)}`);
    }
    const parsed = JSON.parse(text);
    const rows = Array.isArray(parsed.data) ? parsed.data : [];
    return rows
        .filter((r) => typeof r === 'object' && r !== null)
        .map((r) => ({
        matchType: typeof r.match_type === 'string' ? r.match_type : 'department',
        matchValue: typeof r.match_value === 'string' ? r.match_value : '',
        mappedGroup: typeof r.mapped_group === 'string' ? r.mapped_group : '',
        gatewayProjectId: typeof r.gateway_project_id === 'string' ? r.gateway_project_id : '',
        priority: typeof r.priority === 'number' ? r.priority : 100,
        enabled: r.enabled !== false,
    }));
}
/** 列租户全部模型名（ai_models 对账的「宇宙」——不在 allow 内的置 enabled=false）。 */
export async function listModelNames(cfg) {
    const res = await fetch(`${cfg.gatewayCpUrl}/admin/v1/portal-integration/models`, {
        method: 'GET',
        headers: portalHeaders(cfg),
    });
    const text = await res.text();
    if (!res.ok) {
        throw new Error(`portal-integration models API ${res.status}: ${text.slice(0, 300)}`);
    }
    const parsed = JSON.parse(text);
    const rows = Array.isArray(parsed.data) ? parsed.data : [];
    return rows
        .map((m) => (typeof m === 'object' && m !== null ? m.model_name : undefined))
        .filter((n) => typeof n === 'string');
}
/**
 * S4 全托管：建网关 project（名字带 portal-dev-<组名> 前缀由调用方拼好）。
 * 复用 control-plane POST /portal-integration/projects（租户走 header）。
 */
export async function createPortalProject(cfg, input) {
    const res = await fetch(`${cfg.gatewayCpUrl}/admin/v1/portal-integration/projects`, {
        method: 'POST',
        headers: portalHeaders(cfg),
        body: JSON.stringify({ name: input.name, ...(input.teamId ? { team_id: input.teamId } : {}) }),
    });
    const text = await res.text();
    if (!res.ok) {
        throw new Error(`portal-integration projects API ${res.status}: ${text.slice(0, 300)}`);
    }
    const parsed = JSON.parse(text);
    if (typeof parsed.id !== 'string' || typeof parsed.name !== 'string') {
        throw new Error('portal-integration projects 响应缺少 id/name');
    }
    return { id: parsed.id, name: parsed.name };
}
/**
 * S4 全托管：设 project 模型策略 allow/deny（唯一强制点，纵深防御的网关硬拒侧）。
 * 复用 control-plane PUT /portal-integration/policies/model（租户走 header）。
 */
export async function setPortalModelPolicy(cfg, input) {
    const res = await fetch(`${cfg.gatewayCpUrl}/admin/v1/portal-integration/policies/model`, {
        method: 'PUT',
        headers: portalHeaders(cfg),
        body: JSON.stringify({
            project_id: input.projectId,
            allow_list: input.allowList,
            deny_list: input.denyList ?? [],
        }),
    });
    const text = await res.text();
    if (!res.ok) {
        throw new Error(`portal-integration policies/model PUT ${res.status}: ${text.slice(0, 300)}`);
    }
    const parsed = JSON.parse(text);
    const toStrArr = (v) => (Array.isArray(v) ? v.filter((x) => typeof x === 'string') : []);
    return { allowList: toStrArr(parsed.allow_list), denyList: toStrArr(parsed.deny_list) };
}
function isPlainObject(v) {
    return typeof v === 'object' && v !== null && !Array.isArray(v);
}
function num(v) {
    const n = typeof v === 'number' ? v : Number(v);
    return Number.isFinite(n) ? n : 0;
}
function str(v) {
    return typeof v === 'string' ? v : '';
}
function usageSearch(q) {
    const p = new URLSearchParams();
    if (q.startDate)
        p.set('start_date', q.startDate);
    if (q.endDate)
        p.set('end_date', q.endDate);
    if (q.projectIds && q.projectIds.length > 0)
        p.set('project_ids', q.projectIds.join(','));
    const s = p.toString();
    return s ? `?${s}` : '';
}
function auditSearch(q) {
    const p = new URLSearchParams();
    if (q.severity)
        p.set('severity', q.severity);
    if (q.eventType)
        p.set('event_type', q.eventType);
    if (q.userId)
        p.set('user_id', q.userId);
    if (q.clientId)
        p.set('client_id', q.clientId);
    if (q.projectIds && q.projectIds.length > 0)
        p.set('project_ids', q.projectIds.join(','));
    if (typeof q.limit === 'number' && Number.isFinite(q.limit))
        p.set('limit', String(q.limit));
    if (q.cursor)
        p.set('cursor', q.cursor);
    const s = p.toString();
    return s ? `?${s}` : '';
}
/** 统一 GET：注入 portal 头 + 租户头；非 2xx 抛错（截断错误文本，含状态码不含密钥）。 */
async function portalGet(cfg, path) {
    const res = await fetch(`${cfg.gatewayCpUrl}${path}`, { method: 'GET', headers: portalHeaders(cfg) });
    const text = await res.text();
    if (!res.ok) {
        const bare = path.split('?')[0];
        throw new Error(`portal-integration GET ${bare} ${res.status}: ${text.slice(0, 300)}`);
    }
    return JSON.parse(text);
}
/** topline 卡片（GetSummaryScoped）：对象信封直接解包。 */
export async function getUsageSummary(cfg, q) {
    const parsed = await portalGet(cfg, `/admin/v1/portal-integration/usage/summary${usageSearch(q)}`);
    const o = isPlainObject(parsed) ? parsed : {};
    return {
        tenantId: str(o.tenant_id),
        requests: num(o.requests),
        inputTokens: num(o.input_tokens),
        outputTokens: num(o.output_tokens),
        totalCost: num(o.total_cost),
    };
}
/** 逐日趋势（GetTrendScoped，趋势图唯一源）：{data:[...]} 信封。 */
export async function getUsageTrend(cfg, q) {
    const parsed = await portalGet(cfg, `/admin/v1/portal-integration/usage/trend${usageSearch(q)}`);
    const rows = isPlainObject(parsed) && Array.isArray(parsed.data) ? parsed.data : [];
    return rows.filter(isPlainObject).map((r) => ({
        date: str(r.date),
        requests: num(r.requests),
        inputTokens: num(r.input_tokens),
        outputTokens: num(r.output_tokens),
        totalCost: num(r.total_cost),
    }));
}
/** 模型分布（GetByModel）：裸数组信封。 */
export async function getUsageByModel(cfg, q) {
    const parsed = await portalGet(cfg, `/admin/v1/portal-integration/usage/by-model${usageSearch(q)}`);
    const rows = Array.isArray(parsed) ? parsed : [];
    return rows.filter(isPlainObject).map((r) => ({
        id: str(r.id) || str(r.name),
        name: str(r.name),
        requests: num(r.requests),
        totalTokens: num(r.total_tokens),
        totalCost: num(r.total_cost),
    }));
}
/** 按 key 用量（GetPortalUsageByKey）：裸数组信封；带 project_id 供部门 rollup join。 */
export async function getUsageByKey(cfg, q) {
    const parsed = await portalGet(cfg, `/admin/v1/portal-integration/usage/by-key${usageSearch(q)}`);
    const rows = Array.isArray(parsed) ? parsed : [];
    return rows.filter(isPlainObject).map((r) => ({
        id: str(r.id),
        name: str(r.name),
        keyPrefix: str(r.key_prefix),
        projectId: str(r.project_id),
        projectName: str(r.project_name),
        requests: num(r.requests),
        totalTokens: num(r.total_tokens),
        totalCost: num(r.total_cost),
    }));
}
/** 安全事件（ListPortalAuditEvents）：{data:[...],total} 信封；matched_summary 保持原始脱敏 map。 */
export async function getAuditEvents(cfg, q) {
    const parsed = await portalGet(cfg, `/admin/v1/portal-integration/audit-events${auditSearch(q)}`);
    const container = isPlainObject(parsed) ? parsed : {};
    const rows = Array.isArray(container.data) ? container.data : [];
    const events = rows.filter(isPlainObject).map((r) => ({
        id: str(r.id),
        requestId: str(r.request_id),
        eventType: str(r.event_type),
        severity: str(r.severity),
        ruleName: str(r.rule_name),
        ruleType: str(r.rule_type),
        actionTaken: str(r.action_taken),
        matchedSummary: isPlainObject(r.matched_summary) ? r.matched_summary : {},
        evidenceRef: str(r.evidence_ref),
        createdAt: str(r.created_at),
    }));
    return { events, total: num(container.total) || events.length };
}
