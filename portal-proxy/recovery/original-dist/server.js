// portal-proxy 主链：校验内部 token → body.user 查映射 → 分组评估（首签定 project / 惰性重评估换组）
// → 解密员工 key → 替换 Authorization → 删 body.user 转发网关 → SSE/JSON 原样透传，X-Security-Action 记日志。
// 代理面开放三端点（/v1/chat/completions、/v1/responses、/v1/embeddings），复用同一条换 key+转发链路，
// 仅目标 path 参数化（见 proxy.ts resolveProxyPath/forwardToGateway），消除 responses/embeddings 的 404。
// 另挂管理后台：GET /admin 单页 + /admin/api/*（Phase3 OIDC/break-glass 鉴权，要 role=admin），
// 以及门户独立 OIDC 会话 /portal/auth/* 与部门主管 scoped 视图 /portal/dept/*，均与 chat 主链隔离。
import http from 'node:http';
import { randomUUID } from 'node:crypto';
import { PrismaClient } from '@prisma/client';
import { checkInternalToken } from './auth.js';
import { checkAdminToken } from './adminAuth.js';
import { loadConfig } from './config.js';
import { evaluateGroup } from './evaluate.js';
import { createPortalKey, createPortalProject, fetchGroupMappingRules, getModelPolicy, listModelNames, revokePortalKey, setPortalModelPolicy, getUsageSummary, getUsageTrend, getUsageByModel, getUsageByKey, getAuditEvents, ensurePortalUser, ensurePortalTeam, ensureTeamMember, SCOPE_VERSION, } from './gateway.js';
import { JitError, JitProvisioner } from './jit.js';
import { LobeDb } from './lobedb.js';
import { log } from './logger.js';
import { extractLobeUserId, MappingError, stripUser } from './mapping.js';
import { getChatPortalEnabled } from './gateway-flags.js';
import { fromAlias } from './model-alias.js';
import { LobeModelSync } from './modelsync.js';
import { RuleStore } from './rules.js';
import { resolveProxyPath, forwardToGateway, GatewayUnreachableError, } from './proxy.js';
import { KeyStore } from './store.js';
import { parseCookies, serializeCookie, clearCookie } from './cookies.js';
import { buildAuthorizeUrl, exchangeCode, generatePkce, generateState, OidcVerifier, } from './oidc.js';
import { resolveRole } from './roles.js';
import { AdminRules } from './admin/rules.js';
import { RoleStore } from './admin/roles-admin.js';
import { listUsers } from './admin/users.js';
import { resolveTestMapping } from './admin/test-mapping.js';
import { createGroup } from './admin/groups.js';
import { getUsageOverview } from './admin/usage.js';
import { getAlerts } from './admin/alerts.js';
import { deriveScope, handleDeptRequest } from './admin/dept.js';
import { handleAdmin } from './admin/router.js';
import { SystemConfigStore } from './admin/system-config.js';
import { parseDirectIdentity } from './direct-identity.js';
import { runWithIdentity, getDirectIdentity } from './identity-context.js';
const MAX_BODY_BYTES = 10 * 1024 * 1024; // 10MB 上限，超限 413
const cfg = loadConfig();
const prisma = new PrismaClient();
const store = new KeyStore(prisma, cfg.keyEncSecret, cfg.tenantId);
const lobeDb = new LobeDb(cfg.lobeDatabaseUrl);
// B（退役门户后台）：分组映射读侧。env 放行则优先读网关（网关为权威），异常兜底本地 SQLite，绝不断登录。
// 默认关＝读本地（零行为变化）；验证网关读通后翻 PORTAL_GATEWAY_RULES_READ=true。
const ruleStore = new RuleStore(prisma, cfg.gatewayRulesRead ? () => fetchGroupMappingRules(cfg) : undefined, (level, msg, meta) => log(level, msg, meta));
const modelSync = new LobeModelSync(cfg.lobeDatabaseUrl);
// Phase4 阶段C：系统配置存取（网关用户打通开关，双层门）。env 门 config.userSyncAllowed 注入，
// 与 DB 配置 AND 合成；进程内短 TTL 缓存 DB 读，避开每次 chat 打库。
const systemConfig = new SystemConfigStore(prisma, cfg.userSyncAllowed, cfg.tenantId);
// Phase4 阶段C：网关 user/team 打通开关合成——env 放行 AND DB 系统配置开。
// env 未放行时短路恒 false（连 DB 都不读，且遗留 DB=true 也一律当关，双闸铁律）。
// 铁律：判定异常在 jit 内部当「关」，绝不误开撑爆配额。
async function isGatewayUserSyncEnabled() {
    return systemConfig.isGatewayUserSyncEnabled();
}
// 解析分组对应网关 team id：读 GroupMappingRule.gatewayTeamId；空则惰性建 team + 回填该 project 全部规则；
// 无规则（default 组）返 null＝不挂 team。全程由 jit 的 best-effort 包裹，抛错只降级不断链。
async function resolveGatewayTeamId(group) {
    const binding = await ruleStore.findTeamBinding(group.gatewayProjectId);
    if (!binding)
        return null;
    if (binding.gatewayTeamId)
        return binding.gatewayTeamId;
    const { teamId } = await ensurePortalTeam(cfg, { name: group.mappedGroup });
    await ruleStore.backfillGatewayTeamId(group.gatewayProjectId, teamId);
    return teamId;
}
const jit = new JitProvisioner({
    // A2：直接身份模式优先——新门户后端在请求头注入 OIDC sub/email，跳过 LobeHub PG 库查询。
    // 旧 LobeHub 链路（body.user）已废弃；如直接身份缺失则回落 LobeDb（保留兼容，不会命中）。
    lookupEmployee: async (id) => {
        const direct = getDirectIdentity();
        if (direct && direct.ssoSubject === id) {
            return { email: direct.email, ssoSubject: direct.ssoSubject };
        }
        return lobeDb.lookupEmployee(id);
    },
    createGatewayKey: (input) => createPortalKey(cfg, input),
    saveEmployeeKey: (rec) => store.save(rec),
    getStoredKey: (id) => store.getStoredKey(id),
    revokeGatewayKey: (keyId) => revokePortalKey(cfg, keyId),
    markEvaluated: (id, input) => store.markEvaluated(id, input),
    onRevokeFailed: (keyId, err) => log('warn', 'old_key_revoke_failed', { key_id: keyId, err: err instanceof Error ? err.message : String(err) }),
    // Phase4 阶段B 打通依赖（全 best-effort，jit 内部 try/catch 降级，绝不断 chat）
    isUserSyncEnabled: () => isGatewayUserSyncEnabled(),
    ensureGatewayUser: (input) => ensurePortalUser(cfg, input),
    resolveTeamId: (group) => resolveGatewayTeamId(group),
    ensureTeamMember: (teamId, userId) => ensureTeamMember(cfg, teamId, userId),
    onUserSyncFailed: (lobeUserId, reason, err) => log('warn', 'gateway_user_sync_degraded', { lobeUserId, reason, err: err instanceof Error ? err.message : String(err) }),
}, cfg.keyTtlDays, cfg.defaultProjectId, SCOPE_VERSION);
// Phase 3 Track D：EmployeeRole 角色表存取（管理面 CRUD + 中间件角色回落源）。
const roleStore = new RoleStore(prisma, cfg.tenantId);
// 门户 OIDC 校验器（配了 client_secret 才建；否则后台仅剩 break-glass token）。
const oidcVerifier = cfg.oidc ? new OidcVerifier(cfg.oidc) : null;
// 用量/告警的网关侧底层依赖（全局与主管 scoped 路径共用；差别仅在是否注入 projectIds）。
const usageGatewayDeps = {
    getUsageSummary: (q) => getUsageSummary(cfg, q),
    getUsageTrend: (q) => getUsageTrend(cfg, q),
    getUsageByModel: (q) => getUsageByModel(cfg, q),
    getUsageByKey: (q) => getUsageByKey(cfg, q),
    listRules: () => ruleStore.list(),
};
const alertsGatewayDeps = { getAuditEvents: (q) => getAuditEvents(cfg, q) };
const deptDeps = {
    usage: usageGatewayDeps,
    alerts: alertsGatewayDeps,
    listRules: () => ruleStore.list(),
    tenantId: cfg.tenantId,
};
// S4 管理后台依赖：复用主链的 prisma / ruleStore / 网关客户端，装配成后台 handler 用的高层动作。
const adminRules = new AdminRules(prisma, cfg.tenantId);
const adminDeps = {
    adminToken: cfg.adminToken,
    listUsers: () => listUsers(prisma),
    rules: adminRules,
    roleStore,
    systemConfig,
    resolveTestMapping: (department) => resolveTestMapping({
        listRules: () => ruleStore.list(),
        getModelPolicy: (pid) => getModelPolicy(cfg, pid),
        defaultProjectId: cfg.defaultProjectId,
    }, department),
    createGroup: (input) => createGroup({
        createProject: (name) => createPortalProject(cfg, { name }),
        setModelPolicy: async (pid, allow) => {
            await setPortalModelPolicy(cfg, { projectId: pid, allowList: allow });
        },
        createRule: (r) => adminRules.create(r),
    }, input),
    // Phase 3 Track A：用量总览（全局管理，不下发 project_ids＝全租户）+ 安全告警（matched_summary 白名单）。
    getUsage: (query) => getUsageOverview(usageGatewayDeps, query),
    getAlerts: (query) => getAlerts(alertsGatewayDeps, query),
};
// ===== Phase 3 Track D：OIDC 会话 cookie 名与时长 =====
const COOKIE_ID = 'portal_id_token';
const COOKIE_STATE = 'portal_oidc_state';
const COOKIE_VERIFIER = 'portal_oidc_verifier';
const OIDC_TX_TTL = 600; // state/PKCE 短时 cookie 10 分钟
const ID_TOKEN_TTL = 3600; // id_token cookie 1 小时（须 ≤ Keycloak access token 寿命）
const AUTH_COOKIE_PATH = '/portal/auth';
/**
 * 角色中间件：解析请求身份三态——
 * (a) 有效 OIDC cookie → jose 校验 id_token → 角色解析（claim 优先 → EmployeeRole 表回落 → employee）+ department；
 * (b) X-Portal-Admin-Token 有效 → break-glass 超管（role=admin，无 department scope）；
 * (c) 都无 → null（→ 调用方 401）。
 * department 只来自 token / EmployeeRole 表，绝不来自请求参数（安全铁律）。
 */
async function authenticate(req) {
    if (oidcVerifier) {
        const idToken = parseCookies(req.headers.cookie)[COOKIE_ID];
        if (idToken) {
            try {
                const claims = await oidcVerifier.verify(idToken);
                const assignment = await roleStore.findBySubject(claims.sub);
                const role = resolveRole(claims.roleClaim, assignment?.role ?? null);
                return {
                    kind: 'oidc',
                    role,
                    sub: claims.sub,
                    email: claims.email ?? undefined,
                    department: claims.department,
                    managedDepartments: assignment?.managedDepartments ?? [],
                };
            }
            catch (e) {
                // 签名/过期/issuer/aud 不符 → 视作未认证，继续尝试 break-glass
                log('info', 'oidc_cookie_invalid', { err: e instanceof Error ? e.message : String(e) });
            }
        }
    }
    const hdr = req.headers['x-portal-admin-token'];
    const presented = Array.isArray(hdr) ? hdr[0] : hdr;
    if (checkAdminToken(presented, cfg.adminToken))
        return { kind: 'breakglass', role: 'admin' };
    return null;
}
/** 主管 scope 派生（供 /portal/auth/me 展示用）：department（token/表）→ projectIds（规则反查）。 */
async function resolveDeptScope(identity) {
    return deriveScope(identity, await ruleStore.list());
}
function sendJson(res, status, obj) {
    if (!res.headersSent)
        res.writeHead(status, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' });
    res.end(JSON.stringify(obj));
}
/** GET /portal/auth/login → 生成 state+PKCE（存短时 HttpOnly cookie）并 302 到 Keycloak authorize。 */
function handleOidcLogin(res) {
    if (!cfg.oidc) {
        sendJson(res, 503, { error: { code: 'oidc_disabled', message: '门户 OIDC 未配置，请使用应急管理令牌登录' } });
        return;
    }
    const state = generateState();
    const { verifier, challenge } = generatePkce();
    const url = buildAuthorizeUrl(cfg.oidc, { state, codeChallenge: challenge });
    const opts = { httpOnly: true, secure: cfg.cookieSecure, sameSite: 'Lax', path: AUTH_COOKIE_PATH, maxAge: OIDC_TX_TTL };
    res.writeHead(302, {
        location: url,
        'set-cookie': [serializeCookie(COOKIE_STATE, state, opts), serializeCookie(COOKIE_VERIFIER, verifier, opts)],
        'cache-control': 'no-store',
    });
    res.end();
}
/** GET /portal/auth/callback → 校 state（CSRF）→ code 换 token → 校 id_token → 存 cookie → 302 落地。 */
async function handleOidcCallback(req, res, url) {
    if (!cfg.oidc || !oidcVerifier) {
        sendJson(res, 503, { error: { code: 'oidc_disabled', message: '门户 OIDC 未配置' } });
        return;
    }
    const clearTx = [clearCookie(COOKIE_STATE, AUTH_COOKIE_PATH), clearCookie(COOKIE_VERIFIER, AUTH_COOKIE_PATH)];
    const redirectErr = (reason) => {
        log('warn', 'oidc_callback_rejected', { reason });
        res.writeHead(302, { location: `${cfg.postLoginPath}?auth_error=${encodeURIComponent(reason)}`, 'set-cookie': clearTx, 'cache-control': 'no-store' });
        res.end();
    };
    const idpError = url.searchParams.get('error');
    if (idpError)
        return redirectErr(idpError);
    const code = url.searchParams.get('code');
    const state = url.searchParams.get('state');
    const cookies = parseCookies(req.headers.cookie);
    const expectState = cookies[COOKIE_STATE];
    const verifier = cookies[COOKIE_VERIFIER];
    // state 必须与 cookie 一致（CSRF）；缺 code/verifier 一律拒
    if (!code || !state || !expectState || state !== expectState || !verifier) {
        return redirectErr('state_mismatch');
    }
    let idToken;
    try {
        const tok = await exchangeCode(cfg.oidc, { code, codeVerifier: verifier });
        idToken = tok.idToken;
        await oidcVerifier.verify(idToken); // 存 cookie 前先校验一遍（签名/issuer/aud/过期）
    }
    catch (e) {
        log('warn', 'oidc_token_exchange_failed', { err: e instanceof Error ? e.message : String(e) });
        return redirectErr('token_exchange_failed');
    }
    res.writeHead(302, {
        location: cfg.postLoginPath,
        'set-cookie': [
            serializeCookie(COOKIE_ID, idToken, { httpOnly: true, secure: cfg.cookieSecure, sameSite: 'Lax', path: '/', maxAge: ID_TOKEN_TTL }),
            ...clearTx,
        ],
        'cache-control': 'no-store',
    });
    res.end();
}
/** GET /portal/auth/me → 前端据此按角色渲染（未登录返回 authenticated:false，不 401 以便渲染登录门）。 */
async function handleOidcMe(req, res) {
    const identity = await authenticate(req);
    if (!identity) {
        sendJson(res, 200, { authenticated: false, oidcEnabled: !!cfg.oidc });
        return;
    }
    let scope = null;
    if (identity.role === 'manager')
        scope = await resolveDeptScope(identity);
    sendJson(res, 200, {
        authenticated: true,
        oidcEnabled: !!cfg.oidc,
        kind: identity.kind,
        role: identity.role,
        email: identity.email ?? null,
        department: identity.department ?? null,
        managedDepartments: identity.managedDepartments ?? [],
        scope,
    });
}
/** /portal/dept/*（部门主管 scoped）：身份由中间件解析后交 handleDeptRequest（scope 服务端强制）。 */
async function handleDept(req, res, url) {
    const identity = await authenticate(req);
    const resource = url.pathname.split('/').filter(Boolean)[2] ?? ''; // ['portal','dept','<resource>']
    const { status, body } = await handleDeptRequest(deptDeps, identity, resource, url.searchParams);
    sendJson(res, status, body);
}
class PayloadTooLargeError extends Error {
}
function jsonError(res, status, code, message, traceId) {
    if (!res.headersSent)
        res.writeHead(status, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ error: { code, message, trace_id: traceId } }));
}
/** 按分组允许清单对账该 user 的 ai_models（只看到层）。失败降级：仅日志，网关硬拒兜底，不阻断 chat。 */
async function reconcileModels(traceId, lobeUserId, gatewayProjectId) {
    if (!gatewayProjectId)
        return;
    try {
        const [policy, universe] = await Promise.all([getModelPolicy(cfg, gatewayProjectId), listModelNames(cfg)]);
        if (policy.allowList.length === 0) {
            // 无限制策略（default 组等）→ 不收窄可见清单，避免误伤；UI 保持默认
            log('info', 'model_reconcile_skip_open_policy', { trace_id: traceId, lobeUserId, gateway_project_id: gatewayProjectId });
            return;
        }
        const res = await modelSync.reconcile(lobeUserId, policy.allowList, universe);
        log('info', 'model_reconciled', {
            trace_id: traceId,
            lobeUserId,
            gateway_project_id: gatewayProjectId,
            written: res.written,
            enabled: res.enabled,
        });
    }
    catch (e) {
        log('warn', 'model_reconcile_degraded', {
            trace_id: traceId,
            lobeUserId,
            gateway_project_id: gatewayProjectId,
            err: e instanceof Error ? e.message : String(e),
        });
    }
}
/**
 * 分组评估与 key 结算：
 * - 无 EmployeeKey → evaluate 定初始 project → JIT 签发 → ai_models 对账。
 * - 有 EmployeeKey → 惰性重评估（department 变 或 lastEvaluatedAt 超 TTL 才重跑）：
 *   换 project 则 revoke+重建（复用 jit 锁）+ 对账；同 project 仅续期。
 * - department 查询异常 / 规则加载异常 / 换组建 key 失败 → 保守续用旧 key（绝不误降级）。
 * 仅首次 JIT 的 unknown_user/provision_failed 向上抛（对应 403/502）。
 */
async function settleEmployeeKey(traceId, lobeUserId) {
    let existing = await store.findActive(lobeUserId);
    // department：查询异常与「无部门」区别对待
    let department = null;
    let deptLookupFailed = false;
    // A2：直接身份模式下 department 直接从头取，跳过 LobeHub accounts.id_token 查询
    const direct = getDirectIdentity();
    if (direct && direct.ssoSubject === lobeUserId) {
        department = direct.department;
    }
    else {
        try {
            department = await lobeDb.lookupDepartment(lobeUserId);
        }
        catch (e) {
            deptLookupFailed = true;
            log('warn', 'department_lookup_failed', { trace_id: traceId, lobeUserId, err: e instanceof Error ? e.message : String(e) });
        }
    }
    if (!existing) {
        // 首次 JIT：评估定初始 project（规则加载失败则退 default，仍能开机）
        const effectiveDept = deptLookupFailed ? null : department;
        let assignment;
        try {
            const rules = await ruleStore.list();
            assignment = evaluateGroup(effectiveDept, rules, cfg.defaultProjectId);
        }
        catch (e) {
            log('warn', 'rule_load_failed_on_provision', { trace_id: traceId, lobeUserId, err: e instanceof Error ? e.message : String(e) });
            assignment = { mappedGroup: 'default', gatewayProjectId: cfg.defaultProjectId };
        }
        await jit.provision(lobeUserId, assignment, effectiveDept); // unknown_user/provision_failed 上抛
        const employee = await store.findActive(lobeUserId);
        if (!employee)
            throw new JitError('provision_failed', '签发后未能读回员工 key'); // 理论不可达
        log('info', 'jit_provisioned', {
            trace_id: traceId,
            lobeUserId,
            email: employee.email,
            gateway_key_id: employee.gatewayKeyId,
            key_prefix: employee.keyPrefix,
            mapped_group: employee.mappedGroup,
            gateway_project_id: employee.gatewayProjectId,
        });
        await reconcileModels(traceId, lobeUserId, employee.gatewayProjectId);
        return { employee, jitUsed: true, action: 'provisioned' };
    }
    // Phase4 B6 scope 漂移治本：存量 key 的 scopeVersion 落后当前 → 重签自愈（补全 responses/embeddings scope，不再 401）。
    // 必须放在下方 TTL 去抖/重评估之前——否则 TTL 内会被 reused 短路而永不自愈。
    // 与 department 解析无关（即便 dept 查询失败也能 heal）；重签失败保守续用旧 key（chat 不断，下次登录再试）。
    if (existing.scopeVersion < SCOPE_VERSION) {
        const staleFrom = existing.scopeVersion;
        try {
            const r = await jit.resignScope(lobeUserId);
            if (r.resigned) {
                existing = (await store.findActive(lobeUserId)) ?? existing;
                log('info', 'scope_resigned', {
                    trace_id: traceId,
                    lobeUserId,
                    from_version: staleFrom,
                    to_version: SCOPE_VERSION,
                    key_prefix: existing.keyPrefix,
                });
            }
        }
        catch (e) {
            log('warn', 'scope_resign_failed_keep_old', { trace_id: traceId, lobeUserId, err: e instanceof Error ? e.message : String(e) });
        }
    }
    // 已有 key：department 查询异常 → 保守不动
    if (deptLookupFailed) {
        return { employee: existing, jitUsed: false, action: 'conservative_keep' };
    }
    // 去抖：department 未变 且 lastEvaluatedAt 在 TTL 内 → 直接复用
    const now = Date.now();
    const ttlMs = cfg.reevalTtlSec * 1000;
    const withinTtl = existing.lastEvaluatedAt != null && now - existing.lastEvaluatedAt.getTime() < ttlMs;
    const reevalNeeded = existing.lastDepartment !== department || !withinTtl;
    if (!reevalNeeded) {
        return { employee: existing, jitUsed: false, action: 'reused' };
    }
    // 需要重评估：规则加载失败 → 保守不动
    let assignment;
    try {
        const rules = await ruleStore.list();
        assignment = evaluateGroup(department, rules, cfg.defaultProjectId);
    }
    catch (e) {
        log('warn', 'rule_load_failed_on_reeval', { trace_id: traceId, lobeUserId, err: e instanceof Error ? e.message : String(e) });
        return { employee: existing, jitUsed: false, action: 'conservative_keep' };
    }
    if (assignment.gatewayProjectId === existing.gatewayProjectId) {
        // 同 project：仅续期（分组/department/评估时刻），模型不变不必对账
        await store.markEvaluated(lobeUserId, {
            mappedGroup: assignment.mappedGroup,
            gatewayProjectId: assignment.gatewayProjectId,
            department,
        });
        const refreshed = (await store.findActive(lobeUserId)) ?? existing;
        return { employee: refreshed, jitUsed: false, action: 'reevaluated' };
    }
    // 换 project：revoke 旧 + 重建新（jit 锁内双检）；建 key 失败 → 保守续用旧 key
    try {
        const result = await jit.migrate(lobeUserId, {
            mappedGroup: assignment.mappedGroup,
            gatewayProjectId: assignment.gatewayProjectId,
            department,
        });
        const refreshed = (await store.findActive(lobeUserId)) ?? existing;
        if (result.migrated) {
            log('info', 'group_migrated', {
                trace_id: traceId,
                lobeUserId,
                email: refreshed.email,
                from_project: existing.gatewayProjectId,
                to_project: assignment.gatewayProjectId,
                mapped_group: assignment.mappedGroup,
                new_key_prefix: refreshed.keyPrefix,
            });
            await reconcileModels(traceId, lobeUserId, refreshed.gatewayProjectId);
        }
        return { employee: refreshed, jitUsed: false, action: result.migrated ? 'migrated' : 'reevaluated' };
    }
    catch (e) {
        log('warn', 'group_migrate_failed_keep_old', {
            trace_id: traceId,
            lobeUserId,
            err: e instanceof Error ? e.message : String(e),
        });
        return { employee: existing, jitUsed: false, action: 'conservative_keep' };
    }
}
function readBody(req) {
    return new Promise((resolve, reject) => {
        const chunks = [];
        let size = 0;
        req.on('data', (chunk) => {
            size += chunk.length;
            if (size > MAX_BODY_BYTES) {
                reject(new PayloadTooLargeError());
                req.removeAllListeners('data');
                req.removeAllListeners('end');
                return;
            }
            chunks.push(chunk);
        });
        req.on('end', () => resolve(Buffer.concat(chunks)));
        req.on('error', reject);
    });
}
async function handle(req, res) {
    const traceId = randomUUID();
    const startedAt = Date.now();
    const url = new URL(req.url ?? '/', 'http://portal-proxy');
    if (req.method === 'GET' && url.pathname === '/healthz') {
        res.writeHead(200, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ ok: true, service: 'portal-proxy' }));
        return;
    }
    // chat-edge（Caddy forward_auth）门控：网关系统设置 chat_portal_enabled=OFF 时门户整站不暴露。
    // 204=放行；403=拦截（浏览器看到「门户未启用」页）。判定只看全局开关，不依赖请求内容。
    if (url.pathname === '/gate') {
        req.resume(); // 丢弃可能随 forward_auth 带来的请求体，保 keep-alive 干净
        const enabled = await getChatPortalEnabled(cfg);
        if (enabled) {
            res.writeHead(204, { 'cache-control': 'no-store' });
            res.end();
        }
        else {
            res.writeHead(403, { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' });
            res.end('<!doctype html><html lang="zh-CN"><meta charset="utf-8"><title>门户未启用</title><body style="margin:0;font-family:-apple-system,\'PingFang SC\',\'Microsoft YaHei\',sans-serif;background:#f5f6f8;color:#555;display:flex;align-items:center;justify-content:center;min-height:100vh"><div style="text-align:center;max-width:440px;padding:32px"><div style="font-size:44px;margin-bottom:12px">&#128274;</div><h2 style="margin:0 0 10px;color:#222">门户未启用</h2><p style="line-height:1.75;color:#666">Chat / SSO 门户当前未对外开放。<br>请联系管理员在网关「系统设置」中启用「Chat / SSO 门户」。</p></div></body></html>');
        }
        return;
    }
    // Phase 3 Track D：门户独立 OIDC 会话端点（与 chat 主链、LobeHub 登录完全独立）
    if (req.method === 'GET' && url.pathname === '/portal/auth/login') {
        handleOidcLogin(res);
        return;
    }
    if (req.method === 'GET' && url.pathname === '/portal/auth/callback') {
        await handleOidcCallback(req, res, url);
        return;
    }
    if (url.pathname === '/portal/auth/logout') {
        // 清 id_token cookie；GET/POST 均接受（前端按钮走 POST）
        res.writeHead(200, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store', 'set-cookie': clearCookie(COOKIE_ID, '/') });
        res.end(JSON.stringify({ ok: true }));
        return;
    }
    if (req.method === 'GET' && url.pathname === '/portal/auth/me') {
        await handleOidcMe(req, res);
        return;
    }
    // Phase 3 Track D：部门主管 scoped 视图（role=manager；scope 服务端强制下推 project_ids）
    if (req.method === 'GET' && url.pathname.startsWith('/portal/dept/')) {
        await handleDept(req, res, url);
        return;
    }
    // 管理后台（GET /admin 单页无鉴权；/admin/api/* 走 OIDC/break-glass，要 role=admin）
    if (url.pathname === '/admin' || url.pathname.startsWith('/admin/')) {
        const staticPage = req.method === 'GET' &&
            (url.pathname === '/admin' || url.pathname === '/admin/' || url.pathname === '/admin/index.html');
        const auth = staticPage ? undefined : { identity: await authenticate(req) };
        await handleAdmin(adminDeps, req, res, url, auth);
        return;
    }
    // /v1/models：返回当前员工被允许的模型清单（新门户 GET /api/models 调此端点）
    // 鉴权：内部 token + 直接身份头（与 chat 主链同一套，但 GET 方法）
    if (req.method === 'GET' && url.pathname === '/v1/models') {
        if (!checkInternalToken(req.headers.authorization, cfg.internalToken)) {
            jsonError(res, 401, 'unauthorized', '内部服务 token 校验失败', traceId);
            return;
        }
        const direct = parseDirectIdentity(req.headers);
        if (!direct) {
            jsonError(res, 400, 'missing_identity', 'GET /v1/models 需要直接身份头（X-Portal-Direct-*）', traceId);
            return;
        }
        try {
            const employee = await store.findActive(direct.ssoSubject);
            let allowList = [];
            if (employee?.gatewayProjectId) {
                try {
                    const policy = await getModelPolicy(cfg, employee.gatewayProjectId);
                    allowList = policy.allowList;
                }
                catch (e) {
                    log('warn', 'model_policy_lookup_failed', { trace_id: traceId, ssoSubject: direct.ssoSubject, err: e instanceof Error ? e.message : String(e) });
                }
            }
            // allowList 为空（新员工还没 JIT 签 key，或网关策略拉取失败）→ 返租户全量兜底
            if (allowList.length === 0) {
                try {
                    allowList = await listModelNames(cfg);
                }
                catch (e) {
                    log('warn', 'list_model_names_failed', { trace_id: traceId, err: e instanceof Error ? e.message : String(e) });
                }
            }
            const data = allowList.map((id) => ({ id, displayName: id }));
            res.writeHead(200, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'private, max-age=30' });
            res.end(JSON.stringify({ models: data, defaultModelId: data[0]?.id ?? null }));
            log('info', 'models_listed', { trace_id: traceId, ssoSubject: direct.ssoSubject, count: data.length, project: employee?.gatewayProjectId ?? null });
            return;
        }
        catch (e) {
            log('error', 'models_endpoint_failed', { trace_id: traceId, err: e instanceof Error ? e.message : String(e) });
            jsonError(res, 500, 'internal_error', '列出模型失败', traceId);
            return;
        }
    }
    // 代理面路由：仅 POST + 命中白名单（chat/completions、responses、embeddings）才转发，其余 404
    const targetPath = resolveProxyPath(req.method, url.pathname);
    if (!targetPath) {
        log('warn', 'route_not_found', { trace_id: traceId, method: req.method, path: url.pathname });
        jsonError(res, 404, 'not_found', 'portal-proxy 仅提供 POST /v1/chat/completions、/v1/responses、/v1/embeddings', traceId);
        return;
    }
    // 1. 内部 token（constant-time）
    if (!checkInternalToken(req.headers.authorization, cfg.internalToken)) {
        log('warn', 'auth_failed', { trace_id: traceId });
        jsonError(res, 401, 'unauthorized', '内部服务 token 校验失败', traceId);
        return;
    }
    // A2：解析直接身份头（新门户后端注入；浏览器无法伪造，且仅内部 token 校验通过才到此）
    const directIdentity = parseDirectIdentity(req.headers);
    // 后续整个 JIT/转发流程包裹在直接身份上下文里（AsyncLocalStorage 请求级隔离）
    const rest = () => handleProxyRest(req, res, url, traceId, startedAt, targetPath);
    if (directIdentity) {
        return await runWithIdentity(directIdentity, rest);
    }
    return await rest();
    // 占位（实际 handleProxyRest 在下方定义）
}
async function handleProxyRest(req, res, url, traceId, startedAt, targetPath) {
    // 1.5 数据面兜底门控：网关 chat_portal_enabled=OFF 时拒绝转发（与 edge 整站门控同一开关，纵深防御）
    if (!(await getChatPortalEnabled(cfg))) {
        log('warn', 'chat_portal_disabled', { trace_id: traceId });
        jsonError(res, 503, 'chat_portal_disabled', 'Chat 门户已在网关系统设置中关闭', traceId);
        return;
    }
    // 2. 读体（10MB 上限）+ 解析
    let raw;
    try {
        raw = await readBody(req);
    }
    catch (e) {
        if (e instanceof PayloadTooLargeError) {
            log('warn', 'payload_too_large', { trace_id: traceId });
            jsonError(res, 413, 'payload_too_large', `请求体超过 ${MAX_BODY_BYTES} 字节上限`, traceId);
            res.once('close', () => req.destroy());
            return;
        }
        throw e;
    }
    let body;
    try {
        body = JSON.parse(raw.toString('utf8'));
    }
    catch {
        jsonError(res, 400, 'invalid_json', '请求体不是合法 JSON', traceId);
        return;
    }
    // 3. 归因主键（lobeUserId）
    // A2：直接身份模式 = OIDC sub；旧 body.user 模式回落（已废弃，新门户不传）
    const direct = getDirectIdentity();
    let lobeUserId;
    if (direct) {
        lobeUserId = direct.ssoSubject;
    }
    else {
        try {
            lobeUserId = extractLobeUserId(body);
        }
        catch (e) {
            if (e instanceof MappingError) {
                log('warn', 'mapping_rejected', { trace_id: traceId, code: e.code });
                jsonError(res, 400, e.code, e.message, traceId);
                return;
            }
            throw e;
        }
    }
    // 4. 分组评估 + key 结算（首签/换组/续期/保守续用）
    let settled;
    try {
        settled = await settleEmployeeKey(traceId, lobeUserId);
    }
    catch (e) {
        if (e instanceof JitError && e.code === 'unknown_user') {
            log('warn', 'jit_unknown_user', { trace_id: traceId, lobeUserId });
            jsonError(res, 403, 'unknown_user', '该用户在门户中不存在，无法签发网关密钥', traceId);
            return;
        }
        log('error', 'settle_failed', { trace_id: traceId, lobeUserId, err: e instanceof Error ? e.message : String(e) });
        jsonError(res, 502, 'jit_provision_failed', '为该员工签发网关密钥失败，请稍后重试；若持续失败请联系管理员', traceId);
        return;
    }
    const employee = settled.employee;
    // 5. 删 body.user 后以员工 key 转发网关对应端点（targetPath 参数化，三端点同一转发内核）
    const forwardBody = stripUser(body);
    // 目录别名还原：LobeHub 目录里 OpenAI 目录模型用别名承载（规避其强制 Responses API），转发网关前换回真 id，
    // 使网关 project 模型策略与上游都拿到真 id（gpt5.5 → gpt-5.5）。非别名模型原样。
    if (typeof forwardBody.model === 'string') {
        forwardBody.model = fromAlias(forwardBody.model);
    }
    res.socket?.setNoDelay(true);
    let outcome;
    try {
        // 6. 响应透传（SSE 逐帧 / JSON 原样），X-Security-Action 进结构化日志（在 forwardToGateway 内统一处理）
        outcome = await forwardToGateway({
            gatewayBaseUrl: cfg.gatewayBaseUrl,
            targetPath,
            fullKey: employee.fullKey,
            accept: typeof req.headers.accept === 'string' ? req.headers.accept : '*/*',
            forwardBody,
        }, res);
    }
    catch (e) {
        if (e instanceof GatewayUnreachableError) {
            // fetch 失败：此时尚未 writeHead，安全返回 502
            log('error', 'gateway_unreachable', { trace_id: traceId, lobeUserId, endpoint: targetPath, err: e.reason instanceof Error ? e.reason.message : String(e.reason) });
            jsonError(res, 502, 'gateway_unreachable', '安全网关不可达', traceId);
            return;
        }
        throw e; // 流中途出错（headers 已发出）→ 交顶层兜底，与既有行为一致
    }
    store.touch(lobeUserId);
    log('info', 'chat_forwarded', {
        trace_id: traceId,
        lobeUserId,
        endpoint: targetPath,
        email: employee.email,
        key_prefix: employee.keyPrefix,
        mapped_group: employee.mappedGroup,
        gateway_project_id: employee.gatewayProjectId,
        settle_action: settled.action,
        jit: settled.jitUsed,
        model: typeof body.model === 'string' ? body.model : null,
        upstream_status: outcome.upstreamStatus,
        security_action: outcome.securityAction,
        chunks: outcome.stats.chunks,
        bytes: outcome.stats.bytes,
        duration_ms: Date.now() - startedAt,
    });
}
const server = http.createServer((req, res) => {
    handle(req, res).catch((e) => {
        log('error', 'unhandled_error', { err: e instanceof Error ? `${e.name}: ${e.message}` : String(e) });
        try {
            jsonError(res, 500, 'internal_error', 'portal-proxy 内部错误', 'n/a');
        }
        catch {
            /* 响应已损毁则放弃 */
        }
    });
});
server.listen(cfg.port, '0.0.0.0', () => {
    log('info', 'listening', { port: cfg.port, gateway: cfg.gatewayBaseUrl, control_plane: cfg.gatewayCpUrl });
});
async function shutdown(signal) {
    log('info', 'shutting_down', { signal });
    server.close();
    await Promise.allSettled([prisma.$disconnect(), lobeDb.close(), modelSync.close()]);
    process.exit(0);
}
process.on('SIGTERM', () => void shutdown('SIGTERM'));
process.on('SIGINT', () => void shutdown('SIGINT'));
