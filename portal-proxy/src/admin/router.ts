import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { checkAdminToken } from '../adminAuth.js';
import { canAccessAdmin } from '../roles.js';
import { AdminError, errMsg } from './errors.js';
const MAX_ADMIN_BODY = 1 * 1024 * 1024; // 后台请求体 1MB 足够
const HTML_PATH = fileURLToPath(new URL('./public/index.html', import.meta.url));
let cachedHtml = null;
function adminHtml() {
    if (cachedHtml)
        return cachedHtml;
    cachedHtml = readFileSync(HTML_PATH);
    return cachedHtml;
}
function sendJson(res, status, obj) {
    if (!res.headersSent)
        res.writeHead(status, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' });
    res.end(JSON.stringify(obj));
}
function readJsonBody(req) {
    return new Promise((resolve, reject) => {
        const chunks = [];
        let size = 0;
        req.on('data', (c) => {
            size += c.length;
            if (size > MAX_ADMIN_BODY) {
                req.removeAllListeners('data');
                req.removeAllListeners('end');
                reject(new AdminError('payload_too_large', '请求体超过 1MB 上限', 413));
                return;
            }
            chunks.push(c);
        });
        req.on('end', () => {
            const raw = Buffer.concat(chunks).toString('utf8');
            if (raw.trim() === '')
                return resolve({});
            try {
                resolve(JSON.parse(raw));
            }
            catch {
                reject(new AdminError('invalid_json', '请求体不是合法 JSON', 400));
            }
        });
        req.on('error', reject);
    });
}
export async function handleAdmin(deps, req, res, url, auth) {
    const method = req.method ?? 'GET';
    const parts = url.pathname.split('/').filter(Boolean); // e.g. ['admin','api','rules','<id>']
    // 静态页（无鉴权：登录页自身负责发起 OIDC 登录 / 收集应急 token 再调 API）
    if (method === 'GET' && (url.pathname === '/admin' || url.pathname === '/admin/' || url.pathname === '/admin/index.html')) {
        let html;
        try {
            html = adminHtml();
        }
        catch {
            sendJson(res, 500, { error: { code: 'admin_ui_missing', message: '管理后台页面缺失' } });
            return;
        }
        res.writeHead(200, { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' });
        res.end(html);
        return;
    }
    // 其余仅接受 /admin/api/*
    if (parts[1] !== 'api') {
        sendJson(res, 404, { error: { code: 'not_found', message: '未知后台路径' } });
        return;
    }
    // 鉴权：server.ts 传入 auth 时以 OIDC/break-glass 身份判定（要 role=admin）；
    // 未传 auth（单元测试/遗留调用）回退到 X-Portal-Admin-Token 直校（constant-time）。
    if (auth !== undefined) {
        if (!canAccessAdmin(auth.identity)) {
            sendJson(res, 401, { error: { code: 'admin_unauthorized', message: '需要管理员身份（OIDC 登录或应急管理令牌）' } });
            return;
        }
    }
    else {
        const hdr = req.headers['x-portal-admin-token'];
        const presented = Array.isArray(hdr) ? hdr[0] : hdr;
        if (!checkAdminToken(presented, deps.adminToken)) {
            sendJson(res, 401, { error: { code: 'admin_unauthorized', message: '管理令牌校验失败或后台未启用' } });
            return;
        }
    }
    try {
        const resource = parts[2];
        const id = parts[3];
        if (resource === 'users' && method === 'GET' && !id) {
            sendJson(res, 200, { data: await deps.listUsers() });
            return;
        }
        if (resource === 'rules') {
            if (method === 'GET' && !id) {
                sendJson(res, 200, { data: await deps.rules.list() });
                return;
            }
            if (method === 'POST' && !id) {
                const body = await readJsonBody(req);
                sendJson(res, 201, await deps.rules.create(body));
                return;
            }
            if (method === 'PUT' && id) {
                const body = await readJsonBody(req);
                sendJson(res, 200, await deps.rules.update(id, body));
                return;
            }
            if (method === 'DELETE' && id) {
                await deps.rules.remove(id);
                sendJson(res, 200, { ok: true });
                return;
            }
        }
        if (resource === 'test-mapping' && method === 'POST' && !id) {
            const body = (await readJsonBody(req)) as Record<string, unknown>;
            const dept = typeof body?.department === 'string' && body.department.trim() !== '' ? body.department.trim() : null;
            sendJson(res, 200, await deps.resolveTestMapping(dept));
            return;
        }
        if (resource === 'groups' && method === 'POST' && !id) {
            const body = await readJsonBody(req);
            sendJson(res, 201, await deps.createGroup(body));
            return;
        }
        // Phase 3 Track A：用量总览（只读 GET，读 query）。全局管理路径不接受 project_ids/department 参数（安全铁律）。
        if (resource === 'usage' && method === 'GET' && !id) {
            const range = url.searchParams.get('range') ?? undefined;
            sendJson(res, 200, await deps.getUsage({ range }));
            return;
        }
        // Phase 3 Track A：安全告警（只读 GET，读 query）。severity/event_type/limit/cursor 透传网关；range 预留前端。
        if (resource === 'alerts' && method === 'GET' && !id) {
            const q = {
                severity: url.searchParams.get('severity') ?? undefined,
                range: url.searchParams.get('range') ?? undefined,
                eventType: url.searchParams.get('event_type') ?? undefined,
                limit: url.searchParams.get('limit') ?? undefined,
                cursor: url.searchParams.get('cursor') ?? undefined,
            };
            sendJson(res, 200, await deps.getAlerts(q));
            return;
        }
        // Phase 3 Track D：EmployeeRole 角色指派 CRUD（已过 admin 鉴权闸）。
        // GET 列表 / PUT 幂等指派（by subject in body）/ DELETE 撤销（subject 在路径段）。
        if (resource === 'roles') {
            if (method === 'GET' && !id) {
                sendJson(res, 200, { data: await deps.roleStore.list() });
                return;
            }
            if (method === 'PUT' && !id) {
                const body = await readJsonBody(req);
                const view = await deps.roleStore.upsert(body);
                sendJson(res, 200, view);
                return;
            }
            if (method === 'DELETE' && id) {
                await deps.roleStore.remove(decodeURIComponent(id));
                sendJson(res, 200, { ok: true });
                return;
            }
        }
        // Phase4 阶段C：系统配置（网关用户打通开关）。GET 出视图（env/db/合成生效 + 已打通员工数）；
        // PUT 双层门写——env 未放行时 setter 抛 409（部署未放行），关闭恒允许。回最新视图。
        if (resource === 'system-config' && !id) {
            if (method === 'GET') {
                sendJson(res, 200, await deps.systemConfig.view());
                return;
            }
            if (method === 'PUT') {
                const body = (await readJsonBody(req)) as Record<string, unknown>;
                const v = body?.gatewayUserSyncEnabled;
                if (typeof v !== 'boolean') {
                    throw new AdminError('invalid_request', '字段 gatewayUserSyncEnabled 必填且须为布尔值');
                }
                await deps.systemConfig.setGatewayUserSyncEnabled(v);
                sendJson(res, 200, await deps.systemConfig.view());
                return;
            }
        }
        sendJson(res, 404, { error: { code: 'not_found', message: '未知后台接口' } });
    }
    catch (e) {
        if (e instanceof AdminError) {
            sendJson(res, e.status, { error: { code: e.code, message: e.message } });
            return;
        }
        sendJson(res, 500, { error: { code: 'admin_internal_error', message: `后台处理失败：${errMsg(e)}` } });
    }
}
