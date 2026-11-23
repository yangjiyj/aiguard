// 部门主管 scoped 视图的服务端逻辑（Phase 3 Track D 关卡④ 的安全落点）。
// 单一职责、可注入、可 TDD：身份由调用方（server.ts 中间件）注入，本模块只读 query 的
// range/severity/limit/cursor，**绝不读取 project_ids/department 参数**——scope 一律由
// identity（OIDC department claim / EmployeeRole.managedDepartments）经 GroupMappingRule 派生。
// 空 scope 绝不调 Gate0（无 project_ids＝全租户），直接返空。这三条即「主管不得拿整租户裸行」。
import { canAccessDept, departmentsToProjectIds, resolveManagerDepartments } from '../roles.js';
import { getUsageOverview } from './usage.js';
import { getAlerts } from './alerts.js';
/** identity → scope：department（token/表）→ projectIds（规则反查）。纯函数，绝不读请求参数。 */
export function deriveScope(identity, rules) {
    const departments = resolveManagerDepartments(identity.department ?? null, identity.managedDepartments ?? []);
    const projectIds = departmentsToProjectIds(departments, rules);
    return { departments, projectIds };
}
export function emptyDeptOverview(tenantId) {
    return {
        topline: { tenantId, requests: 0, inputTokens: 0, outputTokens: 0, totalCost: 0 },
        trend: [],
        byModel: [],
        byDepartment: [],
    };
}
export const EMPTY_DEPT_ALERTS = { data: [], total: 0, severityCounts: {} };
/**
 * 主管请求处理：鉴权（要 manager）→ 派生 scope → 下推 project_ids 调 Gate0。
 * @param resource 'usage' | 'alerts'
 * @param query 仅用于读 range/severity/limit/cursor；project_ids/department 一律忽略。
 */
export async function handleDeptRequest(deps, identity, resource, query) {
    if (!identity)
        return { status: 401, body: { error: { code: 'unauthorized', message: '未登录' } } };
    if (!canAccessDept(identity))
        return { status: 403, body: { error: { code: 'forbidden', message: '需要部门主管身份' } } };
    const rules = await deps.listRules();
    const scope = deriveScope(identity, rules);
    if (resource === 'usage') {
        const range = query.get('range') ?? undefined; // 只读 range
        const overview = scope.projectIds.length === 0
            ? emptyDeptOverview(deps.tenantId)
            : await getUsageOverview(deps.usage, { range, projectIds: scope.projectIds });
        return { status: 200, body: { ...overview, scope } };
    }
    if (resource === 'alerts') {
        const severity = query.get('severity') ?? undefined;
        const limit = query.get('limit') ?? undefined;
        const cursor = query.get('cursor') ?? undefined;
        const result = scope.projectIds.length === 0
            ? EMPTY_DEPT_ALERTS
            : await getAlerts(deps.alerts, { severity, limit, cursor, projectIds: scope.projectIds });
        return { status: 200, body: { ...result, scope } };
    }
    return { status: 404, body: { error: { code: 'not_found', message: '未知主管接口' } } };
}
