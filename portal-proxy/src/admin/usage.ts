/** 无法经 GroupMappingRule 反查到部门的 project 归入此桶（中文，绝不露原始英文/裸 id）。 */
export const UNMAPPED_DEPARTMENT_LABEL = '未映射部门';
/**
 * 部门 rollup 纯函数（可 TDD）：usage 行 project_id → 经 GroupMappingRule 反查其归属部门（matchValue）→ 按部门聚合。
 * - 反查表 project_id→department：只认 enabled 的 department 规则，priority 升序首个胜出（与 evaluateGroup 同序，冲突稳定）。
 * - 无命中规则的 project → 归入 UNMAPPED_DEPARTMENT_LABEL（绝不丢数据）。
 * - 结果按 totalCost 降序、部门名升序（确定性）。
 */
export function rollupUsageByDepartment(rows, rules) {
    const proj2dept = new Map();
    const ordered = [...rules].filter((r) => r.enabled && r.matchType === 'department').sort((a, b) => a.priority - b.priority);
    for (const r of ordered) {
        if (!proj2dept.has(r.gatewayProjectId))
            proj2dept.set(r.gatewayProjectId, r.matchValue);
    }
    const acc = new Map();
    for (const row of rows) {
        const dept = proj2dept.get(row.projectId) ?? UNMAPPED_DEPARTMENT_LABEL;
        let e = acc.get(dept);
        if (!e) {
            e = { department: dept, requests: 0, totalTokens: 0, totalCost: 0, projectIds: new Set() };
            acc.set(dept, e);
        }
        e.requests += row.requests;
        e.totalTokens += row.totalTokens;
        e.totalCost += row.totalCost;
        e.projectIds.add(row.projectId);
    }
    return [...acc.values()]
        .map((e) => ({
        department: e.department,
        requests: e.requests,
        totalTokens: e.totalTokens,
        totalCost: e.totalCost,
        projectIds: [...e.projectIds].sort(),
    }))
        .sort((a, b) => b.totalCost - a.totalCost || a.department.localeCompare(b.department));
}
const RANGE_DAYS = { '7d': 7, '14d': 14, '30d': 30, '90d': 90 };
function ymd(d) {
    const p = (n) => String(n).padStart(2, '0');
    return `${d.getUTCFullYear()}-${p(d.getUTCMonth() + 1)}-${p(d.getUTCDate())}`;
}
/**
 * range → {start_date,end_date}（YYYY-MM-DD，UTC）。未知/缺省返回 {}，交由网关默认近 30 天。
 * now 可注入以便确定性测试。
 */
export function resolveRange(range, now = new Date()) {
    const days = range ? RANGE_DAYS[range] : undefined;
    if (!days)
        return {};
    const start = new Date(now.getTime() - (days - 1) * 86400000);
    return { startDate: ymd(start), endDate: ymd(now) };
}
export async function getUsageOverview(deps, query) {
    const range = resolveRange(query.range);
    // 全局管理：query.projectIds 恒 undefined（全租户）。主管路径：中间件按 department→projectIds 注入，
    // 服务端下推 Gate0 的 project_ids 收窄——收窄点在此，客户端参数无从干预。
    const projectIds = query.projectIds && query.projectIds.length > 0 ? query.projectIds : undefined;
    const q = { startDate: range.startDate, endDate: range.endDate, projectIds };
    const [topline, trend, byModel, byKey, rules] = await Promise.all([
        deps.getUsageSummary(q),
        deps.getUsageTrend(q),
        deps.getUsageByModel(q),
        deps.getUsageByKey(q),
        deps.listRules(),
    ]);
    const byDepartment = rollupUsageByDepartment(byKey.map((k) => ({ projectId: k.projectId, requests: k.requests, totalTokens: k.totalTokens, totalCost: k.totalCost })), rules);
    return { topline, trend, byModel, byDepartment };
}
