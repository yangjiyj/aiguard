// 分组评估纯函数：department claim → {mappedGroup, gatewayProjectId}。
// 规则来自 GroupMappingRule 表；按 priority 升序取首个 enabled 且 matchType=department、
// matchValue==department 的命中；无命中（含 department=null）走 default 组，
// gatewayProjectId = env PORTAL_DEFAULT_PROJECT_ID（由调用方传入 defaultProjectId）。
// 保持纯函数、无 IO，便于 TDD。
export const DEFAULT_GROUP = 'default';
/**
 * 选出命中规则（不含 default 兜底）：department 为空或无命中返回 null。
 * evaluateGroup 与后台「测试映射」共用此单一判定，避免逻辑分叉。
 */
export function matchRule(department, rules) {
    if (!department)
        return null;
    const hit = rules
        .filter((r) => r.enabled && r.matchType === 'department' && r.matchValue === department)
        .sort((a, b) => a.priority - b.priority)[0];
    return hit ?? null;
}
export function evaluateGroup(department, rules, defaultProjectId) {
    const hit = matchRule(department, rules);
    if (hit) {
        return { mappedGroup: hit.mappedGroup, gatewayProjectId: hit.gatewayProjectId };
    }
    return { mappedGroup: DEFAULT_GROUP, gatewayProjectId: defaultProjectId };
}
