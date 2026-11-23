// 三级角色解析与部门主管 scope 派生（Phase 3 Track D）。纯函数、无 IO，便于 TDD。
// 角色来源优先级（用户拍板）：OIDC role claim 优先 → EmployeeRole 表回落 → 默认 employee。
// SCOPE（部门）永远来自 OIDC department claim / EmployeeRole.managedDepartments，服务端强制，
// 绝不接受请求参数传部门——这是「主管不得拿整租户裸行」安全铁律的落点。
import { matchRule } from './evaluate.js';
// 权限从低到高排序，供数组型 role claim 取最高权。
const ROLE_RANK = { employee: 0, manager: 1, admin: 2 };
export const ROLES = ['employee', 'manager', 'admin'];
/** 校验并归一为合法 Role，非法/缺失 → null。 */
export function normalizeRole(v) {
    return typeof v === 'string' && ROLES.includes(v) ? v : null;
}
/**
 * 从 id_token 声明里解出 role claim（可选覆盖源）。
 * 支持三种形态：单值字符串 `role`；数组 `role`；Keycloak 默认 `realm_access.roles` 数组。
 * 多个合法角色时取最高权（admin > manager > employee）。无合法角色 → null（交由表回落）。
 */
export function extractRoleClaim(claims) {
    if (!claims)
        return null;
    const single = normalizeRole(claims.role);
    if (single)
        return single;
    let arr = [];
    if (Array.isArray(claims.role))
        arr = claims.role;
    else if (Array.isArray(claims.roles))
        arr = claims.roles;
    else {
        const ra = claims.realm_access;
        if (ra && typeof ra === 'object' && Array.isArray(ra.roles)) {
            arr = ra.roles;
        }
    }
    const found = arr.map(normalizeRole).filter((r) => r !== null);
    if (found.length === 0)
        return null;
    return found.sort((a, b) => ROLE_RANK[b] - ROLE_RANK[a])[0];
}
/** 角色解析：claim 优先 → 表回落 → 默认 employee。 */
export function resolveRole(claimRole, dbRole) {
    return normalizeRole(claimRole) ?? normalizeRole(dbRole) ?? 'employee';
}
/** EmployeeRole.managedDepartments（JSON 字符串数组）→ string[]，任何异常一律空数组。 */
export function parseManagedDepartments(json) {
    if (typeof json !== 'string' || json.trim() === '')
        return [];
    try {
        const v = JSON.parse(json);
        return Array.isArray(v) ? v.filter((x) => typeof x === 'string' && x.trim() !== '') : [];
    }
    catch {
        return [];
    }
}
/**
 * 部门主管的受管部门集合（scope 源）：
 * - managedDepartments 非空 → 以其为准（去空白、去重）；
 * - 否则回落到本人 OIDC department claim（主管默认管自己部门）；
 * - 都无 → 空数组（→ 无 project → 主管看不到任何数据，绝不放大到全租户）。
 * 绝不读取任何请求参数。
 */
export function resolveManagerDepartments(ownDepartment, managedDepartments) {
    const cleaned = managedDepartments.map((d) => (typeof d === 'string' ? d.trim() : '')).filter(Boolean);
    if (cleaned.length > 0)
        return [...new Set(cleaned)];
    if (typeof ownDepartment === 'string' && ownDepartment.trim() !== '')
        return [ownDepartment.trim()];
    return [];
}
/**
 * 部门集合 → 网关 projectIds（经 GroupMappingRule 反查，与 evaluateGroup 同一 matchRule 判定，冲突稳定）。
 * 未命中规则的部门被丢弃（无对应 project）。结果去重升序。
 * 这是主管路径下推 Gate0 `project_ids` 的唯一来源——收窄点在服务端，客户端无从干预。
 */
export function departmentsToProjectIds(departments, rules) {
    const ids = new Set();
    for (const dept of departments) {
        const hit = matchRule(dept, rules);
        if (hit && hit.gatewayProjectId)
            ids.add(hit.gatewayProjectId);
    }
    return [...ids].sort();
}
/** /admin/api/*（全局管理）：仅 admin（含 break-glass 超管）。 */
export function canAccessAdmin(identity) {
    return !!identity && identity.role === 'admin';
}
/** /portal/dept/*（部门主管 scoped）：仅 manager（admin 走全局，不占用 scoped 路径）。 */
export function canAccessDept(identity) {
    return !!identity && identity.role === 'manager';
}
