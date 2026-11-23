// 三级角色解析与部门主管 scope 派生（Phase 3 Track D）。纯函数、无 IO，便于 TDD。
// 角色来源（W9 9.6）：只认 EmployeeRole 表 → 无记录默认 employee。
// 不再读取 id_token 的 role / roles / realm_access 声明：一旦 IdP 侧新增 roles mapper 或上游 IdP
// 透传用户可改的属性，claim 优先会让用户自授 admin。授权数据只由门户管理员在本服务内维护。
// SCOPE（部门）永远来自 OIDC department claim / EmployeeRole.managedDepartments，服务端强制，
// 绝不接受请求参数传部门——这是「主管不得拿整租户裸行」安全铁律的落点。
import { matchRule } from './evaluate.js';
export const ROLES = ['employee', 'manager', 'admin'];
/** 校验并归一为合法 Role，非法/缺失 → null。 */
export function normalizeRole(v) {
    return typeof v === 'string' && ROLES.includes(v) ? v : null;
}
/** 角色解析：EmployeeRole 表为唯一来源 → 缺失/非法默认 employee。 */
export function resolveRole(dbRole) {
    return normalizeRole(dbRole) ?? 'employee';
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
