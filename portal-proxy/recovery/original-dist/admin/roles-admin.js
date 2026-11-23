import { AdminError } from './errors.js';
import { normalizeRole, parseManagedDepartments } from '../roles.js';
export function toRoleView(r) {
    return {
        id: r.id,
        tenantId: r.tenantId,
        subject: r.subject,
        email: r.email,
        role: (normalizeRole(r.role) ?? 'employee'),
        managedDepartments: parseManagedDepartments(r.managedDepartments),
        createdAt: r.createdAt.toISOString(),
        updatedAt: r.updatedAt.toISOString(),
    };
}
function reqStr(obj, key) {
    const v = obj[key];
    if (typeof v !== 'string' || v.trim() === '') {
        throw new AdminError('invalid_request', `字段 ${key} 必填且须为非空字符串`);
    }
    return v.trim();
}
/**
 * 指派/更新角色入参校验+归一：
 * - subject（OIDC sub）、email 必填；role 缺省 employee，非法枚举 400；
 * - managedDepartments 可选，须为字符串数组（去空白去重）；仅 manager 有意义（其他角色忽略其值）。
 */
export function normalizeUpsertRole(input) {
    if (typeof input !== 'object' || input === null) {
        throw new AdminError('invalid_request', '请求体须为 JSON 对象');
    }
    const obj = input;
    const subject = reqStr(obj, 'subject');
    const email = reqStr(obj, 'email');
    let role = 'employee';
    if (obj.role !== undefined && obj.role !== null && obj.role !== '') {
        const r = normalizeRole(obj.role);
        if (!r)
            throw new AdminError('invalid_request', "字段 role 仅支持 'employee' | 'manager' | 'admin'");
        role = r;
    }
    let managedDepartments = [];
    if (obj.managedDepartments !== undefined && obj.managedDepartments !== null) {
        if (!Array.isArray(obj.managedDepartments)) {
            throw new AdminError('invalid_request', '字段 managedDepartments 须为字符串数组');
        }
        const cleaned = obj.managedDepartments
            .map((d) => (typeof d === 'string' ? d.trim() : ''))
            .filter((d) => d !== '');
        managedDepartments = [...new Set(cleaned)];
    }
    return { subject, email, role, managedDepartments };
}
export class RoleStore {
    prisma;
    tenantId;
    constructor(prisma, tenantId = 'tenant_default') {
        this.prisma = prisma;
        this.tenantId = tenantId;
    }
    key(subject) {
        return { tenantId_subject: { tenantId: this.tenantId, subject } };
    }
    async list() {
        const rows = await this.prisma.employeeRole.findMany({ orderBy: [{ createdAt: 'asc' }] });
        return rows.map(toRoleView);
    }
    /** 幂等指派：同 (tenantId, subject) 存在则更新，否则新建。 */
    async upsert(input) {
        const data = normalizeUpsertRole(input);
        const fields = {
            email: data.email,
            role: data.role,
            managedDepartments: JSON.stringify(data.managedDepartments),
        };
        const rec = await this.prisma.employeeRole.upsert({
            where: this.key(data.subject),
            update: fields,
            create: { tenantId: this.tenantId, subject: data.subject, ...fields },
        });
        return toRoleView(rec);
    }
    async remove(subject) {
        const existing = await this.prisma.employeeRole.findUnique({ where: this.key(subject) });
        if (!existing)
            throw new AdminError('not_found', '角色指派不存在', 404);
        await this.prisma.employeeRole.delete({ where: this.key(subject) });
    }
    /** 运行时角色查询（表回落源）：无记录 → null（→ resolveRole 默认 employee）。 */
    async findBySubject(subject) {
        const rec = await this.prisma.employeeRole.findUnique({ where: this.key(subject) });
        if (!rec)
            return null;
        return {
            role: normalizeRole(rec.role) ?? 'employee',
            managedDepartments: parseManagedDepartments(rec.managedDepartments),
        };
    }
}
