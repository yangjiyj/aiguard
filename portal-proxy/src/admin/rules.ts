import { AdminError } from './errors.js';
type RuleInput = {
    matchType?: unknown;
    matchValue?: unknown;
    mappedGroup?: unknown;
    gatewayProjectId?: unknown;
    priority?: unknown;
    enabled?: unknown;
};
type RuleUpdate = {
    matchType?: string;
    matchValue?: string;
    mappedGroup?: string;
    gatewayProjectId?: string;
    priority?: number;
    enabled?: boolean;
};
function reqStr(obj: RuleInput, key: keyof RuleInput) {
    const v = obj[key];
    if (typeof v !== 'string' || v.trim() === '') {
        throw new AdminError('invalid_request', `字段 ${key} 必填且须为非空字符串`);
    }
    return v.trim();
}
function optPriority(v) {
    if (v === undefined || v === null)
        return 100;
    const n = typeof v === 'number' ? v : Number(v);
    if (!Number.isInteger(n) || n < 0) {
        throw new AdminError('invalid_request', '字段 priority 须为非负整数');
    }
    return n;
}
function optEnabled(v) {
    if (v === undefined || v === null)
        return true;
    if (typeof v !== 'boolean') {
        throw new AdminError('invalid_request', '字段 enabled 须为布尔值');
    }
    return v;
}
/** 建规则入参校验+归一（缺字段/类型错 → AdminError 400）。 */
export function normalizeCreateRule(input) {
    if (typeof input !== 'object' || input === null) {
        throw new AdminError('invalid_request', '请求体须为 JSON 对象');
    }
    const obj = input as RuleInput;
    const matchType = obj.matchType === undefined ? 'department' : reqStr(obj, 'matchType');
    if (matchType !== 'department') {
        // 目前仅支持按部门；显式拒绝未知 matchType，避免建出永不命中的死规则
        throw new AdminError('invalid_request', "目前 matchType 仅支持 'department'");
    }
    return {
        matchType,
        matchValue: reqStr(obj, 'matchValue'),
        mappedGroup: reqStr(obj, 'mappedGroup'),
        gatewayProjectId: reqStr(obj, 'gatewayProjectId'),
        priority: optPriority(obj.priority),
        enabled: optEnabled(obj.enabled),
    };
}
/** 改规则入参校验：至少一个可改字段；仅校验出现的字段。 */
export function normalizeUpdateRule(input) {
    if (typeof input !== 'object' || input === null) {
        throw new AdminError('invalid_request', '请求体须为 JSON 对象');
    }
    const obj = input as RuleInput;
    const out: RuleUpdate = {};
    if (obj.matchType !== undefined) {
        const mt = reqStr(obj, 'matchType');
        if (mt !== 'department')
            throw new AdminError('invalid_request', "目前 matchType 仅支持 'department'");
        out.matchType = mt;
    }
    if (obj.matchValue !== undefined)
        out.matchValue = reqStr(obj, 'matchValue');
    if (obj.mappedGroup !== undefined)
        out.mappedGroup = reqStr(obj, 'mappedGroup');
    if (obj.gatewayProjectId !== undefined)
        out.gatewayProjectId = reqStr(obj, 'gatewayProjectId');
    if (obj.priority !== undefined)
        out.priority = optPriority(obj.priority);
    if (obj.enabled !== undefined)
        out.enabled = optEnabled(obj.enabled);
    if (Object.keys(out).length === 0) {
        throw new AdminError('invalid_request', '未提供任何可修改字段');
    }
    return out;
}
export function toRuleView(r) {
    return {
        id: r.id,
        matchType: r.matchType,
        matchValue: r.matchValue,
        mappedGroup: r.mappedGroup,
        gatewayProjectId: r.gatewayProjectId,
        priority: r.priority,
        enabled: r.enabled,
        createdAt: r.createdAt.toISOString(),
        updatedAt: r.updatedAt.toISOString(),
    };
}
export class AdminRules {
    prisma;
    tenantId;
    constructor(prisma, 
    // 多租户预留（Phase 3 Track C）：建规则时 stamp tenantId（单租户下 ≡ cfg.tenantId）。
    tenantId = 'tenant_default') {
        this.prisma = prisma;
        this.tenantId = tenantId;
    }
    async list() {
        const rows = await this.prisma.groupMappingRule.findMany({ orderBy: [{ priority: 'asc' }, { createdAt: 'asc' }] });
        return rows.map(toRuleView);
    }
    async create(input) {
        const data = normalizeCreateRule(input);
        const rec = await this.prisma.groupMappingRule.create({ data: { ...data, tenantId: this.tenantId } });
        return toRuleView(rec);
    }
    async update(id, input) {
        const data = normalizeUpdateRule(input);
        const existing = await this.prisma.groupMappingRule.findUnique({ where: { id } });
        if (!existing)
            throw new AdminError('not_found', '规则不存在', 404);
        const rec = await this.prisma.groupMappingRule.update({ where: { id }, data });
        return toRuleView(rec);
    }
    async remove(id) {
        const existing = await this.prisma.groupMappingRule.findUnique({ where: { id } });
        if (!existing)
            throw new AdminError('not_found', '规则不存在', 404);
        await this.prisma.groupMappingRule.delete({ where: { id } });
    }
}
