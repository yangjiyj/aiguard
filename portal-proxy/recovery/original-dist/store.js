import { decryptKey, encryptKey } from './crypto.js';
export class KeyStore {
    prisma;
    encSecret;
    tenantId;
    constructor(prisma, encSecret, 
    // 多租户预留：单租户下恒为 cfg.tenantId（tenant_default）。所有唯一读写据此定位记录。
    tenantId = 'tenant_default') {
        this.prisma = prisma;
        this.encSecret = encSecret;
        this.tenantId = tenantId;
    }
    /** 复合唯一选择器：(tenantId, lobeUserId) → Prisma 的 tenantId_lobeUserId。 */
    key(lobeUserId) {
        return { tenantId_lobeUserId: { tenantId: this.tenantId, lobeUserId } };
    }
    async findActive(lobeUserId) {
        const rec = await this.prisma.employeeKey.findUnique({ where: this.key(lobeUserId) });
        if (!rec || rec.status !== 'active')
            return null;
        return {
            fullKey: decryptKey(rec.keyEnc, this.encSecret),
            email: rec.email,
            ssoSubject: rec.ssoSubject,
            gatewayKeyId: rec.gatewayKeyId,
            keyPrefix: rec.keyPrefix,
            mappedGroup: rec.mappedGroup,
            gatewayProjectId: rec.gatewayProjectId,
            lastDepartment: rec.lastDepartment,
            lastEvaluatedAt: rec.lastEvaluatedAt,
            gatewayUserId: rec.gatewayUserId,
            scopeVersion: rec.scopeVersion,
        };
    }
    /** 换组/重签双检用：不解密 key，取 project/身份 + 已存 user 绑定/scope 版本 + 分组/部门（重签需保留）。 */
    async getStoredKey(lobeUserId) {
        const rec = await this.prisma.employeeKey.findUnique({ where: this.key(lobeUserId) });
        if (!rec || rec.status !== 'active')
            return null;
        return {
            gatewayKeyId: rec.gatewayKeyId,
            gatewayProjectId: rec.gatewayProjectId,
            email: rec.email,
            ssoSubject: rec.ssoSubject,
            gatewayUserId: rec.gatewayUserId,
            scopeVersion: rec.scopeVersion,
            mappedGroup: rec.mappedGroup,
            lastDepartment: rec.lastDepartment,
        };
    }
    async save(rec) {
        const keyEnc = encryptKey(rec.fullKey, this.encSecret);
        const fields = {
            email: rec.email,
            ssoSubject: rec.ssoSubject,
            gatewayKeyId: rec.gatewayKeyId,
            keyPrefix: rec.keyPrefix,
            keyEnc,
            status: 'active',
            mappedGroup: rec.mappedGroup,
            gatewayProjectId: rec.gatewayProjectId,
            lastDepartment: rec.lastDepartment,
            lastEvaluatedAt: new Date(),
            // Phase4 阶段B：开关关/降级时 gatewayUserId 未传→存 null（向后兼容）；scopeVersion 由签发方 stamp 当前版本。
            gatewayUserId: rec.gatewayUserId ?? null,
            scopeVersion: rec.scopeVersion,
        };
        await this.prisma.employeeKey.upsert({
            where: this.key(rec.lobeUserId),
            update: fields,
            // 多租户预留：新写入 stamp this.tenantId（≡ cfg.tenantId）。
            create: { tenantId: this.tenantId, lobeUserId: rec.lobeUserId, ...fields },
        });
    }
    /** 不换 key 时的评估续期：刷新分组/department/评估时刻（去抖用），不动 key 密文。 */
    async markEvaluated(lobeUserId, input) {
        await this.prisma.employeeKey.update({
            where: this.key(lobeUserId),
            data: {
                mappedGroup: input.mappedGroup,
                gatewayProjectId: input.gatewayProjectId,
                lastDepartment: input.department,
                lastEvaluatedAt: new Date(),
            },
        });
    }
    /** 记录最近使用时间，失败不影响主链。 */
    touch(lobeUserId) {
        void this.prisma.employeeKey
            .update({ where: this.key(lobeUserId), data: { lastUsedAt: new Date() } })
            .catch(() => { });
    }
}
