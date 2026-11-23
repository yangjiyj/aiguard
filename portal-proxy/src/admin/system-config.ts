import { AdminError } from './errors.js';
// DB 配置键：网关用户打通开关。value 存字面量 "true"/"false"（缺记录＝关）。
export const GATEWAY_USER_SYNC_KEY = 'gateway_user_sync_enabled';
export class SystemConfigStore {
    prisma;
    envAllowed;
    tenantId;
    cacheTtlMs;
    // 进程内短 TTL 缓存：{value, at(ms)}。null＝未缓存。
    cache = null;
    constructor(prisma, 
    // env 部署级门（config.userSyncAllowed）。启动期定死，运行时不变。
    envAllowed, 
    // 多租户预留：单租户下恒为 cfg.tenantId（tenant_default）。
    tenantId = 'tenant_default', 
    // DB 读缓存 TTL（毫秒），默认 5s。
    cacheTtlMs = 5000) {
        this.prisma = prisma;
        this.envAllowed = envAllowed;
        this.tenantId = tenantId;
        this.cacheTtlMs = cacheTtlMs;
    }
    key(k) {
        return { tenantId_key: { tenantId: this.tenantId, key: k } };
    }
    /** 读 DB 开关（短 TTL 缓存）。无记录 → false（默认关）。仅 value==="true" 视为开。 */
    async getDbEnabled() {
        const now = Date.now();
        if (this.cache && now - this.cache.at < this.cacheTtlMs)
            return this.cache.value;
        const rec = await this.prisma.portalSystemConfig.findUnique({ where: this.key(GATEWAY_USER_SYNC_KEY) });
        const value = rec?.value === 'true';
        this.cache = { value, at: now };
        return value;
    }
    /**
     * 合成开关（jit.ts 读）：env 放行 AND DB 配置开。
     * env 未放行时短路 false——连 DB 都不读，且即便 DB 遗留 true 也一律当关（双闸铁律）。
     */
    async isGatewayUserSyncEnabled() {
        if (!this.envAllowed)
            return false;
        return this.getDbEnabled();
    }
    /**
     * 写 DB 开关（后台 PUT 调）。双层门：env 未放行时**拒绝开启**（返回明确"部署未放行"）；
     * 关闭永远允许（哪怕 env 未放行，也允许把遗留的 true 关掉）。写后立即刷新缓存。
     */
    async setGatewayUserSyncEnabled(value) {
        if (value && !this.envAllowed) {
            throw new AdminError('gateway_user_sync_not_allowed', '当前部署未放行网关用户打通（PORTAL_GATEWAY_USER_SYNC_ALLOWED 未开）；请先在部署环境放行后再开启', 409);
        }
        const v = value ? 'true' : 'false';
        await this.prisma.portalSystemConfig.upsert({
            where: this.key(GATEWAY_USER_SYNC_KEY),
            update: { value: v },
            create: { tenantId: this.tenantId, key: GATEWAY_USER_SYNC_KEY, value: v },
        });
        this.cache = { value, at: Date.now() };
    }
    /** 已打通员工数：EmployeeKey.gatewayUserId 非空计数（同租户）。 */
    async countSyncedEmployees() {
        return this.prisma.employeeKey.count({
            where: { tenantId: this.tenantId, gatewayUserId: { not: null } },
        });
    }
    /** 后台展示视图：env/db/合成生效 + 已打通员工数。 */
    async view() {
        const [dbEnabled, syncedEmployeeCount] = await Promise.all([
            this.getDbEnabled(),
            this.countSyncedEmployees(),
        ]);
        return {
            gatewayUserSync: {
                envAllowed: this.envAllowed,
                dbEnabled,
                effective: this.envAllowed && dbEnabled,
                syncedEmployeeCount,
            },
        };
    }
}
