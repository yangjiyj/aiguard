export class RuleStore {
    prisma;
    fetchRemote;
    log;
    cache = null;
    ttlMs = 15000;
    constructor(prisma, fetchRemote, log) {
        this.prisma = prisma;
        this.fetchRemote = fetchRemote;
        this.log = log;
    }
    async list() {
        // 网关优先（带进程内短 TTL 缓存，避免每次登录同步打网关）；失败兜底 SQLite，绝不断登录。
        if (this.fetchRemote) {
            const now = Date.now();
            if (this.cache && now - this.cache.at < this.ttlMs)
                return this.cache.rules;
            try {
                const rules = await this.fetchRemote();
                this.cache = { at: now, rules };
                return rules;
            }
            catch (e) {
                this.log?.('warn', 'rules_remote_fallback_sqlite', { err: e instanceof Error ? e.message : String(e) });
                // fall through 兜底 SQLite
            }
        }
        return this.listLocal();
    }
    async listLocal() {
        const rows = await this.prisma.groupMappingRule.findMany({ orderBy: { priority: 'asc' } });
        return rows.map((r) => ({
            matchType: r.matchType,
            matchValue: r.matchValue,
            mappedGroup: r.mappedGroup,
            gatewayProjectId: r.gatewayProjectId,
            priority: r.priority,
            enabled: r.enabled,
        }));
    }
    /**
     * Phase4 阶段B：取某 project 的网关 team 绑定（priority 升序首个规则的 gatewayTeamId）。
     * 无规则（default 组）→ null；有规则但未绑 team → {gatewayTeamId:null}（调用方据此惰性建 team + 回填）。
     * 写路径相关，仍走本地 Prisma（B 本期只迁 list 读）。
     */
    async findTeamBinding(gatewayProjectId) {
        const row = await this.prisma.groupMappingRule.findFirst({
            where: { gatewayProjectId },
            orderBy: { priority: 'asc' },
        });
        if (!row)
            return null;
        return { gatewayTeamId: row.gatewayTeamId };
    }
    /** Phase4 阶段B：惰性回填——把新建 team 的 id 写进该 project 下所有尚未绑定的规则（幂等）。仍走本地 Prisma。 */
    async backfillGatewayTeamId(gatewayProjectId, teamId) {
        await this.prisma.groupMappingRule.updateMany({
            where: { gatewayProjectId, gatewayTeamId: null },
            data: { gatewayTeamId: teamId },
        });
    }
}
