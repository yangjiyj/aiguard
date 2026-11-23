// JIT 签发与换组迁移：未知 lobeUserId → 查 LobeHub 用户表拿 email → 调网关 portal-integration
// 开员工专属 key（挂到评估出的分组 project）；换组时 revoke 旧 key + 建新 key 到新 project。
// 单一内存锁按 lobeUserId 合并并发（首签竞态 + 换组重复迁移都靠它），成功失败都释放。
import { DEFAULT_GROUP } from './evaluate.js';
export class JitError extends Error {
    code;
    constructor(code, message) {
        super(message);
        this.code = code;
        this.name = 'JitError';
    }
}
/** 打通失败分级：优先取错误携带的 reason（gateway.ts PortalUserSyncError），否则归为 gateway_error。 */
function reasonOf(e) {
    const r = e?.reason;
    return typeof r === 'string' ? r : 'gateway_error';
}
export class JitProvisioner {
    deps;
    ttlDays;
    fallbackProjectId;
    scopeVersion;
    // 单一内存锁：provision 与 migrate 同 key 互斥（用户「有无 key」状态单调，二者天然不并发）。
    inflight = new Map();
    constructor(deps, ttlDays = 90, fallbackProjectId = 'project_default', 
    // Phase4 B6：新签 key stamp 的 scope 版本（server 传 gateway.ts 的 SCOPE_VERSION）。
    scopeVersion = 1) {
        this.deps = deps;
        this.ttlDays = ttlDays;
        this.fallbackProjectId = fallbackProjectId;
        this.scopeVersion = scopeVersion;
    }
    /**
     * 打通开关 ON 且有 ssoSubject 时，幂等建/查网关 user + 解析 team（全 best-effort，绝不抛出）。
     * 任一步失败该项置 null 并回调 onUserSyncFailed；existingUserId 非空（migrate/resign）则复用不重建。
     * team 解析仅在拿到 userId 后进行（无 user 挂 team 无意义）。
     */
    async resolveUserAndTeam(params) {
        const { lobeUserId, email, ssoSubject, group, existingUserId } = params;
        const d = this.deps;
        // 开关关 / 未注入依赖 / 无 SSO sub → 不打通，保留已存绑定（provision 时 existingUserId=null＝现状）。
        if (!d.ensureGatewayUser || !d.isUserSyncEnabled)
            return { gatewayUserId: existingUserId, teamId: null };
        let enabled = false;
        try {
            enabled = await d.isUserSyncEnabled();
        }
        catch {
            enabled = false; // 开关判定异常＝保守当关，绝不误开撑爆配额
        }
        if (!enabled || !ssoSubject)
            return { gatewayUserId: existingUserId, teamId: null };
        // 建/查 user（复用已存 userId 则跳过——migrate/resign 同一员工幂等）
        let gatewayUserId = existingUserId;
        if (!gatewayUserId) {
            try {
                const u = await d.ensureGatewayUser({ externalSubject: ssoSubject, email });
                gatewayUserId = u.userId;
            }
            catch (e) {
                gatewayUserId = null; // 降级：无 user → key 不绑、后续不挂 team
                d.onUserSyncFailed?.(lobeUserId, reasonOf(e), e);
            }
        }
        // 解析 team（独立 best-effort；仅在有 user 时才有意义）
        let teamId = null;
        if (gatewayUserId && d.resolveTeamId) {
            try {
                teamId = await d.resolveTeamId(group);
            }
            catch (e) {
                teamId = null;
                d.onUserSyncFailed?.(lobeUserId, reasonOf(e), e);
            }
        }
        return { gatewayUserId, teamId };
    }
    /** 挂 team 成员（best-effort）：失败仅回调告警，绝不清 gatewayUserId（user 已打通，部门挂载可下次补）。 */
    async attachMembership(lobeUserId, teamId, gatewayUserId) {
        if (!teamId || !gatewayUserId || !this.deps.ensureTeamMember)
            return;
        try {
            await this.deps.ensureTeamMember(teamId, gatewayUserId);
        }
        catch (e) {
            this.deps.onUserSyncFailed?.(lobeUserId, reasonOf(e), e);
        }
    }
    /** 按 lobeUserId 合并并发的单飞执行器（复用同一把锁）。 */
    single(lobeUserId, fn) {
        const existing = this.inflight.get(lobeUserId);
        if (existing)
            return existing; // 并发合并：等同一个结果
        const task = fn().finally(() => {
            this.inflight.delete(lobeUserId); // 成功失败都释放锁
        });
        this.inflight.set(lobeUserId, task);
        return task;
    }
    /** 首次 JIT：按评估出的 assignment 决定初始 project（不再恒 project_default）。 */
    provision(lobeUserId, assignment, department) {
        return this.single(lobeUserId, () => this.doProvision(lobeUserId, assignment, department ?? null));
    }
    async doProvision(lobeUserId, assignment, department) {
        const identity = await this.deps.lookupEmployee(lobeUserId);
        if (!identity) {
            throw new JitError('unknown_user', `lobeUserId ${lobeUserId} 在 LobeHub 用户表中不存在`);
        }
        const group = assignment ?? { mappedGroup: DEFAULT_GROUP, gatewayProjectId: this.fallbackProjectId };
        const expiresAt = new Date(Date.now() + this.ttlDays * 86400000).toISOString();
        // Phase4 打通（best-effort，绝不抛出）：开关 ON 时建 user + 解析 team；失败降级 gatewayUserId=null 走现状。
        const { gatewayUserId, teamId } = await this.resolveUserAndTeam({
            lobeUserId,
            email: identity.email,
            ssoSubject: identity.ssoSubject,
            group,
            existingUserId: null,
        });
        let created;
        try {
            // key 绑到网关 user（拿到 userId 才带；没有则不带＝现状）——建 key 失败仍是唯一的 provision_failed 路径。
            created = await this.deps.createGatewayKey({ name: identity.email, expiresAt, projectId: group.gatewayProjectId, userId: gatewayUserId ?? undefined });
        }
        catch (e) {
            throw new JitError('provision_failed', `网关签发员工 key 失败：${e instanceof Error ? e.message : String(e)}`);
        }
        // 挂 team（best-effort，在 key 落库前——失败不清 userId、不断 chat）
        await this.attachMembership(lobeUserId, teamId, gatewayUserId);
        await this.deps.saveEmployeeKey({
            lobeUserId,
            email: identity.email,
            ssoSubject: identity.ssoSubject,
            gatewayKeyId: created.id,
            keyPrefix: created.keyPrefix,
            fullKey: created.fullKey,
            expiresAt,
            mappedGroup: group.mappedGroup,
            gatewayProjectId: group.gatewayProjectId,
            lastDepartment: department,
            gatewayUserId,
            scopeVersion: this.scopeVersion,
        });
        return {
            fullKey: created.fullKey,
            email: identity.email,
            gatewayKeyId: created.id,
            keyPrefix: created.keyPrefix,
        };
    }
    /**
     * 换组迁移：目标 project 与当前不同才重建。锁内二次读当前 project 做双检，
     * 命中并发已迁移/同组则只续期 markEvaluated。建新 key 失败保守抛错、绝不先吊旧 key。
     */
    migrate(lobeUserId, target) {
        return this.single(lobeUserId, () => this.doMigrate(lobeUserId, target));
    }
    async doMigrate(lobeUserId, target) {
        if (!this.deps.getStoredKey || !this.deps.markEvaluated) {
            throw new JitError('provision_failed', 'migrate 未注入 getStoredKey/markEvaluated 依赖');
        }
        const current = await this.deps.getStoredKey(lobeUserId);
        if (!current) {
            return { migrated: false, reason: 'no_current_key' };
        }
        if (current.gatewayProjectId === target.gatewayProjectId) {
            // 同组 或 并发已迁移：不动 key，仅刷新分组/department/评估时刻
            await this.deps.markEvaluated(lobeUserId, {
                mappedGroup: target.mappedGroup,
                gatewayProjectId: target.gatewayProjectId,
                department: target.department,
            });
            return { migrated: false, reason: 'already' };
        }
        // Phase4 打通（best-effort）：复用已存 gatewayUserId 不重建；解析新组的 team。失败降级不断链。
        const { gatewayUserId, teamId } = await this.resolveUserAndTeam({
            lobeUserId,
            email: current.email,
            ssoSubject: current.ssoSubject,
            group: { mappedGroup: target.mappedGroup, gatewayProjectId: target.gatewayProjectId },
            existingUserId: current.gatewayUserId,
        });
        // 建新 key 到目标 project（失败抛错，调用方保守续用旧 key）
        const expiresAt = new Date(Date.now() + this.ttlDays * 86400000).toISOString();
        let created;
        try {
            created = await this.deps.createGatewayKey({ name: current.email, expiresAt, projectId: target.gatewayProjectId, userId: gatewayUserId ?? undefined });
        }
        catch (e) {
            throw new JitError('provision_failed', `换组建新 key 失败：${e instanceof Error ? e.message : String(e)}`);
        }
        // 先落库切到新 key（主链此后即读新 key），再挂 team、吊销旧 key
        await this.deps.saveEmployeeKey({
            lobeUserId,
            email: current.email,
            ssoSubject: current.ssoSubject,
            gatewayKeyId: created.id,
            keyPrefix: created.keyPrefix,
            fullKey: created.fullKey,
            expiresAt,
            mappedGroup: target.mappedGroup,
            gatewayProjectId: target.gatewayProjectId,
            lastDepartment: target.department,
            gatewayUserId,
            scopeVersion: this.scopeVersion,
        });
        // 挂新组 team（best-effort，不断链）
        await this.attachMembership(lobeUserId, teamId, gatewayUserId);
        // 吊销旧 key：best-effort，失败仅回调告警（新 key 已生效，不回滚；旧 key 至多留到过期）
        if (this.deps.revokeGatewayKey) {
            try {
                await this.deps.revokeGatewayKey(current.gatewayKeyId);
            }
            catch (e) {
                this.deps.onRevokeFailed?.(current.gatewayKeyId, e);
            }
        }
        return { migrated: true };
    }
    /**
     * Phase4 B6 scope 漂移治本：存量 key 的 scopeVersion < 当前则重签自愈（同换组逻辑：建新 key + 吊旧）。
     * 与 provision/migrate 复用同一把单飞锁；同 project 保留分组/部门/user 绑定，只为补全 scope（不再 401）。
     */
    resignScope(lobeUserId) {
        return this.single(lobeUserId, () => this.doResignScope(lobeUserId));
    }
    async doResignScope(lobeUserId) {
        if (!this.deps.getStoredKey) {
            throw new JitError('provision_failed', 'resignScope 未注入 getStoredKey 依赖');
        }
        const current = await this.deps.getStoredKey(lobeUserId);
        if (!current)
            return { resigned: false, reason: 'no_current_key' };
        // 锁内二次判定：并发已被别的 resign 治愈则直接跳过（幂等）。
        if (current.scopeVersion >= this.scopeVersion)
            return { resigned: false, reason: 'up_to_date' };
        if (!current.gatewayProjectId)
            return { resigned: false, reason: 'no_project' };
        const projectId = current.gatewayProjectId;
        const expiresAt = new Date(Date.now() + this.ttlDays * 86400000).toISOString();
        let created;
        try {
            // 同 project、保留 user 绑定；仅换取带全 scope 的新 key。失败保守抛错、绝不先吊旧 key。
            created = await this.deps.createGatewayKey({ name: current.email, expiresAt, projectId, userId: current.gatewayUserId ?? undefined });
        }
        catch (e) {
            throw new JitError('provision_failed', `scope 重签建新 key 失败：${e instanceof Error ? e.message : String(e)}`);
        }
        await this.deps.saveEmployeeKey({
            lobeUserId,
            email: current.email,
            ssoSubject: current.ssoSubject,
            gatewayKeyId: created.id,
            keyPrefix: created.keyPrefix,
            fullKey: created.fullKey,
            expiresAt,
            mappedGroup: current.mappedGroup ?? DEFAULT_GROUP,
            gatewayProjectId: projectId,
            lastDepartment: current.lastDepartment,
            gatewayUserId: current.gatewayUserId,
            scopeVersion: this.scopeVersion,
        });
        if (this.deps.revokeGatewayKey) {
            try {
                await this.deps.revokeGatewayKey(current.gatewayKeyId);
            }
            catch (e) {
                this.deps.onRevokeFailed?.(current.gatewayKeyId, e);
            }
        }
        return { resigned: true };
    }
}
