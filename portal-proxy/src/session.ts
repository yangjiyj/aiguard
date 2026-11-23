// 门户后台服务端会话（W9 9.6）。
// 旧实现把 id_token 原样放进 HttpOnly cookie、每请求 jose 校验：登出只清浏览器 cookie，
// 被窃取的 token 在 1 小时内仍然有效，服务端无法撤销。现改为：
// - 回调校验 id_token（签名/iss/aud/exp/nonce）通过后，签发不透明随机会话 ID 写 cookie；
// - 服务端只存会话 ID 的 SHA-256 摘要（库泄露也拿不到可用 cookie），带绝对过期与撤销时刻；
// - 登出 / 管理撤销 / IdP back-channel logout（按 sub 或 sid）立即生效。
// 会话只记录身份（sub/email/department/sid），不记录角色：角色每次请求都从 EmployeeRole 表实时读取。
import { createHash, randomBytes } from 'node:crypto';
export const SESSION_COOKIE = 'portal_session';
/** 新会话 ID：256 bit 随机，base64url。 */
export function newSessionId() {
    return randomBytes(32).toString('base64url');
}
/** 会话 ID → 存储键（SHA-256 hex）。 */
export function hashSessionId(id) {
    return createHash('sha256').update(id, 'utf8').digest('hex');
}
function isUsable(rec, now) {
    return !!rec && rec.revokedAt == null && rec.expiresAt.getTime() > now.getTime();
}
/** 进程内实现（测试与无持久化场景用）。 */
export class MemorySessionBackend {
    rows = new Map();
    async insert(rec) {
        this.rows.set(rec.idHash, { ...rec });
    }
    async find(idHash) {
        const r = this.rows.get(idHash);
        return r ? { ...r } : null;
    }
    async revoke(where, at) {
        let n = 0;
        for (const r of this.rows.values()) {
            if (r.revokedAt != null)
                continue;
            if (where.idHash !== undefined && r.idHash !== where.idHash)
                continue;
            if (where.subject !== undefined && r.subject !== where.subject)
                continue;
            if (where.idpSid !== undefined && r.idpSid !== where.idpSid)
                continue;
            if (where.tenantId !== undefined && r.tenantId !== where.tenantId)
                continue;
            r.revokedAt = at;
            n++;
        }
        return n;
    }
    async purge(before) {
        let n = 0;
        for (const [k, r] of this.rows) {
            if (r.expiresAt.getTime() < before.getTime() || (r.revokedAt != null && r.revokedAt.getTime() < before.getTime())) {
                this.rows.delete(k);
                n++;
            }
        }
        return n;
    }
}
/** Prisma（SQLite）实现：表 PortalSession。 */
export class PrismaSessionBackend {
    prisma;
    constructor(prisma) {
        this.prisma = prisma;
    }
    async insert(rec) {
        await this.prisma.portalSession.create({ data: rec });
    }
    async find(idHash) {
        return this.prisma.portalSession.findUnique({ where: { idHash } });
    }
    async revoke(where, at) {
        const filter: Record<string, unknown> = { revokedAt: null };
        for (const k of ['idHash', 'subject', 'idpSid', 'tenantId']) {
            if (where[k] !== undefined)
                filter[k] = where[k];
        }
        const r = await this.prisma.portalSession.updateMany({ where: filter, data: { revokedAt: at } });
        return r.count;
    }
    async purge(before) {
        const r = await this.prisma.portalSession.deleteMany({
            where: { OR: [{ expiresAt: { lt: before } }, { revokedAt: { lt: before } }] },
        });
        return r.count;
    }
}
export class SessionStore {
    backend;
    tenantId;
    ttlSec;
    now;
    constructor(backend, tenantId, ttlSec, now = () => new Date()) {
        this.backend = backend;
        this.tenantId = tenantId;
        this.ttlSec = ttlSec;
        this.now = now;
    }
    /**
     * 为已校验的身份签发会话，返回明文会话 ID（只进 Set-Cookie，不落库、不进日志）。
     * 过期取 min(ttlSec, id_token exp)：会话不会比 IdP 授予的登录寿命更长。
     */
    async create(identity) {
        if (typeof identity.sub !== 'string' || identity.sub === '')
            throw new Error('会话身份缺少 sub');
        const now = this.now();
        let expiresMs = now.getTime() + this.ttlSec * 1000;
        if (typeof identity.exp === 'number' && identity.exp * 1000 < expiresMs)
            expiresMs = identity.exp * 1000;
        const id = newSessionId();
        await this.backend.insert({
            idHash: hashSessionId(id),
            tenantId: this.tenantId,
            subject: identity.sub,
            email: identity.email ?? null,
            department: identity.department ?? null,
            idpSid: identity.sid ?? null,
            createdAt: now,
            expiresAt: new Date(expiresMs),
            revokedAt: null,
        });
        return { id, maxAgeSec: Math.max(0, Math.floor((expiresMs - now.getTime()) / 1000)) };
    }
    /** 明文会话 ID → 有效会话（未撤销、未过期、同租户）；否则 null。 */
    async resolve(id) {
        if (typeof id !== 'string' || id === '' || id.length > 256)
            return null;
        const rec = await this.backend.find(hashSessionId(id));
        if (!isUsable(rec, this.now()) || rec.tenantId !== this.tenantId)
            return null;
        return { subject: rec.subject, email: rec.email, department: rec.department, idpSid: rec.idpSid, expiresAt: rec.expiresAt };
    }
    /** 登出：撤销当前会话。 */
    async revoke(id) {
        if (typeof id !== 'string' || id === '')
            return 0;
        return this.backend.revoke({ idHash: hashSessionId(id), tenantId: this.tenantId }, this.now());
    }
    /** 撤销某用户全部会话（管理撤销 / back-channel logout 仅带 sub）。 */
    async revokeSubject(subject) {
        if (typeof subject !== 'string' || subject === '')
            return 0;
        return this.backend.revoke({ subject, tenantId: this.tenantId }, this.now());
    }
    /** 撤销某 IdP 会话派生的全部门户会话（back-channel logout 带 sid）。 */
    async revokeIdpSession(sid, subject) {
        if (typeof sid !== 'string' || sid === '')
            return 0;
        const where: Record<string, string> = { idpSid: sid, tenantId: this.tenantId };
        if (typeof subject === 'string' && subject !== '')
            where.subject = subject;
        return this.backend.revoke(where, this.now());
    }
    /** 清理过期/已撤销超过 retainSec 的行。 */
    async purge(retainSec = 86400) {
        return this.backend.purge(new Date(this.now().getTime() - retainSec * 1000));
    }
}
