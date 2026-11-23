// 只读查询 LobeHub 的 PG：users.id（即 body.user 的值）→ email；
// SSO subject 在 accounts 表（provider_id 非 credential 时 account_id 即 IdP sub）。
// Phase 2：另从 accounts.id_token（原始 JWT，每登录刷新）解出 department 供分组评估。
import pg from 'pg';
import { verifyDepartment } from './idtoken.js';
export class LobeDb {
    pool;
    deptVerify;
    // deptVerify：{ keySet, issuer }，accounts.id_token 验签所需（W9 9.6）。
    // 缺省时有 token 的部门查询一律失败 → 上层保守续用旧 key，不按未验签部门换组。
    constructor(connectionString, deptVerify = null) {
        this.pool = new pg.Pool({ connectionString, max: 3 });
        this.deptVerify = deptVerify;
    }
    async lookupEmployee(lobeUserId) {
        const users = await this.pool.query('SELECT email FROM users WHERE id = $1', [lobeUserId]);
        const email = users.rows[0]?.email;
        if (!email)
            return null; // 无此用户或无邮箱都无法归因，一律视作未知
        let ssoSubject = null;
        try {
            const accounts = await this.pool.query("SELECT account_id FROM accounts WHERE user_id = $1 AND provider_id <> 'credential' LIMIT 1", [lobeUserId]);
            ssoSubject = accounts.rows[0]?.account_id ?? null;
        }
        catch {
            // accounts 表结构变动不阻断主链，ssoSubject 允许为空
        }
        return { email, ssoSubject };
    }
    /**
     * 从 accounts.id_token 解出 department（分组评估上游）。
     * 防御语义：无 account / 无 id_token → 返回 null（走 default 组，合法归属）。
     * id_token 验签失败 / issuer 不符 → 抛 DepartmentTokenError，与 PG 异常同样按「查询失败」处理（W9 9.6）。
     * 但 PG 查询异常（如库不可达）会向上抛出——由 server 区别对待：不能因一次 DB 抖动
     * 把已归组员工误降到 default（换组会 revoke 旧 key），故查询失败走「保守不动旧 key」。
     * provider_id 固定 'generic-oidc'（dev Keycloak；生产换真实 IdP providerId 时同步此常量）。
     */
    async lookupDepartment(lobeUserId) {
        const res = await this.pool.query("SELECT id_token FROM accounts WHERE user_id = $1 AND provider_id = 'generic-oidc' LIMIT 1", [lobeUserId]);
        return verifyDepartment(res.rows[0]?.id_token ?? null, this.deptVerify);
    }
    async close() {
        await this.pool.end();
    }
}
