// S3.4 ai_models 对账（模型过滤「只看到」层）：按分组允许清单直写 LobeHub per-user ai_models 行，
// 允许模型 enabled=true、其余 enabled=false。独立只写连接池；失败由调用方降级（仅日志，不阻断 chat）。
// 红线：只碰 dev 栈 chatportal-postgres 的 lobehub 库（LOBE_DATABASE_URL）；provider_id 固定 openai
// （portal-proxy 对 LobeHub 暴露为 OpenAI 兼容 provider）。
// caveat：LobeHub 内置推荐模型不受本表控制、始终出现——「只看到」非气密，真正强制点是网关硬拒。
import pg from 'pg';
import { toAlias } from './model-alias.js';
export class LobeModelSync {
    pool;
    constructor(connectionString) {
        this.pool = new pg.Pool({ connectionString, max: 2 });
    }
    /**
     * 对账某 lobeUser 的 openai provider 模型可见性。
     * @param allowedModels 分组允许清单（enabled=true）
     * @param universeModels 全量模型名（不在允许清单内者写 enabled=false 以从下拉隐藏）
     */
    async reconcile(lobeUserId, allowedModels, universeModels) {
        const allowed = new Set(allowedModels);
        const all = Array.from(new Set([...universeModels, ...allowedModels]));
        if (all.length === 0)
            return { written: 0, enabled: 0 };
        const client = await this.pool.connect();
        try {
            let written = 0;
            let enabledCount = 0;
            for (const name of all) {
                const isEnabled = allowed.has(name);
                // OpenAI 目录模型（gpt-*/o*）用别名 id 承载，规避 LobeHub 强制 Responses API；显示名仍用真名（员工无感）。
                const catalogId = toAlias(name);
                await client.query(`INSERT INTO public.ai_models (id, provider_id, user_id, enabled, source, type, display_name)
           VALUES ($1, 'openai', $2, $3, 'custom', 'chat', $4)
           ON CONFLICT (id, provider_id, user_id) WHERE workspace_id IS NULL
           DO UPDATE SET enabled = EXCLUDED.enabled, display_name = EXCLUDED.display_name, updated_at = now()`, [catalogId, lobeUserId, isEnabled, name]);
                written += 1;
                if (isEnabled)
                    enabledCount += 1;
                // 别名后把未别名的真 id 行强制隐藏（清存量重复 + 旧的走 responses 的坏行）。
                if (catalogId !== name) {
                    await client.query(`INSERT INTO public.ai_models (id, provider_id, user_id, enabled, source, type, display_name)
             VALUES ($1, 'openai', $2, false, 'custom', 'chat', $1)
             ON CONFLICT (id, provider_id, user_id) WHERE workspace_id IS NULL
             DO UPDATE SET enabled = false, updated_at = now()`, [name, lobeUserId]);
                }
            }
            return { written, enabled: enabledCount };
        }
        finally {
            client.release();
        }
    }
    async close() {
        await this.pool.end();
    }
}
