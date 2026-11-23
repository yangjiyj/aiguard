-- 098_secret_flow_first_seen.sql
-- secret 首见登记表：记录某租户下「密钥内容指纹 × 目的地主机」首次被观测到的时间。
-- 告警桥（control-plane secevent_bridge）用它做 novelty 判定：重复的 (指纹,目的地) 流动
-- 折叠进告警组、不再进收件箱/不通知；新密钥或旧密钥流向新目的地照常提升。
-- 开关 SECEVENT_SECRET_NOVELTY_ENABLED（默认关）。只作用于收件箱/通知层，
-- security_events 留证不受任何影响。
-- 指纹取 finding.matched_text_preview_sha256（引擎已算好的内容哈希），
-- 目的地取事件 matched_summary 顶层 target_host（正向代理路径特征；gateway/反代
-- finding 无 sha256，自然不参与）。

CREATE TABLE IF NOT EXISTS secret_flow_first_seen (
    tenant_id VARCHAR(64) NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    secret_fp VARCHAR(128) NOT NULL,
    target_host VARCHAR(255) NOT NULL,
    first_seen_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, secret_fp, target_host)
);

COMMENT ON TABLE secret_flow_first_seen IS '密钥流动首见登记（租户×指纹×目的地），供告警桥 secret novelty 首见告警使用';
COMMENT ON COLUMN secret_flow_first_seen.secret_fp IS 'finding.matched_text_preview_sha256（密钥内容指纹）';
COMMENT ON COLUMN secret_flow_first_seen.target_host IS '事件 matched_summary 顶层 target_host（流量目的地主机）';
