-- 049_app_settings.sql — 极简部署级 KV 设置（首用：组织称谓可配置）
CREATE TABLE IF NOT EXISTS app_settings (
    key        VARCHAR(128) PRIMARY KEY,
    value      TEXT NOT NULL,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

INSERT INTO app_settings (key, value) VALUES
    ('org_tier1_label', '单位'),
    ('org_tier2_label', '部门')
ON CONFLICT (key) DO NOTHING;
