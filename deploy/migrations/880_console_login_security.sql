-- 880_console_login_security.sql
-- W3 控制台登录安全（等保三级）：失败事件留痕、密码历史、定期改密、TOTP。
-- 只做扩展（新增列/表/默认设置），不改已有数据的语义。
BEGIN;

-- 登录失败可能针对不存在的账号：允许 user_id 为空，并记录尝试的用户名与事件类型。
ALTER TABLE user_login_history ALTER COLUMN user_id DROP NOT NULL;
ALTER TABLE user_login_history ADD COLUMN IF NOT EXISTS attempted_username VARCHAR(255);
ALTER TABLE user_login_history ADD COLUMN IF NOT EXISTS event VARCHAR(32) NOT NULL DEFAULT 'login';
CREATE INDEX IF NOT EXISTS idx_login_history_logged_at ON user_login_history(logged_at DESC);

ALTER TABLE users ADD COLUMN IF NOT EXISTS password_changed_at TIMESTAMP WITH TIME ZONE;
ALTER TABLE users ADD COLUMN IF NOT EXISTS totp_secret_enc TEXT;
ALTER TABLE users ADD COLUMN IF NOT EXISTS totp_enabled BOOLEAN NOT NULL DEFAULT FALSE;
-- 已有账号从升级时刻起算定期改密周期，避免升级后所有管理员立即被强制改密。
UPDATE users SET password_changed_at = NOW()
 WHERE password_changed_at IS NULL AND COALESCE(password_hash, '') <> '';

CREATE TABLE IF NOT EXISTS user_password_history (
    id BIGSERIAL PRIMARY KEY,
    user_id VARCHAR(64) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    password_hash TEXT NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_user_password_history_user ON user_password_history(user_id, created_at DESC);

-- 默认值：已存在的键（管理员改过）不覆盖。
INSERT INTO system_settings (key, value, updated_at) VALUES
    ('console_login_lockout_threshold', '5', NOW()),
    ('console_login_lockout_minutes', '30', NOW()),
    ('console_password_min_length', '12', NOW()),
    ('console_password_min_classes', '3', NOW()),
    ('console_password_history_count', '5', NOW()),
    ('console_password_max_age_days', '90', NOW()),
    ('console_session_idle_minutes', '30', NOW()),
    ('console_session_absolute_hours', '12', NOW()),
    ('console_session_max_concurrent', '3', NOW()),
    ('console_admin_totp_required', 'false', NOW()),
    ('console_admin_ip_allowlist', '', NOW())
ON CONFLICT (key) DO NOTHING;

COMMIT;
