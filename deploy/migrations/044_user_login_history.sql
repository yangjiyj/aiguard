-- 044_user_login_history.sql
CREATE TABLE IF NOT EXISTS user_login_history (
    id BIGSERIAL PRIMARY KEY,
    user_id VARCHAR(64) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    logged_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    ip VARCHAR(64),
    user_agent VARCHAR(512),
    success BOOLEAN NOT NULL DEFAULT TRUE,
    failure_reason VARCHAR(128)
);
CREATE INDEX IF NOT EXISTS idx_login_user ON user_login_history(user_id, logged_at DESC);

ALTER TABLE users ADD COLUMN IF NOT EXISTS last_login_at TIMESTAMP WITH TIME ZONE;
COMMENT ON COLUMN users.last_login_at IS 'last successful login time, synced from user_login_history';
