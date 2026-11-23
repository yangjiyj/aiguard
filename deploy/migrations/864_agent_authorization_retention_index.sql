-- Bounded cleanup scans for old Agent authorization quota windows.
CREATE INDEX IF NOT EXISTS idx_agent_authorization_usage_window_start
    ON agent_authorization_usage (window_start);
