-- 046_teams_budget.sql
-- Add monthly/daily budget columns to teams table
ALTER TABLE teams ADD COLUMN IF NOT EXISTS monthly_budget_cny DECIMAL(18,2) NOT NULL DEFAULT 0;
ALTER TABLE teams ADD COLUMN IF NOT EXISTS daily_budget_cny DECIMAL(18,2) NOT NULL DEFAULT 0;
COMMENT ON COLUMN teams.monthly_budget_cny IS '部门月度预算（CNY），0=无限制';
COMMENT ON COLUMN teams.daily_budget_cny IS '部门日度预算（CNY），0=无限制';
