-- 048_users_personal_budget.sql
-- Add optional personal monthly budget cap for users (must be <= team budget)
ALTER TABLE users ADD COLUMN IF NOT EXISTS personal_monthly_budget_cny DECIMAL(18,2);
COMMENT ON COLUMN users.personal_monthly_budget_cny IS '个人月度预算上限（CNY，NULL=只受部门约束）';
