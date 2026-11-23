-- 953: 员工额度预占过期清理需要按创建时间扫描。
-- 只新增索引，不改表结构，也不改已有迁移；可在空库和现有库上重复执行。
-- billing_employee_reservations 只在请求在途期间存在行（最长约 35 分钟），表很小，普通事务内建索引即可。
CREATE INDEX IF NOT EXISTS idx_employee_reservations_created
    ON billing_employee_reservations (created_at);
