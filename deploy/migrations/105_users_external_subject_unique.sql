-- Phase4 A1：门户员工↔网关 user 打通的并发双建前置（P0）。
-- external_subject（SSO sub）在租户内唯一，作为门户惰性建 user 的幂等键。
-- 部分索引（WHERE external_subject IS NOT NULL）：现存 user 该列全 NULL，不受此约束影响；
-- 硬依赖：UserRepository.Create/Update 已改为对空 external_subject 写 NULL（NULLIF($n,'')），
-- 使常规「用户管理」建的 user 该列恒 NULL、不参与本索引——本迁移与该仓储改动必须同批上线，
-- 否则老代码直写空串 '' 会满足 IS NOT NULL，同租户第二个常规 user 即撞 23505 打断建用户功能；
-- 仅门户建的、带 external_subject 的 user 参与唯一性判定，杜绝并发双建（两次登录同时建同一 SSO 主体）。
-- 幂等：IF NOT EXISTS，可重复执行；加索引前请确认 external_subject 现无重复（当前生产该列全 NULL）。
CREATE UNIQUE INDEX IF NOT EXISTS uniq_users_tenant_external_subject
    ON users (tenant_id, external_subject)
    WHERE external_subject IS NOT NULL;
