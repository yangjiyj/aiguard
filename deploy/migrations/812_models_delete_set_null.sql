-- 812_models_delete_set_null.sql
-- +goose Up
-- 让「模型路由 / 模型管理」能真正删除失效模型，而不是因历史日志外键阻塞被降级为「停用保留」。
--
-- 背景：models 被 4 张表引用，其中两个是 NO ACTION，会阻塞 DELETE：
--   request_logs.model_id       (NO ACTION) -> 改 ON DELETE SET NULL（保留审计日志）
--   proxy_usage_daily.model_id  (NO ACTION) -> 改 ON DELETE CASCADE
--       该列是主键 (date, model_id) 的一部分，不能置 NULL；这张表是按天聚合的派生数据，
--       可从明细重算，随模型一并删除是安全的。
--   team_models.model_id        已是 CASCADE，无需改
--   models.downgrade_to         已是 SET NULL，无需改
--
-- 为什么 request_logs 用置空而不是删日志：审计与合规必须留存。
--   - request_logs 另有 original_model_id（客户端请求时的模型名文本），置空 model_id
--     后仍可追溯这条调用打的是哪个模型。
--   - 真正的计费事实在 billing_usage_facts，它自带 model_name/model_id 快照，
--     不通过外键指向 models，完全不受本迁移影响。
-- 因此删除模型目录记录后，历史审计与账单明细都还在，只是不再关联已删除的目录行。

ALTER TABLE request_logs
  DROP CONSTRAINT IF EXISTS request_logs_model_id_fkey;
ALTER TABLE request_logs
  ADD CONSTRAINT request_logs_model_id_fkey
  FOREIGN KEY (model_id) REFERENCES models(id) ON DELETE SET NULL;

ALTER TABLE proxy_usage_daily
  DROP CONSTRAINT IF EXISTS proxy_usage_daily_model_id_fkey;
ALTER TABLE proxy_usage_daily
  ADD CONSTRAINT proxy_usage_daily_model_id_fkey
  FOREIGN KEY (model_id) REFERENCES models(id) ON DELETE CASCADE;

-- +goose Down
-- 回滚：恢复 NO ACTION。若期间已产生 request_logs.model_id IS NULL 的行，
-- 恢复后这些行仍合法（该列本身允许 NULL），不影响回滚。
ALTER TABLE request_logs
  DROP CONSTRAINT IF EXISTS request_logs_model_id_fkey;
ALTER TABLE request_logs
  ADD CONSTRAINT request_logs_model_id_fkey
  FOREIGN KEY (model_id) REFERENCES models(id);

ALTER TABLE proxy_usage_daily
  DROP CONSTRAINT IF EXISTS proxy_usage_daily_model_id_fkey;
ALTER TABLE proxy_usage_daily
  ADD CONSTRAINT proxy_usage_daily_model_id_fkey
  FOREIGN KEY (model_id) REFERENCES models(id);
