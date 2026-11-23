-- 090_usage_rollup_latency_count_first_priced.sql
-- +goose Up
-- 给 usage_rollup_hourly 补两列,让成本页 Provider(平均延迟)/Coverage(首个计费时间)也能读 rollup:
--   latency_count   = 桶内 latency_ms 非空的请求数(AVG 延迟的正确分母;原 latency_ms_sum/request_count
--                     会被 NULL 延迟零填稀释,实测 prov_local_qwen25 因此 2531.878 vs 真值 2532.827);
--   first_priced_at = 桶内首个已计费(total_cost 非空)请求的时间(成本可信起始日)。
-- 历史桶由 migration 844 注册的持久化后台任务重算；同步迁移只扩展
-- nullable/default-compatible schema，不再按 request_logs 规模阻塞启动。
ALTER TABLE usage_rollup_hourly
    ADD COLUMN IF NOT EXISTS latency_count   bigint NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS first_priced_at timestamptz;

-- +goose Down
ALTER TABLE usage_rollup_hourly
    DROP COLUMN IF EXISTS latency_count,
    DROP COLUMN IF EXISTS first_priced_at;
