-- 1001_request_logs_retention_summary_columns: 留存完整汇总的预算列（2.9.22 批次 7）。
--
-- 留存概览的完整汇总每一行都要展开输入/输出审计结果和安全事件的 finding 取风险原因，并读正文判断
-- “有没有请求正文 / 响应正文”。客户现场关掉 JIT 后 30 天窗口仍要 22.5 秒：取风险原因 12.6 秒、
-- 读正文判断 7.6 秒。这里把三项预算成 request_logs 上的列，与已有的 risk_state / has_retained_content
-- 同一套机制维护：控制面启动时分批回填，之后每 2 分钟刷新最近 15 分钟窗口（吸收晚到的安全事件与留存）。
-- 读路径一律 COALESCE(预算列, 原表达式)：列还没算出来的行照旧实时计算，结果不变。
--
-- 只加可空列、不带默认值，PostgreSQL 只改目录不重写表。
-- 回滚：deploy/migrations/rollback/1001_request_logs_retention_summary_columns.sql。

ALTER TABLE request_logs
    ADD COLUMN IF NOT EXISTS risk_reasons jsonb,
    ADD COLUMN IF NOT EXISTS request_body_exists boolean,
    ADD COLUMN IF NOT EXISTS response_body_exists boolean;
