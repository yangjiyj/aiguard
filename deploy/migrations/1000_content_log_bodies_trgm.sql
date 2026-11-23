-- +goose NO TRANSACTION
-- 1000_content_log_bodies_trgm: 去重正文表的关键字检索索引（2.9.22 批次 7）。
--
-- 留存关键字检索对 content_log_bodies 做 ILIKE '%关键字%'。旧正文表 content_logs_legacy 早有
-- trigram 索引（076），去重后的新正文表没有，客户现场 7.4 万条正文每次全表 ILIKE 加正则要 3.2 秒。
-- 3 个字符及以上的关键字由控制面把 ILIKE 放在客户正文判定之前，计划可直接走本索引；不足 3 个字符的
-- 关键字 trigram 抽不出词元，控制面保持原来的顺序扫描写法，不会走本索引。
--
-- CONCURRENTLY 不阻塞正文写入，必须在事务外执行（见上方 goose 指令，执行器据此不包事务）。
-- 中断重跑：建到一半失败会留下无效索引，IF NOT EXISTS 会跳过它；所以先删掉无效的同名索引再建。
-- 回滚：deploy/migrations/rollback/1000_content_log_bodies_trgm.sql。

CREATE EXTENSION IF NOT EXISTS pg_trgm;

DROP INDEX CONCURRENTLY IF EXISTS idx_content_log_bodies_content_trgm_invalid_guard;

DO $$
BEGIN
  IF EXISTS (
    SELECT 1 FROM pg_index i JOIN pg_class c ON c.oid = i.indexrelid
    WHERE c.relname = 'idx_content_log_bodies_content_trgm' AND NOT i.indisvalid
  ) THEN
    ALTER INDEX idx_content_log_bodies_content_trgm RENAME TO idx_content_log_bodies_content_trgm_invalid_guard;
  END IF;
END
$$;

DROP INDEX CONCURRENTLY IF EXISTS idx_content_log_bodies_content_trgm_invalid_guard;

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_content_log_bodies_content_trgm
    ON content_log_bodies USING gin (content gin_trgm_ops);
