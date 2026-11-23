-- deploy/migrations/rollback/1000_content_log_bodies_trgm.sql
-- 删除去重正文表的 trigram 索引；不删除 pg_trgm 扩展（076 的旧正文表索引仍依赖它）。
-- 回退后关键字检索恢复为顺序扫描，结果不变，只是变慢。
DROP INDEX CONCURRENTLY IF EXISTS idx_content_log_bodies_content_trgm;
