BEGIN;
-- 先回退应用版本，再删除语料扫描任务表；不触及任何业务表与审计记录。
-- 留存卷里 corpus/<tenant>/<job>/ 下的报告和副本由应用清理，回滚后可手工删除该目录。
DROP TABLE IF EXISTS corpus_scan_jobs;
COMMIT;
