#!/usr/bin/env bash
# 仅供显式指定的可丢弃测试库使用；不读取生产配置，不启动数据库。
set -euo pipefail
: "${CORPUS_SCAN_MIGRATION_TEST_DATABASE_URL:?请指定可丢弃测试库连接串}"
repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
fixture_schema="corpus_scan_990_${$}_${RANDOM}"
psql_test() { psql -X "$CORPUS_SCAN_MIGRATION_TEST_DATABASE_URL" -v ON_ERROR_STOP=1 "$@"; }
psql_test -c "CREATE SCHEMA $fixture_schema"
trap 'psql_test -c "DROP SCHEMA IF EXISTS $fixture_schema CASCADE"' EXIT
export PGOPTIONS="-c search_path=$fixture_schema"
psql_test <<'SQL'
CREATE TABLE audit_operations (id text PRIMARY KEY, action_type text);
INSERT INTO audit_operations VALUES ('a1', 'download_corpus_scan_masked');
SQL
# 执行两次，验证幂等
psql_test -f "$repo_root/deploy/migrations/990_corpus_scan_jobs.sql"
psql_test -f "$repo_root/deploy/migrations/990_corpus_scan_jobs.sql"
psql_test <<'SQL'
DO $$ BEGIN
 IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema=current_schema() AND table_name='corpus_scan_jobs' AND column_name='samples_json' AND data_type='jsonb') THEN RAISE EXCEPTION '缺少 samples_json 列'; END IF;
 IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema=current_schema() AND table_name='corpus_scan_jobs' AND column_name='lease_until') THEN RAISE EXCEPTION '缺少租约列'; END IF;
 IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema=current_schema() AND table_name='corpus_scan_jobs' AND column_name='source_keys' AND data_type='jsonb') THEN RAISE EXCEPTION '缺少分片对象列'; END IF;
 IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema=current_schema() AND table_name='corpus_scan_jobs' AND column_name='upload_hash_state' AND data_type='bytea') THEN RAISE EXCEPTION '缺少累计哈希列'; END IF;
 IF NOT EXISTS (SELECT 1 FROM pg_indexes WHERE schemaname=current_schema() AND indexname='idx_corpus_scan_jobs_tenant_created') THEN RAISE EXCEPTION '缺少租户列表索引'; END IF;
 IF NOT EXISTS (SELECT 1 FROM pg_indexes WHERE schemaname=current_schema() AND indexname='idx_corpus_scan_jobs_expires') THEN RAISE EXCEPTION '缺少过期清理索引'; END IF;
 IF NOT EXISTS (SELECT 1 FROM pg_indexes WHERE schemaname=current_schema() AND indexname='idx_corpus_scan_jobs_single_active') THEN RAISE EXCEPTION '缺少单任务约束'; END IF;
END $$;
INSERT INTO corpus_scan_jobs(id, tenant_id, created_by, file_name, format, size_bytes, sha256, status, expires_at)
VALUES ('j1','t1','u1','a.jsonl','jsonl',10,'00','uploading',NOW()+interval '7 days');
DO $$ BEGIN
 IF (SELECT stats_json FROM corpus_scan_jobs WHERE id='j1') <> '{}'::jsonb THEN RAISE EXCEPTION 'stats_json 默认应为空对象'; END IF;
 IF (SELECT samples_json FROM corpus_scan_jobs WHERE id='j1') <> '[]'::jsonb THEN RAISE EXCEPTION 'samples_json 默认应为空数组'; END IF;
 IF (SELECT source_keys FROM corpus_scan_jobs WHERE id='j1') <> '[]'::jsonb THEN RAISE EXCEPTION 'source_keys 默认应为空数组'; END IF;
 IF (SELECT cancel_requested FROM corpus_scan_jobs WHERE id='j1') IS NOT FALSE THEN RAISE EXCEPTION 'cancel_requested 默认应为 false'; END IF;
END $$;
-- 状态与格式只接受规格列出的取值
DO $$ BEGIN
 BEGIN
  INSERT INTO corpus_scan_jobs(id, tenant_id, created_by, file_name, format, size_bytes, sha256, status, expires_at)
  VALUES ('bad','t1','u1','a.exe','exe',10,'00','uploading',NOW());
  RAISE EXCEPTION '非法格式未被拒绝';
 EXCEPTION WHEN check_violation THEN NULL;
 END;
 BEGIN
  INSERT INTO corpus_scan_jobs(id, tenant_id, created_by, file_name, format, size_bytes, sha256, status, expires_at)
  VALUES ('bad','t1','u1','a.txt','txt',10,'00','done',NOW());
  RAISE EXCEPTION '非法状态未被拒绝';
 EXCEPTION WHEN check_violation THEN NULL;
 END;
END $$;
-- 全局同时只能有一个运行中的任务（跨租户）；排队的任务可以有多个
UPDATE corpus_scan_jobs SET status='running' WHERE id='j1';
INSERT INTO corpus_scan_jobs(id, tenant_id, created_by, file_name, format, size_bytes, sha256, status, expires_at)
VALUES ('j2','t2','u2','b.txt','txt',10,'00','queued',NOW()+interval '7 days');
INSERT INTO corpus_scan_jobs(id, tenant_id, created_by, file_name, format, size_bytes, sha256, status, expires_at)
VALUES ('j3','t3','u3','c.txt','txt',10,'00','queued',NOW()+interval '7 days');
DO $$ BEGIN
 BEGIN
  UPDATE corpus_scan_jobs SET status='running' WHERE id='j2';
  RAISE EXCEPTION '第二个运行中任务未被拒绝';
 EXCEPTION WHEN unique_violation THEN NULL;
 END;
END $$;
SQL
psql_test -f "$repo_root/deploy/migrations/rollback/990_corpus_scan_jobs.sql"
psql_test -f "$repo_root/deploy/migrations/rollback/990_corpus_scan_jobs.sql"
psql_test <<'SQL'
DO $$ BEGIN
 IF to_regclass('corpus_scan_jobs') IS NOT NULL THEN RAISE EXCEPTION '语料扫描表未移除'; END IF;
 IF (SELECT count(*) FROM audit_operations) <> 1 THEN RAISE EXCEPTION '回滚不得影响审计记录'; END IF;
END $$;
SQL
# 回滚后可再次迁移
psql_test -f "$repo_root/deploy/migrations/990_corpus_scan_jobs.sql"
echo "test_990_corpus_scan_jobs: ok"
