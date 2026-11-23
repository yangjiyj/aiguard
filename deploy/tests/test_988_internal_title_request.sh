#!/usr/bin/env bash
# 仅供显式指定的可丢弃测试库使用；不读取生产配置，不启动数据库。
set -euo pipefail
: "${INTERNAL_TITLE_MIGRATION_TEST_DATABASE_URL:?请指定可丢弃测试库连接串}"
repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
fixture_schema="internal_title_988_${$}_${RANDOM}"
psql_test() { psql -X "$INTERNAL_TITLE_MIGRATION_TEST_DATABASE_URL" -v ON_ERROR_STOP=1 "$@"; }
psql_test -c "CREATE SCHEMA $fixture_schema"
trap 'psql_test -c "DROP SCHEMA IF EXISTS $fixture_schema CASCADE"' EXIT
export PGOPTIONS="-c search_path=$fixture_schema"
psql_test <<'SQL'
CREATE TABLE request_logs (id text PRIMARY KEY, created_at timestamptz NOT NULL DEFAULT now());
INSERT INTO request_logs(id) VALUES ('历史请求');
SQL
psql_test -f "$repo_root/deploy/migrations/988_internal_title_request.sql"
psql_test <<'SQL'
DO $$ BEGIN
 IF NOT EXISTS (SELECT 1 FROM request_logs WHERE id='历史请求' AND internal_title_request IS NULL) THEN RAISE EXCEPTION '历史数据必须保留为未判定'; END IF;
 IF NOT EXISTS (SELECT 1 FROM pg_indexes WHERE schemaname=current_schema() AND indexname='idx_request_logs_internal_title_pending' AND indexdef LIKE '%WHERE (internal_title_request IS NULL)%') THEN RAISE EXCEPTION '缺少待回填部分索引'; END IF;
END $$;
INSERT INTO request_logs(id, internal_title_request) VALUES ('内部',true),('普通',false),('待判定',NULL);
SQL
psql_test -f "$repo_root/deploy/migrations/rollback/988_internal_title_request.sql"
psql_test <<'SQL'
DO $$ BEGIN
 IF (SELECT count(*) FROM request_logs) <> 4 THEN RAISE EXCEPTION '回滚不得丢失请求'; END IF;
 IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema=current_schema() AND table_name='request_logs' AND column_name='internal_title_request') THEN RAISE EXCEPTION '派生列未移除'; END IF;
END $$;
SQL
