#!/usr/bin/env bash
# 仅供显式指定的可丢弃测试库使用；不读取生产配置，不启动数据库。
set -euo pipefail
: "${OPS_DIAG_MIGRATION_TEST_DATABASE_URL:?请指定可丢弃测试库连接串}"
repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
fixture_schema="ops_diag_989_${$}_${RANDOM}"
psql_test() { psql -X "$OPS_DIAG_MIGRATION_TEST_DATABASE_URL" -v ON_ERROR_STOP=1 "$@"; }
psql_test -c "CREATE SCHEMA $fixture_schema"
trap 'psql_test -c "DROP SCHEMA IF EXISTS $fixture_schema CASCADE"' EXIT
export PGOPTIONS="-c search_path=$fixture_schema"
psql_test <<'SQL'
CREATE TABLE audit_operations (id text PRIMARY KEY, action_type text);
INSERT INTO audit_operations VALUES ('a1', 'diagnostics_run');
SQL
# 执行两次，验证幂等
psql_test -f "$repo_root/deploy/migrations/989_ops_diagnostics.sql"
psql_test -f "$repo_root/deploy/migrations/989_ops_diagnostics.sql"
psql_test <<'SQL'
DO $$ BEGIN
 IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema=current_schema() AND table_name='diag_sessions' AND column_name='steps_json' AND data_type='jsonb') THEN RAISE EXCEPTION '缺少 steps_json 列'; END IF;
 IF NOT EXISTS (SELECT 1 FROM pg_indexes WHERE schemaname=current_schema() AND indexname='idx_diag_sessions_user') THEN RAISE EXCEPTION '缺少用户索引'; END IF;
 IF NOT EXISTS (SELECT 1 FROM pg_indexes WHERE schemaname=current_schema() AND indexname='idx_diag_sessions_created') THEN RAISE EXCEPTION '缺少清理索引'; END IF;
END $$;
INSERT INTO diag_settings(tenant_id) VALUES ('t1');
INSERT INTO diag_sessions(id, tenant_id, user_id, is_admin, input_json, status) VALUES ('s1','t1','u1',true,'{"kind":"health"}','running');
DO $$ BEGIN
 IF (SELECT ai_enabled FROM diag_settings WHERE tenant_id='t1') IS NOT TRUE THEN RAISE EXCEPTION 'ai_enabled 默认应为 true'; END IF;
 IF (SELECT messages_json FROM diag_sessions WHERE id='s1') <> '[]'::jsonb THEN RAISE EXCEPTION 'messages_json 默认应为空数组'; END IF;
END $$;
SQL
psql_test -f "$repo_root/deploy/migrations/rollback/989_ops_diagnostics.sql"
psql_test -f "$repo_root/deploy/migrations/rollback/989_ops_diagnostics.sql"
psql_test <<'SQL'
DO $$ BEGIN
 IF to_regclass('diag_sessions') IS NOT NULL OR to_regclass('diag_settings') IS NOT NULL THEN RAISE EXCEPTION '诊断表未移除'; END IF;
 IF (SELECT count(*) FROM audit_operations) <> 1 THEN RAISE EXCEPTION '回滚不得影响审计记录'; END IF;
END $$;
SQL
# 回滚后可再次迁移
psql_test -f "$repo_root/deploy/migrations/989_ops_diagnostics.sql"
echo "test_989_ops_diagnostics: ok"
