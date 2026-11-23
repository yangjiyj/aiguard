#!/usr/bin/env bash
# 仅供显式指定的可丢弃测试库使用：库必须已按完整迁移链初始化。
# 用法：OVERRIDE_SEVERITY_TEST_DATABASE_URL=postgres://... bash deploy/tests/test_996_builtin_override_severity.sh
set -euo pipefail
: "${OVERRIDE_SEVERITY_TEST_DATABASE_URL:?请指定可丢弃测试库连接串}"
repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
migration="$repo_root/deploy/migrations/996_builtin_override_severity.sql"
rollback="$repo_root/deploy/migrations/rollback/996_builtin_override_severity.sql"
psql_test() { psql -X "$OVERRIDE_SEVERITY_TEST_DATABASE_URL" -v ON_ERROR_STOP=1 "$@"; }

! grep -v '^[[:space:]]*--' "$migration" | grep -Eiq '(^|[[:space:];])(UPDATE|DELETE[[:space:]]+FROM)[[:space:]]+"?[a-z_]+"?'
[ "$(grep -v '^[[:space:]]*--' "$migration" | grep -c 'NOT VALID')" -ge 2 ]
[ "$(grep -v '^[[:space:]]*--' "$migration" | grep -c 'VALIDATE CONSTRAINT')" -ge 2 ]

cleanup() {
  psql_test -q <<'SQL' >/dev/null
DELETE FROM builtin_rule_overrides WHERE tenant_id LIKE 't_996_%';
DELETE FROM rules WHERE rule_set_id LIKE 'rs_996_%';
DELETE FROM rule_sets WHERE id LIKE 'rs_996_%';
DELETE FROM tenants WHERE id LIKE 't_996_%';
SQL
}
trap cleanup EXIT
cleanup

psql_test -q -f "$migration" >/dev/null
psql_test -q -f "$migration" >/dev/null

psql_test -q <<'SQL'
INSERT INTO tenants(id, name) VALUES ('t_996_a','a');
INSERT INTO rule_sets(id, tenant_id, name, source_type, published) VALUES ('rs_996_a','t_996_a','默认安全策略','system',true);
INSERT INTO rules(id, rule_set_id, rule_type, name, severity, action, enabled, scope_json) VALUES
  ('rule_996_only','rs_996_a','code_security','只改级别','high','audit',true,'{}'),
  ('rule_996_mixed','rs_996_a','code_security','级别和动作都改','high','audit',true,'{}'),
  ('rule_996_empty','rs_996_a','code_security','无覆盖','high','audit',true,'{}');
INSERT INTO builtin_rule_overrides(tenant_id, rule_id, severity) VALUES ('t_996_a','rule_996_only','medium');
INSERT INTO builtin_rule_overrides(tenant_id, rule_id, action, severity) VALUES ('t_996_a','rule_996_mixed','block','critical');
SQL

psql_test -q <<'SQL'
DO $$
BEGIN
  IF (SELECT count(*) FROM pg_constraint
      WHERE conrelid='builtin_rule_overrides'::regclass
        AND conname IN ('ck_builtin_rule_overrides_severity','ck_builtin_rule_overrides_has_value')
        AND convalidated) <> 2 THEN
    RAISE EXCEPTION '迁移后 severity / has_value 约束缺失或未校验';
  END IF;
END $$;
SQL

if psql_test -q -c "INSERT INTO builtin_rule_overrides(tenant_id, rule_id) VALUES ('t_996_a','rule_996_empty')" >/dev/null 2>&1; then
  echo "迁移后全空覆盖行未被约束拒绝" >&2; exit 1
fi

if psql_test -q -c "UPDATE builtin_rule_overrides SET severity='urgent' WHERE rule_id='rule_996_mixed'" >/dev/null 2>&1; then
  echo "非法 severity 未被约束拒绝" >&2; exit 1
fi

psql_test -q -f "$rollback" >/dev/null

psql_test -q <<'SQL'
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM information_schema.columns
             WHERE table_name='builtin_rule_overrides' AND column_name='severity') THEN
    RAISE EXCEPTION '回滚后 severity 列仍存在';
  END IF;
  IF EXISTS (SELECT 1 FROM builtin_rule_overrides WHERE rule_id='rule_996_only') THEN
    RAISE EXCEPTION '只含 severity 的覆盖行应删除';
  END IF;
  IF (SELECT action FROM builtin_rule_overrides WHERE rule_id='rule_996_mixed') <> 'block' THEN
    RAISE EXCEPTION '含其它覆盖值的行应保留';
  END IF;
  IF COALESCE(pg_get_constraintdef((SELECT oid FROM pg_constraint
        WHERE conrelid='builtin_rule_overrides'::regclass AND conname='ck_builtin_rule_overrides_has_value')), '')
     NOT LIKE '%semantic_action%' THEN
    RAISE EXCEPTION '回滚后 has_value 约束缺失或不含 semantic_action';
  END IF;
  IF COALESCE(pg_get_constraintdef((SELECT oid FROM pg_constraint
        WHERE conrelid='builtin_rule_overrides'::regclass AND conname='ck_builtin_rule_overrides_has_value')), '')
     LIKE '%severity%' THEN
    RAISE EXCEPTION '回滚后 has_value 约束仍含 severity';
  END IF;
END $$;
SQL

if psql_test -q -c "INSERT INTO builtin_rule_overrides(tenant_id, rule_id) VALUES ('t_996_a','rule_996_empty')" >/dev/null 2>&1; then
  echo "回滚后全空覆盖行未被旧约束拒绝" >&2; exit 1
fi
psql_test -q -c "INSERT INTO builtin_rule_overrides(tenant_id, rule_id, semantic_action) VALUES ('t_996_a','rule_996_only','block')" >/dev/null

psql_test -q -f "$migration" >/dev/null
printf 'builtin_override_severity=ok\n'
