#!/usr/bin/env bash
# 仅供显式指定的可丢弃测试库使用：库必须已按完整迁移链初始化（含 001 初始化与全部迁移）。
# 用法：SEMANTIC_MIGRATION_TEST_DATABASE_URL=postgres://... bash deploy/tests/test_993_semantic_policy_block.sh
# 验证 993 迁移幂等、回滚能清掉只含 semantic_action 的覆盖行并恢复旧约束、回滚后可再次迁移。
set -euo pipefail
: "${SEMANTIC_MIGRATION_TEST_DATABASE_URL:?请指定可丢弃测试库连接串}"
repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
migration="$repo_root/deploy/migrations/993_semantic_policy_block.sql"
rollback="$repo_root/deploy/migrations/rollback/993_semantic_policy_block.sql"
psql_test() { psql -X "$SEMANTIC_MIGRATION_TEST_DATABASE_URL" -v ON_ERROR_STOP=1 "$@"; }

# 升级不改写存量策略；新增 CHECK 用 NOT VALID + VALIDATE，避免长时间锁表
! grep -Eiq '^[[:space:]]*(UPDATE|DELETE)[[:space:]]' "$migration"
[ "$(grep -c 'NOT VALID' "$migration")" -ge 2 ]
[ "$(grep -c 'VALIDATE CONSTRAINT' "$migration")" -ge 2 ]

cleanup() {
  psql_test -q <<'SQL' >/dev/null
DELETE FROM builtin_rule_overrides WHERE tenant_id LIKE 't_993_%';
DELETE FROM rules WHERE rule_set_id LIKE 'rs_993_%';
DELETE FROM rule_sets WHERE id LIKE 'rs_993_%';
DELETE FROM tenants WHERE id LIKE 't_993_%';
SQL
}
trap cleanup EXIT
cleanup

# 迁移执行两次，验证幂等
psql_test -q -f "$migration" >/dev/null
psql_test -q -f "$migration" >/dev/null

psql_test -q <<'SQL'
INSERT INTO tenants(id, name) VALUES ('t_993_a','a');
INSERT INTO rule_sets(id, tenant_id, name, source_type, published) VALUES ('rs_993_a','t_993_a','默认安全策略','system',true);
INSERT INTO rules(id, rule_set_id, rule_type, name, severity, action, enabled, scope_json) VALUES
  ('rule_993_only','rs_993_a','content_safety','只改智能分析','medium','audit',true,'{}'),
  ('rule_993_mixed','rs_993_a','content_safety','改了动作也改智能分析','medium','audit',true,'{}'),
  ('rule_993_custom','rs_993_a','keyword','自建策略','medium','audit',true,'{"semantic_action":"block","keep":"x"}');
INSERT INTO builtin_rule_overrides(tenant_id, rule_id, action, semantic_action) VALUES
  ('t_993_a','rule_993_only',NULL,'block'),
  ('t_993_a','rule_993_mixed','block','observe');
SQL

# 新约束生效：非法取值被拒
if psql_test -q -c "UPDATE builtin_rule_overrides SET semantic_action='mask' WHERE rule_id='rule_993_mixed'" >/dev/null 2>&1; then
  echo "非法 semantic_action 未被约束拒绝" >&2; exit 1
fi

psql_test -q -f "$rollback" >/dev/null

psql_test -q <<'SQL'
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM information_schema.columns
             WHERE table_name='builtin_rule_overrides' AND column_name='semantic_action') THEN
    RAISE EXCEPTION '回滚后 semantic_action 列仍存在';
  END IF;
  IF EXISTS (SELECT 1 FROM builtin_rule_overrides WHERE rule_id='rule_993_only') THEN
    RAISE EXCEPTION '只含 semantic_action 的覆盖行应删除';
  END IF;
  IF (SELECT action FROM builtin_rule_overrides WHERE rule_id='rule_993_mixed') <> 'block' THEN
    RAISE EXCEPTION '含其它覆盖值的行应保留原动作';
  END IF;
  IF (SELECT scope_json FROM rules WHERE id='rule_993_custom') <> '{"keep":"x"}'::jsonb THEN
    RAISE EXCEPTION '自建策略 scope_json 只应去掉 semantic_action 键';
  END IF;
  IF pg_get_constraintdef((SELECT oid FROM pg_constraint WHERE conname='ck_builtin_rule_overrides_has_value'))
     LIKE '%semantic_action%' THEN
    RAISE EXCEPTION '旧约束未恢复';
  END IF;
  IF EXISTS (SELECT 1 FROM security_capabilities c
             WHERE c.metadata_json->>'catalog'='semantic_policy_block'
               AND NOT EXISTS (SELECT 1 FROM rule_capability_bindings b WHERE b.capability_id=c.id)) THEN
    RAISE EXCEPTION '未绑定的 993 能力目录行应删除';
  END IF;
END $$;
SQL

# 旧约束下全空覆盖行仍被拒
if psql_test -q -c "INSERT INTO builtin_rule_overrides(tenant_id, rule_id, action) VALUES ('t_993_a','rule_993_only',NULL)" >/dev/null 2>&1; then
  echo "回滚后全空覆盖行未被旧约束拒绝" >&2; exit 1
fi

# 回滚后可再次迁移、再次回滚
psql_test -q -f "$migration" >/dev/null
psql_test -q -c "INSERT INTO builtin_rule_overrides(tenant_id, rule_id, action, semantic_action) VALUES ('t_993_a','rule_993_only',NULL,'block')" >/dev/null
psql_test -q -f "$rollback" >/dev/null
psql_test -q -f "$migration" >/dev/null
echo "test_993_semantic_policy_block: ok"
