#!/usr/bin/env bash
# 仅供显式指定的可丢弃测试库使用：库必须已按完整迁移链初始化（含 001 初始化与全部迁移）。
# 用法：SEMANTIC_MIGRATION_TEST_DATABASE_URL=postgres://... bash deploy/tests/test_995_semantic_context_capability.sh
# 验证 995 迁移幂等、回滚只删未被引用的上下文语义能力（被引用则跳过并提示）、回滚后可再次迁移。
set -euo pipefail
: "${SEMANTIC_MIGRATION_TEST_DATABASE_URL:?请指定可丢弃测试库连接串}"
repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
migration="$repo_root/deploy/migrations/995_semantic_context_capability.sql"
rollback="$repo_root/deploy/migrations/rollback/995_semantic_context_capability.sql"
psql_test() { psql -X "$SEMANTIC_MIGRATION_TEST_DATABASE_URL" -v ON_ERROR_STOP=1 "$@"; }
semantic_count() {
  psql_test -Atc "SELECT COUNT(*) FROM security_capabilities WHERE component='security-engine.semantic'"
}
expect_count() {
  local want="$1" step="$2" got
  got=$(semantic_count)
  if [ "$got" != "$want" ]; then
    echo "$step：语义能力数 $got，期望 $want" >&2; exit 1
  fi
  echo "$step：语义能力数 $got"
}

# 升级与回滚都不改写策略
! grep -Eiq '^[[:space:]]*(UPDATE|DELETE)[[:space:]]' "$migration"
! grep -Eiq '^[[:space:]]*UPDATE[[:space:]]' "$rollback"

cleanup() {
  psql_test -q <<'SQL' >/dev/null
DELETE FROM rule_capability_bindings WHERE rule_id LIKE 'rule_995_%';
DELETE FROM rules WHERE rule_set_id LIKE 'rs_995_%';
DELETE FROM rule_sets WHERE id LIKE 'rs_995_%';
DELETE FROM tenants WHERE id LIKE 't_995_%';
SQL
}
trap cleanup EXIT
cleanup

# 完整迁移链已含 995：先回滚到 994 的目录状态
psql_test -q -f "$rollback" >/dev/null
expect_count 7 "回滚到迁移前"

# 迁移执行两次，验证幂等
psql_test -q -f "$migration" >/dev/null
psql_test -q -f "$migration" >/dev/null
expect_count 8 "迁移两次后"
[ "$(psql_test -Atc "SELECT supported_stages::text || allowed_actions::text FROM security_capabilities WHERE id='cap.dynamic.prompt_input_semantic_risk'")" = '["input"]["audit", "block"]' ]

# 回滚
psql_test -q -f "$rollback" >/dev/null
expect_count 7 "回滚后"

# 再前滚
psql_test -q -f "$migration" >/dev/null
expect_count 8 "再前滚后"

# 被策略引用时回滚明确跳过并提示，策略绑定保持完整
psql_test -q <<'SQL'
INSERT INTO tenants(id, name) VALUES ('t_995_a','a');
INSERT INTO rule_sets(id, tenant_id, name, source_type, published) VALUES ('rs_995_a','t_995_a','默认安全策略','system',true);
INSERT INTO rules(id, rule_set_id, rule_type, name, severity, action, enabled, scope_json)
VALUES ('rule_995_bound','rs_995_a','prompt_injection','上下文语义拦截','high','audit',true,'{"semantic_action":"block"}');
INSERT INTO rule_capability_bindings(rule_id, capability_id, binding_mode, priority, config_json)
VALUES ('rule_995_bound','cap.dynamic.prompt_input_semantic_risk','any',1,'{}');
SQL
notice=$(psql_test -q -f "$rollback" 2>&1 >/dev/null || true)
case "$notice" in
  *"已跳过删除"*) echo "被引用时回滚提示：$notice" ;;
  *) echo "被引用时回滚未给出跳过说明：$notice" >&2; exit 1 ;;
esac
expect_count 8 "被引用时回滚"
[ "$(psql_test -Atc "SELECT COUNT(*) FROM rule_capability_bindings WHERE rule_id='rule_995_bound'")" = 1 ]

# 解除引用后可正常回滚、再前滚
psql_test -q -c "DELETE FROM rule_capability_bindings WHERE rule_id='rule_995_bound'" >/dev/null
psql_test -q -f "$rollback" >/dev/null
expect_count 7 "解除引用后回滚"
psql_test -q -f "$migration" >/dev/null
expect_count 8 "最终前滚"
echo "test_995_semantic_context_capability: ok"
