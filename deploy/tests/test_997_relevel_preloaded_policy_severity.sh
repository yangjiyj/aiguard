#!/usr/bin/env bash
# 仅供显式指定的可丢弃测试库使用：库必须先灌 deploy/docker-compose/initdb/001_init_enterprise.sql，再用 deploy/lib/migration-runner.sh 灌到 996 为止（不含 997）；
# 注意：initdb 脚本用 \i /migrations/... 绝对路径引用迁移，需在挂载了 /migrations 的容器里执行（或把迁移目录挂载到 /migrations）。
# 脚本会清理 schema_migrations 里 997 的记录并自行建删测试数据与备份表。
# 用法：RELEVEL_TEST_DATABASE_URL=postgres://... bash deploy/tests/test_997_relevel_preloaded_policy_severity.sh
set -euo pipefail
: "${RELEVEL_TEST_DATABASE_URL:?请指定可丢弃测试库连接串}"
repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
migration="$repo_root/deploy/migrations/997_relevel_preloaded_policy_severity.sql"
rollback="$repo_root/deploy/migrations/rollback/997_relevel_preloaded_policy_severity.sql"
psql_test() { psql -X "$RELEVEL_TEST_DATABASE_URL" -v ON_ERROR_STOP=1 "$@"; }

# 只允许改 rules.severity
# 静态检查：SET 子句只有 severity 一列；迁移里除 UPDATE rules 与备份表 INSERT 外没有别的写操作
awk '/^[[:space:]]*SET severity = relevel\.new_severity[[:space:]]*$/{f=1;next} f{if($0 ~ /^[[:space:]]*FROM relevel[[:space:]]*$/)ok=1;exit} END{exit !ok}' "$migration"
write_ops=$(grep -v '^[[:space:]]*--' "$migration" | tr '\n' ' ' \
  | grep -Eoi '(UPDATE|DELETE|INSERT|TRUNCATE|MERGE)([[:space:]]+(INTO|FROM))?[[:space:]]+"?[a-z_]+"?' | tr -s ' ' | tr 'A-Z' 'a-z')
[ "$write_ops" = "update rules
insert into policy_severity_relevel_backup" ]

cleanup() {
  psql_test -q <<'SQL' >/dev/null
DROP TABLE IF EXISTS policy_severity_relevel_backup;
DELETE FROM schema_migrations WHERE version='997_relevel_preloaded_policy_severity.sql';
DELETE FROM builtin_rule_overrides WHERE tenant_id LIKE 't_997_%';
DELETE FROM rules WHERE rule_set_id LIKE 'rs_997_%';
DELETE FROM rule_sets WHERE id LIKE 'rs_997_%';
DELETE FROM tenants WHERE id LIKE 't_997_%';
SQL
}
trap cleanup EXIT
cleanup

psql_test -q <<'SQL'
INSERT INTO tenants(id, name) VALUES ('t_997_a','a');
INSERT INTO rule_sets(id, tenant_id, name, source_type, published) VALUES ('rs_997_a','t_997_a','默认安全策略','system',true);
INSERT INTO rules(id, rule_set_id, policy_code, rule_type, name, severity, action, enabled, scope_json) VALUES
  ('rule_997_sql','rs_997_a','builtin.code_security.d82567ae4c6cba2a','code_security','SQL 注入代码生成','critical','block',true,'{}'),
  ('rule_997_manual','rs_997_a','builtin.code_security.46a74885f15123bb','code_security','XSS 代码生成','low','audit',true,'{}'),
  ('rule_997_cc','rs_997_a','builtin.agent_detect.f93768ab6617606e','agent_detect','Claude Code 管控','medium','audit',true,'{}'),
  ('rule_997_other','rs_997_a','builtin.code_security.not_in_list','code_security','不在清单内','high','audit',true,'{}'),
  ('rule_997_off','rs_997_a','builtin.dos_protection.26b5a56593b2a884','dos_protection','初始停用的清单内策略','high','block',false,'{}');
INSERT INTO builtin_rule_overrides(tenant_id, rule_id, severity) VALUES ('t_997_a','rule_997_sql','high');
SQL

psql_test -q -f "$migration" >/dev/null
psql_test -q -f "$migration" >/dev/null   # 重复执行结果不变

check_after_migration() {
  psql_test -q <<'SQL'
DO $$
BEGIN
  IF (SELECT severity FROM rules WHERE id='rule_997_sql') IS DISTINCT FROM 'medium' THEN RAISE EXCEPTION 'SQL 注入代码生成应改为中危'; END IF;
  IF (SELECT action FROM rules WHERE id='rule_997_sql') IS DISTINCT FROM 'block' THEN RAISE EXCEPTION '动作不能被改'; END IF;
  IF (SELECT severity FROM rules WHERE id='rule_997_manual') IS DISTINCT FROM 'low' THEN RAISE EXCEPTION '人工改过的级别不能被覆盖'; END IF;
  IF (SELECT severity FROM rules WHERE id='rule_997_cc') IS DISTINCT FROM 'low' THEN RAISE EXCEPTION 'Claude Code 管控应改为低危'; END IF;
  IF (SELECT enabled FROM rules WHERE id='rule_997_sql') IS DISTINCT FROM true THEN RAISE EXCEPTION 'SQL 注入代码生成的启用状态不能被改'; END IF;
  IF (SELECT enabled FROM rules WHERE id='rule_997_cc') IS DISTINCT FROM true THEN RAISE EXCEPTION 'Claude Code 管控的启用状态不能被改'; END IF;
  IF (SELECT severity FROM rules WHERE id='rule_997_off') IS DISTINCT FROM 'medium' THEN RAISE EXCEPTION '初始停用的清单内策略应改为中危'; END IF;
  IF (SELECT enabled FROM rules WHERE id='rule_997_off') IS DISTINCT FROM false THEN RAISE EXCEPTION '初始停用的策略不能被启用'; END IF;
  IF (SELECT action FROM rules WHERE id='rule_997_off') IS DISTINCT FROM 'block' THEN RAISE EXCEPTION '停用策略的动作不能被改'; END IF;
  IF (SELECT action FROM rules WHERE id='rule_997_cc') IS DISTINCT FROM 'audit' THEN RAISE EXCEPTION 'Claude Code 管控的动作不能被改'; END IF;
  IF (SELECT severity FROM rules WHERE id='rule_997_other') IS DISTINCT FROM 'high' THEN RAISE EXCEPTION '不在清单内的策略不能被改'; END IF;
  IF (SELECT severity FROM builtin_rule_overrides WHERE tenant_id='t_997_a' AND rule_id='rule_997_sql') IS DISTINCT FROM 'high' THEN RAISE EXCEPTION '租户覆盖级别不能被改'; END IF;
  IF (SELECT COUNT(*) FROM policy_severity_relevel_backup WHERE rule_id LIKE 'rule_997_%') IS DISTINCT FROM 3 THEN RAISE EXCEPTION '备份行数应为 3'; END IF;
END $$;
SQL
}
check_after_migration

psql_test -q -f "$rollback" >/dev/null

psql_test -q <<'SQL'
DO $$
BEGIN
  IF (SELECT severity FROM rules WHERE id='rule_997_sql') IS DISTINCT FROM 'critical' THEN RAISE EXCEPTION '回滚应还原为严重'; END IF;
  IF (SELECT severity FROM rules WHERE id='rule_997_cc') IS DISTINCT FROM 'medium' THEN RAISE EXCEPTION '回滚应还原为中危'; END IF;
  IF (SELECT severity FROM rules WHERE id='rule_997_off') IS DISTINCT FROM 'high' THEN RAISE EXCEPTION '回滚应还原停用策略为高危'; END IF;
  IF (SELECT enabled FROM rules WHERE id='rule_997_off') IS DISTINCT FROM false THEN RAISE EXCEPTION '回滚后停用策略仍应停用'; END IF;
  IF (SELECT enabled FROM rules WHERE id='rule_997_sql') IS DISTINCT FROM true THEN RAISE EXCEPTION '回滚后启用策略仍应启用'; END IF;
  IF (SELECT severity FROM rules WHERE id='rule_997_manual') IS DISTINCT FROM 'low' THEN RAISE EXCEPTION '回滚不能动人工改过的行'; END IF;
  IF to_regclass('policy_severity_relevel_backup') IS NOT NULL THEN RAISE EXCEPTION '回滚后备份表应删除'; END IF;
END $$;
SQL

# 回滚后再升级一遍仍然正确
psql_test -q -f "$migration" >/dev/null
check_after_migration

# 走迁移运行器的真实路径（schema_migrations 账本语义）：升级 -> 回滚 -> 运行器跳过（已知行为）-> 删记录 -> 运行器再升级
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"; cleanup' EXIT
mkdir "$tmp/migrations"
cp "$migration" "$tmp/migrations/"
cat >"$tmp/psql" <<PSQL
#!/usr/bin/env bash
exec psql -X "$RELEVEL_TEST_DATABASE_URL" "\$@"
PSQL
chmod +x "$tmp/psql"
run_runner() { MIGRATION_PSQL="$tmp/psql" bash "$repo_root/deploy/lib/migration-runner.sh" --migrations-dir "$tmp/migrations" 2>&1; }
# 先收集完整输出再匹配：grep -q 提前退出会让运行器吃 SIGPIPE
runner_says() { local out; out=$(run_runner); printf '%s\n' "$out" | grep -Fq -- "$1"; }
version='997_relevel_preloaded_policy_severity.sql'

psql_test -q -f "$rollback" >/dev/null
psql_test -q -c "DELETE FROM schema_migrations WHERE version='$version'" >/dev/null
runner_says "[done] $version"
check_after_migration

psql_test -q -f "$rollback" >/dev/null
runner_says "[skip] $version (already applied)"
[ "$(psql_test -Atc "SELECT severity FROM rules WHERE id='rule_997_sql'")" = critical ]   # 不删记录就再升级：被跳过，级别停在旧值

psql_test -q -c "DELETE FROM schema_migrations WHERE version='$version'" >/dev/null
runner_says "[done] $version"
check_after_migration
printf 'relevel_preloaded_policy_severity=ok\n'
