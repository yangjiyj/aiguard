#!/usr/bin/env bash
# 仅供显式指定的可丢弃测试库使用：库必须已按完整迁移链初始化（含 001 初始化与全部迁移）。
# 用法：PROFANITY_MIGRATION_TEST_DATABASE_URL=postgres://... bash deploy/tests/test_992_profanity_abuse_policy.sh
set -euo pipefail
: "${PROFANITY_MIGRATION_TEST_DATABASE_URL:?请指定可丢弃测试库连接串}"
repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
migration="$repo_root/deploy/migrations/992_profanity_abuse_policy.sql"
rollback="$repo_root/deploy/migrations/rollback/992_profanity_abuse_policy.sql"
code='builtin.content_safety.ffbbdfb2e823022d'
psql_test() { psql -X "$PROFANITY_MIGRATION_TEST_DATABASE_URL" -v ON_ERROR_STOP=1 "$@"; }

# 升级不得改动客户动作：迁移只允许插入，不允许 UPDATE / DELETE 既有行
! grep -Eiq '^[[:space:]]*(UPDATE|DELETE)[[:space:]]' "$migration"

cleanup() {
  psql_test -q <<'SQL' >/dev/null
DELETE FROM security_events WHERE id LIKE 'evt_992_%';
DELETE FROM request_logs WHERE id LIKE 'rl_992_%';
DELETE FROM rule_capability_bindings WHERE rule_id IN (SELECT id FROM rules WHERE rule_set_id LIKE 'rs_992_%');
DELETE FROM rules WHERE rule_set_id LIKE 'rs_992_%';
DELETE FROM rule_sets WHERE id LIKE 'rs_992_%';
DELETE FROM tenants WHERE id LIKE 't_992_%';
SQL
}
trap cleanup EXIT
cleanup
# 回到迁移前：移除 992 的能力登记与默认策略（库里没有其他 992 之外的绑定）
psql_test -q -f "$rollback" >/dev/null

psql_test -q <<SQL
INSERT INTO tenants(id, name) VALUES ('t_992_a','a'),('t_992_b','b'),('t_992_c','c');
INSERT INTO rule_sets(id, tenant_id, name, source_type, published) VALUES
  ('rs_992_a','t_992_a','默认安全策略','system',true),
  ('rs_992_b','t_992_b','只有客户自建规则','manual',true),
  ('rs_992_c','t_992_c','默认安全策略','system',true);
-- a：已采用内置策略目录（有骚扰/霸凌内容），还没有辱骂脏话
INSERT INTO rules(id, rule_set_id, policy_code, rule_type, name, severity, action, enabled)
VALUES ('rule_992_a1','rs_992_a','builtin.content_safety.dc547e0b41610cca','content_safety','骚扰/霸凌内容','medium','block',true);
-- b：没有任何内置策略（客户自建）
INSERT INTO rules(id, rule_set_id, rule_type, name, severity, action, enabled)
VALUES ('rule_992_b1','rs_992_b','keyword','客户自建关键字','medium','block',true);
-- c：已经有同 policy_code 的行，客户设成了 block 并停用；迁移不得改动
INSERT INTO rules(id, rule_set_id, policy_code, rule_type, name, severity, action, enabled)
VALUES ('rule_992_c1','rs_992_c','builtin.content_safety.dc547e0b41610cca','content_safety','骚扰/霸凌内容','medium','block',true),
       ('rule_992_c2','rs_992_c','$code','content_safety','辱骂脏话','medium','block',false);
SQL

# 执行两次，验证幂等
psql_test -q -f "$migration" >/dev/null
psql_test -q -f "$migration" >/dev/null

psql_test -q <<SQL
DO \$\$
DECLARE n int; a text; e boolean;
BEGIN
  -- 能力登记
  IF (SELECT count(*) FROM security_capabilities
      WHERE category IN ('content_profanity_abuse','harassment_profanity_cn')
        AND supported_stages = '["input","output"]'::jsonb
        AND allowed_actions = '["audit","block"]'::jsonb
        AND mask_capable = FALSE AND enabled) <> 2 THEN
    RAISE EXCEPTION '能力登记不符：需要 input/output、audit/block、不支持 mask';
  END IF;
  -- a：补一条且为 audit，绑两个能力
  SELECT count(*), min(action) INTO n, a FROM rules WHERE rule_set_id='rs_992_a' AND policy_code='$code';
  IF n <> 1 OR a <> 'audit' THEN RAISE EXCEPTION '存量租户应补一条 audit，实际 n=% action=%', n, a; END IF;
  IF (SELECT count(*) FROM rule_capability_bindings b JOIN rules r ON r.id=b.rule_id
      WHERE r.rule_set_id='rs_992_a' AND r.policy_code='$code') <> 2 THEN
    RAISE EXCEPTION '存量租户的辱骂脏话应绑定两个能力';
  END IF;
  -- 同一租户其他策略不被改动
  IF (SELECT action FROM rules WHERE id='rule_992_a1') <> 'block' THEN RAISE EXCEPTION '既有策略动作被改动'; END IF;
  -- b：未采用内置目录的规则集不补
  IF EXISTS (SELECT 1 FROM rules WHERE rule_set_id='rs_992_b' AND policy_code='$code') THEN
    RAISE EXCEPTION '未采用内置目录的规则集不应被补策略';
  END IF;
  -- c：客户已有的行（block、停用）原样保留，也不替客户补绑定
  SELECT action, enabled INTO a, e FROM rules WHERE id='rule_992_c2';
  IF a <> 'block' OR e THEN RAISE EXCEPTION '客户已有的辱骂脏话策略被改动 action=% enabled=%', a, e; END IF;
  IF (SELECT count(*) FROM rules WHERE rule_set_id='rs_992_c' AND policy_code='$code') <> 1 THEN
    RAISE EXCEPTION '不得重复创建';
  END IF;
  IF EXISTS (SELECT 1 FROM rule_capability_bindings WHERE rule_id='rule_992_c2') THEN
    RAISE EXCEPTION '不得替客户恢复绑定';
  END IF;
END \$\$;
SQL

# 回滚时策略已经命中过（security_events.rule_id 外键指向 992 的规则）：回滚不得被外键卡住，
# 安全事件保留、rule_id 置空；与 992 无关的事件不受影响。
psql_test -q <<SQL
INSERT INTO request_logs(id, request_id, tenant_id, proxy_mode) VALUES
  ('rl_992_hit','req_992_hit','t_992_a','chat_completion'), ('rl_992_other','req_992_other','t_992_a','chat_completion');
INSERT INTO security_events(id, request_id, tenant_id, project_id, event_type, severity, action_taken, rule_id)
SELECT 'evt_992_hit', 'req_992_hit', 't_992_a', 'project_default', 'content_safety', 'medium', 'security_audit', id
FROM rules WHERE rule_set_id='rs_992_a' AND policy_code='$code';
INSERT INTO security_events(id, request_id, tenant_id, project_id, event_type, severity, action_taken, rule_id)
VALUES ('evt_992_other', 'req_992_other', 't_992_a', 'project_default', 'content_safety', 'medium', 'security_blocked', 'rule_992_a1');
SQL
psql_test -q -f "$rollback" >/dev/null
psql_test -q <<SQL
DO \$\$
BEGIN
  IF EXISTS (SELECT 1 FROM rules WHERE policy_code='$code') THEN RAISE EXCEPTION '回滚后不应残留辱骂脏话策略'; END IF;
  IF NOT EXISTS (SELECT 1 FROM security_events WHERE id='evt_992_hit' AND rule_id IS NULL) THEN
    RAISE EXCEPTION '命中过的安全事件应保留且 rule_id 置空';
  END IF;
  IF (SELECT rule_id FROM security_events WHERE id='evt_992_other') IS DISTINCT FROM 'rule_992_a1' THEN
    RAISE EXCEPTION '与 992 无关的安全事件不得被改动';
  END IF;
END \$\$;
SQL

# 回滚后可再次迁移
psql_test -q -f "$migration" >/dev/null
echo "test_992_profanity_abuse_policy: ok"
