#!/usr/bin/env bash
# deploy/tests/test_998_scrub_private_key_evidence_context.sh
# 仅供显式指定的可丢弃测试库使用。脚本只在专用 schema（scrub998_test）里建最小的
# security_events / alert_groups / alert_inbox 表，不对 public 下任何表做 DROP；结束时删掉这个 schema。
# 所有 psql 调用带 search_path=scrub998_test，迁移里不带 schema 前缀的表名因此落在测试 schema 里。
# 用法：SCRUB_TEST_DATABASE_URL=postgres://... bash deploy/tests/test_998_scrub_private_key_evidence_context.sh
set -euo pipefail
: "${SCRUB_TEST_DATABASE_URL:?请指定可丢弃测试库连接串}"
repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
migration="$repo_root/deploy/migrations/998_scrub_private_key_evidence_context.sql"
schema=scrub998_test
psql_admin() { psql -X "$SCRUB_TEST_DATABASE_URL" -v ON_ERROR_STOP=1 "$@"; }
psql_test() { PGOPTIONS="-c search_path=$schema" psql -X "$SCRUB_TEST_DATABASE_URL" -v ON_ERROR_STOP=1 "$@"; }
# 只有脚本自己成功建出专用 schema 之后才会在退出时删它；没建成功就不删任何东西
created_schema=0
cleanup() { if [ "$created_schema" = 1 ]; then psql_admin -q -c "DROP SCHEMA IF EXISTS $schema CASCADE" >/dev/null 2>&1 || true; fi; }
trap cleanup EXIT

# ---- 静态检查 ----
# 只允许 UPDATE security_events / alert_groups / alert_inbox / request_logs，不建备份表
write_ops=$(grep -v '^[[:space:]]*--' "$migration" | tr '\n' ' ' \
  | grep -Eoi '(UPDATE|DELETE|INSERT|TRUNCATE|MERGE|CREATE TABLE)([[:space:]]+(INTO|FROM))?[[:space:]]+"?[a-z_]+"?' | tr -s ' ' | tr 'A-Z' 'a-z' | sort -u)
expected_ops=$'update alert_groups\nupdate alert_inbox\nupdate request_logs\nupdate security_events'
[ "$write_ops" = "$expected_ops" ] || { echo "迁移里的写操作不符合预期：$write_ops"; exit 1; }
# 不使用显式事务：没有 BEGIN/COMMIT，并带 NO TRANSACTION 指令（执行器据此不套外层事务）
! grep -Eiq '^[[:space:]]*(BEGIN|COMMIT)[[:space:]]*;' "$migration" || { echo "998 不应使用显式事务"; exit 1; }
grep -Eiq '^[[:space:]]*--[[:space:]]*\+?goose[[:space:]]+NO[[:space:]]+TRANSACTION' "$migration" || { echo "998 缺少 NO TRANSACTION 指令"; exit 1; }
# 不带日期条件，预过滤只用打码标记，不依赖类别的大小写
code=$(grep -v '^[[:space:]]*--' "$migration")
# 日期下限只用于 request_logs 的两条 UPDATE（问题出现时间之前两天），其余三处不带日期条件
[ "$(grep -ci 'created_at' <<<"$code")" = 2 ] || { echo "998 里 created_at 只应出现在 request_logs 的两条 UPDATE 里"; exit 1; }
[ "$(grep -c "created_at >= TIMESTAMPTZ '2026-10-20 00:00:00+00'" <<<"$code")" = 2 ] || { echo "request_logs 的两条 UPDATE 缺少 2026-10-20 日期下限"; exit 1; }
! grep -Fq "LIKE '%private_key%'" <<<"$code" || { echo "998 不应再用区分大小写的 private_key 预过滤"; exit 1; }
grep -Fq "LIKE '%<已打码%'" <<<"$code" || { echo "998 缺少打码标记预过滤"; exit 1; }

# ---- 专用 schema 与测试数据 ----
# schema 已存在（别人的，或上次异常中断留下的）：不删除、不继续
if [ "$(psql_admin -At -c "SELECT count(*) FROM pg_namespace WHERE nspname = '$schema'")" != 0 ]; then
  echo "测试库里已经存在 schema $schema（连接串指向的库：${SCRUB_TEST_DATABASE_URL##*/}）。脚本不会删除它，请确认内容后手工 DROP SCHEMA $schema CASCADE 再重跑。" >&2
  exit 1
fi
# 不带 IF NOT EXISTS：检查与创建之间被别人抢建时，创建失败，脚本也不会去删别人的
psql_admin -q -c "CREATE SCHEMA $schema" >/dev/null
created_schema=1
[ "$(psql_test -At -c 'SELECT current_schema()')" = "$schema" ] || { echo "search_path 没有生效，终止"; exit 1; }

psql_test -q <<'SQL'
CREATE TABLE security_events (
  id VARCHAR(64) PRIMARY KEY, tenant_id VARCHAR(64) NOT NULL DEFAULT 't',
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), matched_summary JSONB
);
CREATE TABLE alert_groups (id VARCHAR(64) PRIMARY KEY, tenant_id VARCHAR(64) NOT NULL DEFAULT 't', body_json JSONB NOT NULL DEFAULT '{}'::jsonb);
CREATE TABLE alert_inbox  (id VARCHAR(64) PRIMARY KEY, tenant_id VARCHAR(64) NOT NULL DEFAULT 't', body_json JSONB NOT NULL);
CREATE TABLE request_logs (
  id VARCHAR(64) PRIMARY KEY, tenant_id VARCHAR(64) NOT NULL DEFAULT 't', created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  input_audit_result JSONB DEFAULT NULL, output_audit_result JSONB DEFAULT NULL
);
CREATE INDEX idx_request_logs_backfill_cursor ON request_logs(created_at, id);

CREATE FUNCTION kf(cat text, ctx text) RETURNS jsonb LANGUAGE sql IMMUTABLE AS
$$ SELECT jsonb_build_object('type','secret','category',cat,'severity','critical','rule_id','r1','evidence_context',ctx) $$;
CREATE FUNCTION dirty() RETURNS text LANGUAGE sql IMMUTABLE AS
$$ SELECT E'帮我看看\n<已打码 31 位>\nMIIEowFAKEBODY-----END RSA PRIVATE KEY-----' $$;
CREATE FUNCTION clean() RETURNS text LANGUAGE sql IMMUTABLE AS
$$ SELECT E'帮我看看\n<已打码 31 位>' $$;
-- 一份完整的 matched_summary：三个数组、根上的 category、primary_finding 全带同一段前后文
CREATE FUNCTION mk(ctx text) RETURNS jsonb LANGUAGE sql IMMUTABLE AS $$
  SELECT jsonb_build_object('category','ssh_private_key','summary','x',
    'findings', jsonb_build_array(kf('ssh_private_key',ctx), kf('agent_direct_api_call','direct_api')),
    'raw_findings', jsonb_build_array(kf('ssh_private_key',ctx)),
    'observations', jsonb_build_array(kf('openssh_private_key',ctx)),
    'primary_finding', kf('ssh_private_key',ctx)) $$;
-- 不该动的非私钥类、带正文的上下文，用 KEEPBODY 标记，与会被清掉的 FAKEBODY 区分
CREATE FUNCTION keep() RETURNS text LANGUAGE sql IMMUTABLE AS $$ SELECT E'<已打码 5 位>\nKEEPBODY' $$;

CREATE TABLE cases (tbl text, id text, created_at timestamptz, input jsonb, expected jsonb);
INSERT INTO cases(tbl, id, created_at, input, expected) VALUES
 -- security_events：完整形态与非私钥类
 ('se','e_key','2026-11-13', mk(dirty()), mk(clean())),
 ('se','e_password','2026-11-13', jsonb_build_object('findings', jsonb_build_array(kf('plain_password','password=<已打码 12 位> 后面的话')), 'primary_finding', kf('plain_password','password=<已打码 12 位> 后面的话')),
                                 jsonb_build_object('findings', jsonb_build_array(kf('plain_password','password=<已打码 12 位> 后面的话')), 'primary_finding', kf('plain_password','password=<已打码 12 位> 后面的话'))),
 ('se','e_nonkey_body','2026-11-13', jsonb_build_object('findings', jsonb_build_array(kf('plain_password',keep())), 'primary_finding', kf('plain_password',keep())),
                                  jsonb_build_object('findings', jsonb_build_array(kf('plain_password',keep())), 'primary_finding', kf('plain_password',keep()))),
 -- 日期条件已去掉：上线后头 40 分钟、更早的事件都要清
 ('se','e_old','2026-10-01', mk(dirty()), mk(clean())),
 ('se','e_launch_window','2026-10-21 23:30+00', mk(dirty()), mk(clean())),
 ('se','e_legacy_root','2026-11-13', kf('private_key', E'前文 <已打码 27 位>\nMIIEowROOTFAKEBODY'), kf('private_key', '前文 <已打码 27 位>')),
 ('se','e_clean','2026-11-13', jsonb_build_object('findings', jsonb_build_array(kf('ssh_private_key','前文 <已打码 31 位>'))), jsonb_build_object('findings', jsonb_build_array(kf('ssh_private_key','前文 <已打码 31 位>')))),
 -- matched_summary 不是对象
 ('se','e_null','2026-11-13', NULL, NULL),
 ('se','e_arr_root','2026-11-13', jsonb_build_array(kf('ssh_private_key',keep())), jsonb_build_array(kf('ssh_private_key',keep()))),
 ('se','e_scalar_str','2026-11-13', to_jsonb(E'private_key <已打码 3 位>\nKEEPBODY'::text), to_jsonb(E'private_key <已打码 3 位>\nKEEPBODY'::text)),
 ('se','e_scalar_num','2026-11-13', '5'::jsonb, '5'::jsonb),
 ('se','e_json_null','2026-11-13', 'null'::jsonb, 'null'::jsonb),
 -- 类别的大小写与空白
 ('se','e_case','2026-11-13',
    jsonb_build_object('findings', jsonb_build_array(kf('SSH_PRIVATE_KEY',dirty()), kf('Ssh_Private_Key',dirty()), kf('  ssh_private_key  ',dirty()), kf(E'\tPrivate_Key\n',dirty()))),
    jsonb_build_object('findings', jsonb_build_array(kf('SSH_PRIVATE_KEY',clean()), kf('Ssh_Private_Key',clean()), kf('  ssh_private_key  ',clean()), kf(E'\tPrivate_Key\n',clean())))),
 -- 标记与截断位置
 ('se','e_digits','2026-11-13',
    jsonb_build_object('findings', jsonb_build_array(kf('ssh_private_key', E'x <已打码 173 位>\nFAKEBODY'), kf('ssh_private_key', E'<已打码 1675 位>\nFAKEBODY'))),
    jsonb_build_object('findings', jsonb_build_array(kf('ssh_private_key', 'x <已打码 173 位>'), kf('ssh_private_key', '<已打码 1675 位>')))),
 ('se','e_two_markers','2026-11-13',
    jsonb_build_object('findings', jsonb_build_array(kf('ssh_private_key', E'a <已打码 5 位>\nFAKEBODY1 b <已打码 6 位>\nFAKEBODY2'))),
    jsonb_build_object('findings', jsonb_build_array(kf('ssh_private_key', 'a <已打码 5 位>')))),
 ('se','e_ws_after','2026-11-13',
    jsonb_build_object('findings', jsonb_build_array(kf('ssh_private_key', E'<已打码 31 位>\n \t\n'), kf('ssh_private_key', E'<已打码 31 位> '))),
    jsonb_build_object('findings', jsonb_build_array(kf('ssh_private_key', '<已打码 31 位>'), kf('ssh_private_key', '<已打码 31 位>')))),
 ('se','e_ellipsis','2026-11-13',
    jsonb_build_object('findings', jsonb_build_array(kf('ssh_private_key', E'…前文 <已打码 31 位>\n后文FAKEBODY…'))),
    jsonb_build_object('findings', jsonb_build_array(kf('ssh_private_key', '…前文 <已打码 31 位>')))),
 -- 数组里混有非对象元素：顺序与各元素原样
 ('se','e_mixed','2026-11-13',
    jsonb_build_object('findings', jsonb_build_array(to_jsonb('str'::text),'null'::jsonb,'7'::jsonb,'[1,[2]]'::jsonb,kf('ssh_private_key',dirty()),'true'::jsonb),
                       'raw_findings', jsonb_build_array('null'::jsonb,kf('ssh_private_key',dirty()),to_jsonb('s'::text))),
    jsonb_build_object('findings', jsonb_build_array(to_jsonb('str'::text),'null'::jsonb,'7'::jsonb,'[1,[2]]'::jsonb,kf('ssh_private_key',clean()),'true'::jsonb),
                       'raw_findings', jsonb_build_array('null'::jsonb,kf('ssh_private_key',clean()),to_jsonb('s'::text)))),
 -- findings 不是数组
 ('se','e_findings_null','2026-11-13',
    jsonb_build_object('findings','null'::jsonb,'primary_finding',kf('ssh_private_key',dirty())),
    jsonb_build_object('findings','null'::jsonb,'primary_finding',kf('ssh_private_key',clean()))),
 ('se','e_findings_obj','2026-11-13',
    jsonb_build_object('findings',kf('ssh_private_key',keep())), jsonb_build_object('findings',kf('ssh_private_key',keep()))),
 ('se','e_findings_str','2026-11-13',
    jsonb_build_object('findings',to_jsonb(E'private_key <已打码 3 位>\nKEEPBODY'::text)), jsonb_build_object('findings',to_jsonb(E'private_key <已打码 3 位>\nKEEPBODY'::text))),
 -- primary_finding 为 null、缺失、非对象
 ('se','e_pf_null','2026-11-13',
    jsonb_build_object('findings',jsonb_build_array(kf('ssh_private_key',dirty())),'primary_finding','null'::jsonb),
    jsonb_build_object('findings',jsonb_build_array(kf('ssh_private_key',clean())),'primary_finding','null'::jsonb)),
 ('se','e_pf_missing','2026-11-13',
    jsonb_build_object('findings',jsonb_build_array(kf('ssh_private_key',dirty()))),
    jsonb_build_object('findings',jsonb_build_array(kf('ssh_private_key',clean())))),
 ('se','e_pf_str','2026-11-13',
    jsonb_build_object('findings',jsonb_build_array(kf('ssh_private_key',dirty())),'primary_finding',to_jsonb('<已打码 1 位> text'::text)),
    jsonb_build_object('findings',jsonb_build_array(kf('ssh_private_key',clean())),'primary_finding',to_jsonb('<已打码 1 位> text'::text))),
 -- 缺类别、evidence_context 不是字符串
 ('se','e_odd_fields','2026-11-13',
    jsonb_build_object('findings',jsonb_build_array(jsonb_build_object('evidence_context',keep()), jsonb_build_object('category','ssh_private_key','evidence_context','null'::jsonb), jsonb_build_object('category','ssh_private_key','evidence_context',123)),'summary','<已打码 1 位>'),
    jsonb_build_object('findings',jsonb_build_array(jsonb_build_object('evidence_context',keep()), jsonb_build_object('category','ssh_private_key','evidence_context','null'::jsonb), jsonb_build_object('category','ssh_private_key','evidence_context',123)),'summary','<已打码 1 位>')),
 -- alert_groups.body_json
 ('ag','g_full','2026-11-13',
    jsonb_build_object('rule_name','x','matched',mk(dirty()),'primary_finding',kf('ssh_private_key',dirty())),
    jsonb_build_object('rule_name','x','matched',mk(clean()),'primary_finding',kf('ssh_private_key',clean()))),
 ('ag','g_root_matched','2026-11-13',
    jsonb_build_object('matched',kf('private_key',dirty()),'primary_finding',kf('private_key',dirty())),
    jsonb_build_object('matched',kf('private_key',clean()),'primary_finding',kf('private_key',clean()))),
 ('ag','g_nomatched','2026-11-13', jsonb_build_object('primary_finding',kf('ssh_private_key',dirty())), jsonb_build_object('primary_finding',kf('ssh_private_key',clean()))),
 ('ag','g_nopf','2026-11-13', jsonb_build_object('matched',mk(dirty())), jsonb_build_object('matched',mk(clean()))),
 ('ag','g_none','2026-11-13', jsonb_build_object('rule_name','x'), jsonb_build_object('rule_name','x')),
 ('ag','g_nulls','2026-11-13', jsonb_build_object('matched','null'::jsonb,'primary_finding','null'::jsonb,'note','<已打码 3 位>'), jsonb_build_object('matched','null'::jsonb,'primary_finding','null'::jsonb,'note','<已打码 3 位>')),
 ('ag','g_shapes','2026-11-13',
    jsonb_build_object('matched',jsonb_build_array(kf('ssh_private_key',keep())),'primary_finding',to_jsonb('<已打码 1 位>'::text)),
    jsonb_build_object('matched',jsonb_build_array(kf('ssh_private_key',keep())),'primary_finding',to_jsonb('<已打码 1 位>'::text))),
 ('ag','g_nonkey','2026-11-13',
    jsonb_build_object('matched',jsonb_build_object('findings',jsonb_build_array(kf('plain_password',keep()))),'primary_finding',kf('plain_password',keep())),
    jsonb_build_object('matched',jsonb_build_object('findings',jsonb_build_array(kf('plain_password',keep()))),'primary_finding',kf('plain_password',keep()))),
 ('ag','g_arrayroot','2026-11-13', '[1,"<已打码 2 位>"]'::jsonb, '[1,"<已打码 2 位>"]'::jsonb),
 -- alert_inbox.body_json
 ('ai','i_full','2026-11-13',
    jsonb_build_object('rule_name','x','matched',mk(dirty()),'primary_finding',kf('ssh_private_key',dirty())),
    jsonb_build_object('rule_name','x','matched',mk(clean()),'primary_finding',kf('ssh_private_key',clean()))),
 ('ai','i_nopf','2026-11-13', jsonb_build_object('matched',mk(dirty())), jsonb_build_object('matched',mk(clean()))),
 ('ai','i_nomatched','2026-11-13', jsonb_build_object('primary_finding',kf('ssh_private_key',dirty())), jsonb_build_object('primary_finding',kf('ssh_private_key',clean()))),
 ('ai','i_none','2026-11-13', jsonb_build_object('rule_name','x','title','y'), jsonb_build_object('rule_name','x','title','y'));

-- request_logs：2.9.18 形态，两列都是 {findings:[...], action, ...}，没有 primary_finding
CREATE FUNCTION audit(ctx text, extra jsonb DEFAULT '{}') RETURNS jsonb LANGUAGE sql IMMUTABLE AS
$$ SELECT jsonb_build_object('action','audit','findings', jsonb_build_array(kf('ssh_private_key',ctx), kf('agent_direct_api_call','direct_api'))) || extra $$;
CREATE FUNCTION keepctx() RETURNS text LANGUAGE sql IMMUTABLE AS $$ SELECT E'帮我看看\n<已打码 31 位>\nKEEPBODY' $$;
CREATE TABLE rl_cases (id text PRIMARY KEY, created_at timestamptz, in_input jsonb, in_output jsonb, exp_input jsonb, exp_output jsonb);
INSERT INTO rl_cases VALUES
 ('r_in','2026-11-13', audit(dirty()), NULL, audit(clean()), NULL),
 ('r_out','2026-11-13', NULL, audit(dirty(), jsonb_build_object('response_metadata',jsonb_build_object('usage_source','billing'),'block',jsonb_build_object('rule','x'))),
                         NULL, audit(clean(), jsonb_build_object('response_metadata',jsonb_build_object('usage_source','billing'),'block',jsonb_build_object('rule','x')))),
 ('r_both','2026-10-22 08:00+00', audit(dirty()), audit(dirty()), audit(clean()), audit(clean())),
 ('r_floor','2026-10-20 00:00:00+00', audit(dirty()), audit(dirty()), audit(clean()), audit(clean())),
 ('r_before_floor','2026-10-19 23:59:59+00', audit(keepctx()), audit(keepctx()), audit(keepctx()), audit(keepctx())),
 ('r_nonkey','2026-11-13', audit('x'), jsonb_build_object('action','audit','findings',jsonb_build_array(kf('plain_password',keep()))),
                          audit('x'), jsonb_build_object('action','audit','findings',jsonb_build_array(kf('plain_password',keep())))),
 ('r_null','2026-11-13', NULL, NULL, NULL, NULL),
 ('r_nomarker','2026-11-13', jsonb_build_object('action','audit','findings',jsonb_build_array(kf('ssh_private_key','前文 <已打码 31 位>'), kf('ssh_private_key','no marker here'))), NULL,
                            jsonb_build_object('action','audit','findings',jsonb_build_array(kf('ssh_private_key','前文 <已打码 31 位>'), kf('ssh_private_key','no marker here'))), NULL),
 ('r_shapes','2026-11-13', '[1]'::jsonb, to_jsonb('<已打码 1 位>'::text), '[1]'::jsonb, to_jsonb('<已打码 1 位>'::text)),
 ('r_empty_findings','2026-11-13', jsonb_build_object('action','allow','findings','[]'::jsonb), 'null'::jsonb, jsonb_build_object('action','allow','findings','[]'::jsonb), 'null'::jsonb);
INSERT INTO request_logs(id, created_at, input_audit_result, output_audit_result) SELECT id, created_at, in_input, in_output FROM rl_cases;
-- 行版本快照：没被更新的行迁移后 xmin 必须不变
CREATE TABLE rl_xmin AS SELECT id, xmin::text AS x FROM request_logs;

INSERT INTO security_events(id, created_at, matched_summary) SELECT id, created_at, input FROM cases WHERE tbl='se';
INSERT INTO alert_groups(id, body_json) SELECT id, input FROM cases WHERE tbl='ag';
INSERT INTO alert_inbox(id, body_json) SELECT id, input FROM cases WHERE tbl='ai';

-- 对账函数：库里每一行都必须等于 expected（NULL 与 JSON null 区分对待）
CREATE FUNCTION verify_all() RETURNS void LANGUAGE plpgsql AS $$
DECLARE r record; n int := 0;
BEGIN
  FOR r IN
    SELECT c.tbl, c.id, c.expected,
           CASE c.tbl WHEN 'se' THEN s.matched_summary WHEN 'ag' THEN a.body_json ELSE i.body_json END AS actual,
           CASE c.tbl WHEN 'se' THEN s.id WHEN 'ag' THEN a.id ELSE i.id END AS found
    FROM cases c
    LEFT JOIN security_events s ON c.tbl='se' AND s.id=c.id
    LEFT JOIN alert_groups   a ON c.tbl='ag' AND a.id=c.id
    LEFT JOIN alert_inbox    i ON c.tbl='ai' AND i.id=c.id
  LOOP
    n := n + 1;
    IF r.found IS NULL THEN RAISE EXCEPTION '行 %/% 丢失', r.tbl, r.id; END IF;
    IF r.actual IS DISTINCT FROM r.expected OR r.actual::text IS DISTINCT FROM r.expected::text THEN
      RAISE EXCEPTION '行 %/% 不符：实际=% 期望=%', r.tbl, r.id, r.actual, r.expected;
    END IF;
  END LOOP;
  IF n <> (SELECT count(*) FROM cases) THEN RAISE EXCEPTION '对账行数不对'; END IF;
  FOR r IN
    SELECT c.*, l.input_audit_result AS a_in, l.output_audit_result AS a_out, l.id AS found, l.xmin::text AS nx, x.x AS ox
    FROM rl_cases c LEFT JOIN request_logs l ON l.id=c.id LEFT JOIN rl_xmin x ON x.id=c.id
  LOOP
    IF r.found IS NULL THEN RAISE EXCEPTION 'request_logs 行 % 丢失', r.id; END IF;
    IF r.a_in IS DISTINCT FROM r.exp_input OR r.a_in::text IS DISTINCT FROM r.exp_input::text
       OR r.a_out IS DISTINCT FROM r.exp_output OR r.a_out::text IS DISTINCT FROM r.exp_output::text THEN
      RAISE EXCEPTION 'request_logs 行 % 不符：实际=% / % 期望=% / %', r.id, r.a_in, r.a_out, r.exp_input, r.exp_output;
    END IF;
    -- 内容没变的行不能被重写（xmin 不变）
    IF r.in_input IS NOT DISTINCT FROM r.exp_input AND r.in_output IS NOT DISTINCT FROM r.exp_output AND r.nx <> r.ox THEN
      RAISE EXCEPTION 'request_logs 行 % 内容没变却被重写了', r.id;
    END IF;
  END LOOP;
  IF EXISTS (SELECT 1 FROM security_events WHERE matched_summary::text LIKE '%FAKEBODY%')
     OR EXISTS (SELECT 1 FROM alert_groups WHERE body_json::text LIKE '%FAKEBODY%')
     OR EXISTS (SELECT 1 FROM alert_inbox WHERE body_json::text LIKE '%FAKEBODY%')
     OR EXISTS (SELECT 1 FROM request_logs WHERE input_audit_result::text LIKE '%FAKEBODY%' OR output_audit_result::text LIKE '%FAKEBODY%') THEN
    RAISE EXCEPTION '三张表里还有私钥正文片段';
  END IF;
END $$;
SQL

# 迁移前：测试数据的确含正文（防止测试本身是空转）
before=$(psql_test -At -c "SELECT (SELECT count(*) FROM security_events WHERE matched_summary::text LIKE '%FAKEBODY%') + (SELECT count(*) FROM alert_groups WHERE body_json::text LIKE '%FAKEBODY%') + (SELECT count(*) FROM alert_inbox WHERE body_json::text LIKE '%FAKEBODY%') + (SELECT count(*) FROM request_logs WHERE input_audit_result::text LIKE '%FAKEBODY%') + (SELECT count(*) FROM request_logs WHERE output_audit_result::text LIKE '%FAKEBODY%')")
[ "$before" -ge 25 ] || { echo "测试数据没有按预期含私钥片段：$before"; exit 1; }
! psql_test -q -c "SELECT verify_all()" >/dev/null 2>&1 || { echo "迁移前对账不应通过"; exit 1; }

snapshot_sql="SELECT md5(coalesce((SELECT string_agg(id||coalesce(matched_summary::text,'~'),'|' ORDER BY id) FROM security_events),'') || coalesce((SELECT string_agg(id||body_json::text,'|' ORDER BY id) FROM alert_groups),'') || coalesce((SELECT string_agg(id||body_json::text,'|' ORDER BY id) FROM alert_inbox),'') || coalesce((SELECT string_agg(id||coalesce(input_audit_result::text,'~')||coalesce(output_audit_result::text,'~'),'|' ORDER BY id) FROM request_logs),''))"

# ---- 执行迁移并对账 ----
psql_test -q -f "$migration" >/dev/null
psql_test -q -c "SELECT verify_all()" >/dev/null
first=$(psql_test -At -c "$snapshot_sql")
psql_test -q -f "$migration" >/dev/null   # 重复执行结果不变
second=$(psql_test -At -c "$snapshot_sql")
[ "$first" = "$second" ] || { echo "重复执行改变了数据"; exit 1; }
psql_test -q -c "SELECT verify_all()" >/dev/null
# 第一次迁移之后记下 request_logs 的行版本，再跑一次不应重写任何行
psql_test -q -c "DROP TABLE rl_xmin" -c "CREATE TABLE rl_xmin AS SELECT id, xmin::text AS x FROM request_logs"
psql_test -q -f "$migration" >/dev/null
[ "$(psql_test -At -c "SELECT count(*) FROM request_logs l JOIN rl_xmin x USING (id) WHERE l.xmin::text <> x.x")" = 0 ] || { echo "重复执行重写了 request_logs 的行"; exit 1; }

# ---- 告警表不存在时迁移照常成功 ----
psql_test -q <<'SQL'
DROP TABLE alert_groups, alert_inbox, request_logs;
UPDATE security_events SET matched_summary = mk(dirty()) WHERE id='e_key';
SQL
psql_test -q -f "$migration" >/dev/null
[ "$(psql_test -At -c "SELECT matched_summary = mk(clean()) FROM security_events WHERE id='e_key'")" = t ] || { echo "两张告警表都不存在时 security_events 没有被清"; exit 1; }
# 只缺 alert_inbox
psql_test -q <<'SQL'
CREATE TABLE alert_groups (id VARCHAR(64) PRIMARY KEY, tenant_id VARCHAR(64) NOT NULL DEFAULT 't', body_json JSONB NOT NULL DEFAULT '{}'::jsonb);
INSERT INTO alert_groups VALUES ('g_one','t', jsonb_build_object('matched',mk(dirty()),'primary_finding',kf('ssh_private_key',dirty())));
SQL
psql_test -q -f "$migration" >/dev/null
[ "$(psql_test -At -c "SELECT body_json = jsonb_build_object('matched',mk(clean()),'primary_finding',kf('ssh_private_key',clean())) FROM alert_groups WHERE id='g_one'")" = t ] || { echo "只缺 alert_inbox 时 alert_groups 没有被清"; exit 1; }

# 只缺两张告警表，request_logs 存在
psql_test -q <<'SQL'
DROP TABLE alert_groups;
CREATE TABLE request_logs (id VARCHAR(64) PRIMARY KEY, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), input_audit_result JSONB, output_audit_result JSONB);
INSERT INTO request_logs VALUES ('r_one','2026-11-13', audit(dirty()), audit(dirty()));
SQL
psql_test -q -f "$migration" >/dev/null
[ "$(psql_test -At -c "SELECT input_audit_result = audit(clean()) AND output_audit_result = audit(clean()) FROM request_logs WHERE id='r_one'")" = t ] || { echo "只缺告警表时 request_logs 没有被清"; exit 1; }

echo "998 迁移测试通过"
