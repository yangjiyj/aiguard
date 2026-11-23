-- deploy/migrations/998_scrub_private_key_evidence_context.sql
-- 清理历史告警里的私钥正文片段（private_key_context_scrub_v1）。
--
-- 2026-10-22 起（提交 86aadd922），网关把凭据类命中的前后文存进 security_events.matched_summary
-- 的 evidence_context，并把命中文本换成“<已打码 N 位>”。私钥规则命中的是头行，头行之后的私钥正文
-- 因此原样留在了前后文里。本迁移把私钥类 finding 的 evidence_context 截到第一个打码标记为止。
--
-- 清理范围（三张表，每处都按 finding 的类别判断，只改私钥类的 evidence_context）：
--   1. security_events.matched_summary
--        自身（旧的根形态：整个 matched_summary 就是一条 finding）
--        .findings[] / .raw_findings[] / .observations[]
--        .primary_finding（网关把主 finding 整条复制了一份）
--   2. alert_groups.body_json（控制面告警桥接写入的告警组正文）
--   3. alert_inbox.body_json（同一份正文的收件箱副本）
--        2、3 的路径相同：.matched（即整份 matched_summary，范围同 1）和顶层 .primary_finding
--   4. request_logs.input_audit_result、request_logs.output_audit_result（2.9.18 时期网关经同一个摘要函数
--      写入：根上是 {findings:[…], action, …}，没有 primary_finding，结构与 matched_summary 一致，
--      直接复用 scrub_summary）
-- 类别判断：LOWER(BTRIM(category)) 属于 ssh_private_key / openssh_private_key / private_key。
-- 数组里不是对象的元素、不是对象的 matched / primary_finding、缺失的键一律原样保留，也不会新增键。
--
-- 不建备份表：备份等于把私钥片段再存一份。所以本迁移不可回滚，rollback 目录下的同名文件只有说明。
-- 幂等：截断后标记后面没有内容，再次执行不会匹配。
-- 不带日期条件：功能上线时间（2026-10-22 07:18 +08，即 10-21 23:18 UTC）早于“10-22 00:00 UTC”，
-- 日期条件会漏掉上线后头 40 多分钟的事件；表上也没有可用的 created_at 索引，条件省不了扫描。
-- 靠 matched_summary / body_json 文本里含“<已打码”预过滤；更早版本的数据没有这个标记，不受影响。
-- request_logs 例外，带 created_at >= 2026-10-20 的下限：该表很大，下限能走 (created_at, id) 上的
-- idx_request_logs_backfill_cursor 把扫描限定在问题存在的时间段内；问题由 2026-10-22 的提交引入，
-- 下限留了两天余量，早于问题出现时间，因此不会漏掉任何受影响的行（与上面不带日期条件并不矛盾）。
--
-- 不使用显式事务（没有 BEGIN/COMMIT，并带 NO TRANSACTION 指令，执行器因此不再套外层事务）：
-- 治理规则不允许在 security_events 这类大表上长时间持有显式事务。本迁移只更新含私钥片段的极少数行，
-- 每条 UPDATE 各自提交；中途失败不会被记入 schema_migrations，重跑即可补齐，已清理的行不会再匹配。
-- 以下临时函数和各条 UPDATE 依赖同一会话（pg_temp），执行器把整个文件交给同一个 psql 进程，会话保持有效。
-- alert_groups / alert_inbox / request_logs 由更早的迁移创建，正常部署一定存在；仍用 to_regclass 判断，
-- 表不存在时跳过，不让迁移失败。
-- +goose NO TRANSACTION

-- 单条 finding：私钥类且前后文里有“<已打码 N 位>”后面还有内容时，截到第一个标记为止；否则原样返回。
CREATE OR REPLACE FUNCTION pg_temp.scrub_finding(finding jsonb) RETURNS jsonb
LANGUAGE sql IMMUTABLE AS $$
  SELECT CASE
    WHEN jsonb_typeof(finding)='object'
     AND LOWER(BTRIM(COALESCE(finding->>'category',''), E' \t\r\n')) IN ('ssh_private_key','openssh_private_key','private_key')
     AND jsonb_typeof(finding->'evidence_context')='string'
     AND (finding->>'evidence_context') ~ '<已打码 [0-9]+ 位>.'
    THEN jsonb_set(finding, '{evidence_context}',
           to_jsonb(substring(finding->>'evidence_context' from '^(.*?<已打码 [0-9]+ 位>)')))
    ELSE finding END
$$;

-- 一份 matched_summary：自身（根形态）、三个数组、primary_finding。非对象原样返回，不新增键。
CREATE OR REPLACE FUNCTION pg_temp.scrub_summary(summary jsonb) RETURNS jsonb
LANGUAGE plpgsql IMMUTABLE AS $$
DECLARE
  result jsonb;
  array_key text;
BEGIN
  IF jsonb_typeof(summary) IS DISTINCT FROM 'object' THEN
    RETURN summary;
  END IF;
  result := pg_temp.scrub_finding(summary);
  FOREACH array_key IN ARRAY ARRAY['findings','raw_findings','observations'] LOOP
    IF jsonb_typeof(result->array_key)='array' THEN
      result := jsonb_set(result, ARRAY[array_key], COALESCE((
        SELECT jsonb_agg(pg_temp.scrub_finding(item.value) ORDER BY item.ordinality)
        FROM jsonb_array_elements(result->array_key) WITH ORDINALITY AS item(value, ordinality)
      ), '[]'::jsonb));
    END IF;
  END LOOP;
  IF jsonb_typeof(result->'primary_finding')='object' THEN
    result := jsonb_set(result, '{primary_finding}', pg_temp.scrub_finding(result->'primary_finding'));
  END IF;
  RETURN result;
END
$$;

-- 告警正文：matched（整份 matched_summary）和顶层 primary_finding。键必须存在且类型对才处理，
-- 避免 jsonb_set 给原本没有这些键的行新建键。
CREATE OR REPLACE FUNCTION pg_temp.scrub_alert_body(body jsonb) RETURNS jsonb
LANGUAGE plpgsql IMMUTABLE AS $$
DECLARE result jsonb := body;
BEGIN
  IF jsonb_typeof(result) IS DISTINCT FROM 'object' THEN
    RETURN body;
  END IF;
  IF jsonb_typeof(result->'matched')='object' THEN
    result := jsonb_set(result, '{matched}', pg_temp.scrub_summary(result->'matched'));
  END IF;
  IF jsonb_typeof(result->'primary_finding')='object' THEN
    result := jsonb_set(result, '{primary_finding}', pg_temp.scrub_finding(result->'primary_finding'));
  END IF;
  RETURN result;
END
$$;

UPDATE security_events
SET matched_summary = pg_temp.scrub_summary(matched_summary)
WHERE matched_summary::text LIKE '%<已打码%'
  AND matched_summary IS DISTINCT FROM pg_temp.scrub_summary(matched_summary);

DO $do$
BEGIN
  IF to_regclass('alert_groups') IS NOT NULL THEN
    EXECUTE $q$
      UPDATE alert_groups
      SET body_json = pg_temp.scrub_alert_body(body_json)
      WHERE body_json::text LIKE '%<已打码%'
        AND body_json IS DISTINCT FROM pg_temp.scrub_alert_body(body_json)
    $q$;
  END IF;
END
$do$;

DO $do$
BEGIN
  IF to_regclass('alert_inbox') IS NOT NULL THEN
    EXECUTE $q$
      UPDATE alert_inbox
      SET body_json = pg_temp.scrub_alert_body(body_json)
      WHERE body_json::text LIKE '%<已打码%'
        AND body_json IS DISTINCT FROM pg_temp.scrub_alert_body(body_json)
    $q$;
  END IF;
END
$do$;

DO $do$
BEGIN
  IF to_regclass('request_logs') IS NOT NULL THEN
    EXECUTE $q$
      UPDATE request_logs
      SET input_audit_result = pg_temp.scrub_summary(input_audit_result)
      WHERE created_at >= TIMESTAMPTZ '2026-10-20 00:00:00+00'
        AND input_audit_result::text LIKE '%<已打码%'
        AND input_audit_result IS DISTINCT FROM pg_temp.scrub_summary(input_audit_result)
    $q$;
  END IF;
END
$do$;

DO $do$
BEGIN
  IF to_regclass('request_logs') IS NOT NULL THEN
    EXECUTE $q$
      UPDATE request_logs
      SET output_audit_result = pg_temp.scrub_summary(output_audit_result)
      WHERE created_at >= TIMESTAMPTZ '2026-10-20 00:00:00+00'
        AND output_audit_result::text LIKE '%<已打码%'
        AND output_audit_result IS DISTINCT FROM pg_temp.scrub_summary(output_audit_result)
    $q$;
  END IF;
END
$do$;
