-- 回滚迁移 1010（告警命中原文入库后证据身份保持不变）：恢复 850 的 jjd_alert_finding_metadata_v1 函数体。
-- 先回退应用版本（网关、正向代理、控制面），再执行本文件。
--
-- 回退前必须知道（原文已经入库，回退应用和数据库都删不掉它）：
-- 1. 原文暴露：应用回退到 2.9.21 后，2.9.22 期间入库的命中原文（security_events.matched_summary、
--    request_logs 的输入输出审计结果、alert_inbox 与 alert_groups 的正文）会经 /admin/v1/audit/events、
--    审计日志导出（/admin/v1/audit/export 的 JSON）、门户集成安全事件、告警收件箱（列表、折叠视图、导出），
--    原样暴露给没有内容证据权限的角色（部门负责人、按项目授权或自定义授权的角色、门户集成）——2.9.21 的
--    控制面不做剔除。阻断记录在 2.9.21 只读打码的 detail、溯源不返回摘要，不经它暴露。
-- 2. 告警组拆分：2.9.21 的控制面对 data_leak 命中按 raw_evidence 算告警组指纹，2.9.22 期间入库的事件
--    会按原文分成多个告警组（2.9.22 带 raw_evidence_sha256 时按规则编号归组）。
-- 3. 升级窗口：网关、正向代理先升到 2.9.22、控制面后升（或控制面升级失败停留在 2.9.21）时，
--    以上两条同样存在，直到控制面升到 2.9.22。
-- 4. 备份恢复：pg_restore 会重算存储型生成列 alert_read_metadata_v1。恢复到只有 850 函数体的库
--    （执行过本回滚，或没有 1010）时，带原文的事件按原文重算证据身份，所在案件可能显示为有新证据。
-- 5. 发件箱：网关异步写入安全事件经 outbox_events（事件发件箱）中转，payload_json 里同样是带原文的
--    matched_summary。outbox_events 不会自动删除（没有清理任务），回滚也不清理发件箱。
-- 如需在回退后让无权限角色看不到原文，只能在回退前用 2.9.22 控制面处置，或回退后人工清理上述表里的
-- raw_evidence、evidence_context（含 outbox_events 里的载荷；不可逆，需另行评估）。
--
-- 存量行的 alert_read_metadata_v1 是存储型生成列，回滚不重算；2.9.22 期间写入、带原文的事件以后若被更新
-- （例如 AI 复核回写），会按原文重算证据身份，所在案件可能因此显示为有新证据。
--
-- 关于证据身份的信任：1010 的函数直接采用 finding 里的 evidence_identity_sha256（只校验是 64 位十六进制）。
-- 这个字段由网关（securityFindingsToSummary 白名单构造）和正向代理（redactFindings，2.9.22 起丢弃引擎回包里
-- 的同名字段、只写自己按旧口径算出的值）写入；端点事件入库路径不透传 finding。
-- 本文件不删除 schema_migrations 里 1010 的记录：回滚后直接再升级，迁移运行器会认为 1010 已执行而跳过。
-- 回滚后如需再升级，先手工执行
--   DELETE FROM schema_migrations WHERE version = '1010_alert_evidence_identity_raw.sql';
-- 再运行升级。
BEGIN;

CREATE OR REPLACE FUNCTION jjd_alert_finding_metadata_v1(source jsonb)
RETURNS jsonb LANGUAGE plpgsql IMMUTABLE PARALLEL SAFE AS $$
DECLARE result jsonb; evidence text; key text;
BEGIN
  IF jsonb_typeof(source) IS DISTINCT FROM 'object' THEN RETURN 'null'::jsonb; END IF;
  SELECT COALESCE(jsonb_object_agg(k,v),'{}'::jsonb) INTO result
  FROM jsonb_each(source) AS fields(k,v)
  WHERE k=ANY(ARRAY['type','category','severity','effective_severity','rule_id','rule_name','rule_type',
    'action','action_taken','message_index','attachment_index','message_role','content_source',
    'source','stage','matched_location','location','review_state','counts_as_security_finding',
    'evidence_kind','exception_id','suppressed','semantic_status','inspection_status','target_host']);
  IF jsonb_typeof(source->'triage')='object' THEN
    result=result||jsonb_build_object('triage',jsonb_build_object(
      'review_state',source#>'{triage,review_state}','verdict',source#>'{triage,verdict}'));
  END IF;
  -- Only existence is used when deciding whether an unstructured legacy root
  -- declares a finding. Actual text is read from the original event for the page.
  FOREACH key IN ARRAY ARRAY['raw_evidence','matched_text_preview','redacted_evidence'] LOOP
    IF NULLIF(btrim(source->>key),'') IS NOT NULL THEN
      result=result||jsonb_build_object(key,'present');
    END IF;
  END LOOP;
  IF source->>'type'='semantic_attack' OR COALESCE(source->>'category','') LIKE 'semantic_%' THEN
    evidence=COALESCE(NULLIF(source->>'evidence_context',''),NULLIF(source->>'raw_evidence',''),NULLIF(source->>'matched_text_preview',''));
  ELSE
    evidence=COALESCE(NULLIF(source->>'raw_evidence',''),NULLIF(source->>'evidence_context',''),NULLIF(source->>'matched_text_preview',''));
  END IF;
  IF evidence IS NOT NULL THEN
    result=result||jsonb_build_object('_jjd_evidence_identity',encode(sha256(convert_to(evidence,'UTF8')),'hex'));
  END IF;
  RETURN result;
END $$;

COMMIT;
