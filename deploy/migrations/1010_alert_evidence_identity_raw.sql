BEGIN;

-- 1010_alert_evidence_identity_raw.sql
-- 告警命中原文入库后证据身份保持不变（2.9.22 批次 6，用户 11-17 定命中内容、证据、前后文给原文）。
--
-- 背景：迁移 850 的 jjd_alert_finding_metadata_v1 按 raw_evidence → evidence_context → matched_text_preview
-- 的顺序取第一个非空值算 _jjd_evidence_identity（案件“有无新证据”据此判断）。2.9.21 及更早只存原文哈希和
-- 打码前后文；2.9.22 起网关和正向代理给字面类命中存了原文，若仍按原文算，同一命中升级前后会算出两个身份，
-- 已处置的案件会因为“新证据”重新打开。
--
-- 改法：数据面给存了原文的命中写 evidence_identity_sha256（按 2.9.21 落库内容算好的身份，空串表示 2.9.21
-- 下没有证据身份）。本迁移重定义 jjd_alert_finding_metadata_v1：带这个键的 finding 直接取它作证据身份，
-- 并且不输出 raw_evidence 的存在标记（2.9.21 的落库内容里没有原文），读取元数据与 2.9.21 逐字段相同。
-- 不带这个键的 finding（全部存量事件、语义类命中）走原有逻辑，函数输出与 850 完全一样。
--
-- 信任边界：函数直接采用 finding 里的 evidence_identity_sha256，只校验是 64 位小写十六进制，不重算。
-- 写入方只有网关（securityFindingsToSummary 按白名单构造 finding）和正向代理（redactFindings，2.9.22 起丢弃
-- 引擎回包里的同名字段、只写自己按旧口径算出的值）；端点事件入库路径自己组装摘要，不透传 finding。
-- 以后新增往 security_events.matched_summary 写 finding 的路径，必须同样丢弃外部传入的这个字段。
--
-- 只替换函数体，不改表、不重算存量行：security_events.alert_read_metadata_v1 是存储型生成列，存量行保持
-- 原值；之后插入或更新的行用新函数计算，存量行重算结果也不变（不含 evidence_identity_sha256）。
-- 函数属性（IMMUTABLE PARALLEL SAFE、无 search_path 设置）与 850 相同；调用它的 v1/v2 读取元数据函数
-- 在 876 设置的 search_path 不受影响。
-- 真库验证（库按 initdb 快照 + migration-runner 正式流程迁移，用例带 *_TEST_DATABASE_URL 才运行）：
-- governance-test: apps/gateway-core/internal/handler/alert_raw_evidence_db_test.go::TestRawEvidenceSummaryKeepsAlertReadMetadataOnPostgres
-- governance-test: apps/control-plane/internal/repository/alert_evidence_identity_raw_db_test.go::TestRawEvidenceEventsKeepCaseAndEvidenceNoveltyOnPostgres
-- 回滚：deploy/migrations/rollback/1010_alert_evidence_identity_raw.sql 恢复 850 的函数体；回退应用前先读
-- 那里的须知（回退后已入库原文对无内容证据权限角色的暴露、data_leak 拆组、升级窗口、备份恢复重算生成列）。

CREATE OR REPLACE FUNCTION jjd_alert_finding_metadata_v1(source jsonb)
RETURNS jsonb LANGUAGE plpgsql IMMUTABLE PARALLEL SAFE AS $$
DECLARE result jsonb; evidence text; key text; precomputed boolean;
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
  -- 2.9.22 起存了原文的命中带 evidence_identity_sha256：身份已按 2.9.21 落库内容算好。
  precomputed=source ? 'evidence_identity_sha256';
  -- Only existence is used when deciding whether an unstructured legacy root
  -- declares a finding. Actual text is read from the original event for the page.
  FOREACH key IN ARRAY ARRAY['raw_evidence','matched_text_preview','redacted_evidence'] LOOP
    IF precomputed AND key='raw_evidence' THEN CONTINUE; END IF;
    IF NULLIF(btrim(source->>key),'') IS NOT NULL THEN
      result=result||jsonb_build_object(key,'present');
    END IF;
  END LOOP;
  IF precomputed THEN
    IF (source->>'evidence_identity_sha256') ~ '^[0-9a-f]{64}$' THEN
      result=result||jsonb_build_object('_jjd_evidence_identity',source->>'evidence_identity_sha256');
    END IF;
    RETURN result;
  END IF;
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
