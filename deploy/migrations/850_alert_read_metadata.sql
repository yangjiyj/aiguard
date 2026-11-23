BEGIN;

-- Compact, derived read metadata. Original evidence/severity/actions are untouched.
-- The versioned generated column stays synchronized on every insert/update.
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

CREATE OR REPLACE FUNCTION jjd_alert_read_metadata_v1(source jsonb)
RETURNS jsonb LANGUAGE plpgsql IMMUTABLE PARALLEL SAFE AS $$
DECLARE result jsonb; items jsonb;
BEGIN
  IF jsonb_typeof(source) IS DISTINCT FROM 'object' THEN RETURN '{}'::jsonb; END IF;
  -- Hold a detoasted value while extracting fields from a large evidence record.
  source=source||'{}'::jsonb;
  result=jjd_alert_finding_metadata_v1(source);
  IF jsonb_typeof(source->'findings')='array' THEN
    SELECT COALESCE(jsonb_agg(jjd_alert_finding_metadata_v1(value) ORDER BY ordinality),'[]'::jsonb)
      INTO items FROM jsonb_array_elements(source->'findings') WITH ORDINALITY;
    result=result||jsonb_build_object('findings',items);
  END IF;
  IF jsonb_typeof(source->'observations')='array' THEN
    result=result||jsonb_build_object('observations',CASE WHEN source->'observations'='[]'::jsonb THEN '[]'::jsonb ELSE '[{}]'::jsonb END);
  END IF;
  RETURN result;
END $$;

ALTER TABLE security_events ADD COLUMN IF NOT EXISTS alert_read_metadata_v1 jsonb
  GENERATED ALWAYS AS (jjd_alert_read_metadata_v1(matched_summary)) STORED;
COMMENT ON COLUMN security_events.alert_read_metadata_v1 IS
  'Derived compact list metadata; original security_events evidence is authoritative. Never returned as raw evidence.';

COMMIT;
