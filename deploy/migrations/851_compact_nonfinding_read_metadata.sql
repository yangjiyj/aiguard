BEGIN;
-- Only the derived column introduced by 850 is rebuilt. Original events remain
-- untouched. Null slots preserve the original finding indices exactly.
CREATE OR REPLACE FUNCTION jjd_alert_read_metadata_v2(source jsonb)
RETURNS jsonb LANGUAGE plpgsql IMMUTABLE PARALLEL SAFE AS $$
DECLARE result jsonb; items jsonb;
BEGIN
  IF jsonb_typeof(source) IS DISTINCT FROM 'object' THEN RETURN '{}'::jsonb; END IF;
  -- Hold a detoasted value while extracting fields from a large evidence record.
  source=source||'{}'::jsonb;
  result=jjd_alert_finding_metadata_v1(source);
  IF jsonb_typeof(source->'findings')='array' THEN
    SELECT COALESCE(jsonb_agg(CASE WHEN lower(btrim(coalesce(value->>'counts_as_security_finding','true')))='false' THEN 'null'::jsonb ELSE jjd_alert_finding_metadata_v1(value) END ORDER BY ordinality),'[]'::jsonb)
      INTO items FROM jsonb_array_elements(source->'findings') WITH ORDINALITY;
    result=result||jsonb_build_object('findings',items);
  END IF;
  IF jsonb_typeof(source->'observations')='array' THEN
    result=result||jsonb_build_object('observations',CASE WHEN source->'observations'='[]'::jsonb THEN '[]'::jsonb ELSE '[{}]'::jsonb END);
  END IF;
  RETURN result;
END $$;

ALTER TABLE security_events DROP COLUMN alert_read_metadata_v1;
ALTER TABLE security_events ADD COLUMN alert_read_metadata_v1 jsonb
 GENERATED ALWAYS AS (jjd_alert_read_metadata_v2(matched_summary)) STORED;
COMMENT ON COLUMN security_events.alert_read_metadata_v1 IS
 'Compact derived metadata; counts=false findings are null placeholders, original evidence remains authoritative.';
COMMIT;
