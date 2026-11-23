package repository

// Normalize and deduplicate in PostgreSQL before LIMIT/OFFSET. The request and
// message anchors are part of the key; a conversation key is never a grouping key.
const alertOccurrenceCTE = `
WITH events AS (
 SELECT se.id AS event_id, COALESCE(se.request_id,'') AS request_id,
   @case_event_fields@
   se.tenant_id, COALESCE(se.project_id,'') AS project_id, se.created_at,
   se.event_type, se.severity AS event_severity, se.rule_id AS event_rule_id,
   COALESCE(se.action_taken,'') AS event_action_taken,
   COALESCE(se.matched_summary,'{}'::jsonb) AS summary,
   -- Endpoint ingestion has already made a risk decision, but its compact read
   -- metadata contains no legacy finding declaration. Do not generalize this
   -- exception to arbitrary event types, severities, or untrusted sources.
   (se.event_type IN ('tool_execution_risk','agent_endpoint_risk')
     AND se.matched_summary->>'source'='agent_endpoint'
     AND ((se.action_taken='flag'
         AND se.matched_summary->>'risk_level' IN ('high','critical')
         AND se.matched_summary->>'decision' NOT IN ('would_block','would-block'))
       OR (se.action_taken='confirm' AND se.matched_summary->>'decision'='confirm')
       OR (se.action_taken='block'
         AND se.matched_summary->>'decision' IN ('block','blocked','deny','denied')))) AS verified_endpoint_risk,
   COALESCE(se.alert_group_id,'') AS alert_group_id,
   COALESCE(se.conversation_key,'') AS conversation_key,
   COALESCE(disposition_event.status,disposition_request.status,disposition_group.status,'open') AS disposition_status
 FROM security_events se
 @request_join@
 @case_join@
 LEFT JOIN audit_dispositions disposition_event ON disposition_event.tenant_id=se.tenant_id
   AND disposition_event.subject_type='security_event' AND disposition_event.subject_id=se.id
 LEFT JOIN audit_dispositions disposition_request ON disposition_request.tenant_id=se.tenant_id
   AND disposition_request.subject_type='request' AND disposition_request.subject_id=se.request_id
 LEFT JOIN alert_groups disposition_group ON disposition_group.tenant_id=se.tenant_id AND disposition_group.id=se.alert_group_id
 WHERE @event_where@
   AND LOWER(COALESCE(se.event_type,'')) NOT IN
     ('security_check_failed','security_output_check_failed','security_inspection_completed',
      'runtime_fault','runtime_failure','engine_error','detector_error')
),
expanded AS (
 SELECT e.*, x.finding, root.stage AS event_stage, root.review_state AS event_review_state,root.target_host AS root_target_host,
   CASE WHEN shape.structured THEN (x.ordinality-1)::int ELSE NULL END AS finding_index
 FROM events e
 CROSS JOIN LATERAL jsonb_to_record(
   CASE WHEN jsonb_typeof(summary)='object' THEN summary ELSE '{}'::jsonb END
 ) AS root(findings jsonb,observations jsonb,stage text,review_state text,target_host text)
 CROSS JOIN LATERAL (
   -- An explicit array is authoritative, including an empty/remediated result.
   SELECT COALESCE(jsonb_typeof(root.findings)='array',FALSE) AS structured
 ) shape
 CROSS JOIN LATERAL jsonb_array_elements(
   CASE WHEN shape.structured THEN root.findings
   ELSE jsonb_build_array(CASE WHEN jsonb_typeof(summary)='object'
     THEN summary - 'observations' - 'raw_findings' ELSE '{}'::jsonb END) END
 ) WITH ORDINALITY x(finding,ordinality)
 WHERE jsonb_typeof(x.finding)='object'
   -- Legacy roots require a recorded risk declaration, rule or hit evidence.
   -- An event type/severity/action alone must never manufacture a finding.
   AND (shape.structured OR verified_endpoint_risk OR COALESCE(
     CASE WHEN LOWER(TRIM(COALESCE(finding->>'category',''))) NOT IN
       ('','security_check','security_event','unknown','none','safe') THEN finding->>'category' END,
     CASE WHEN LOWER(TRIM(COALESCE(finding->>'type',''))) NOT IN
       ('','security_check','security_event','unknown','none','safe') THEN finding->>'type' END,
     NULLIF(TRIM(finding->>'rule_id'),''),NULLIF(TRIM(event_rule_id),''),
     NULLIF(TRIM(finding->>'redacted_evidence'),''),NULLIF(TRIM(finding->>'matched_text_preview'),''),
     NULLIF(TRIM(finding->>'raw_evidence'),'')
   ) IS NOT NULL)
   AND (shape.structured OR NOT COALESCE((
     jsonb_typeof(root.observations)='array' AND root.observations<>'[]'::jsonb),FALSE))
),
normalized AS (
 SELECT e.*,
   @case_category@ AS case_category,@case_key@ AS case_id,@case_evidence_key@ AS evidence_identity,
   'ao_' || md5(jsonb_build_array(event_id,finding_index)::text) AS id,
   COALESCE(NULLIF(finding->>'type',''),NULLIF(finding->>'category',''),event_type,'unknown') AS type,
   COALESCE(NULLIF(finding->>'category',''),NULLIF(finding->>'type',''),event_type,'unknown') AS category,
   LOWER(COALESCE(NULLIF(finding->>'effective_severity',''),NULLIF(finding->>'severity',''),
     CASE WHEN finding_index IS NULL THEN event_severity END,'unknown')) AS severity,
   COALESCE(NULLIF(finding->>'rule_id',''),CASE WHEN finding_index IS NULL THEN event_rule_id END,'') AS rule_id,
   COALESCE(finding->>'rule_name','') AS rule_name,
   LOWER(COALESCE(NULLIF(finding->>'action',''),NULLIF(finding->>'action_taken',''),
     CASE WHEN finding_index IS NULL THEN NULLIF(event_action_taken,'') END,'unknown')) AS action_taken,
   CASE WHEN COALESCE(finding->>'message_index',finding#>>'{location,message_index}') ~ '^[0-9]{1,9}$'
     THEN COALESCE(finding->>'message_index',finding#>>'{location,message_index}')::int END AS message_index,
   CASE WHEN COALESCE(finding->>'attachment_index',finding#>>'{location,attachment_index}') ~ '^[0-9]{1,9}$'
     THEN COALESCE(finding->>'attachment_index',finding#>>'{location,attachment_index}')::int END AS attachment_index,
   COALESCE(finding->>'message_role','') AS message_role,
   COALESCE(NULLIF(finding->>'content_source',''),finding->>'source','') AS content_source,
   COALESCE(NULLIF(finding->>'stage',''),event_stage,'') AS stage,
   COALESCE(NULLIF(finding->>'matched_location',''),finding#>>'{location,matched_location}',
     CASE WHEN jsonb_typeof(finding->'location')='string' THEN finding->>'location' END,'') AS matched_location,
   LOWER(COALESCE(NULLIF(finding->>'review_state',''),NULLIF(finding#>>'{triage,review_state}',''),
     NULLIF(finding#>>'{triage,verdict}',''),event_review_state,'')) AS review_state,
   COALESCE(NULLIF(finding->>'evidence_reason',''),NULLIF(finding->>'reason',''),finding#>>'{triage,reason}','') AS reason
 FROM expanded e
 WHERE LOWER(TRIM(COALESCE(finding->>'counts_as_security_finding','true'))) <> 'false'
   AND NOT @operational_finding@
   AND (finding_index IS NOT NULL OR NOT @operational_legacy@)
   AND LOWER(COALESCE(finding->>'evidence_kind','')) NOT IN ('runtime','observation','telemetry')
   AND LOWER(COALESCE(finding->>'type','')) NOT IN ('system','runtime','runtime_fault','runtime_failure','observation','telemetry')
   AND LOWER(COALESCE(finding->>'category','')) NOT IN
     ('system','runtime','runtime_fault','runtime_failure','security_check_failed','security_output_check_failed',
      'security_engine_unavailable','security_engine_error','detector_error','engine_error',
      'file_content_request_oversized','request_body_limit_exceeded','security_inspection_completed')
),
classified AS (
 SELECT n.*,
   -- Review labels are advisory, including pending/benign/false-positive
   -- opinions on an active finding. Only explicit dispositions or suppression
   -- controls can hide a row; authoritative counts=false was excluded above.
   CASE
     WHEN disposition_status IN ('false_positive','suppressed','ignored') THEN disposition_status
     WHEN COALESCE(finding->>'exception_id','')<>'' THEN 'policy_exception'
     WHEN LOWER(COALESCE(finding->>'suppressed','false'))='true' THEN 'finding_suppressed'
     ELSE '' END AS suppression_reason
 FROM normalized n
 WHERE NOT (
   LOWER(COALESCE(finding->>'rule_type',''))='agent_detect'
   AND LOWER(category) LIKE 'agent_%' AND LOWER(category) NOT LIKE 'agent_canary%'
   AND action_taken NOT IN ('block','mask','quarantine','deny')
   AND review_state NOT IN ('confirmed_risk','confirmed')
 )
),
keyed AS MATERIALIZED (
 SELECT event_id,request_id,tenant_id,project_id,created_at,event_action_taken,
   case_id,case_category,evidence_identity,occurred_at,time_known,case_conversation,
   alert_group_id,conversation_key,disposition_status,
   finding_index,id,type,category,severity,rule_id,rule_name AS finding_rule_name,action_taken,
   (content_source='model_output' AND matched_location ~ '^content\[[0-9]+:[0-9]+\]$') AS has_output_anchor,
   message_index,attachment_index,message_role,content_source,stage,matched_location,
   review_state,suppression_reason,suppression_reason<>'' AS suppressed,
   CASE WHEN content_source='model_output' AND matched_location ~ '^content\[[0-9]+:[0-9]+\]$'
   THEN jsonb_build_array(event_id,project_id,stage,content_source,type,category,matched_location)
   WHEN request_id<>'' AND message_index IS NOT NULL
     AND matched_location ~ '\[[0-9]+:[0-9]+\]$'
   THEN jsonb_build_array(request_id,project_id,message_index,attachment_index,message_role,stage,content_source,type,category,matched_location)
   ELSE jsonb_build_array(event_id,finding_index) END AS occurrence_key
 FROM classified c WHERE @category_prefilter@
),
ranked AS (
 SELECT k.*,
   ROW_NUMBER() OVER (PARTITION BY occurrence_key ORDER BY suppressed,CASE WHEN has_output_anchor THEN CASE severity WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END ELSE 0 END DESC,event_id,finding_index) AS occurrence_rank,
   COUNT(*) OVER (PARTITION BY occurrence_key) AS duplicate_count
 FROM keyed k
),
effective AS (
 SELECT * FROM ranked WHERE occurrence_rank=1
),
filtered AS MATERIALIZED (
 SELECT * FROM effective WHERE @row_where@
),
visible AS (
 SELECT * FROM filtered WHERE ($4::boolean OR NOT suppressed) AND (@status_where@)
),
page AS (
 SELECT * FROM visible ORDER BY created_at DESC,event_id DESC,finding_index ASC NULLS LAST
 LIMIT $5 OFFSET $6
),
page_occurrence_keys AS MATERIALIZED (
 SELECT DISTINCT occurrence_key FROM page
),
page_occurrence_stats AS MATERIALIZED (
 SELECT k.occurrence_key,COUNT(*) AS duplicate_count,
   COALESCE(jsonb_agg(DISTINCT k.rule_id) FILTER(WHERE k.rule_id<>''),'[]'::jsonb) AS rule_ids
 FROM keyed k JOIN page_occurrence_keys wanted USING(occurrence_key)
 GROUP BY k.occurrence_key
),
page_details AS (
 -- Large evidence and request identities are read only for this page. Carrying
 -- raw JSON through ranking/counts used hundreds of MB of temporary disk and
 -- rescanned it once per displayed rule list on the default 90-day view.
 SELECT p.*, evidence.finding,
   COALESCE(se.matched_summary->>'semantic_status','') AS semantic_status,
   COALESCE(se.matched_summary->>'semantic_reason','') AS semantic_reason,
   COALESCE(NULLIF(to_jsonb(rl)->>'proxy_target_host',''),se.matched_summary->>'target_host','') AS target_host,
   COALESCE(to_jsonb(rl)->>'model_id','') AS model_id,
   COALESCE(display_model.model_name,'') AS model_name,
   COALESCE(to_jsonb(rl)->>'delivery_outcome','') AS delivery_outcome,
   COALESCE(to_jsonb(rl)->>'request_status','') AS request_status,
   COALESCE(evidence.finding->>'rule_name','') AS rule_name,
   COALESCE(se.matched_summary->'block'->>'managed_behavior','') AS managed_behavior,
   COALESCE(NULLIF(evidence.finding->>'evidence_reason',''),NULLIF(evidence.finding->>'reason',''),
     evidence.finding#>>'{triage,reason}','') AS reason,
   COALESCE(NULLIF(se.principal_key,''),pc.value->>'principal_key','') AS principal_key,
   @actor@ AS actor_user_id,
   COALESCE(rl.client_id,'') AS client_id, COALESCE(rl.session_id,'') AS session_id,
   CASE WHEN se.matched_summary->>'source'='agent_endpoint' AND agent_evidence_event.id IS NOT NULL
     THEN COALESCE(agent_evidence_event.session_id,'') ELSE '' END AS agent_session_id,
   CASE WHEN se.matched_summary->>'source'='agent_endpoint' THEN jsonb_build_object(
     'status',CASE WHEN agent_evidence_event.id IS NULL THEN 'unmatched' ELSE 'matched' END,
     'agent_event_id',COALESCE(agent_evidence_event.id,''),
     'endpoint_id',COALESCE(agent_evidence_event.endpoint_id,''),
     'session_id',COALESCE(agent_evidence_event.session_id,''),
     'event_type',COALESCE(agent_evidence_event.event_type,''),
     'tool_use_id',COALESCE(agent_evidence_event.tool_use_id,''),
     'tool_name',COALESCE(agent_evidence_event.tool_name,''),
     'tool_type',COALESCE(agent_evidence_event.tool_type,''),
     'local_decision',CASE WHEN agent_evidence_event.id IS NULL THEN '{}'::jsonb ELSE
       jsonb_strip_nulls(jsonb_build_object(
         'source',NULLIF(agent_evidence_event.local_decision->>'source',''),
         'mode',NULLIF(agent_evidence_event.local_decision->>'mode',''),
         'effective_decision',COALESCE(NULLIF(agent_evidence_event.local_decision->>'effective_decision',''),NULLIF(agent_evidence_event.local_decision->>'effective','')),
         'decision',NULLIF(agent_evidence_event.local_decision->>'decision',''),
         'raw_decision',NULLIF(agent_evidence_event.local_decision->>'raw_decision',''),
         'rule_id',NULLIF(agent_evidence_event.local_decision->>'rule_id',''),
         'matched_rule_id',NULLIF(agent_evidence_event.local_decision->>'matched_rule_id',''),
         'policy_version',agent_evidence_event.local_decision->'policy_version',
         'policy_checksum',NULLIF(agent_evidence_event.local_decision->>'policy_checksum',''),
         'risk_level',NULLIF(agent_evidence_event.local_decision->>'risk_level','')
       )) END
   ) ELSE NULL END AS agent_endpoint_evidence,
   COALESCE(rl.agent_type,'') AS agent_type, pc.value AS principal,
   COALESCE(NULLIF(rl.proxy_source_ip,''),NULLIF(rl.source_ip,''),se.matched_summary->>'source_ip','') AS source_ip,
   COALESCE(rl.proxy_mode,'') AS access_direction,
   COALESCE(NULLIF(rl.access_type,''),se.matched_summary->>'access_type','') AS access_type,
   COALESCE(NULLIF(rl.client_product,''),se.matched_summary->>'product','') AS client_product
 FROM page p
 JOIN security_events se ON se.tenant_id=p.tenant_id AND se.id=p.event_id
 LEFT JOIN agent_events agent_evidence_event ON
   agent_evidence_event.tenant_id=p.tenant_id
   AND agent_evidence_event.id=se.matched_summary->>'agent_event_id'
   AND agent_evidence_event.security_event_id=se.id
   AND agent_evidence_event.endpoint_id=se.matched_summary->>'endpoint_id'
   AND agent_evidence_event.session_id=COALESCE(se.matched_summary->>'session_id','')
   AND agent_evidence_event.event_type=se.matched_summary->>'event_type'
   AND agent_evidence_event.tool_use_id=COALESCE(se.matched_summary->>'tool_use_id','')
 @page_request_join@
 LEFT JOIN LATERAL (
   SELECT m.model_name FROM models m JOIN providers provider ON provider.id=m.provider_id
   WHERE provider.tenant_id=p.tenant_id
     AND m.id=COALESCE(NULLIF(to_jsonb(rl)->>'model_id',''),se.matched_summary->>'target_host','')
   LIMIT 1
 ) display_model ON true
 CROSS JOIN LATERAL (
   SELECT CASE WHEN p.finding_index IS NOT NULL THEN se.matched_summary->'findings'->p.finding_index
     ELSE se.matched_summary - 'observations' - 'raw_findings' END AS finding
 ) evidence
)
`
