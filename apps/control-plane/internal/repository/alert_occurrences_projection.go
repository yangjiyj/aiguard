package repository

// Only page rows are enriched with display identities. Never return the original
// finding JSON: it contains raw source windows and detector free-text reasons.
const alertOccurrenceProjection = `
, decorated AS (
 SELECT p.created_at,p.event_id,p.finding_index,
   jsonb_build_object(
     'id',p.id,'event_id',p.event_id,'request_id',p.request_id,'project_id',p.project_id,
     'case_id',p.case_id,'occurred_at',p.occurred_at,'time_known',p.time_known,
     'created_at',p.created_at,'finding_index',p.finding_index,'duplicate_count',occurrence_stats.duplicate_count,
     'rule_ids',occurrence_stats.rule_ids,
     'type',p.type,'category',p.category,'severity',p.severity,'rule_id',p.rule_id,'rule_name',p.rule_name,
     'managed_behavior',p.managed_behavior,
     'rule_type',COALESCE(p.finding->>'rule_type',''),'policy_code',COALESCE(p.finding->>'policy_code',''),
     'severity_downgrade_reason',COALESCE(p.finding#>>'{triage,severity_downgrade_reason}',''),
     'action_taken',p.action_taken,'event_action_taken',p.event_action_taken,
     'suppressed',p.suppressed,'suppression_reason',p.suppression_reason,
     'review_state',p.review_state,'disposition_status',p.disposition_status,'alert_group_id',p.alert_group_id
   ) || jsonb_build_object(
     'message_index',p.message_index,'attachment_index',p.attachment_index,'message_role',p.message_role,
     'content_source',p.content_source,'stage',p.stage,'matched_location',p.matched_location,
     'location_status',CASE WHEN (p.message_index IS NOT NULL OR p.content_source='model_output') AND p.matched_location ~ '^content\[[0-9]+:[0-9]+\]$' THEN 'available' ELSE 'missing' END,
     'reason',CASE WHEN $3::boolean THEN p.reason ELSE '' END,
     'reason_status',CASE WHEN p.reason='' THEN 'missing' WHEN $3::boolean THEN 'available' ELSE 'restricted' END,
     'semantic_status',p.semantic_status,'semantic_reason',p.semantic_reason,
     'raw_evidence_sha256',CASE WHEN $2::boolean THEN COALESCE(p.finding->>'raw_evidence_sha256','') ELSE '' END,
     'evidence_context_sha256',CASE WHEN $2::boolean THEN COALESCE(p.finding->>'evidence_context_sha256','') ELSE '' END,
     'evidence_kind',COALESCE(p.finding->>'evidence_kind',''),
     'detection_method',COALESCE(p.finding#>>'{triage,detection_method}',''),
     'confidence_kind',COALESCE(p.finding#>>'{triage,confidence_kind}',''),
     'validation_status',COALESCE(p.finding#>>'{triage,validation_status}',''),
     'credential_validity',COALESCE(p.finding#>>'{triage,credential_validity}',''),
     'model_review_status',COALESCE(p.finding#>>'{triage,review_status}',''),
     'risk_basis',COALESCE(p.finding#>>'{triage,risk_basis}',''),
     'redacted_evidence',COALESCE(NULLIF(p.finding->>'redacted_evidence',''),NULLIF(p.finding->>'matched_text_preview',''),''),
     'evidence_status',CASE
       WHEN COALESCE(NULLIF(p.finding->>'redacted_evidence',''),NULLIF(p.finding->>'matched_text_preview',''),'')<>'' THEN 'available'
       WHEN COALESCE(p.finding->>'raw_evidence','')='' AND COALESCE(p.finding->>'evidence_context','')=''
         AND COALESCE(p.finding->>'matched_text_preview','')='' THEN 'missing'
       WHEN $3::boolean THEN 'available' ELSE 'restricted' END,
     'raw_evidence',CASE WHEN $2::boolean THEN COALESCE(p.finding->>'raw_evidence','') ELSE '' END,
     'raw_evidence_truncated',$2::boolean AND COALESCE(p.finding->>'raw_evidence','')<>'' AND LOWER(COALESCE(p.finding->>'raw_evidence_truncated',''))='true',
     'raw_evidence_omitted',LOWER(COALESCE(p.finding->>'raw_evidence_omitted',''))='true',
     'matched_text_preview',CASE WHEN $2::boolean THEN COALESCE(p.finding->>'matched_text_preview','') ELSE '' END,
     'evidence_context',CASE WHEN $2::boolean THEN COALESCE(p.finding->>'evidence_context','') ELSE '' END,
     'raw_evidence_status',CASE WHEN NOT $3::boolean THEN 'restricted'
       WHEN COALESCE(p.finding->>'raw_evidence','')='' AND COALESCE(p.finding->>'evidence_context','')='' THEN 'missing'
       WHEN NOT $2::boolean THEN 'not_requested' ELSE 'available' END
   ) || jsonb_build_object(
     'actor_user_id',p.actor_user_id,'actor_name',COALESCE(actor.username,''),
     'actor_department_id',dep.actor_department_id,'actor_department_name',COALESCE(actor_department.name,''),
     'key_owner_user_id',COALESCE(NULLIF(p.principal->>'key_owner_user_id',''),ik.user_id,''),
     'key_owner_name',COALESCE(owner_user.username,''),
     'department_id',dep.department_id,'department_name',COALESCE(department.name,''),
     'agent_type',p.agent_type,
     'credential_id',COALESCE(NULLIF(p.principal->>'key_id',''),ik.id,NULLIF(p.client_id,''),''),
     'credential_name',COALESCE(ik.name,''),
     'principal_key',p.principal_key,'identity_source',COALESCE(p.principal->>'identity_source',''),
     'identity_reliability',CASE
       WHEN p.actor_user_id<>'' AND p.principal->>'trust_level'='authenticated' THEN 'authenticated'
       WHEN p.actor_user_id<>'' THEN 'recorded_user'
       WHEN ik.id IS NOT NULL OR p.principal->>'trust_level'='key_bound'
         OR p.principal->>'identity_source' IN ('upstream_credential','upstream_account') THEN 'credential'
       ELSE 'unknown' END,
     'source_ip',p.source_ip,'access_direction',p.access_direction,
     'access_type',p.access_type,'client_product',p.client_product,
     'target_host',p.target_host,'model_id',p.model_id,'model_name',p.model_name,'delivery_outcome',p.delivery_outcome,'request_status',p.request_status,
     'conversation_key',p.conversation_key,'conversation_id',COALESCE(conv.conversation_id,''),
     'session_id',p.session_id,'agent_session_id',p.agent_session_id,
      'agent_endpoint_evidence',p.agent_endpoint_evidence,
     'conversation_source',CASE WHEN p.conversation_key<>'' THEN 'security_event'
       WHEN p.session_id<>'' THEN 'request_session'
       WHEN COALESCE(conv.conversation_id,'')<>'' THEN 'access_content' ELSE 'missing' END,
     'conversation_reliability',CASE WHEN p.conversation_key<>'' AND p.conversation_key=p.request_id THEN 'request_only'
       WHEN p.conversation_key<>'' OR p.session_id<>'' OR COALESCE(conv.conversation_id,'')<>'' THEN 'recorded'
       ELSE 'unknown' END
   ) AS payload
 FROM page_details p
 JOIN page_occurrence_stats occurrence_stats ON occurrence_stats.occurrence_key=p.occurrence_key
 LEFT JOIN users actor ON actor.tenant_id=p.tenant_id AND actor.id=p.actor_user_id
 LEFT JOIN LATERAL (
   SELECT k.id,k.name,k.user_id FROM internal_keys k
   WHERE k.tenant_id=p.tenant_id AND
     (k.id=COALESCE(NULLIF(p.principal->>'key_id',''),p.client_id)
      OR (LEFT(p.client_id,7)='caller_' AND LEFT(k.key_hash,12)=SUBSTRING(p.client_id FROM 8)))
   ORDER BY k.id LIMIT 1
 ) ik ON TRUE
 LEFT JOIN users owner_user ON owner_user.tenant_id=p.tenant_id
   AND owner_user.id=COALESCE(NULLIF(p.principal->>'key_owner_user_id',''),ik.user_id)
 LEFT JOIN LATERAL (
   SELECT tm.team_id FROM team_members tm
   JOIN teams t ON t.id=tm.team_id AND t.tenant_id=p.tenant_id
   WHERE tm.user_id=p.actor_user_id ORDER BY tm.created_at,tm.team_id LIMIT 1
 ) actor_team ON TRUE
 LEFT JOIN LATERAL (
   SELECT CASE WHEN p.actor_user_id<>'' THEN
     COALESCE(NULLIF(p.principal#>>'{actor_department_ids,0}',''),NULLIF(to_jsonb(actor)->>'department_id',''),actor_team.team_id,'')
     ELSE '' END AS actor_department_id,
     COALESCE(NULLIF(p.principal->>'application_department_id',''),
       CASE WHEN p.actor_user_id<>'' THEN COALESCE(NULLIF(p.principal#>>'{actor_department_ids,0}',''),
         NULLIF(to_jsonb(actor)->>'department_id',''),actor_team.team_id) END,'') AS department_id
 ) dep ON TRUE
 LEFT JOIN teams actor_department ON actor_department.tenant_id=p.tenant_id AND actor_department.id=dep.actor_department_id
 LEFT JOIN teams department ON department.tenant_id=p.tenant_id AND department.id=dep.department_id
 LEFT JOIN LATERAL (
   SELECT a.conversation_id FROM access_content_logs a
   WHERE a.tenant_id=p.tenant_id AND a.request_id=p.request_id AND COALESCE(a.conversation_id,'')<>''
   ORDER BY a.created_at DESC,a.id LIMIT 1
 ) conv ON TRUE
)
SELECT COALESCE((SELECT jsonb_agg(payload ORDER BY created_at DESC,event_id DESC,finding_index ASC NULLS LAST) FROM decorated),'[]'::jsonb),
 (SELECT COUNT(*) FROM visible),
 (SELECT jsonb_build_object(
   'handled',COUNT(*) FILTER (WHERE NOT suppressed AND disposition_status IN ('resolved','closed','accepted','escalated','acknowledged','confirmed')),
   'false_positive',COUNT(*) FILTER (WHERE disposition_status='false_positive' OR suppression_reason='false_positive'),
   'last_24h',COUNT(*) FILTER (WHERE created_at>=now()-interval '24 hours'),
   'previous_24h',COUNT(*) FILTER (WHERE created_at>=now()-interval '48 hours' AND created_at<now()-interval '24 hours'),
   'blocked_24h',COUNT(*) FILTER (WHERE created_at>=now()-interval '24 hours' AND event_action_taken IN ('block','blocked','deny','security_blocked','tool_attempt_blocked')),
   'pending_high',COUNT(*) FILTER (WHERE NOT suppressed AND disposition_status='open' AND severity IN ('critical','high')),
   'pending_medium',COUNT(*) FILTER (WHERE NOT suppressed AND disposition_status='open' AND severity='medium'),
   'pending_low',COUNT(*) FILTER (WHERE NOT suppressed AND disposition_status='open' AND severity='low'),
   'total',COUNT(*),'active',COUNT(*) FILTER (WHERE NOT suppressed),
   'suppressed',COUNT(*) FILTER (WHERE suppressed),
   'pending',COUNT(*) FILTER (WHERE NOT suppressed AND disposition_status='open'),
   'critical',COUNT(*) FILTER (WHERE NOT suppressed AND severity='critical'),
   'high',COUNT(*) FILTER (WHERE NOT suppressed AND severity='high'),
   'medium',COUNT(*) FILTER (WHERE NOT suppressed AND severity='medium'),
   'low',COUNT(*) FILTER (WHERE NOT suppressed AND severity='low')
 ) FROM filtered),
 @operational_count@
`
