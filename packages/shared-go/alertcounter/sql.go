// Package alertcounter defines the same derived counters for every writer.
package alertcounter

const facts = `,
 linked_facts AS (
  SELECT se.request_id, COALESCE(NULLIF(se.conversation_key,''),se.request_id) AS occurrence_key,se.principal_key
  FROM security_events se,target WHERE se.tenant_id=$1 AND se.alert_group_id=target.group_id
  UNION ALL
  SELECT seo.request_id,COALESCE(NULLIF(seo.conversation_key,''),seo.request_id),seo.principal_key
  FROM security_event_occurrences seo,target WHERE seo.tenant_id=$1 AND seo.alert_group_id=target.group_id
 ), occurrence_facts AS (
  SELECT occurrence_key,principal_key FROM linked_facts
  UNION ALL
  SELECT COALESCE(NULLIF(se.conversation_key,''),ag.request_id),COALESCE(NULLIF(se.principal_key,''),ag.principal_key)
  FROM alert_groups ag JOIN target ON ag.id=target.group_id
  LEFT JOIN security_events se ON se.tenant_id=ag.tenant_id AND se.id=ag.representative_event_id
  WHERE ag.tenant_id=$1 AND NOT EXISTS(SELECT 1 FROM linked_facts f WHERE f.request_id=ag.request_id)
 ), agg AS (
  SELECT COUNT(DISTINCT occurrence_key) FILTER(WHERE COALESCE(occurrence_key,'')<>'') AS occ,
   COUNT(DISTINCT principal_key) FILTER(WHERE COALESCE(principal_key,'')<>'') AS users
  FROM occurrence_facts
 )`

const writeCounters = ` UPDATE alert_groups ag SET distinct_occurrences=agg.occ,affected_users=agg.users,last_calc_at=NOW()
 FROM target,agg WHERE ag.tenant_id=$1 AND ag.id=target.group_id RETURNING agg.occ,agg.users`

// ByGroup uses tenant ID and group ID. Counts are snapshots, never increments.
const ByGroup = `WITH target AS (SELECT id AS group_id FROM alert_groups WHERE tenant_id=$1 AND id=$2)` + facts + writeCounters

// ByRepresentative uses tenant ID and representative event ID.
const ByRepresentative = `WITH target AS (SELECT alert_group_id AS group_id FROM security_events WHERE tenant_id=$1 AND id=$2)` + facts + writeCounters

// PreviewByGroup uses exactly the same facts without a write or row lock.
const PreviewByGroup = `WITH target AS (SELECT id AS group_id FROM alert_groups WHERE tenant_id=$1 AND id=$2)` + facts + ` SELECT agg.occ,agg.users FROM agg`
