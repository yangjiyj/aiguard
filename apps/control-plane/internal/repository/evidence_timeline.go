package repository

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"
)

type EvidenceTimelineEvent struct {
	ID        string
	RequestID string
	Type      string
	Title     string
	Detail    string
	Status    string
	EventKind string
	FactLabel string
	Timestamp time.Time
	Count     int
}

const evidenceTimelineAttemptPredicateSQL = `(
	(` + riskOverviewEventKindSQL + `) = 'invocation_proposed'
	OR ((` + riskOverviewEventKindSQL + `) = 'execution_forwarded' AND COALESCE(tcl.execution_observed, FALSE))
)`

const evidenceTimelineAttemptKeySQL = `CASE
	WHEN COALESCE(tcl.tool_call_id, '') <> '' AND COALESCE(tcl.request_id, '') <> ''
		THEN jsonb_build_array('request', tcl.request_id, 'call', tcl.tool_call_id)::text
	WHEN COALESCE(tcl.tool_call_id, '') <> '' AND COALESCE(tcl.trace_id, '') <> ''
		THEN jsonb_build_array('trace', tcl.trace_id, 'call', tcl.tool_call_id)::text
	ELSE jsonb_build_array('id', tcl.id)::text END`

type evidenceTimelineSummaryBucket struct {
	event   EvidenceTimelineEvent
	samples []string
	seen    map[string]bool
}

func evidenceTimelineFactLabel(event EvidenceTimelineEvent) string {
	if event.Type != "tool_action" && event.Type != "tool_inventory" {
		return ""
	}
	switch event.EventKind {
	case "definition_exposed":
		return "已暴露工具定义"
	case "invocation_proposed":
		return "调用请求"
	case "execution_forwarded":
		return "已转发执行"
	case "result_observed":
		return "已观察结果"
	case "confirmation_replay":
		return "审批回放"
	default:
		return "工具审计事件"
	}
}

func evidenceTimelineModelOutcome(status string) string {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "success", "succeeded", "completed", "ok":
		return "success"
	case "", "unknown":
		return "unknown"
	case "in_progress", "received":
		return "in_progress"
	default:
		return "failed"
	}
}

func retentionOutcomeTitle(status string) string {
	switch status {
	case "blocked":
		return "请求被拒绝（具体原因未留存）"
	case "egress_denied":
		return "目标地址被访问控制拒绝"
	case "target_resolution_failed":
		return "目标域名解析失败或超时"
	case "model_not_found":
		return "请求的模型不存在或已停用"
	case "cancelled", "canceled", "interrupted":
		return "请求已取消或中断"
	case "failed", "provider_error", "model_route_unavailable":
		return "模型调用失败"
	case "security_replied":
		return "网关返回安全回复"
	default:
		return ""
	}
}

func summarizeEvidenceTimeline(events []EvidenceTimelineEvent) []EvidenceTimelineEvent {
	buckets := make(map[string]*evidenceTimelineSummaryBucket, len(events))
	for _, event := range events {
		key := event.ID
		switch event.Type {
		case "model_call", "model_calls":
			event.Status = evidenceTimelineModelOutcome(event.Status)
			key = "model_calls:" + event.Status
		case "tool_action":
			if event.EventKind == "invocation_proposed" {
				event.Status = ""
			}
			key = strings.Join([]string{"tool", event.EventKind, event.Title, event.Status}, "\x00")
		case "tool_inventory":
			key = "tool_inventory"
		case "artifact":
			key = strings.Join([]string{"artifact", event.Title, event.Status}, "\x00")
		}

		bucket, ok := buckets[key]
		if !ok {
			event.Count = 0
			if event.Type == "model_call" || event.Type == "model_calls" {
				event.ID = "summary:model_calls:" + event.Status
				event.Type = "model_calls"
				event.Title = "模型交互"
			}
			bucket = &evidenceTimelineSummaryBucket{event: event, seen: make(map[string]bool)}
			buckets[key] = bucket
		}

		count := event.Count
		if count < 1 {
			count = 1
		}
		bucket.event.Count += count
		if event.Timestamp.Before(bucket.event.Timestamp) {
			bucket.event.Timestamp = event.Timestamp
		}
		if event.Detail != "" && !bucket.seen[event.Detail] {
			bucket.seen[event.Detail] = true
			if len(bucket.samples) < 3 {
				bucket.samples = append(bucket.samples, event.Detail)
			}
		}
	}

	out := make([]EvidenceTimelineEvent, 0, len(buckets))
	for _, bucket := range buckets {
		bucket.event.Detail = strings.Join(bucket.samples, "；")
		if bucket.event.Count > len(bucket.samples) && len(bucket.samples) > 0 {
			bucket.event.Detail += fmt.Sprintf("；其余 %d 次已折叠", bucket.event.Count-len(bucket.samples))
		}
		out = append(out, bucket.event)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Timestamp.Equal(out[j].Timestamp) {
			return out[i].ID < out[j].ID
		}
		return out[i].Timestamp.Before(out[j].Timestamp)
	})
	return out
}

func compactEvidenceToolInventory(detail string, count int) string {
	const maxVisibleTools = 12
	names := strings.Split(detail, "、")
	if len(names) <= maxVisibleTools {
		return detail
	}
	remaining := count - maxVisibleTools
	if remaining < 1 {
		remaining = len(names) - maxVisibleTools
	}
	return strings.Join(names[:maxVisibleTools], "、") + fmt.Sprintf("，另有 %d 种工具已折叠", remaining)
}

func normalizeEvidenceTimelineIDs(ids []string) []string {
	seen := make(map[string]bool, len(ids))
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		id = strings.TrimSpace(id)
		if id == "" || seen[id] {
			continue
		}
		seen[id] = true
		out = append(out, id)
	}
	return out
}

func (r *RequestLogRepository) ListEvidenceTimeline(ctx context.Context, tenantID string, requestIDs []string) ([]EvidenceTimelineEvent, error) {
	return r.listEvidenceTimeline(ctx, tenantID, requestIDs, "", time.Time{}, time.Time{})
}

func (r *RequestLogRepository) ListEvidenceTimelineScoped(ctx context.Context, tenantID string, requestIDs []string, start, end time.Time, scope string) ([]EvidenceTimelineEvent, error) {
	return r.listEvidenceTimeline(ctx, tenantID, requestIDs, scope, start, end)
}

func (r *RequestLogRepository) listEvidenceTimeline(ctx context.Context, tenantID string, requestIDs []string, scope string, start, end time.Time) ([]EvidenceTimelineEvent, error) {
	requestIDs = normalizeEvidenceTimelineIDs(requestIDs)
	if tenantID == "" || len(requestIDs) == 0 {
		return []EvidenceTimelineEvent{}, nil
	}
	scopes := EnvironmentScopesForRead(scope)
	scoped := len(scopes) > 0 && !start.IsZero() && !end.IsZero()
	requestWindow := ""
	toolWindow := ""
	artifactWindow := ""
	args := []interface{}{tenantID, requestIDs}
	if scoped {
		args = append(args, scopes, start.UTC(), end.UTC())
		requestWindow = " AND rl.environment_scope = ANY($3) AND rl.created_at >= $4 AND rl.created_at < $5"
		toolWindow = " AND tcl.created_at >= $4 AND tcl.created_at < $5 AND EXISTS (SELECT 1 FROM request_logs tcl_scope_rl WHERE tcl_scope_rl.tenant_id = $1 AND tcl_scope_rl.request_id = tcl.request_id AND tcl_scope_rl.environment_scope = ANY($3) AND tcl_scope_rl.created_at >= $4 AND tcl_scope_rl.created_at < $5)"
		artifactWindow = " AND al.environment_scope = ANY($3) AND al.created_at >= $4 AND al.created_at < $5 AND ra.environment_scope = ANY($3) AND ra.created_at >= $4 AND ra.created_at < $5 AND EXISTS (SELECT 1 FROM request_logs artifact_scope_rl WHERE artifact_scope_rl.tenant_id = $1 AND artifact_scope_rl.request_id = al.request_id AND artifact_scope_rl.environment_scope = ANY($3) AND artifact_scope_rl.created_at >= $4 AND artifact_scope_rl.created_at < $5)"
	}
	events := make([]EvidenceTimelineEvent, 0, len(requestIDs)+8)

	requestRows, err := r.retentionRead().Query(ctx, `
		SELECT rl.request_id, rl.created_at,
			COALESCE(NULLIF(m.model_label, ''), NULLIF(m.model_name, ''), NULLIF(rl.proxy_target_host, ''), rl.model_id, ''),
			COALESCE(rl.request_status, ''), COALESCE(rl.latency_ms, 0), COALESCE(rl.upstream_status_code, 0)
		FROM request_logs rl
		LEFT JOIN models m ON m.id = rl.model_id
		WHERE rl.tenant_id = $1 AND rl.request_id = ANY($2)`+requestWindow+`
		ORDER BY rl.created_at, rl.request_id
	`, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to list evidence model calls: %w", err)
	}
	for requestRows.Next() {
		var event EvidenceTimelineEvent
		var latency, statusCode int
		if err := requestRows.Scan(&event.RequestID, &event.Timestamp, &event.Detail, &event.Status, &latency, &statusCode); err != nil {
			requestRows.Close()
			return nil, err
		}
		event.ID = "model:" + event.RequestID
		event.Type, event.Title, event.Count = "model_call", "模型调用", 1
		if latency > 0 {
			if event.Detail != "" {
				event.Detail += " · "
			}
			event.Detail += fmt.Sprintf("%d ms", latency)
		}
		events = append(events, event)
		if title := retentionOutcomeTitle(event.Status); title != "" {
			detail := fmt.Sprintf("返回码 %d", statusCode)
			if statusCode == 0 {
				detail = "未记录返回码"
			}
			if event.Status == "blocked" {
				detail += "；历史记录未区分内容策略、地址限制与目标解析异常，不能据此认定内容策略阻断。"
			}
			if event.Status == "egress_denied" {
				detail += "；目标地址违反出站访问限制，该限制独立于内容审计模式。"
			}
			if event.Status == "target_resolution_failed" {
				detail += "；未连接上游，属于访问故障，不是内容策略阻断。"
			}
			events = append(events, EvidenceTimelineEvent{ID: "outcome:" + event.RequestID, RequestID: event.RequestID, Type: "request_outcome", Title: title, Detail: detail, Status: event.Status, Timestamp: event.Timestamp, Count: 1})
		}
	}
	if err := requestRows.Err(); err != nil {
		requestRows.Close()
		return nil, err
	}
	requestRows.Close()

	// Join against the same tenant, environment and time-scoped request set.
	securityRows, err := r.retentionRead().Query(ctx, `
 SELECT DISTINCT se.id, se.request_id, se.created_at, se.event_type, COALESCE(se.rule_id,''), COALESCE(se.action_taken,'')
 FROM security_events se JOIN request_logs rl ON rl.request_id=se.request_id AND rl.tenant_id=se.tenant_id
 WHERE rl.tenant_id=$1 AND rl.request_id=ANY($2) AND NOT (`+forwardProxyIgnoredSecurityEventExpr("se")+`)`+requestWindow+`
 ORDER BY se.created_at, se.id`, args...)
	if err != nil {
		return nil, fmt.Errorf("read retained security evidence: %w", err)
	}
	for securityRows.Next() {
		var event EvidenceTimelineEvent
		var kind, rule, action string
		if err := securityRows.Scan(&event.ID, &event.RequestID, &event.Timestamp, &kind, &rule, &action); err != nil {
			securityRows.Close()
			return nil, err
		}
		event.ID = "security:" + event.ID
		event.Type, event.Title, event.Count = "security_event", "安全规则命中", 1
		if kind == "security_check_failed" {
			event.Title = "安全检测未完成"
		}
		switch action {
		case "audit", "security_audit_only", "security_audit", "tool_audit_only", "tool_audited":
			event.Detail = "本条安全事件仅作审计记录，未执行拦截。"
		case "block", "security_blocked":
			event.Detail = "本条安全事件记录的动作：策略阻断。"
		case "reply", "security_replied":
			event.Detail = "实际动作：安全回复。"
		case "allow":
			event.Detail = "实际动作：放行。"
		default:
			event.Detail = "实际动作未明确留存，请复核原始记录。"
		}
		if rule != "" {
			event.Detail += " 规则：" + rule
		}
		event.Status = action
		events = append(events, event)
	}
	if err := securityRows.Err(); err != nil {
		securityRows.Close()
		return nil, err
	}
	securityRows.Close()

	// Inspection progress is joined to the same authorized request set. Old
	// installations can still read evidence before migration 846 is applied.
	var inspectionReady bool
	if err = r.retentionRead().QueryRow(ctx, "SELECT to_regclass('proxy_inspection_jobs') IS NOT NULL").Scan(&inspectionReady); err != nil {
		return nil, err
	}
	if inspectionReady {
		inspectionRows, e := r.retentionRead().Query(ctx, inspectionProgressQuery+requestWindow, args...)
		if e != nil {
			return nil, e
		}
		for inspectionRows.Next() {
			var id, status, admission string
			var completed, total int
			var updated time.Time
			if e = inspectionRows.Scan(&id, &status, &completed, &total, &admission, &updated); e != nil {
				inspectionRows.Close()
				return nil, e
			}
			title := "安全检测排队补检"
			display := "in_progress"
			detail := fmt.Sprintf("已完成 %d/%d 个检测部分。", completed, total)
			if status == "completed" {
				title = "安全检测已完成"
				display = "success"
			} else if status == "failed" {
				title = "安全补检失败，需处理"
				display = "failed"
				detail += "自动重试已耗尽或任务过期，请检查检测服务容量。"
			} else {
				detail += "未完成部分将自动重试，服务重启后继续。"
			}
			if strings.HasPrefix(admission, "forwarded") {
				detail += "按审计模式准许转发，补检发现不代表事前已阻断。"
			} else if strings.HasPrefix(admission, "blocked") {
				detail += "本次请求未获准转发；补检完成不会自动重放业务请求。"
			}
			events = append(events, EvidenceTimelineEvent{ID: "inspection:" + id, RequestID: id, Type: "inspection_progress", Title: title, Detail: detail, Status: display, Timestamp: updated, Count: 1})
		}
		e = inspectionRows.Err()
		inspectionRows.Close()
		if e != nil {
			return nil, e
		}
	}

	toolRows, err := r.retentionRead().Query(ctx, `
		SELECT id, request_id, created_at, tool_name, detail, status, event_kind
		FROM (
			SELECT DISTINCT ON (attempt_key)
				tcl.id, tcl.request_id, tcl.created_at, tcl.tool_name,
				COALESCE(NULLIF(tcl.target_summary, ''), NULLIF(tcl.normalized_target, ''), '') AS detail,
				COALESCE(tcl.status, '') AS status,
				`+riskOverviewEventKindSQL+` AS event_kind,
				`+evidenceTimelineAttemptKeySQL+` AS attempt_key
			FROM tool_call_logs tcl
			WHERE tcl.tenant_id = $1 AND tcl.request_id = ANY($2)`+toolWindow+`
				AND `+evidenceTimelineAttemptPredicateSQL+`
			ORDER BY attempt_key,
				CASE (`+riskOverviewEventKindSQL+`) WHEN 'invocation_proposed' THEN 0 ELSE 1 END,
				tcl.created_at, tcl.id
		) attempts
		ORDER BY created_at, id
	`, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to list evidence tool actions: %w", err)
	}
	for toolRows.Next() {
		var event EvidenceTimelineEvent
		if err := toolRows.Scan(&event.ID, &event.RequestID, &event.Timestamp, &event.Title, &event.Detail, &event.Status, &event.EventKind); err != nil {
			toolRows.Close()
			return nil, err
		}
		event.Type, event.Count = "tool_action", 1
		event.FactLabel = evidenceTimelineFactLabel(event)
		events = append(events, event)
	}
	if err := toolRows.Err(); err != nil {
		toolRows.Close()
		return nil, err
	}
	toolRows.Close()

	var inventory EvidenceTimelineEvent
	if err := r.retentionRead().QueryRow(ctx, `
		SELECT COALESCE(MIN(tcl.id), ''), COALESCE(MIN(tcl.created_at), NOW()),
			COALESCE(string_agg(DISTINCT tcl.tool_name, '、' ORDER BY tcl.tool_name), ''),
			COUNT(DISTINCT NULLIF(tcl.tool_name, ''))::int
		FROM tool_call_logs tcl
		WHERE tcl.tenant_id = $1 AND tcl.request_id = ANY($2)`+toolWindow+`
			AND (`+riskOverviewEventKindSQL+`) = 'definition_exposed'
			AND COALESCE(tcl.tool_name, '') <> ''
	`, args...).Scan(&inventory.ID, &inventory.Timestamp, &inventory.Detail, &inventory.Count); err != nil {
		return nil, fmt.Errorf("failed to list evidence tool inventory: %w", err)
	}
	if inventory.Count > 0 {
		inventory.ID = "summary:tool_inventory"
		inventory.Type = "tool_inventory"
		inventory.Title = "可用工具"
		inventory.EventKind = "definition_exposed"
		inventory.FactLabel = evidenceTimelineFactLabel(inventory)
		inventory.Detail = compactEvidenceToolInventory(inventory.Detail, inventory.Count)
		events = append(events, inventory)
	}

	artifactRows, err := r.retentionRead().Query(ctx, `
		SELECT al.id, al.request_id, al.created_at, al.direction,
			COALESCE(NULLIF(ra.display_name, ''), CASE WHEN ra.kind = 'image' THEN '图片' ELSE '文件' END),
			COALESCE(ra.retention_status, '')
		FROM access_content_artifact_links al
		JOIN retained_artifacts ra ON ra.id = al.artifact_id AND ra.tenant_id = al.tenant_id
		WHERE al.tenant_id = $1 AND al.request_id = ANY($2)`+artifactWindow+`
		ORDER BY al.created_at, al.ordinal, al.id
	`, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to list evidence artifacts: %w", err)
	}
	for artifactRows.Next() {
		var event EvidenceTimelineEvent
		var direction string
		if err := artifactRows.Scan(&event.ID, &event.RequestID, &event.Timestamp, &direction, &event.Detail, &event.Status); err != nil {
			artifactRows.Close()
			return nil, err
		}
		event.Type, event.Count = "artifact", 1
		if direction == "output" {
			event.Title = "生成附件"
		} else {
			event.Title = "输入附件"
		}
		events = append(events, event)
	}
	if err := artifactRows.Err(); err != nil {
		artifactRows.Close()
		return nil, err
	}
	artifactRows.Close()

	sort.SliceStable(events, func(i, j int) bool {
		if events[i].Timestamp.Equal(events[j].Timestamp) {
			return events[i].ID < events[j].ID
		}
		return events[i].Timestamp.Before(events[j].Timestamp)
	})
	return summarizeEvidenceTimeline(events), nil
}

const inspectionProgressQuery = `SELECT DISTINCT j.request_id,j.status,j.completed_parts,j.total_parts,j.admission,j.updated_at
   FROM proxy_inspection_jobs j JOIN request_logs rl ON rl.tenant_id=j.tenant_id AND rl.request_id=j.request_id AND rl.environment_scope=j.environment_scope
   WHERE rl.tenant_id=$1 AND rl.request_id=ANY($2)`
