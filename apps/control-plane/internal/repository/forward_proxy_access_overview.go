package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
)

func newForwardProxyAccessSummary() ForwardProxyAccessSummary {
	return ForwardProxyAccessSummary{
		TopProviders:      []ForwardProxyAccessDimension{},
		TopTargets:        []ForwardProxyAccessDimension{},
		TopAgents:         []ForwardProxyAccessDimension{},
		Timeline:          []ForwardProxyAccessTimelinePoint{},
		TopRiskCategories: []ForwardProxyRiskCategory{},
	}
}

func (r *RequestLogRepository) aggregateForwardProxyGroupedSummary(ctx context.Context, groupedRows string, args []interface{}, granularity string) (ForwardProxyAccessSummary, error) {
	rows, err := r.retentionRead().Query(ctx, groupedRows, args...)
	if err != nil {
		return newForwardProxyAccessSummary(), fmt.Errorf("failed to query grouped forward proxy summary rows: %w", err)
	}
	defer rows.Close()

	out := newForwardProxyAccessSummary()
	providerCounts := map[string]ForwardProxyAccessDimension{}
	targetCounts := map[string]ForwardProxyAccessDimension{}
	agentCounts := map[string]ForwardProxyAccessDimension{}
	targetNames := map[string]struct{}{}
	riskCategoryCounts := map[string]int{}
	timeline := map[time.Time]ForwardProxyAccessTimelinePoint{}

	addDimension := func(counts map[string]ForwardProxyAccessDimension, name, riskState string) {
		if name == "" {
			return
		}
		item := counts[name]
		item.Name = name
		item.Count++
		if riskState == "risk" || riskState == "blocked" {
			item.RiskCount++
		}
		counts[name] = item
	}

	for rows.Next() {
		var (
			riskState, accessType, provider, proxyMode, agentType     string
			riskReasonsJSON                                           []byte
			hasRetainedContent, requestBody, responseBody, undetected bool
			targetHost                                                sql.NullString
			createdAt                                                 time.Time
		)
		if err := rows.Scan(
			&riskState,
			&riskReasonsJSON,
			&accessType,
			&hasRetainedContent,
			&provider,
			&targetHost,
			&proxyMode,
			&agentType,
			&createdAt,
			&requestBody,
			&responseBody,
			&undetected,
		); err != nil {
			return out, fmt.Errorf("failed to scan grouped forward proxy summary row: %w", err)
		}

		out.Total++
		switch riskState {
		case "risk":
			out.RiskCount++
		case "blocked":
			out.BlockedCount++
		default:
			out.NormalCount++
		}
		switch accessType {
		case "llm":
			out.LLMCount++
		case "ai_ide":
			out.AIIdeCount++
		case "normal_public":
			out.NormalPublicCount++
		}
		if hasRetainedContent {
			out.RetainedContentCount++
		}
		if undetected {
			out.UndetectedCount++
		}
		if proxyMode == "forward" {
			out.ForwardCount++
		} else {
			out.ReverseCount++
		}
		if agentType != "" {
			out.AgentRequestCount++
			if agentType == "agent-tool-call" {
				out.UnidentifiedAgentCount++
			} else {
				out.IdentifiedAgentCount++
			}
		}

		switch {
		case requestBody && responseBody:
			out.EvidenceQuality.CompleteCount++
		case requestBody:
			out.EvidenceQuality.RequestOnlyCount++
		case responseBody:
			out.EvidenceQuality.ResponseOnlyCount++
		default:
			out.EvidenceQuality.MetadataOnlyCount++
		}

		addDimension(providerCounts, provider, riskState)
		if targetHost.Valid {
			addDimension(targetCounts, targetHost.String, riskState)
			targetNames[targetHost.String] = struct{}{}
		}
		addDimension(agentCounts, agentType, riskState)

		var riskReasons []string
		if err := json.Unmarshal(riskReasonsJSON, &riskReasons); err != nil {
			return out, fmt.Errorf("failed to decode grouped forward proxy risk reasons: %w", err)
		}
		seenReasons := map[string]struct{}{}
		for _, reason := range riskReasons {
			reason = strings.TrimSpace(reason)
			if reason == "" {
				continue
			}
			if _, exists := seenReasons[reason]; exists {
				continue
			}
			seenReasons[reason] = struct{}{}
			riskCategoryCounts[reason]++
		}

		bucket := summaryTimelineBucket(createdAt, granularity)
		point := timeline[bucket]
		point.Bucket = bucket
		point.TotalCount++
		switch riskState {
		case "risk":
			point.RiskCount++
		case "blocked":
			point.BlockedCount++
		default:
			point.NormalCount++
		}
		timeline[bucket] = point
		if out.DataFreshUntil == nil || createdAt.After(*out.DataFreshUntil) {
			fresh := createdAt
			out.DataFreshUntil = &fresh
		}
	}
	if err := rows.Err(); err != nil {
		return out, fmt.Errorf("failed while reading grouped forward proxy summary rows: %w", err)
	}

	out.UniqueModelCount = len(targetNames)
	out.TopProviders = sortedForwardProxyDimensions(providerCounts)
	out.TopTargets = sortedForwardProxyDimensions(targetCounts)
	out.TopAgents = sortedForwardProxyDimensions(agentCounts)
	out.TopRiskCategories = sortedForwardProxyRiskCategories(riskCategoryCounts, 8)
	out.Timeline = sortedForwardProxyTimeline(timeline, 31)
	return out, nil
}

func summaryTimelineBucket(value time.Time, granularity string) time.Time {
	value = value.UTC()
	if granularity == "hour" {
		return time.Date(value.Year(), value.Month(), value.Day(), value.Hour(), 0, 0, 0, time.UTC)
	}
	return time.Date(value.Year(), value.Month(), value.Day(), 0, 0, 0, 0, time.UTC)
}

func sortedForwardProxyDimensions(counts map[string]ForwardProxyAccessDimension) []ForwardProxyAccessDimension {
	items := make([]ForwardProxyAccessDimension, 0, len(counts))
	for _, item := range counts {
		items = append(items, item)
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].Count != items[j].Count {
			return items[i].Count > items[j].Count
		}
		if items[i].RiskCount != items[j].RiskCount {
			return items[i].RiskCount > items[j].RiskCount
		}
		return items[i].Name < items[j].Name
	})
	return items
}

func sortedForwardProxyRiskCategories(counts map[string]int, limit int) []ForwardProxyRiskCategory {
	items := make([]ForwardProxyRiskCategory, 0, len(counts))
	for name, count := range counts {
		items = append(items, ForwardProxyRiskCategory{Name: name, Count: count})
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].Count != items[j].Count {
			return items[i].Count > items[j].Count
		}
		return items[i].Name < items[j].Name
	})
	if limit > 0 && len(items) > limit {
		items = items[:limit]
	}
	return items
}

func sortedForwardProxyTimeline(points map[time.Time]ForwardProxyAccessTimelinePoint, limit int) []ForwardProxyAccessTimelinePoint {
	items := make([]ForwardProxyAccessTimelinePoint, 0, len(points))
	for _, point := range points {
		items = append(items, point)
	}
	sort.Slice(items, func(i, j int) bool { return items[i].Bucket.Before(items[j].Bucket) })
	if limit > 0 && len(items) > limit {
		items = items[len(items)-limit:]
	}
	return items
}

func forwardProxyPublicTargetExpr() string {
	return `COALESCE(
		CASE
			WHEN NULLIF(rl.proxy_target_host, '') IS NULL THEN NULL
			WHEN rl.proxy_target_host = COALESCE(rl.model_id, '') THEN NULL
			WHEN rl.proxy_target_host ~ '^model_[[:alnum:]_-]+$' THEN NULL
			ELSE rl.proxy_target_host
		END,
		NULLIF(m.model_label, ''),
		NULLIF(m.model_name, '')
	)`
}

func forwardProxyTimelineGranularity(filter ForwardProxyAccessFilter) string {
	if filter.StartTime.IsZero() || filter.EndTime.IsZero() || filter.EndTime.Before(filter.StartTime) {
		return "day"
	}
	if filter.EndTime.Sub(filter.StartTime) <= 48*time.Hour {
		return "hour"
	}
	return "day"
}

func forwardProxyRequestBodyExistsExpr() string {
	return `(EXISTS (
		SELECT 1
		FROM access_content_logs acl
		WHERE acl.tenant_id = rl.tenant_id
			AND acl.request_id = rl.request_id
			AND acl.environment_scope = rl.environment_scope
			AND NULLIF(BTRIM(COALESCE(acl.request_content_redacted, '')), '') IS NOT NULL
	)
	OR EXISTS (
		SELECT 1
		FROM content_logs cl
		WHERE cl.tenant_id = rl.tenant_id
			AND cl.request_id = rl.id
			AND cl.environment_scope = rl.environment_scope
			AND COALESCE(cl.role, '') <> 'assistant'
			AND NULLIF(BTRIM(COALESCE(cl.content, '')), '') IS NOT NULL
	))`
}

func forwardProxyResponseBodyExistsExpr() string {
	return `(EXISTS (
		SELECT 1
		FROM access_content_logs acl
		WHERE acl.tenant_id = rl.tenant_id
			AND acl.request_id = rl.request_id
			AND acl.environment_scope = rl.environment_scope
			AND NULLIF(BTRIM(COALESCE(acl.response_content_redacted, '')), '') IS NOT NULL
	)
	OR EXISTS (
		SELECT 1
		FROM content_logs cl
		WHERE cl.tenant_id = rl.tenant_id
			AND cl.request_id = rl.id
			AND cl.environment_scope = rl.environment_scope
			AND cl.role = 'assistant'
			AND NULLIF(BTRIM(COALESCE(cl.content, '')), '') IS NOT NULL
	))`
}

// forwardProxyPrecomputedRequestBodyExpr 读预算列 request_body_exists（迁移 1001），未算出时回退原表达式。
func forwardProxyPrecomputedRequestBodyExpr() string {
	return "COALESCE(rl.request_body_exists, " + forwardProxyRequestBodyExistsExpr() + ")"
}

// forwardProxyPrecomputedResponseBodyExpr 读预算列 response_body_exists（迁移 1001），未算出时回退原表达式。
func forwardProxyPrecomputedResponseBodyExpr() string {
	return "COALESCE(rl.response_body_exists, " + forwardProxyResponseBodyExistsExpr() + ")"
}

func forwardProxyEvidenceQualityQuery(where []string) string {
	requestBody := forwardProxyPrecomputedRequestBodyExpr()
	responseBody := forwardProxyPrecomputedResponseBodyExpr()
	return fmt.Sprintf(`
		SELECT
			COUNT(*) FILTER (WHERE %s AND %s),
			COUNT(*) FILTER (WHERE %s AND NOT (%s)),
			COUNT(*) FILTER (WHERE NOT (%s) AND %s),
			COUNT(*) FILTER (WHERE NOT (%s) AND NOT (%s))
		FROM request_logs rl
		WHERE %s
	`,
		requestBody, responseBody,
		requestBody, responseBody,
		requestBody, responseBody,
		requestBody, responseBody,
		strings.Join(where, " AND "),
	)
}

func forwardProxyTimelineQuery(where []string, granularity string, riskExpr string) string {
	if granularity != "hour" {
		granularity = "day"
	}
	return fmt.Sprintf(`
		WITH latest_buckets AS (
			SELECT
				date_trunc('%s', rl.created_at) AS bucket,
				COUNT(*) AS total_count,
				COUNT(*) FILTER (WHERE %s = 'normal') AS normal_count,
				COUNT(*) FILTER (WHERE %s = 'risk') AS risk_count,
				COUNT(*) FILTER (WHERE %s = 'blocked') AS blocked_count
			FROM request_logs rl
			WHERE %s
			GROUP BY bucket
			ORDER BY bucket DESC
			LIMIT 31
		)
		SELECT bucket, total_count, normal_count, risk_count, blocked_count
		FROM latest_buckets
		ORDER BY bucket ASC
	`, granularity, riskExpr, riskExpr, riskExpr, strings.Join(where, " AND "))
}

func forwardProxyTopRiskCategoriesQuery(where []string) string {
	findingAlias := "se_category_finding"
	findings := forwardProxySecurityEventFindingsArrayExpr("se")
	findingName := forwardProxyFindingReasonExpr(findingAlias)
	ignored := forwardProxyIgnoredFindingExpr(findingAlias, "COALESCE(se.matched_summary->>'stage', '')", forwardProxyEventTargetHostExpr("se"))
	return fmt.Sprintf(`
		WITH request_categories AS (
			SELECT DISTINCT rl.request_id,
				NULLIF(BTRIM(%s), '') AS name
			FROM request_logs rl
		JOIN security_events se
			ON se.tenant_id = rl.tenant_id
			AND se.request_id = rl.request_id
			AND EXISTS (SELECT 1 FROM request_logs se_scope_rl WHERE se_scope_rl.tenant_id = rl.tenant_id AND se_scope_rl.request_id = se.request_id AND se_scope_rl.environment_scope = rl.environment_scope)
			CROSS JOIN LATERAL jsonb_array_elements(
				CASE
					WHEN jsonb_array_length(%s) > 0 THEN %s
					WHEN NULLIF(BTRIM(se.matched_summary->>'category'), '') IS NOT NULL
						THEN jsonb_build_array(jsonb_build_object('category', se.matched_summary->>'category'))
					ELSE '[]'::jsonb
				END
			) %s
			WHERE %s
				AND NOT (%s)
		)
		SELECT name, COUNT(*) AS affected_request_count
		FROM request_categories
		WHERE name IS NOT NULL
		GROUP BY name
		ORDER BY affected_request_count DESC, name ASC
		LIMIT 8
	`, findingName, findings, findings, findingAlias, strings.Join(where, " AND "), ignored)
}

// forwardProxyTopRiskCategoriesForReasonsQuery 按已聚合的逻辑 turn 原因统计风险类别。
func forwardProxyTopRiskCategoriesForReasonsQuery(where []string, riskReasonsExpr string) string {
	return fmt.Sprintf(`
		WITH request_categories AS (
			SELECT DISTINCT rl.request_id,
				NULLIF(BTRIM(turn_reason.value), '') AS name
			FROM request_logs rl
			CROSS JOIN LATERAL jsonb_array_elements_text(%s) AS turn_reason(value)
			WHERE %s
		)
		SELECT name, COUNT(*) AS affected_request_count
		FROM request_categories
		WHERE name IS NOT NULL
		GROUP BY name
		ORDER BY affected_request_count DESC, name ASC
		LIMIT 8
	`, riskReasonsExpr, strings.Join(where, " AND "))
}

func (r *RequestLogRepository) forwardProxyEvidenceQuality(ctx context.Context, where []string, args []interface{}) (ForwardProxyEvidenceQuality, error) {
	var out ForwardProxyEvidenceQuality
	if err := r.retentionRead().QueryRow(ctx, forwardProxyEvidenceQualityQuery(where), args...).Scan(
		&out.CompleteCount,
		&out.RequestOnlyCount,
		&out.ResponseOnlyCount,
		&out.MetadataOnlyCount,
	); err != nil {
		return out, fmt.Errorf("failed to summarize forward proxy evidence quality: %w", err)
	}
	return out, nil
}

func (r *RequestLogRepository) forwardProxyTimeline(ctx context.Context, filter ForwardProxyAccessFilter, riskExpr string, where []string, args []interface{}) ([]ForwardProxyAccessTimelinePoint, error) {
	rows, err := r.retentionRead().Query(ctx, forwardProxyTimelineQuery(where, forwardProxyTimelineGranularity(filter), riskExpr), args...)
	if err != nil {
		return nil, fmt.Errorf("failed to query forward proxy timeline: %w", err)
	}
	defer rows.Close()

	out := []ForwardProxyAccessTimelinePoint{}
	for rows.Next() {
		var point ForwardProxyAccessTimelinePoint
		if err := rows.Scan(
			&point.Bucket,
			&point.TotalCount,
			&point.NormalCount,
			&point.RiskCount,
			&point.BlockedCount,
		); err != nil {
			return nil, fmt.Errorf("failed to scan forward proxy timeline: %w", err)
		}
		out = append(out, point)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to iterate forward proxy timeline: %w", err)
	}
	return out, nil
}

func (r *RequestLogRepository) forwardProxyTopRiskCategories(ctx context.Context, where []string, args []interface{}, riskReasonsExpr string) ([]ForwardProxyRiskCategory, error) {
	query := forwardProxyTopRiskCategoriesQuery(where)
	if riskReasonsExpr != "" {
		query = forwardProxyTopRiskCategoriesForReasonsQuery(where, riskReasonsExpr)
	}
	rows, err := r.retentionRead().Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to query forward proxy risk categories: %w", err)
	}
	defer rows.Close()

	out := []ForwardProxyRiskCategory{}
	for rows.Next() {
		var item ForwardProxyRiskCategory
		if err := rows.Scan(&item.Name, &item.Count); err != nil {
			return nil, fmt.Errorf("failed to scan forward proxy risk category: %w", err)
		}
		out = append(out, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to iterate forward proxy risk categories: %w", err)
	}
	return out, nil
}
