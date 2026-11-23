package repository

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

type AlertCaseCategoryCount struct {
	Category string `json:"category"`
	Count    int    `json:"count"`
}
type AlertCaseSummary struct {
	CountUnit  string                   `json:"count_unit"`
	Total      int                      `json:"total"`
	Categories []AlertCaseCategoryCount `json:"categories"`
}

func (r *AlertOccurrenceRepository) SummarizeCases(ctx context.Context, f AlertOccurrenceFilter) (*AlertCaseSummary, error) {
	if strings.TrimSpace(f.TenantID) == "" {
		return nil, fmt.Errorf("alert summary requires tenant scope")
	}
	f.Grouping = "cases"
	f.RecentLimit = 0
	f.Limit = 1
	f.Offset = 0
	f.IncludeRaw = false
	var err error
	f.useReadMetadata, err = r.useReadMetadata(ctx)
	if err != nil {
		return nil, err
	}
	query, args, materialized, err := r.alertQuery(ctx, f)
	if err != nil {
		return nil, fmt.Errorf("prepare alert cases: %w", err)
	}
	summary, summaryArgs, err := alertCaseSummaryQueryFrom(query, args)
	if err != nil && materialized {
		logAlertCaseShapeError(err)
		summary, summaryArgs, err = buildAlertCaseSummaryQuery(f)
	}
	if err != nil {
		return nil, fmt.Errorf("alert case summary: %w", err)
	}
	query, args = summary, summaryArgs
	out := &AlertCaseSummary{CountUnit: "triage_cases", Categories: []AlertCaseCategoryCount{}}
	var categories []byte
	if err = r.queryAlertRead(ctx, query, args, &out.Total, &categories); err != nil {
		return nil, fmt.Errorf("alert case summary: %w", err)
	}
	if err = json.Unmarshal(categories, &out.Categories); err != nil {
		return nil, err
	}
	return out, nil
}

func buildAlertCaseSummaryQuery(f AlertOccurrenceFilter) (string, []any, error) {
	query, args := buildAlertOccurrenceQuery(f)
	return alertCaseSummaryQueryFrom(query, args)
}

// alertCaseSummaryQueryFrom 把整页查询（实时或物化）截成只出总数和类别分布的汇总查询。
func alertCaseSummaryQueryFrom(query string, args []any) (string, []any, error) {
	// One snapshot and one category aggregation. No evidence or identity display
	// joins, per-category HTTP fan-out, sampling, or repeated session queries.
	head, err := sqlBeforeMarker(query, ",\npage AS (")
	if err != nil {
		return "", nil, err
	}
	query = head + `
 SELECT (SELECT COUNT(*) FROM visible),
 COALESCE((SELECT jsonb_agg(jsonb_build_object('category',case_category,'count',n) ORDER BY n DESC,case_category)
 FROM (SELECT case_category,COUNT(*) AS n FROM visible GROUP BY case_category) categories),'[]'::jsonb)
 WHERE $2::boolean IS NOT NULL AND $3::boolean IS NOT NULL AND $5::integer>=0 AND $6::integer>=0`
	return query, args, nil
}
