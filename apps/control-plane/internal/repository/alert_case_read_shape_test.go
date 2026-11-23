package repository

import (
	"errors"
	"strings"
	"testing"
	"time"
)

// 物化读法把实时查询从固定标记处截开、换上物化表的前半段。实时查询改了结构、标记找不到时必须报错
// （调用方据此改走实时查询），不能静默拼出错位的 SQL。这里对有代表性的筛选组合核对每个标记都找得到。
func TestAlertCaseQuerySplicingFindsEveryMarker(t *testing.T) {
	end := time.Now()
	filters := []AlertOccurrenceFilter{
		{TenantID: "t", Grouping: "cases", Limit: 10},
		{TenantID: "t", Grouping: "cases", LaneAware: true, Lane: "action", Limit: 10, Disposition: "pending"},
		{TenantID: "t", Grouping: "cases", LaneAware: true, Lane: "eval", Limit: 10, EndTime: &end, IncludeDevTraffic: true},
		{TenantID: "t", Grouping: "cases", Limit: 10, UserID: "u", SessionID: "s", ConversationKey: "ck", Category: "pii_email,secret_api_key"},
		{TenantID: "t", Grouping: "cases", Limit: 10, ProjectIDs: []string{"p1"}, ProjectID: "p1", RecentLimit: 100, EndTime: &end},
		{TenantID: "t", Grouping: "hits", CaseID: "ac1_00000000000000000000000000000000", Limit: 20, IncludeSuppressed: true},
		{TenantID: "t", Grouping: "hits", CaseID: "ac1_00000000000000000000000000000000", Limit: 20, EndTime: &end, IncludeRaw: true, CanReadEvidence: true},
	}
	for _, f := range filters {
		query, _, err := buildMaterializedAlertQuery(f)
		if err != nil {
			t.Fatalf("materialized query for %+v: %v", f, err)
		}
		if !strings.Contains(query, "alert_case_members") {
			t.Fatalf("materialized query for %+v does not read the store", f)
		}
		if f.Grouping == "cases" {
			if _, _, err := alertCaseSummaryQueryFrom(query, nil); err != nil {
				t.Fatalf("summary from materialized query %+v: %v", f, err)
			}
			live, args := buildAlertOccurrenceQuery(f)
			if _, _, err := alertCaseSummaryQueryFrom(live, args); err != nil {
				t.Fatalf("summary from live query %+v: %v", f, err)
			}
		}
	}
	for _, meta := range []bool{false, true} {
		if _, _, err := buildAlertCaseMemberInsert(meta, "t", []string{"e1"}, []string{"g1"}, []bool{true}); err != nil {
			t.Fatalf("member insert (read metadata=%v): %v", meta, err)
		}
		if _, err := alertCaseLogicVersion(meta); err != nil {
			t.Fatalf("logic version (read metadata=%v): %v", meta, err)
		}
	}
}

func TestAlertCaseQuerySplicingReportsAMissingMarker(t *testing.T) {
	if _, err := sqlFromMarker("SELECT 1", "\nfiltered AS MATERIALIZED ("); !errors.Is(err, errAlertCaseQueryShape) {
		t.Fatalf("missing marker must be reported, got %v", err)
	}
	if _, err := sqlBeforeMarker("SELECT 1", "ranked AS ("); !errors.Is(err, errAlertCaseQueryShape) {
		t.Fatalf("missing marker must be reported, got %v", err)
	}
	if _, err := replaceOnceInSQL("a b a", "a", "c"); !errors.Is(err, errAlertCaseQueryShape) {
		t.Fatalf("ambiguous replacement must be reported, got %v", err)
	}
	if got, err := replaceOnceInSQL("a b", "b", "c"); err != nil || got != "a c" {
		t.Fatalf("replaceOnceInSQL = %q, %v", got, err)
	}
}

// 物化聚合（alertCaseAggregateSQL）与实时聚合（alertCaseRollup）是两份要保持一致的 SQL：口径指纹两边都算进去，
// 任一边改了都会触发物化结果重建。
func TestAlertCaseLogicVersionCoversBothAggregations(t *testing.T) {
	inputs, err := alertCaseLogicInputs(true)
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(inputs, "\x00")
	for name, part := range map[string]string{
		"alertCaseRollup":         alertCaseRollup,
		"alertCaseLaneRollup":     alertCaseLaneRollup,
		"alertCaseAggregateSQL":   alertCaseAggregateSQL("SELECT m.* FROM alert_case_members m"),
		"alertCaseGroupFoldQuery": alertCaseGroupFoldQuery,
	} {
		if !strings.Contains(joined, part) {
			t.Fatalf("logic version must include %s", name)
		}
	}
}
