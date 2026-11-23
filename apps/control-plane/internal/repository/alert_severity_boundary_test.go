package repository

import (
	"context"
	"testing"
)

func TestAlertListExcludesLowSeverityIncludingBlockedRuntimeFailures(t *testing.T) {
	db := verifiedModelsTestDB(t)
	for _, tc := range []struct {
		severity, action string
		want             bool
	}{{"low", "tool_failure_loop", false}, {"low", "block", false}, {"low", "audit", false}, {"info", "audit", false}, {"medium", "audit", true}, {"high", "block", true}, {"critical", "block", true}} {
		query := "SELECT (" + contentActionableAlertCondition("se") + ") FROM (SELECT 'group'::text alert_group_id,$1::text severity,$2::text action_taken,'{}'::jsonb matched_summary) se"
		var got bool
		if err := db.QueryRow(context.Background(), query, tc.severity, tc.action).Scan(&got); err != nil {
			t.Fatal(err)
		}
		if got != tc.want {
			t.Fatalf("%s %s actionable=%v", tc.severity, tc.action, got)
		}
	}
}
