package repository

import (
	"context"
	"testing"
)

func TestRequestCapacityAlertBoundaryPostgres(t *testing.T) {
	db := verifiedModelsTestDB(t)
	for _, tc := range []struct {
		name, summary string
		want          bool
	}{
		{"legacy capacity", `{"findings":[{"type":"file","category":"file_content_request_oversized","severity":"high"}]}`, false},
		{"new capacity", `{"findings":[{"type":"system","category":"request_body_limit_exceeded","counts_as_security_finding":false}]}`, false},
		{"real file policy", `{"findings":[{"type":"file","category":"file_policy_blocked_type"}]}`, true},
		{"mixed real secret", `{"findings":[{"category":"file_content_request_oversized"},{"category":"ssh_private_key"}]}`, true},
		{"unknown finding", `{"findings":[{"category":"file_content_request_oversized"},{}]}`, true},
		{"legacy empty", `{}`, true},
		{"null findings", `{"findings":null}`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			query := "SELECT NOT " + requestCapacityOnlyEventCondition("se") + " FROM (SELECT 'group'::text AS alert_group_id, 'audit'::text AS action_taken, $1::jsonb AS matched_summary) se"
			var got bool
			if err := db.QueryRow(context.Background(), query, tc.summary).Scan(&got); err != nil {
				t.Fatal(err)
			}
			if got != tc.want {
				t.Fatalf("actionable=%v want=%v", got, tc.want)
			}
			query = "SELECT NOT " + forwardProxyIgnoredSecurityEventExpr("se") + " FROM (SELECT 'proxy_input_audit'::text AS event_type, $1::jsonb AS matched_summary) se CROSS JOIN (SELECT 'api.example.com'::text AS proxy_target_host, ''::text AS model_id) rl"
			if err := db.QueryRow(context.Background(), query, tc.summary).Scan(&got); err != nil {
				t.Fatal(err)
			}
			if got != tc.want {
				t.Fatalf("forward proxy actionable=%v want=%v", got, tc.want)
			}

		})
	}
}
