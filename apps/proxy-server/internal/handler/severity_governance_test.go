package handler

import "testing"

func TestSeverityIsImpactNotAction(t *testing.T) {
	for _, tc := range []struct {
		action   string
		findings []map[string]interface{}
		want     string
	}{
		{"audit", []map[string]interface{}{{"severity": "critical"}}, "critical"},
		{"block", []map[string]interface{}{{"severity": "medium"}}, "medium"},
		{"mask", []map[string]interface{}{{"severity": "low"}}, "low"},
		{"audit", []map[string]interface{}{{"severity": "critical", "counts_as_security_finding": false}}, "low"},
	} {
		if got := severityForActionAndFindings(tc.action, tc.findings); got != tc.want {
			t.Fatalf("%s got %s want %s", tc.action, got, tc.want)
		}
	}
}
