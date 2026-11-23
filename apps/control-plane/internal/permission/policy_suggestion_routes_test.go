package permission

import (
	"net/http/httptest"
	"testing"
)

func TestPolicySuggestionRoutePermissionsAndConnectorBoundary(t *testing.T) {
	for _, tc := range []struct {
		method, path, action string
		class                SoDClass
	}{
		{"POST", "/admin/v1/eval-integration/policy-suggestions", "write", ""},
		{"GET", "/admin/v1/eval-integration/policy-suggestions/ps_example", "read", ""},
		{"GET", "/admin/v1/policy-suggestions", "read", SoDSecurityConfigRead},
		{"POST", "/admin/v1/policy-suggestions/ps_example/approve", "write", SoDSecurityWrite},
		{"POST", "/admin/v1/policy-suggestions/ps_example/reject", "write", SoDSecurityWrite},
	} {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			r := httptest.NewRequest(tc.method, tc.path, nil)
			got := Resolve(r)
			if got.Resource != "security_events" || got.Action != tc.action || got.ScopeType != "tenant" || got.RequirePlatformAdmin {
				t.Fatalf("permission = %+v, want tenant security_events:%s", got, tc.action)
			}
			if gotClass := SoDClassFor(r.Method, normalizePathToTemplate(r.URL.Path)); tc.class != "" && gotClass != tc.class {
				t.Fatalf("SoD class = %q, want %q", gotClass, tc.class)
			}
			if connectorRouteAllowed(r) {
				t.Fatal("platform connector must not receive suggestion ingestion or approval access")
			}
		})
	}
}
