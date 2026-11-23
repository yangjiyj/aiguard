package handler

import (
	"encoding/json"
	"github.com/yangjiyj/aiguard/packages/shared-go/headeraudit"
	"github.com/yangjiyj/aiguard/packages/shared-go/inspectionscope"
	"net/http"
	"net/http/httptest"
	"testing"
)

type fakeRuntimeStatus struct{ value inspectionscope.RuntimeStatus }

func (f fakeRuntimeStatus) RuntimeStatus() inspectionscope.RuntimeStatus { return f.value }

func TestInspectionRuntimeEndpointShowsFailureAndProtectsState(t *testing.T) {
	for _, tc := range []struct {
		name, token string
		status      inspectionscope.RuntimeStatus
		want        int
	}{
		{"unauthenticated", "", inspectionscope.RuntimeStatus{}, 401},
		{"missing key", "test-secret", inspectionscope.RuntimeStatus{Component: "proxy-server", Status: "degraded", ErrorCode: "attestation_key_missing"}, 503},
		{"stale held config", "test-secret", inspectionscope.RuntimeStatus{Component: "proxy-server", Status: "degraded", ConfigLoaded: true, HeldRevision: "held", ErrorCode: "config_stale"}, 503},
		{"loaded but stale", "test-secret", inspectionscope.RuntimeStatus{Component: "proxy-server", Status: "applied", ConfigLoaded: true, Fresh: false}, 503},
		{"applied", "test-secret", inspectionscope.RuntimeStatus{Component: "proxy-server", ConfigComponent: "gateway-core", Status: "applied", ConfigLoaded: true, Fresh: true, AppliedRevision: "current"}, 200},
	} {
		t.Run(tc.name, func(t *testing.T) {
			handler := InspectionRuntimeStatusHandler(fakeRuntimeStatus{tc.status}, "test-secret", nil)
			r := httptest.NewRequest("GET", InspectionRuntimeStatusPath, nil)
			if tc.token != "" {
				r.Header.Set(headeraudit.InternalTokenHeader, tc.token)
			}
			w := httptest.NewRecorder()
			handler(w, r)
			if w.Code != tc.want {
				t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
			}
			if w.Header().Get("Cache-Control") != "no-store" {
				t.Fatal("runtime response cacheable")
			}
			if tc.want != 401 {
				var body inspectionscope.RuntimeStatus
				if json.Unmarshal(w.Body.Bytes(), &body) != nil || body.Component != "proxy-server" {
					t.Fatalf("proxy identity hidden: %s", w.Body.String())
				}
			}
		})
	}
}
func TestInspectionRuntimeEndpointDoesNotInterceptForwardTraffic(t *testing.T) {
	forwarded := false
	handler := InspectionRuntimeStatusHandler(nil, "test-secret", func(w http.ResponseWriter, r *http.Request) { forwarded = true; w.WriteHeader(204) })
	r := httptest.NewRequest("GET", "http://upstream.test"+InspectionRuntimeStatusPath, nil)
	w := httptest.NewRecorder()
	handler(w, r)
	if !forwarded || w.Code != 204 {
		t.Fatal("internal status route intercepted absolute-form upstream request")
	}
}
func TestInspectionRuntimeEndpointRejectsConflictingTokensAndMissingSecret(t *testing.T) {
	for _, secret := range []string{"test-secret", ""} {
		handler := InspectionRuntimeStatusHandler(nil, secret, nil)
		r := httptest.NewRequest("GET", InspectionRuntimeStatusPath, nil)
		r.Header[headeraudit.InternalTokenHeader] = []string{"test-secret", "different"}
		w := httptest.NewRecorder()
		handler(w, r)
		if w.Code != 401 && w.Code != 503 {
			t.Fatalf("auth failure accepted: %d", w.Code)
		}
	}
}
