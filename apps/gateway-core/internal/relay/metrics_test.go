package relay

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestMetricsEndpointIsProtectedAndStable(t *testing.T) {
	metrics := NewMetrics()
	metrics.Inc("stream_events")
	metrics.StreamStarted()
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/admin/v1/internal/metrics", nil)
	metrics.Handler("internal-secret")(recorder, request)
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated status=%d", recorder.Code)
	}

	recorder = httptest.NewRecorder()
	request = httptest.NewRequest(http.MethodGet, "/admin/v1/internal/metrics", nil)
	request.Header.Set("X-JJDGuard-Internal-Secret", "internal-secret")
	metrics.Handler("internal-secret")(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("authenticated status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var snapshot map[string]uint64
	if err := json.Unmarshal(recorder.Body.Bytes(), &snapshot); err != nil {
		t.Fatal(err)
	}
	if snapshot["stream_events"] != 1 || snapshot["active_streams"] != 1 || snapshot["billing_settle"] != 0 {
		t.Fatalf("snapshot=%v", snapshot)
	}
}
