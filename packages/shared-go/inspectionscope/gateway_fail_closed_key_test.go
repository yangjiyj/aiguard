package inspectionscope

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// The gateway projection now carries guardrail_fail_closed_enabled; the proxy
// reader shares the projection and must keep accepting it.
func TestProxyReaderAcceptsSignedFailClosedOption(t *testing.T) {
	config := signedRuntimeFixture()
	config["guardrail_fail_closed_enabled"] = true
	signRuntimeFixture(config)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { json.NewEncoder(w).Encode(config) }))
	defer server.Close()
	reader := NewGatewayReader(server.URL, "test-internal-token", runtimeTestKey)
	if err := reader.Refresh(context.Background()); err != nil {
		t.Fatalf("projection with fail-closed option rejected: %v", err)
	}
}
