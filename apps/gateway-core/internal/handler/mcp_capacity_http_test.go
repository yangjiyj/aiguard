package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/config"
)

func TestCapacityMCPNonStreamingResultUsesHTTP503OnlyForProtectClosed(t *testing.T) {
	for _, test := range []struct {
		name                      string
		auditOnly, capacityClosed bool
		want                      int
	}{
		{"default", false, false, http.StatusOK},
		{"closed", false, true, http.StatusServiceUnavailable},
		{"record", true, true, http.StatusOK},
	} {
		t.Run(test.name, func(t *testing.T) {
			env := newWS1Env(t, test.auditOnly, allowAll)
			t.Setenv("SECURITY_CAPACITY_FAIL_CLOSED", strconv.FormatBool(test.capacityClosed))
			engine := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusServiceUnavailable)
				_ = json.NewEncoder(w).Encode(map[string]any{"detail": map[string]any{"code": "input_capacity_overflow", "inspection_status": "incomplete"}})
			}))
			defer engine.Close()
			env.handler.SetToolResultChecker(NewRealSecurityChecker(&config.Config{SecurityEngineURL: engine.URL}))
			response := env.post(t, `{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"fetch","arguments":{"url":"https://api.example.test/docs"}}}`)
			if response.Code != test.want {
				t.Fatalf("capacity result status=%d want=%d body=%s", response.Code, test.want, response.Body.String())
			}
			wantRPC := 0
			if test.want == http.StatusServiceUnavailable {
				wantRPC = -32000
			}
			if got := rpcErrorCode(t, response.Body.String()); got != wantRPC {
				t.Fatalf("capacity result RPC error=%d want=%d body=%s", got, wantRPC, response.Body.String())
			}
		})
	}
}
