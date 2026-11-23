package main

import (
	"net/http"
	"testing"
	"time"
)

func TestControlPlaneHTTPServerBoundsHeadersAndSlowClients(t *testing.T) {
	server := newControlPlaneHTTPServer("127.0.0.1:0", http.NewServeMux())
	if server.ReadHeaderTimeout <= 0 || server.ReadTimeout <= 0 || server.WriteTimeout <= 0 {
		t.Fatalf("server timeouts must be explicit: %+v", server)
	}
	if server.ReadHeaderTimeout > 10*time.Second {
		t.Fatalf("read header timeout too permissive: %s", server.ReadHeaderTimeout)
	}
	if server.MaxHeaderBytes < 8<<10 || server.MaxHeaderBytes > 64<<10 {
		t.Fatalf("MaxHeaderBytes=%d want a bounded 8..64KiB", server.MaxHeaderBytes)
	}
}

func TestControlPlaneRequestTimeoutAllowsBoundedModelSynchronization(t *testing.T) {
	tests := []struct {
		method string
		path   string
		want   time.Duration
	}{
		{http.MethodGet, "/admin/v1/models", standardControlPlaneRequestTimeout},
		{http.MethodPost, "/admin/v1/models/sync", modelSyncControlPlaneRequestTimeout},
		{http.MethodPost, "/admin/v1/models/sync/candidates", modelSyncControlPlaneRequestTimeout},
		{http.MethodPost, "/admin/v1/models/sync/preview", modelSyncControlPlaneRequestTimeout},
		{http.MethodPost, "/admin/v1/models/sync/verify", modelSyncControlPlaneRequestTimeout},
		{http.MethodPost, "/admin/v1/models/sync/commit", modelSyncControlPlaneRequestTimeout},
		{http.MethodGet, "/admin/v1/models/sync", standardControlPlaneRequestTimeout},
	}
	for _, tt := range tests {
		req, err := http.NewRequest(tt.method, tt.path, nil)
		if err != nil {
			t.Fatal(err)
		}
		if got := controlPlaneRequestTimeout(req); got != tt.want {
			t.Errorf("%s %s timeout=%s want=%s", tt.method, tt.path, got, tt.want)
		}
	}

	server := newControlPlaneHTTPServer("127.0.0.1:0", http.NewServeMux())
	if server.WriteTimeout <= modelSyncControlPlaneRequestTimeout {
		t.Fatalf("server write timeout %s must leave response budget after model sync timeout %s", server.WriteTimeout, modelSyncControlPlaneRequestTimeout)
	}
}

// A selected image catalog batch can spend 120 seconds on each of the three
// native image probes. Keep directory fetch and persistence time in the same
// request budget so successful probes are not canceled before commit.
func TestModelSyncBudgetCoversThreeSlowNativeImageProbes(t *testing.T) {
	const imageBatchBudget = 3*120*time.Second + 30*time.Second
	if modelSyncControlPlaneRequestTimeout <= imageBatchBudget {
		t.Fatalf("model sync budget %s cannot cover three image probes plus catalog/commit overhead %s", modelSyncControlPlaneRequestTimeout, imageBatchBudget)
	}
	if standardControlPlaneRequestTimeout != 30*time.Second {
		t.Fatal("ordinary management request budget must remain bounded at 30 seconds")
	}
}
