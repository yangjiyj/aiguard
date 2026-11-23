package handler

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/yangjiyj/aiguard/packages/shared-go/probereports"
)

func validGatewayProbeReport(t *testing.T, endpoint string) []byte {
	t.Helper()
	names := []string{"homes", "host", "process", "netsock", "agents", "apps", "browser_extensions", "container", "schedule", "modelsvc"}
	collectors := make([]probereports.CollectorResult, 0, len(names))
	for _, name := range names {
		collectors = append(collectors, probereports.CollectorResult{Name: name, Status: "complete"})
	}
	r := probereports.Report{SchemaVersion: probereports.SchemaVersion, EndpointID: endpoint, ProbeVersion: "0.1.0", ScannedAt: "2025-01-02T03:04:05Z", Status: "complete", Collectors: collectors, Assets: []probereports.Asset{}, SocketObservations: []probereports.SocketObservation{}}
	r.ReportID = probereports.ReportID(endpoint, r.ScannedAt)
	raw, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
func gzipProbeBody(t *testing.T, body []byte) []byte {
	t.Helper()
	var b bytes.Buffer
	w := gzip.NewWriter(&b)
	if _, err := w.Write(body); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func TestProbeReportGatewayBindsEndpointAndForwardsOnlyTypedReport(t *testing.T) {
	var resolves, ingests atomic.Int32
	body := validGatewayProbeReport(t, "ep-gateway")
	control := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/admin/v1/internal/agent/endpoints/resolve":
			resolves.Add(1)
			if r.Header.Get("X-JJDGuard-Internal-Token") != "internal-secret" {
				t.Errorf("missing internal resolve auth")
			}
			_, _ = io.Copy(io.Discard, r.Body)
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"tenant_id": "tenant-1", "endpoint_id": "ep-gateway", "agent_product": "aiprobe", "licensed": true, "revoked": false})
		case "/admin/v1/internal/agent/probe-reports":
			ingests.Add(1)
			if r.Header.Get("Authorization") != "Bearer endpoint-token" || r.Header.Get("X-JJDGuard-Internal-Token") != "internal-secret" {
				t.Errorf("unexpected upstream credentials")
			}
			if r.Header.Get("Content-Encoding") != "" {
				t.Errorf("gateway should forward decoded JSON")
			}
			got, _ := io.ReadAll(r.Body)
			if !bytes.Equal(got, body) {
				t.Errorf("gateway changed typed payload")
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			ack := map[string]any{"schema_version": "aiprobe.report.ack.v1", "report_id": probereports.ReportID("ep-gateway", "2025-01-02T03:04:05Z"), "accepted": true, "duplicate": false, "asset_count": 0}
			_ = json.NewEncoder(w).Encode(ack)
		default:
			t.Errorf("unexpected upstream route %s", r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	defer control.Close()
	g := &AgentEndpointGateway{enabled: true, controlURL: control.URL, secret: "internal-secret", client: control.Client(), bodyLimit: 8 << 20, auth: make(map[string]endpointAuthCacheEntry), rateLimiter: newEndpointRateLimiter()}
	req := httptest.NewRequest(http.MethodPost, "/agent/v1/probe-reports", bytes.NewReader(gzipProbeBody(t, body)))
	req.Header.Set("Authorization", "Bearer endpoint-token")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Content-Encoding", "gzip")
	rr := httptest.NewRecorder()
	g.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	if resolves.Load() != 1 || ingests.Load() != 1 {
		t.Fatalf("resolve/ingest counts=%d/%d", resolves.Load(), ingests.Load())
	}
}
func TestProbeReportGatewayRejectsWrongProductEndpointAndUnknownFields(t *testing.T) {
	body := validGatewayProbeReport(t, "ep-gateway")
	var resolves, ingests atomic.Int32
	product := "aiprobe"
	control := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/admin/v1/internal/agent/endpoints/resolve" {
			ingests.Add(1)
			http.NotFound(w, r)
			return
		}
		resolves.Add(1)
		_, _ = io.Copy(io.Discard, r.Body)
		_ = json.NewEncoder(w).Encode(map[string]any{"tenant_id": "tenant-1", "endpoint_id": "ep-gateway", "agent_product": product, "licensed": true, "revoked": false})
	}))
	defer control.Close()
	g := &AgentEndpointGateway{enabled: true, controlURL: control.URL, secret: "s", client: control.Client(), bodyLimit: 8 << 20, auth: make(map[string]endpointAuthCacheEntry), rateLimiter: newEndpointRateLimiter()}
	mismatchedBody := string(validGatewayProbeReport(t, "ep-other"))
	cases := []struct {
		name, product, body string
		want                int
	}{{"wrong product", "not-aiprobe", string(body), http.StatusForbidden}, {"mismatched endpoint", "aiprobe", mismatchedBody, http.StatusUnauthorized}, {"unknown field", "aiprobe", strings.TrimSuffix(string(body), "}") + ",\"raw_command\":\"x\"}", http.StatusUnprocessableEntity}}
	for index, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			product = tc.product
			req := httptest.NewRequest(http.MethodPost, "/agent/v1/probe-reports", strings.NewReader(tc.body))
			req.Header.Set("Authorization", "Bearer endpoint-token-"+strconv.Itoa(index))
			req.Header.Set("Content-Type", "application/json")
			rr := httptest.NewRecorder()
			g.ServeHTTP(rr, req)
			if rr.Code != tc.want {
				t.Fatalf("status=%d want=%d body=%s", rr.Code, tc.want, rr.Body.String())
			}
			if ingests.Load() != 0 {
				t.Fatal("rejected report reached CP")
			}
		})
	}
}
