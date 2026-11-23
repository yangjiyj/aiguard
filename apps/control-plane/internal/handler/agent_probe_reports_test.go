package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
	"github.com/yangjiyj/aiguard/packages/shared-go/probereports"
)

type aiprobeReportRepoFixture struct {
	agentEndpointRepository
	calls    int
	tenant   string
	endpoint string
	report   *probereports.Report
	err      error
}

func (f *aiprobeReportRepoFixture) AcceptAiprobeReport(_ context.Context, tenant, endpoint string, report *probereports.Report) (*repository.AiprobeReportReceipt, error) {
	f.calls++
	f.tenant = tenant
	f.endpoint = endpoint
	f.report = report
	if f.err != nil {
		return nil, f.err
	}
	return &repository.AiprobeReportReceipt{SchemaVersion: "aiprobe.report.ack.v1", ReportID: report.ReportID, Accepted: true, AssetCount: len(report.Assets)}, nil
}
func validProbeReportBody(t *testing.T, endpoint string) []byte {
	t.Helper()
	names := []string{"homes", "host", "process", "netsock", "agents", "apps", "browser_extensions", "container", "schedule", "modelsvc"}
	collectors := make([]probereports.CollectorResult, 0, len(names))
	for _, name := range names {
		collectors = append(collectors, probereports.CollectorResult{Name: name, Status: "complete"})
	}
	report := probereports.Report{SchemaVersion: probereports.SchemaVersion, EndpointID: endpoint, ProbeVersion: "0.1.0", ScannedAt: "2025-01-02T03:04:05Z", Status: "complete", Collectors: collectors, Assets: []probereports.Asset{}, SocketObservations: []probereports.SocketObservation{}}
	report.ReportID = probereports.ReportID(endpoint, report.ScannedAt)
	body, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	return body
}
func withProbeEndpoint(req *http.Request, endpoint, product string) *http.Request {
	return req.WithContext(contextWithEndpoint(req.Context(), &repository.AgentEndpointContext{TenantID: "tenant-from-auth", EndpointID: endpoint, AgentProduct: product}))
}
func TestProbeReportsUsesAuthenticatedEndpointAndTypedDTO(t *testing.T) {
	repo := &aiprobeReportRepoFixture{}
	api := &AgentEndpointAPI{Repo: repo}
	body := validProbeReportBody(t, "ep-auth")
	req := withProbeEndpoint(httptest.NewRequest(http.MethodPost, "/admin/v1/internal/agent/probe-reports", bytes.NewReader(body)), "ep-auth", "aiprobe")
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	api.ProbeReports(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	if repo.calls != 1 || repo.tenant != "tenant-from-auth" || repo.endpoint != "ep-auth" || repo.report == nil {
		t.Fatalf("server-auth scope not used: %#v", repo)
	}
	if rr.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("receipt should not be cached")
	}
}
func TestProbeReportsRejectsEndpointProductSchemaAndSize(t *testing.T) {
	body := validProbeReportBody(t, "ep-auth")
	cases := []struct {
		name              string
		body              []byte
		endpoint, product string
		want              int
	}{
		{"endpoint mismatch", body, "ep-other", "aiprobe", http.StatusUnauthorized},
		{"wrong product", body, "ep-auth", "other", http.StatusForbidden},
		{"unknown field", append(append([]byte(nil), bytes.TrimSuffix(body, []byte("}"))...), []byte(`,"raw_command":"secret"}`)...), "ep-auth", "aiprobe", http.StatusUnprocessableEntity},
		{"oversized", bytes.Repeat([]byte(" "), probereports.MaxBodyBytes+1), "ep-auth", "aiprobe", http.StatusRequestEntityTooLarge},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			repo := &aiprobeReportRepoFixture{}
			api := &AgentEndpointAPI{Repo: repo}
			req := withProbeEndpoint(httptest.NewRequest(http.MethodPost, "/admin/v1/internal/agent/probe-reports", bytes.NewReader(tc.body)), tc.endpoint, tc.product)
			req.Header.Set("Content-Type", "application/json")
			rr := httptest.NewRecorder()
			api.ProbeReports(rr, req)
			if rr.Code != tc.want {
				t.Fatalf("status=%d want=%d body=%s", rr.Code, tc.want, rr.Body.String())
			}
			if repo.calls != 0 {
				t.Fatal("invalid report reached repository")
			}
		})
	}
}
func TestProbeReportsReturnsConflictFromReportLedger(t *testing.T) {
	repo := &aiprobeReportRepoFixture{err: repository.ErrAiprobeReportConflict}
	api := &AgentEndpointAPI{Repo: repo}
	body := validProbeReportBody(t, "ep-auth")
	req := withProbeEndpoint(httptest.NewRequest(http.MethodPost, "/admin/v1/internal/agent/probe-reports", bytes.NewReader(body)), "ep-auth", "aiprobe")
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	api.ProbeReports(rr, req)
	if rr.Code != http.StatusConflict {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	if errors.Is(repo.err, repository.ErrAiprobeReportConflict) == false {
		t.Fatal("fixture is invalid")
	}
	if strings.Contains(rr.Body.String(), "secret") {
		t.Fatal("unexpected detailed response")
	}
}

func TestProbeReportsRejectsQueryParameters(t *testing.T) {
	repo := &aiprobeReportRepoFixture{}
	api := &AgentEndpointAPI{Repo: repo}
	req := withProbeEndpoint(httptest.NewRequest(http.MethodPost, "/admin/v1/internal/agent/probe-reports?extra=1", bytes.NewReader(validProbeReportBody(t, "ep-auth"))), "ep-auth", "aiprobe")
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	api.ProbeReports(rr, req)
	if rr.Code != http.StatusBadRequest || repo.calls != 0 {
		t.Fatalf("status=%d repo_calls=%d", rr.Code, repo.calls)
	}
}
