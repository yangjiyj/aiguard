package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/yangjiyj/aiguard/packages/shared-go/inspectionscope"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestProxyScopeMustVerifyBeforeOverallApplied(t *testing.T) {
	now := time.Now().UTC()
	revision := strings.Repeat("a", 32)
	valid := inspectionscope.RuntimeStatus{Component: "proxy-server", ConfigComponent: "gateway-core", NodeID: "proxy-server:test", Status: "applied", ConfigLoaded: true, Fresh: true, AppliedRevision: revision, LastSuccessAt: now.Format(time.RFC3339Nano)}
	for _, name := range []string{"missing_key", "signature_failure", "old_revision", "refresh_failure", "stale", "recovered"} {
		t.Run(name, func(t *testing.T) {
			report := valid
			var err error
			switch name {
			case "missing_key":
				report.ConfigLoaded = false
				report.ErrorCode = "config_auth_unavailable"
			case "signature_failure":
				report.ErrorCode = "config_attestation_invalid"
			case "old_revision":
				report.AppliedRevision = strings.Repeat("b", 32)
			case "refresh_failure":
				err = fmt.Errorf("unavailable")
			case "stale":
				report.LastSuccessAt = now.Add(-121 * time.Second).Format(time.RFC3339Nano)
			}
			status := semanticRuntimeStatus{Status: semanticRuntimeStatusApplied, RuntimeVerified: true}
			applyProxyInspectionStatus(&status, revision, report, err, now)
			if status.RuntimeVerified != (name == "recovered") {
				t.Fatalf("incorrect verified state: %#v", status)
			}
			if !status.ProxyRequired || len(status.Components) != 1 || status.Components[0].Component != "proxy-server" {
				t.Fatal("proxy identity/requirement lost")
			}
			if name != "recovered" && status.Status == semanticRuntimeStatusApplied {
				t.Fatal("stale/missing proxy shown applied")
			}
		})
	}
}

type inspectionRoundTripFunc func(*http.Request) (*http.Response, error)

func (f inspectionRoundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestProxyScopeProbeUsesFixedInternalAuthenticatedAddress(t *testing.T) {
	client := &http.Client{Transport: inspectionRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.String() != "http://proxy-server:3128/internal/v1/inspection-scope/status" || r.Header.Get(InternalAPISecretHeader) != "test-internal-token" {
			t.Fatal("untrusted probe route or missing authentication")
		}
		body, _ := json.Marshal(inspectionscope.RuntimeStatus{Component: "proxy-server", ConfigComponent: "gateway-core"})
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(string(body)))}, nil
	})}
	if _, err := probeProxyInspectionScope(context.Background(), client, "test-internal-token"); err != nil {
		t.Fatal(err)
	}
	if _, err := probeProxyInspectionScope(context.Background(), client, ""); err == nil {
		t.Fatal("missing internal key accepted")
	}
}
