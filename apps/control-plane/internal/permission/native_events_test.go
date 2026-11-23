package permission

import (
	"net/http/httptest"
	"testing"
)

func TestNativeEventRoutePermissions(t *testing.T) {
	read, ok := routeTable["GET /admin/v1/agent/native-events"]
	if !ok || read.Resource != "agent_sessions" || read.Action != "read" || read.ScopeType != "tenant" {
		t.Fatalf("native read=%+v exists=%v", read, ok)
	}
	ingest, ok := routeTable["POST /admin/v1/internal/agent/identity-events"]
	if !ok || ingest.Resource != "agent_sessions" || ingest.Action != "write" || ingest.ScopeType != "tenant" {
		t.Fatalf("native ingest=%+v exists=%v", ingest, ok)
	}
}

func TestProbeReportRouteUsesEndpointTenantWritePermission(t *testing.T) {
	got := Resolve(httptest.NewRequest("POST", "/admin/v1/internal/agent/probe-reports", nil))
	if got.RequirePlatformAdmin || got.Resource != "agent_endpoints" || got.Action != "write" || got.ScopeType != "tenant" {
		t.Fatalf("probe report permission = %+v", got)
	}
}
