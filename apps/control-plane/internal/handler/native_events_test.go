package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

type nativeHandlerFake struct {
	auth   repository.NativeEventTransport
	tenant string
	calls  int
	err    error
}

func (f *nativeHandlerFake) Ingest(_ context.Context, a repository.NativeEventTransport, _ []byte) (*repository.NativeEventReceipt, error) {
	f.calls++
	f.auth = a
	return &repository.NativeEventReceipt{SchemaVersion: "identity-events.ack.v1", Accepted: []string{"id"}, Duplicates: []string{}}, f.err
}
func (f *nativeHandlerFake) List(_ context.Context, tenant string, _ repository.NativeEventFilter) (*repository.NativeEventPage, error) {
	f.calls++
	f.tenant = tenant
	return &repository.NativeEventPage{Items: []repository.NativeEventObservation{{
		EventID: "id", Payload: json.RawMessage(`{"subject_claim":{"native_id":"private-subject"}}`),
		Investigation: &repository.NativeEventInvestigation{
			LegacyEvent: repository.NativeEventResolution{Status: "matched", ID: "private-agent-event"},
			Session:     repository.NativeEventResolution{Status: "matched", ID: "private-session"},
			Alert:       repository.NativeEventResolution{Status: "matched", ID: "private-alert"},
		},
	}}}, f.err
}
func nativeHandlerRequest(body string) *http.Request {
	req := httptest.NewRequest(http.MethodPost, "/admin/v1/internal/agent/identity-events", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer test-token")
	req.Header.Set("Content-Type", "application/json")
	return req.WithContext(contextWithEndpoint(req.Context(), &repository.AgentEndpointContext{TenantID: "tenant-a", EndpointID: "ep-a"}))
}
func TestNativeEventHandlerUsesAuthenticatedTransportAndErrorStatus(t *testing.T) {
	for _, tc := range []struct {
		err    error
		status int
	}{
		{nil, 200}, {repository.ErrNativeEventUnauthorized, 401}, {repository.ErrNativeEventInvalid, 422}, {repository.ErrNativeEventConflict, 409}, {errors.New("private database detail"), 500},
	} {
		fake := &nativeHandlerFake{err: tc.err}
		api := NewNativeEventAPI(fake)
		rec := httptest.NewRecorder()
		api.Ingest(rec, nativeHandlerRequest("{}"))
		if rec.Code != tc.status || fake.auth.TenantID != "tenant-a" || fake.auth.EndpointID != "ep-a" || fake.auth.CredentialHash != repository.HashAgentToken("test-token") {
			t.Fatalf("status=%d auth=%+v", rec.Code, fake.auth)
		}
		if strings.Contains(rec.Body.String(), "private database detail") {
			t.Fatal("leaked storage detail")
		}
		if tc.err != nil && strings.Contains(rec.Body.String(), "\"accepted\"") {
			t.Fatal("failure returned ACK")
		}
	}
}
func TestNativeEventHandlerRejectsUnboundOversizeAndEncoding(t *testing.T) {
	fake := &nativeHandlerFake{}
	api := NewNativeEventAPI(fake)
	reqs := []*http.Request{
		httptest.NewRequest(http.MethodPost, "/", strings.NewReader("{}")),
		nativeHandlerRequest(strings.Repeat("a", nativeEventBodyLimit+1)),
		nativeHandlerRequest("{}"),
	}
	reqs[2].Header.Set("Content-Encoding", "gzip")
	for i, req := range reqs {
		rec := httptest.NewRecorder()
		api.Ingest(rec, req)
		if rec.Code != []int{401, 413, 415}[i] || fake.calls != 0 {
			t.Fatalf("case%d status=%d calls=%d", i, rec.Code, fake.calls)
		}
	}
}
func TestNativeEventHandlerListTenantAndPayloadPermission(t *testing.T) {
	for _, role := range []string{"tenant_admin", "emergency_tenant_admin"} {
		fake := &nativeHandlerFake{}
		api := NewNativeEventAPI(fake)
		rec := httptest.NewRecorder()
		api.List(rec, agentAdminRequest(http.MethodGet, "/admin/v1/agent/native-events", role, nil))
		if rec.Code != 200 || fake.tenant != "tenant-a" {
			t.Fatalf("status=%d tenant=%s", rec.Code, fake.tenant)
		}
		private := strings.Contains(rec.Body.String(), "private-subject")
		if private != (role == "tenant_admin") {
			t.Fatalf("role=%s private=%v", role, private)
		}
		projected := strings.Contains(rec.Body.String(), "private-agent-event")
		if projected != (role == "tenant_admin") {
			t.Fatalf("role=%s projected=%v", role, projected)
		}
	}
	for _, query := range []string{"?tenant_id=tenant-b", "?limit=201", "?limit=1&limit=2", "?before_sequence=-1"} {
		fake := &nativeHandlerFake{}
		rec := httptest.NewRecorder()
		NewNativeEventAPI(fake).List(rec, agentAdminRequest(http.MethodGet, "/admin/v1/agent/native-events"+query, "tenant_admin", nil))
		if rec.Code != 400 || fake.calls != 0 {
			t.Fatalf("query=%s status=%d calls=%d", query, rec.Code, fake.calls)
		}
	}
}
