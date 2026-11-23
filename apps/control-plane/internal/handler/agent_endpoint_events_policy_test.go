package handler

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

type eventsPolicyRepo struct {
	*repository.AgentEndpointRepository
	t                       *testing.T
	policy                  map[string]any
	policyErr               error
	batchErr                error
	policyCalls, batchCalls int
}

func (f *eventsPolicyRepo) Policy(_ context.Context, tenant string) (map[string]any, error) {
	f.t.Helper()
	if tenant != "authenticated-tenant" {
		f.t.Fatalf("policy tenant = %q", tenant)
	}
	f.policyCalls++
	return f.policy, f.policyErr
}

func (f *eventsPolicyRepo) AcceptEventBatch(_ context.Context, tenant, endpoint string, request repository.AgentEventBatchRequest) (*repository.AgentEventBatchResult, error) {
	f.t.Helper()
	if tenant != "authenticated-tenant" || endpoint != "authenticated-endpoint" || request.EndpointID != endpoint || request.SchemaVersion != "events.v1" {
		f.t.Fatalf("batch scope = %q/%q/%q", tenant, endpoint, request.SchemaVersion)
	}
	f.batchCalls++
	if f.batchErr != nil {
		return nil, f.batchErr
	}
	return &repository.AgentEventBatchResult{
		Accepted: []string{"new-event"}, Duplicates: []string{"replayed-event"}, Rejected: []string{},
	}, nil
}

func eventsPolicyRequest() *http.Request {
	r := httptest.NewRequest(http.MethodPost, "/events", strings.NewReader(
		`{"schema_version":"events.v1","endpoint_id":"authenticated-endpoint","hookd_version":"test-hookd","sent_at":"2026-09-25T00:00:00Z","events":[{"event_id":"new-event"},{"event_id":"replayed-event"}]}`))
	return r.WithContext(contextWithEndpoint(r.Context(), &repository.AgentEndpointContext{
		TenantID: "authenticated-tenant", EndpointID: "authenticated-endpoint",
		PolicyVersion: 1, Mode: "monitor",
	}))
}

func TestEventsRejectsEndpointMismatchBeforeRepository(t *testing.T) {
	repo := &eventsPolicyRepo{t: t, policy: map[string]any{"version": int64(7), "checksum": "sha256:" + strings.Repeat("a", 64)}}
	r := httptest.NewRequest(http.MethodPost, "/events", strings.NewReader(`{"schema_version":"events.v1","endpoint_id":"different-endpoint","hookd_version":"test-hookd","sent_at":"2026-09-25T00:00:00Z","events":[{"event_id":"new-event"}]}`))
	r = r.WithContext(eventsPolicyRequest().Context())
	w := httptest.NewRecorder()
	(&AgentEndpointAPI{Repo: repo}).Events(w, r)
	if w.Code != http.StatusUnauthorized || repo.policyCalls != 0 || repo.batchCalls != 0 {
		t.Fatalf("status=%d policy calls=%d batch calls=%d", w.Code, repo.policyCalls, repo.batchCalls)
	}
}

func TestEventsACKPolicyUsesDownloadableMetadata(t *testing.T) {
	checksum := "sha256:" + strings.Repeat("a", 64)
	repo := &eventsPolicyRepo{t: t, policy: map[string]any{
		"version": int64(7), "checksum": checksum, "rules": []any{},
	}}
	api := &AgentEndpointAPI{Repo: repo}
	download := httptest.NewRecorder()
	api.Policy(download, eventsPolicyRequest())
	if download.Code != http.StatusOK {
		t.Fatalf("download status = %d", download.Code)
	}
	var bundle map[string]any
	if err := json.Unmarshal(download.Body.Bytes(), &bundle); err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	api.Events(w, eventsPolicyRequest())
	var response struct {
		Accepted, Duplicates, Rejected []string
		Policy                         map[string]any
	}
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if w.Code != http.StatusOK || repo.batchCalls != 1 || repo.policyCalls != 2 {
		t.Fatalf("status=%d policy calls=%d batch calls=%d", w.Code, repo.policyCalls, repo.batchCalls)
	}
	if response.Policy["version"] != bundle["version"] || response.Policy["checksum"] != bundle["checksum"] {
		t.Fatalf("ACK policy=%v downloadable version=%v checksum=%v", response.Policy, bundle["version"], bundle["checksum"])
	}
	if !reflect.DeepEqual(response.Accepted, []string{"new-event"}) ||
		!reflect.DeepEqual(response.Duplicates, []string{"replayed-event"}) || len(response.Rejected) != 0 {
		t.Fatalf("ACK IDs changed: %+v", response)
	}
}

func TestEventsACKPolicyUnavailableDoesNotCommit(t *testing.T) {
	validChecksum := "sha256:" + strings.Repeat("a", 64)
	for _, tt := range []struct {
		name   string
		policy map[string]any
		err    error
	}{
		{"repository error", nil, errors.New("policy unavailable")},
		{"nil policy", nil, nil},
		{"no current bundle", map[string]any{"version": int64(0), "checksum": "sha256:" + strings.Repeat("0", 64)}, nil},
		{"negative version", map[string]any{"version": int64(-1), "checksum": validChecksum}, nil},
		{"invalid version type", map[string]any{"version": "7", "checksum": validChecksum}, nil},
		{"missing checksum", map[string]any{"version": int64(7)}, nil},
		{"invalid checksum type", map[string]any{"version": int64(7), "checksum": 7}, nil},
		{"invalid checksum prefix", map[string]any{"version": int64(7), "checksum": strings.Repeat("a", 64)}, nil},
		{"invalid checksum length", map[string]any{"version": int64(7), "checksum": "sha256:aa"}, nil},
		{"invalid checksum hex", map[string]any{"version": int64(7), "checksum": "sha256:" + strings.Repeat("z", 64)}, nil},
		{"placeholder checksum", map[string]any{"version": int64(7), "checksum": "sha256:" + strings.Repeat("0", 64)}, nil},
	} {
		t.Run(tt.name, func(t *testing.T) {
			repo := &eventsPolicyRepo{t: t, policy: tt.policy, policyErr: tt.err}
			w := httptest.NewRecorder()
			(&AgentEndpointAPI{Repo: repo}).Events(w, eventsPolicyRequest())
			if w.Code != http.StatusServiceUnavailable || repo.batchCalls != 0 || repo.policyCalls != 1 {
				t.Fatalf("status=%d policy calls=%d committed batch calls=%d", w.Code, repo.policyCalls, repo.batchCalls)
			}
			var response map[string]any
			if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
				t.Fatal(err)
			}
			if response["error"] != "policy_unavailable" || response["policy"] != nil {
				t.Fatalf("unsafe policy error response: %v", response)
			}
			for _, field := range []string{"accepted", "duplicates", "rejected"} {
				if ids, ok := response[field].([]any); !ok || len(ids) != 0 {
					t.Fatalf("%s must not acknowledge an uncommitted request: %v", field, response[field])
				}
			}
		})
	}
}

func TestEventsACKPolicyPreservesBatchErrors(t *testing.T) {
	for _, tt := range []struct {
		name   string
		err    error
		status int
		code   string
	}{
		{"conflict", &repository.AgentEventBatchError{Code: "event_conflict", EventIDs: []string{"conflicting-event"}}, 409, "event_conflict"},
		{"invalid", &repository.AgentEventBatchError{Code: "invalid_event", EventIDs: []string{"invalid-event"}}, 422, "invalid_event"},
		{"internal", errors.New("storage unavailable"), 500, "batch_failed"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			repo := &eventsPolicyRepo{t: t, policy: map[string]any{"version": int64(7), "checksum": "sha256:" + strings.Repeat("a", 64)}, batchErr: tt.err}
			w := httptest.NewRecorder()
			(&AgentEndpointAPI{Repo: repo}).Events(w, eventsPolicyRequest())
			var response map[string]any
			if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
				t.Fatal(err)
			}
			if w.Code != tt.status || response["error"] != tt.code || response["policy"] != nil || repo.batchCalls != 1 {
				t.Fatalf("status=%d body=%s batch calls=%d", w.Code, w.Body.String(), repo.batchCalls)
			}
		})
	}
}

func TestEventsACKPolicyRejectsBeforeRepository(t *testing.T) {
	for _, tt := range []struct {
		name, body string
		auth       bool
		status     int
	}{
		{"unauthenticated", "{}", false, 401},
		{"invalid JSON", "{", true, 422},
		{"unknown root field", `{"schema_version":"events.v1","events":[],"secret":"must-not-accept"}`, true, 422},
	} {
		t.Run(tt.name, func(t *testing.T) {
			repo := &eventsPolicyRepo{t: t}
			r := httptest.NewRequest(http.MethodPost, "/events", strings.NewReader(tt.body))
			if tt.auth {
				r = r.WithContext(eventsPolicyRequest().Context())
			}
			w := httptest.NewRecorder()
			(&AgentEndpointAPI{Repo: repo}).Events(w, r)
			if w.Code != tt.status || repo.policyCalls != 0 || repo.batchCalls != 0 {
				t.Fatalf("status=%d policy calls=%d batch calls=%d", w.Code, repo.policyCalls, repo.batchCalls)
			}
		})
	}
}

func gzipEventsPolicyRequest(t *testing.T, raw string) *http.Request {
	t.Helper()
	var encoded bytes.Buffer
	writer := gzip.NewWriter(&encoded)
	if _, err := writer.Write([]byte(raw)); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodPost, "/events", bytes.NewReader(encoded.Bytes()))
	r.Header.Set("Content-Encoding", "gzip")
	return r.WithContext(eventsPolicyRequest().Context())
}

func TestEventsGzipBodyAndEncodingLimits(t *testing.T) {
	validBody := `{"schema_version":"events.v1","endpoint_id":"authenticated-endpoint","hookd_version":"test-hookd","sent_at":"2026-09-25T00:00:00Z","events":[{"event_id":"new-event"},{"event_id":"replayed-event"}]}`
	t.Run("valid gzip ACK", func(t *testing.T) {
		repo := &eventsPolicyRepo{t: t, policy: map[string]any{"version": int64(7), "checksum": "sha256:" + strings.Repeat("a", 64)}}
		w := httptest.NewRecorder()
		(&AgentEndpointAPI{Repo: repo}).Events(w, gzipEventsPolicyRequest(t, validBody))
		if w.Code != http.StatusOK || repo.batchCalls != 1 || repo.policyCalls != 1 {
			t.Fatalf("status=%d policy calls=%d batch calls=%d body=%s", w.Code, repo.policyCalls, repo.batchCalls, w.Body.String())
		}
	})
	t.Run("invalid gzip", func(t *testing.T) {
		repo := &eventsPolicyRepo{t: t}
		r := httptest.NewRequest(http.MethodPost, "/events", strings.NewReader("not gzip"))
		r.Header.Set("Content-Encoding", "gzip")
		r = r.WithContext(eventsPolicyRequest().Context())
		w := httptest.NewRecorder()
		(&AgentEndpointAPI{Repo: repo}).Events(w, r)
		if w.Code != http.StatusUnprocessableEntity || repo.policyCalls != 0 || repo.batchCalls != 0 {
			t.Fatalf("status=%d policy calls=%d batch calls=%d", w.Code, repo.policyCalls, repo.batchCalls)
		}
	})
	t.Run("unsupported encoding", func(t *testing.T) {
		repo := &eventsPolicyRepo{t: t}
		r := eventsPolicyRequest()
		r.Header.Set("Content-Encoding", "br")
		w := httptest.NewRecorder()
		(&AgentEndpointAPI{Repo: repo}).Events(w, r)
		if w.Code != http.StatusUnsupportedMediaType || repo.policyCalls != 0 || repo.batchCalls != 0 {
			t.Fatalf("status=%d policy calls=%d batch calls=%d", w.Code, repo.policyCalls, repo.batchCalls)
		}
	})
	t.Run("decompressed limit", func(t *testing.T) {
		repo := &eventsPolicyRepo{t: t}
		r := gzipEventsPolicyRequest(t, validBody+strings.Repeat(" ", agentEventsBodyLimit+1))
		w := httptest.NewRecorder()
		(&AgentEndpointAPI{Repo: repo}).Events(w, r)
		if w.Code != http.StatusUnprocessableEntity || repo.policyCalls != 0 || repo.batchCalls != 0 {
			t.Fatalf("status=%d policy calls=%d batch calls=%d", w.Code, repo.policyCalls, repo.batchCalls)
		}
	})
}
