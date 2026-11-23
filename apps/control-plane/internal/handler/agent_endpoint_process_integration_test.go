package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

type hookdProcessRepo struct {
	*repository.AgentEndpointRepository
	t               *testing.T
	ackAll          bool
	mu              sync.Mutex
	batchCalls      int
	heartbeatCalls  int
	gotGzip         bool
	gotSchema       string
	gotHookdVersion string
	gotSentAt       string
	gotEventIDs     []string
	gotHealth       any
}

func (f *hookdProcessRepo) Policy(_ context.Context, tenant string) (map[string]any, error) {
	if tenant != "integration-tenant" {
		f.t.Errorf("policy tenant=%q", tenant)
	}
	return map[string]any{"version": int64(7), "checksum": "sha256:" + strings.Repeat("a", 64), "rules": []any{}}, nil
}

func (f *hookdProcessRepo) Heartbeat(_ context.Context, tenant, endpoint string, health any, policyVersion, configVersion int64) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.heartbeatCalls++
	f.gotHealth = health
	if tenant != "integration-tenant" || endpoint != "integration-endpoint" || policyVersion != 7 || configVersion != 1 {
		f.t.Errorf("heartbeat scope/version tenant=%q endpoint=%q policy=%d config=%d", tenant, endpoint, policyVersion, configVersion)
	}
	return nil
}

func (f *hookdProcessRepo) AcceptEventBatch(_ context.Context, tenant, endpoint string, request repository.AgentEventBatchRequest) (*repository.AgentEventBatchResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.batchCalls++
	f.gotSchema = request.SchemaVersion
	f.gotHookdVersion = request.HookdVersion
	f.gotSentAt = request.SentAt
	if tenant != "integration-tenant" || endpoint != "integration-endpoint" || request.EndpointID != "integration-endpoint" {
		f.t.Errorf("event scope tenant=%q endpoint=%q batch=%q", tenant, endpoint, request.EndpointID)
	}
	for _, raw := range request.Events {
		var item struct {
			EventID   string `json:"event_id"`
			EventType string `json:"event_type"`
		}
		if err := json.Unmarshal(raw, &item); err != nil {
			f.t.Fatal(err)
		}
		if item.EventType != "tool.pre" {
			f.t.Errorf("event type=%q", item.EventType)
		}
		f.gotEventIDs = append(f.gotEventIDs, item.EventID)
	}
	accepted := []string{}
	if f.ackAll {
		accepted = append(accepted, f.gotEventIDs...)
	}
	return &repository.AgentEventBatchResult{Accepted: accepted, Duplicates: []string{}, Rejected: []string{}}, nil
}

func TestT04HookdProcessToEventsHandler(t *testing.T) {
	binary := os.Getenv("T04_HOOKD_BIN")
	if binary == "" {
		t.Skip("set T04_HOOKD_BIN to the exact reviewed hookd candidate binary")
	}
	for _, tc := range []struct {
		name      string
		ackAll    bool
		wantQueue int
	}{
		{"complete ACK clears queue", true, 0},
		{"incomplete ACK retains queue", false, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			repo := &hookdProcessRepo{t: t, ackAll: tc.ackAll}
			api := &AgentEndpointAPI{Repo: repo}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Authorization") != "Bearer integration-only-token" {
					http.Error(w, "unauthorized", 401)
					return
				}
				if r.Method != http.MethodPost {
					http.Error(w, "method", 405)
					return
				}
				ctx := contextWithEndpoint(r.Context(), &repository.AgentEndpointContext{TenantID: "integration-tenant", EndpointID: "integration-endpoint", PolicyVersion: 7, Mode: "monitor", CaptureLevel: "metadata"})
				r = r.WithContext(ctx)
				switch r.URL.Path {
				case "/agent/v1/events":
					repo.mu.Lock()
					repo.gotGzip = strings.EqualFold(r.Header.Get("Content-Encoding"), "gzip")
					repo.mu.Unlock()
					api.Events(w, r)
				case "/agent/v1/endpoints/heartbeat":
					api.Heartbeat(w, r)
				default:
					http.NotFound(w, r)
				}
			}))
			defer server.Close()

			stateRoot := t.TempDir()
			endpoint := map[string]any{"server": server.URL + "/agent/v1", "endpoint_id": "integration-endpoint", "endpoint_token": "integration-only-token", "mode": "monitor", "capture_level": "metadata", "policy_version": 7, "policy_checksum": "sha256:" + strings.Repeat("a", 64), "config": map[string]any{"version": 1, "heartbeat_interval_sec": 300, "report_interval_sec": 10, "report_batch_max": 20, "decide_timeout_ms": 300, "decide_fail_mode": "open", "queue_max_bytes": 1048576}}
			data, err := json.Marshal(endpoint)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(stateRoot, "endpoint.json"), data, 0600); err != nil {
				t.Fatal(err)
			}
			queueDir := filepath.Join(stateRoot, "queue")
			if err := os.MkdirAll(queueDir, 0700); err != nil {
				t.Fatal(err)
			}
			event := `{"event_id":"integration-event-1","event_type":"tool.pre","occurred_at":"2026-09-25T00:00:00Z","agent":{"product":"integration","version":"1"},"session":{"session_id":"session-1"},"context":{"machine_id":"machine-1","hostname":"host-1","os_user":"tester"},"tool":{"tool_use_id":"tool-1","name":"read_file","type":"function"}}` + "\n"
			if err := os.WriteFile(filepath.Join(queueDir, "fixture.jsonl"), []byte(event), 0600); err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command(binary, "uploader", "--once")
			cmd.Env = append(os.Environ(), "JJDGUARD_STATE_DIR="+stateRoot)
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("hookd uploader failed: %v: %s", err, out)
			}
			repo.mu.Lock()
			assertHookdControlBoundary(t, repo.gotHealth)
			if !repo.gotGzip || repo.gotSchema != "events.v1" || repo.gotHookdVersion == "" || repo.gotSentAt == "" || repo.batchCalls != 1 || repo.heartbeatCalls != 1 || len(repo.gotEventIDs) != 1 || repo.gotEventIDs[0] != "integration-event-1" {
				t.Fatalf("observed gzip=%v schema=%q hookd=%q sent_at=%q batches=%d heartbeats=%d ids=%v", repo.gotGzip, repo.gotSchema, repo.gotHookdVersion, repo.gotSentAt, repo.batchCalls, repo.heartbeatCalls, repo.gotEventIDs)
			}
			repo.mu.Unlock()
			files, err := filepath.Glob(filepath.Join(queueDir, "*.jsonl"))
			if err != nil {
				t.Fatal(err)
			}
			if len(files) != tc.wantQueue {
				t.Fatalf("pending queue files=%d want=%d", len(files), tc.wantQueue)
			}
			endpointAfter := map[string]any{}
			data, err = os.ReadFile(filepath.Join(stateRoot, "endpoint.json"))
			if err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(data, &endpointAfter); err != nil {
				t.Fatal(err)
			}
			if endpointAfter["policy_version"] != float64(7) || endpointAfter["desired_policy_version"] != float64(7) || endpointAfter["sync_pending"] == true {
				t.Fatalf("desired/applied/sync state=%v", endpointAfter)
			}
		})
	}
}

// assertHookdControlBoundary checks the real hookd heartbeat carries the
// control boundary through the non-strict heartbeat decode unchanged, and that
// the admin projection would surface it.
func assertHookdControlBoundary(t *testing.T, health any) {
	t.Helper()
	raw, err := json.Marshal(health)
	if err != nil {
		t.Fatal(err)
	}
	projected := repository.ControlBoundaryFromHealth(raw)
	var report struct {
		Schema                           string                     `json:"schema"`
		RequireTrustedAgentAuthorization *bool                      `json:"require_trusted_agent_authorization"`
		DecideFailMode                   string                     `json:"decide_fail_mode"`
		Hosts                            map[string]json.RawMessage `json:"hosts"`
	}
	if err := json.Unmarshal(projected, &report); err != nil || report.Schema != "jjdguard-control-boundary/v1" || report.RequireTrustedAgentAuthorization == nil || report.DecideFailMode != "open" || report.Hosts["openclaw"] == nil || report.Hosts["claude-code"] == nil {
		t.Fatalf("hookd heartbeat control_boundary=%s err=%v (health=%s)", projected, err, raw)
	}
	if out := os.Getenv("T04_HOOKD_HEALTH_OUT"); out != "" {
		if err := os.WriteFile(out, raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
}
