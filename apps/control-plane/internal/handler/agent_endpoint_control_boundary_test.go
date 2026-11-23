package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

type controlBoundaryHeartbeatRepo struct {
	agentEndpointRepository
	health any
}

func (f *controlBoundaryHeartbeatRepo) Heartbeat(_ context.Context, _, _ string, health any, _, _ int64) error {
	f.health = health
	return nil
}

func (f *controlBoundaryHeartbeatRepo) Policy(context.Context, string) (map[string]any, error) {
	return map[string]any{"version": int64(1), "checksum": "sha256:" + strings.Repeat("b", 64)}, nil
}

const controlBoundaryHealth = `{"queue_events":2,"control_boundary":{"schema":"jjdguard-control-boundary/v1","require_trusted_agent_authorization":true,"decide_fail_mode":"open","hosts":{"openclaw":{"pre_tool_gate":true,"paths":[{"trigger":"before_handshake_failure_or_timeout","behavior":"fail_closed"}]}}}}`

// The heartbeat body stores health verbatim (jsonb); control_boundary needs no
// envelope change and must reach the repository unchanged.
func TestHeartbeatStoresControlBoundaryVerbatim(t *testing.T) {
	repo := &controlBoundaryHeartbeatRepo{}
	api := &AgentEndpointAPI{Repo: repo}
	body := `{"endpoint_id":"ep-1","hookd_version":"0.1.0","policy_version":1,"config_version":1,"health":` + controlBoundaryHealth + `}`
	req := httptest.NewRequest(http.MethodPost, "/admin/v1/internal/agent/endpoints/heartbeat", strings.NewReader(body))
	req = req.WithContext(contextWithEndpoint(req.Context(), &repository.AgentEndpointContext{TenantID: "t", EndpointID: "ep-1", Mode: "monitor", CaptureLevel: "metadata"}))
	rec := httptest.NewRecorder()
	api.Heartbeat(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	stored, _ := json.Marshal(repo.health)
	got := repository.ControlBoundaryFromHealth(stored)
	var want, have any
	_ = json.Unmarshal([]byte(controlBoundaryHealth), &want)
	_ = json.Unmarshal(got, &have)
	wantCB, _ := json.Marshal(want.(map[string]any)["control_boundary"])
	haveCB, _ := json.Marshal(have)
	if string(wantCB) != string(haveCB) {
		t.Fatalf("control_boundary changed in transit:\nwant %s\nhave %s", wantCB, haveCB)
	}
}

// control_boundary is heartbeat-only. The strict registration envelope was
// not relaxed: control_boundary and any other unknown field there still fail.
func TestRegistrationEnvelopeStillRejectsUnknownFields(t *testing.T) {
	for _, raw := range []string{
		strings.Replace(hookdRegistrationFixture, `"hookd_version":"0.1.0"`, `"hookd_version":"0.1.0","control_boundary":{"schema":"jjdguard-control-boundary/v1"}`, 1),
		strings.Replace(hookdRegistrationFixture, `"hookd_version":"0.1.0"`, `"hookd_version":"0.1.0","health":{}`, 1),
		strings.Replace(hookdRegistrationFixture, `"hookd_version":"0.1.0"`, `"hookd_version":"0.1.0","unexpected":1`, 1),
	} {
		if _, err := decodeAgentRegistration(strings.NewReader(raw)); err == nil {
			t.Fatalf("registration accepted unknown field: %s", raw)
		}
	}
	if _, err := decodeAgentRegistration(strings.NewReader(hookdRegistrationFixture)); err != nil {
		t.Fatalf("baseline registration rejected: %v", err)
	}
}

func TestAdminEndpointAPIExposesControlBoundaryOrNull(t *testing.T) {
	for _, tc := range []struct {
		name, health, want string
	}{
		{"legacy hookd", `{"queue_events":1}`, "null"},
		{"reporting hookd", controlBoundaryHealth, `"jjdguard-control-boundary/v1"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			health := json.RawMessage(tc.health)
			repo := &agentAdminFakeRepo{endpoint: &repository.AgentAdminEndpoint{ID: "ep-1", Health: health, ControlBoundary: repository.ControlBoundaryFromHealth(health)}}
			router := chi.NewRouter()
			router.Get("/admin/v1/agent/endpoints/{id}", NewAgentAdminAPI(repo, &Dependencies{}).GetEndpoint)
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, agentAdminRequest(http.MethodGet, "/admin/v1/agent/endpoints/ep-1", "tenant_admin", nil))
			if rec.Code != http.StatusOK {
				t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
			}
			var body map[string]json.RawMessage
			if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
				t.Fatal(err)
			}
			cb, ok := body["control_boundary"]
			if !ok {
				t.Fatalf("control_boundary missing: %s", rec.Body.String())
			}
			if tc.want == "null" {
				if string(cb) != "null" {
					t.Fatalf("legacy control_boundary=%s", cb)
				}
				return
			}
			var report map[string]json.RawMessage
			if err := json.Unmarshal(cb, &report); err != nil || string(report["schema"]) != tc.want {
				t.Fatalf("control_boundary=%s err=%v", cb, err)
			}
		})
	}
}
