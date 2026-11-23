package handler

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestUpdateSystemSettingsRejectsInvalidSemanticValues(t *testing.T) {
	tests := []map[string]any{
		{"semantic_enabled": "yes"},
		{"semantic_output_enabled": true},
		{"semantic_sample_rate": 1.1},
		{"semantic_total_timeout": 0},
		{"judge_backend": "mystery"},
		{"judge_allow_private_egress": "yes"},
		{"tier1_enabled": "yes"},
		{"tier1_url": "http://attacker.example/collect"},
		{"judge_url": "file:///etc/passwd"},
		{"judge_url": "http://169.254.169.254/latest/meta-data"},
		{"judge_url": "http://10.0.0.8/v1/chat/completions"},
		{"judge_url": "http://100.64.0.8/v1/chat/completions"},
		{"judge_url": "http://100.100.100.200/latest/meta-data"},
	}
	for _, payload := range tests {
		t.Run(strings.ReplaceAll(strings.TrimSpace(mustJSONForSemanticTest(payload)), " ", "_"), func(t *testing.T) {
			repo := &capturingSystemRepo{}
			deps := &Dependencies{SystemRepo: repo}
			body, _ := json.Marshal(payload)
			response := httptest.NewRecorder()
			UpdateSystemSettings(deps).ServeHTTP(
				response,
				adminCtxRequest(http.MethodPut, "/admin/v1/system/settings", body),
			)
			if response.Code != http.StatusBadRequest {
				t.Fatalf("payload=%s status=%d want 400 body=%s", body, response.Code, response.Body.String())
			}
		})
	}
}

func TestUpdateSystemSettingsAllowsPrivateJudgeOnlyWithExplicitOptIn(t *testing.T) {
	repo := &capturingSystemRepo{}
	deps := &Dependencies{SystemRepo: repo}
	body, _ := json.Marshal(map[string]any{
		"judge_backend":              "custom",
		"judge_url":                  "https://10.0.0.8/v1/chat/completions",
		"judge_allow_private_egress": true,
	})
	response := httptest.NewRecorder()

	UpdateSystemSettings(deps).ServeHTTP(
		response,
		adminCtxRequest(http.MethodPut, "/admin/v1/system/settings", body),
	)

	if response.Code != http.StatusOK {
		t.Fatalf("status=%d want 200 body=%s", response.Code, response.Body.String())
	}
	if repo.settings["judge_allow_private_egress"] != "true" {
		t.Fatalf("private egress opt-in was not persisted: %#v", repo.settings)
	}
}

func TestUpdateSystemSettingsRejectsMixedPublicAndPrivateDNSAnswers(t *testing.T) {
	resolver := &staticSemanticJudgeResolver{records: map[string][]net.IPAddr{
		"judge.example": {
			{IP: net.ParseIP("93.184.216.34")},
			{IP: net.ParseIP("10.0.0.8")},
		},
	}}
	network := semanticJudgeTestNetwork(resolver, nil)

	repo := &capturingSystemRepo{}
	deps := &Dependencies{SystemRepo: repo}
	body, _ := json.Marshal(map[string]any{
		"judge_backend": "custom",
		"judge_url":     "https://judge.example/v1/chat/completions",
	})
	response := httptest.NewRecorder()
	updateSystemSettingsWithSemanticNetwork(deps, network).ServeHTTP(
		response,
		adminCtxRequest(http.MethodPut, "/admin/v1/system/settings", body),
	)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("status=%d want 400 body=%s", response.Code, response.Body.String())
	}
	if len(repo.settings) != 0 {
		t.Fatalf("unsafe DNS target must not be persisted: %#v", repo.settings)
	}
}

func TestUpdateSystemSettingsPrivateEgressOptInRequiresPlatformAdmin(t *testing.T) {
	repo := &capturingSystemRepo{}
	deps := &Dependencies{SystemRepo: repo}
	body, _ := json.Marshal(map[string]any{"judge_allow_private_egress": true})
	response := httptest.NewRecorder()

	UpdateSystemSettings(deps).ServeHTTP(
		response,
		nonAdminCtxRequest(http.MethodPut, "/admin/v1/system/settings", body),
	)

	if response.Code != http.StatusForbidden {
		t.Fatalf("status=%d want 403 body=%s", response.Code, response.Body.String())
	}
	if len(repo.settings) != 0 {
		t.Fatalf("non platform admin must not persist private egress opt-in: %#v", repo.settings)
	}
}

func TestUpdateSystemSettingsRejectsOversizedBody(t *testing.T) {
	repo := &capturingSystemRepo{}
	deps := &Dependencies{SystemRepo: repo}
	body := []byte(`{"unrelated":"` + strings.Repeat("x", 70<<10) + `"}`)
	response := httptest.NewRecorder()

	UpdateSystemSettings(deps).ServeHTTP(
		response,
		adminCtxRequest(http.MethodPut, "/admin/v1/system/settings", body),
	)

	if response.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status=%d want 413 body=%s", response.Code, response.Body.String())
	}
}

func mustJSONForSemanticTest(value map[string]any) string {
	payload, _ := json.Marshal(value)
	return string(payload)
}

func TestUpdateSystemSettingsAllowsPlainHTTPPrivateJudgeOnlyWithExplicitOptIn(t *testing.T) {
	for _, tc := range []struct {
		name     string
		optIn    bool
		wantHTTP int
	}{
		{name: "opt-in", optIn: true, wantHTTP: http.StatusOK},
		{name: "no-opt-in", optIn: false, wantHTTP: http.StatusBadRequest},
	} {
		t.Run(tc.name, func(t *testing.T) {
			repo := &capturingSystemRepo{}
			deps := &Dependencies{SystemRepo: repo}
			body, _ := json.Marshal(map[string]any{
				"judge_backend":              "custom",
				"judge_url":                  "http://172.16.20.10:8000/v1/chat/completions",
				"judge_allow_private_egress": tc.optIn,
			})
			response := httptest.NewRecorder()
			UpdateSystemSettings(deps).ServeHTTP(
				response,
				adminCtxRequest(http.MethodPut, "/admin/v1/system/settings", body),
			)
			if response.Code != tc.wantHTTP {
				t.Fatalf("status=%d want %d body=%s", response.Code, tc.wantHTTP, response.Body.String())
			}
			if tc.wantHTTP == http.StatusOK && repo.settings["judge_url"] != "http://172.16.20.10:8000/v1/chat/completions" {
				t.Fatalf("private http judge_url was not persisted: %#v", repo.settings)
			}
			if tc.wantHTTP != http.StatusOK && len(repo.settings) != 0 {
				t.Fatalf("rejected judge_url must not be persisted: %#v", repo.settings)
			}
		})
	}
}
