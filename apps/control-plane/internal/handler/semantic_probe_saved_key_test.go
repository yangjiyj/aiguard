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
	"github.com/yangjiyj/aiguard/packages/shared-go/secrets"
)

type savedJudgeSettingsFailureRepo struct{ *capturingSystemRepo }

func (r *savedJudgeSettingsFailureRepo) GetAll(context.Context) ([]*repository.SystemSetting, error) {
	return nil, errors.New("test store unavailable")
}

func TestSemanticJudgeProbeSavedKeyEndpointBinding(t *testing.T) {
	t.Setenv("JJD_PROVIDER_SECRET_KEY", "test-only-encryption-key")
	encrypted, _, err := secrets.EncryptProviderSecret("test-saved-judge-key")
	if err != nil {
		t.Fatalf("encrypt fixture: %v", err)
	}

	var receivedAuthorization string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedAuthorization = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"{\"verdict\":\"benign\"}"}}]}`))
	}))
	defer server.Close()
	endpoint, network := semanticJudgeNetworkForTestServer(t, server, "judge.example")

	cases := []struct {
		name              string
		savedBackend      string
		savedURL          string
		requestURL        string
		suppliedKey       string
		savedKey          string
		wantAuthorization string
	}{
		{"matching endpoint reuses encrypted key", "custom", endpoint, endpoint, "", encrypted, "Bearer test-saved-judge-key"},
		{"changed path never receives saved key", "custom", endpoint, endpoint + "/other", "", encrypted, ""},
		{"changed query never receives saved key", "custom", endpoint, endpoint + "?destination=other", "", encrypted, ""},
		{"inactive custom settings never reuse key", "bundled", endpoint, endpoint, "", encrypted, ""},
		{"fresh key takes priority", "custom", endpoint, endpoint, "test-new-key", encrypted, "Bearer test-new-key"},
		{"fresh key works for changed endpoint", "custom", endpoint, endpoint + "/other", "test-new-key", encrypted, "Bearer test-new-key"},
		{"absent saved key allows anonymous endpoint", "custom", endpoint, endpoint, "", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			receivedAuthorization = "request-not-received"
			repo := &capturingSystemRepo{settings: map[string]string{
				"judge_backend": tc.savedBackend,
				"judge_url":     tc.savedURL,
				"judge_api_key": tc.savedKey,
			}}
			body, _ := json.Marshal(map[string]any{
				"judge_backend": "custom",
				"judge_url":     tc.requestURL,
				"judge_model":   "test-model",
				"judge_api_key": tc.suppliedKey,
			})
			response := httptest.NewRecorder()
			testSemanticJudgeWithNetwork(&Dependencies{SystemRepo: repo}, network).ServeHTTP(
				response, adminCtxRequest(http.MethodPost, "/admin/v1/security/semantic/test-judge", body))
			if response.Code != http.StatusOK {
				t.Fatalf("status=%d", response.Code)
			}
			var result struct {
				OK bool `json:"ok"`
			}
			if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil || !result.OK {
				t.Fatalf("expected successful test, result=%s err=%v", response.Body.String(), err)
			}
			if receivedAuthorization != tc.wantAuthorization {
				t.Errorf("authorization mismatch: got length %d, want length %d", len(receivedAuthorization), len(tc.wantAuthorization))
			}
			if strings.Contains(response.Body.String(), "test-saved-judge-key") {
				t.Error("response leaked the saved credential")
			}
		})
	}
}

func TestSemanticJudgeProbeSavedKeyStoreFailureDoesNotDial(t *testing.T) {
	called := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	endpoint, network := semanticJudgeNetworkForTestServer(t, server, "judge.example")
	repo := &savedJudgeSettingsFailureRepo{&capturingSystemRepo{settings: map[string]string{}}}
	body, _ := json.Marshal(map[string]any{"judge_backend": "custom", "judge_url": endpoint, "judge_model": "test-model"})
	response := httptest.NewRecorder()
	testSemanticJudgeWithNetwork(&Dependencies{SystemRepo: repo}, network).ServeHTTP(
		response, adminCtxRequest(http.MethodPost, "/admin/v1/security/semantic/test-judge", body))
	var result struct {
		OK bool `json:"ok"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.OK || called {
		t.Fatalf("settings read failure must not send an unauthenticated test; ok=%v called=%v", result.OK, called)
	}
}

func TestSemanticJudgeProbeSavedKeyRequiresPersistedPrivateAuthorization(t *testing.T) {
	t.Setenv("JJD_PROVIDER_SECRET_KEY", "test-only-encryption-key")
	encrypted, _, err := secrets.EncryptProviderSecret("test-saved-judge-key")
	if err != nil {
		t.Fatal(err)
	}
	var received string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received = r.Header.Get("Authorization")
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"{\"verdict\":\"benign\"}"}}]}`))
	}))
	defer server.Close()
	endpoint, network := semanticJudgeNetworkForTestServerAddress(t, server, "private-judge.example", "10.0.0.9")
	for _, tc := range []struct {
		savedAllow string
		want       string
	}{
		{"false", ""},
		{"true", "Bearer test-saved-judge-key"},
	} {
		received = "not-called"
		repo := &capturingSystemRepo{settings: map[string]string{
			"judge_backend": "custom", "judge_url": endpoint, "judge_api_key": encrypted,
			"judge_allow_private_egress": tc.savedAllow,
		}}
		body, _ := json.Marshal(map[string]any{
			"judge_backend": "custom", "judge_url": endpoint, "judge_model": "test-model", "judge_allow_private_egress": true,
		})
		response := httptest.NewRecorder()
		testSemanticJudgeWithNetwork(&Dependencies{SystemRepo: repo}, network).ServeHTTP(
			response, adminCtxRequest(http.MethodPost, "/admin/v1/security/semantic/test-judge", body))
		if received != tc.want {
			t.Errorf("saved private authorization=%s: got length %d, want length %d", tc.savedAllow, len(received), len(tc.want))
		}
	}
}

func TestSemanticJudgeProbeCorruptSavedKeyDoesNotDial(t *testing.T) {
	t.Setenv("JJD_PROVIDER_SECRET_KEY", "test-only-encryption-key")
	called := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	}))
	defer server.Close()
	endpoint, network := semanticJudgeNetworkForTestServer(t, server, "judge.example")
	repo := &capturingSystemRepo{settings: map[string]string{
		"judge_backend": "custom", "judge_url": endpoint, "judge_api_key": "enc:v1:invalid",
	}}
	body, _ := json.Marshal(map[string]any{"judge_backend": "custom", "judge_url": endpoint, "judge_model": "test-model"})
	response := httptest.NewRecorder()
	testSemanticJudgeWithNetwork(&Dependencies{SystemRepo: repo}, network).ServeHTTP(
		response, adminCtxRequest(http.MethodPost, "/admin/v1/security/semantic/test-judge", body))
	var result struct {
		OK bool `json:"ok"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.OK || called {
		t.Fatalf("corrupt saved key must fail before dialing; ok=%v called=%v", result.OK, called)
	}
}
