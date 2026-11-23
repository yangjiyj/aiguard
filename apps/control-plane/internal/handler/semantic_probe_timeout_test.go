package handler

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestSemanticJudgeProbeUsesConfiguredTimeout(t *testing.T) {
	for _, tc := range []struct {
		value   string
		seconds int
		valid   bool
	}{
		{"", 8, true}, {"20", 20, true}, {"14.5", 15, true}, {"0", 0, false}, {"61", 0, false}, {"NaN", 0, false}, {"+Inf", 0, false}, {"invalid", 0, false},
	} {
		t.Run(tc.value, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"{\"verdict\":\"malicious\"}"}}]}`))
			}))
			defer server.Close()
			endpoint, network := semanticJudgeNetworkForTestServer(t, server, "judge-timeout.example")
			originalDial := network.dialContext
			calls := 0
			network.dialContext = func(ctx context.Context, n, a string) (net.Conn, error) {
				calls++

				return originalDial(ctx, n, a)
			}
			repo := &capturingSystemRepo{settings: map[string]string{"judge_timeout": tc.value}}
			budget, configErr := configuredJudgeProbeTimeout(context.Background(), &Dependencies{SystemRepo: repo})
			if tc.valid && (configErr != nil || budget != tc.seconds) {
				t.Fatalf("budget=%d error=%v", budget, configErr)
			}
			if !tc.valid && configErr == nil {
				t.Fatal("invalid timeout accepted")
			}
			body, _ := json.Marshal(map[string]any{"judge_backend": "custom", "judge_url": endpoint, "judge_model": "fixture"})
			response := httptest.NewRecorder()
			testSemanticJudgeWithNetwork(&Dependencies{SystemRepo: repo}, network).ServeHTTP(response, adminCtxRequest(http.MethodPost, "/admin/v1/security/semantic/test-judge", body))
			var result map[string]any
			if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
				t.Fatal(err)
			}
			if ok, _ := result["ok"].(bool); ok != tc.valid {
				t.Fatalf("ok=%v want %v response=%v", ok, tc.valid, result)
			}
			if !tc.valid && calls != 0 {
				t.Fatalf("invalid timeout reached network %d times", calls)
			}
		})
	}
}

func TestSemanticJudgeProbeHonorsShortConfiguredBudget(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
			return
		case <-time.After(1500 * time.Millisecond):
		}
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"{\"verdict\":\"malicious\"}"}}]}`))
	}))
	defer server.Close()
	endpoint, network := semanticJudgeNetworkForTestServer(t, server, "judge-budget.example")
	deps := &Dependencies{SystemRepo: &capturingSystemRepo{settings: map[string]string{"judge_timeout": "1"}}}
	body, _ := json.Marshal(map[string]any{"judge_backend": "custom", "judge_url": endpoint, "judge_model": "fixture"})
	response := httptest.NewRecorder()
	started := time.Now()
	testSemanticJudgeWithNetwork(deps, network).ServeHTTP(response, adminCtxRequest(http.MethodPost, "/admin/v1/security/semantic/test-judge", body))
	var result map[string]any
	_ = json.Unmarshal(response.Body.Bytes(), &result)
	if result["ok"] != false {
		t.Fatalf("configured 1s must expire before 1.5s response: %v", result)
	}
	if time.Since(started) > 1400*time.Millisecond {
		t.Fatalf("probe ignored configured deadline: %v", time.Since(started))
	}
}
