package security

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCheckTriage_PostsToCheckTriagePathWithToken(t *testing.T) {
	var gotPath, gotToken string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotToken = (func() string {
			if legacy := r.Header.Get("X-NewAPI-Internal-Token"); legacy != "" {
				t.Errorf("legacy internal token header must be absent")
			}
			return r.Header.Get("X-JJDGuard-Internal-Token")
		})()
		_ = json.NewEncoder(w).Encode(map[string]any{
			"request_id": "rid",
			"findings": []map[string]any{
				{"type": "prompt_injection", "triage": map[string]any{"verdict": "likely_false_positive"}},
			},
		})
	}))
	defer srv.Close()

	c := NewClientWithSecret(srv.URL, "sekret")
	resp, err := c.CheckTriage(context.Background(), &CheckTriageRequest{
		RequestID: "rid", Content: "你好",
		Findings: []SecurityFinding{{Type: "prompt_injection"}},
	})
	if err != nil {
		t.Fatalf("CheckTriage err: %v", err)
	}
	if gotPath != "/check-triage/" {
		t.Fatalf("path = %q, want /check-triage/", gotPath)
	}
	if gotToken != "sekret" {
		t.Fatalf("token = %q, want sekret", gotToken)
	}
	if len(resp.Findings) != 1 || resp.Findings[0].Triage["verdict"] != "likely_false_positive" {
		t.Fatalf("triage not carried: %+v", resp.Findings)
	}
}
