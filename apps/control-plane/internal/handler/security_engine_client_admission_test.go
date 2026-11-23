package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func TestScanToolDescriptionCheckedDistinguishesCleanFromUnavailable(t *testing.T) {
	if _, err := newSecurityEngineClient("", "").ScanToolDescriptionChecked(t.Context(), "r", "tool", "description"); err == nil {
		t.Fatal("unconfigured scanner was reported as clean")
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"findings":[]}`))
	}))
	defer server.Close()
	flags, err := newSecurityEngineClient(server.URL, "").ScanToolDescriptionChecked(t.Context(), "r", "tool", "description")
	if err != nil || flags == nil || len(flags) != 0 {
		t.Fatalf("clean scan not proven: flags=%v err=%v", flags, err)
	}
}

func TestSecurityEngineClientSendsInternalTokenOnEveryScan(t *testing.T) {
	const internalToken = "unit-test-internal-secret"
	var accepted atomic.Int32
	var admissionScans atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get(InternalAPISecretHeader); got != internalToken {
			http.Error(w, "invalid internal token", http.StatusUnauthorized)
			return
		}
		accepted.Add(1)
		var payload struct {
			Context map[string]any `json:"context"`
		}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		if payload.Context["mcp_admission_scan"] == true {
			admissionScans.Add(1)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"action":"allow","findings":[]}`))
	}))
	defer server.Close()

	client := newSecurityEngineClient(server.URL, internalToken)
	flags, err := client.ScanToolDescriptionChecked(
		t.Context(), "checked", "echo", "Echo a supplied value.")
	if err != nil || len(flags) != 0 {
		t.Fatalf("checked scan failed with valid internal token: flags=%v err=%v", flags, err)
	}
	if flags := client.ScanToolDescription(
		t.Context(), "legacy", "echo", "Echo a supplied value."); flags != nil {
		t.Fatalf("legacy scan returned unexpected flags: %v", flags)
	}
	action, findings, err := client.scanContent(
		t.Context(), "content-request", "safe content", "safe.txt", "ref", "abc")
	if err != nil {
		t.Fatalf("content scan failed with valid internal token: %v", err)
	}
	if action != "allow" || len(findings) != 0 {
		t.Fatalf("unexpected content scan response: action=%q findings=%v",
			action, findings)
	}
	if got := accepted.Load(); got != 3 {
		t.Fatalf("authenticated requests = %d, want 3", got)
	}
	if got := admissionScans.Load(); got != 2 {
		t.Fatalf("admission-grade description scans = %d, want 2", got)
	}
}
