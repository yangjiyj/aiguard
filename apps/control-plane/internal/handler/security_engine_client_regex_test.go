package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestValidateRegexReturnsEngineDecision(t *testing.T) {
	tests := []struct {
		name          string
		response      string
		wantValid     bool
		wantErrorCode string
	}{
		{
			name:      "valid",
			response:  "{\"valid\":true,\"error_code\":null}",
			wantValid: true,
		},
		{
			name:          "invalid syntax",
			response:      "{\"valid\":false,\"error_code\":\"invalid_syntax\"}",
			wantErrorCode: "invalid_syntax",
		},
		{
			name:          "unsafe regex",
			response:      "{\"valid\":false,\"error_code\":\"unsafe_regex\"}",
			wantErrorCode: "unsafe_regex",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(tt.response))
			}))
			t.Cleanup(server.Close)

			valid, errorCode, err := newSecurityEngineClient(server.URL, "internal-secret").ValidateRegex(
				t.Context(), "(?=secret)secret",
			)
			if err != nil {
				t.Fatalf("ValidateRegex() error = %v", err)
			}
			if valid != tt.wantValid || errorCode != tt.wantErrorCode {
				t.Fatalf(
					"ValidateRegex() = (%v, %q), want (%v, %q)",
					valid, errorCode, tt.wantValid, tt.wantErrorCode,
				)
			}
		})
	}
}

func TestValidateRegexUsesInternalEndpointAndToken(t *testing.T) {
	const (
		pattern = "(?P<account>[a-z]+)"
		token   = "regex-validation-internal-secret"
	)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %q, want POST", r.Method)
		}
		if r.URL.Path != "/admin/v1/internal/regex/validate" {
			t.Errorf("path = %q, want regex validation endpoint", r.URL.Path)
		}
		if got := r.Header.Get(InternalAPISecretHeader); got != token {
			t.Errorf("internal token = %q, want configured token", got)
		}
		if got := r.Header.Get("Content-Type"); got != "application/json" {
			t.Errorf("Content-Type = %q, want application/json", got)
		}
		var request map[string]string
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Errorf("decode request: %v", err)
		}
		if request["pattern"] != pattern {
			t.Errorf("request pattern = %q, want configured pattern", request["pattern"])
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_, _ = w.Write([]byte("{\"valid\":true,\"error_code\":null}"))
	}))
	t.Cleanup(server.Close)

	valid, errorCode, err := newSecurityEngineClient(server.URL+"/", token).ValidateRegex(t.Context(), pattern)
	if err != nil || !valid || errorCode != "" {
		t.Fatalf("ValidateRegex() = (%v, %q, %v), want (true, empty, nil)", valid, errorCode, err)
	}
}

func TestValidateRegexFailsClosedWhenUnavailable(t *testing.T) {
	const pattern = "regex-pattern-must-not-leak"

	t.Run("nil client", func(t *testing.T) {
		var client *securityEngineClient
		_, _, err := client.ValidateRegex(t.Context(), pattern)
		assertRegexValidationErrorRedacted(t, err, pattern)
	})

	t.Run("missing endpoint", func(t *testing.T) {
		_, _, err := newSecurityEngineClient("", "internal-secret").ValidateRegex(t.Context(), pattern)
		assertRegexValidationErrorRedacted(t, err, pattern)
	})

	t.Run("missing token", func(t *testing.T) {
		_, _, err := newSecurityEngineClient("http://security-engine.invalid", "").ValidateRegex(t.Context(), pattern)
		assertRegexValidationErrorRedacted(t, err, pattern)
	})

	t.Run("timeout", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			time.Sleep(100 * time.Millisecond)
			_, _ = w.Write([]byte("{\"valid\":true,\"error_code\":null}"))
		}))
		t.Cleanup(server.Close)
		client := newSecurityEngineClient(server.URL, "internal-secret")
		client.client.Timeout = 20 * time.Millisecond

		_, _, err := client.ValidateRegex(t.Context(), pattern)
		assertRegexValidationErrorRedacted(t, err, pattern)
	})

	t.Run("non 200", func(t *testing.T) {
		const responseCanary = "upstream-response-must-not-leak"
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, responseCanary, http.StatusServiceUnavailable)
		}))
		t.Cleanup(server.Close)

		_, _, err := newSecurityEngineClient(server.URL, "internal-secret").ValidateRegex(t.Context(), pattern)
		assertRegexValidationErrorRedacted(t, err, pattern, responseCanary)
	})
}

func TestValidateRegexRejectsMalformedResponseWithoutLeakingDetails(t *testing.T) {
	const (
		pattern        = "malformed-response-pattern-canary"
		responseCanary = "malformed-response-body-canary"
	)
	tests := []struct {
		name        string
		contentType string
		body        string
	}{
		{name: "non JSON content type", contentType: "text/plain", body: "{\"valid\":true,\"error_code\":null}"},
		{name: "invalid JSON", contentType: "application/json", body: responseCanary},
		{name: "trailing JSON", contentType: "application/json", body: "{\"valid\":true,\"error_code\":null}{}"},
		{name: "missing valid", contentType: "application/json", body: "{\"error_code\":null}"},
		{name: "missing error code", contentType: "application/json", body: "{\"valid\":true}"},
		{name: "valid with error code", contentType: "application/json", body: "{\"valid\":true,\"error_code\":\"unsafe_regex\"}"},
		{name: "invalid without error code", contentType: "application/json", body: "{\"valid\":false,\"error_code\":null}"},
		{name: "invalid error code type", contentType: "application/json", body: "{\"valid\":false,\"error_code\":123}"},
		{name: "unknown error code", contentType: "application/json", body: "{\"valid\":false,\"error_code\":\"" + responseCanary + "\"}"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", tt.contentType)
				_, _ = w.Write([]byte(tt.body))
			}))
			t.Cleanup(server.Close)

			_, _, err := newSecurityEngineClient(server.URL, "internal-secret").ValidateRegex(t.Context(), pattern)
			assertRegexValidationErrorRedacted(t, err, pattern, responseCanary, tt.body)
		})
	}
}

func assertRegexValidationErrorRedacted(t *testing.T, err error, forbidden ...string) {
	t.Helper()
	if err == nil {
		t.Fatal("ValidateRegex() error = nil, want fail-closed error")
	}
	for _, value := range forbidden {
		if value != "" && strings.Contains(err.Error(), value) {
			t.Fatalf("ValidateRegex() error leaked sensitive value %q: %v", value, err)
		}
	}
}
