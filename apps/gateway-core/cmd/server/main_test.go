package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
)

func TestRuntimeRoutesExposeOpenAIModelRetrieve(t *testing.T) {
	router := chi.NewRouter()
	authMiddleware := func(next http.Handler) http.Handler { return next }
	modelCalls := 0
	modelHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		modelCalls++
		w.WriteHeader(http.StatusOK)
	})
	unused := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) })
	registerRuntimeRoutes(router, authMiddleware, nil, unused, unused, unused, unused, unused, modelHandler)

	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/v1/models/gpt-5.6-sol", nil))
	if response.Code != http.StatusOK || modelCalls != 1 {
		t.Fatalf("model retrieve route status=%d calls=%d", response.Code, modelCalls)
	}
}

func TestGatewayRuntimeTimeoutAllowsLargeAgentRequests(t *testing.T) {
	if gatewayRuntimeRequestTimeout < 5*time.Minute {
		t.Fatalf("runtime request timeout must allow large agent continuations, got %s", gatewayRuntimeRequestTimeout)
	}
	if gatewayHTTPWriteTimeout <= gatewayRuntimeRequestTimeout {
		t.Fatalf("HTTP write timeout %s must exceed runtime request timeout %s", gatewayHTTPWriteTimeout, gatewayRuntimeRequestTimeout)
	}
}

func TestGatewayHTTPServerUsesSlowUploadSafeTimeouts(t *testing.T) {
	t.Setenv("GATEWAY_HTTP_READ_HEADER_TIMEOUT", "")
	t.Setenv("GATEWAY_HTTP_READ_TIMEOUT", "")

	server := newGatewayHTTPServer(":0", http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))

	if server.ReadHeaderTimeout != 10*time.Second {
		t.Fatalf("ReadHeaderTimeout=%s, want 10s", server.ReadHeaderTimeout)
	}
	if server.ReadTimeout != 5*time.Minute {
		t.Fatalf("ReadTimeout=%s, want 5m", server.ReadTimeout)
	}
	if server.WriteTimeout != gatewayHTTPWriteTimeout {
		t.Fatalf("WriteTimeout=%s, want %s", server.WriteTimeout, gatewayHTTPWriteTimeout)
	}
	if server.IdleTimeout != 30*time.Second {
		t.Fatalf("IdleTimeout=%s, want 30s", server.IdleTimeout)
	}
}

func TestGatewayHTTPReadTimeoutsHonorsSafeOverrides(t *testing.T) {
	t.Setenv("GATEWAY_HTTP_READ_HEADER_TIMEOUT", "12s")
	t.Setenv("GATEWAY_HTTP_READ_TIMEOUT", "7m")

	headerTimeout, readTimeout := gatewayHTTPReadTimeouts()

	if headerTimeout != 12*time.Second {
		t.Fatalf("headerTimeout=%s, want 12s", headerTimeout)
	}
	if readTimeout != 7*time.Minute {
		t.Fatalf("readTimeout=%s, want 7m", readTimeout)
	}
}

func TestGatewayHTTPReadTimeoutsFallsBackFromUnsafeConfig(t *testing.T) {
	tests := []struct {
		name   string
		header string
		read   string
	}{
		{name: "invalid values", header: "invalid", read: "0s"},
		{name: "read not greater than header", header: "30s", read: "20s"},
		{name: "read below safe minimum", header: "10s", read: "2m"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("GATEWAY_HTTP_READ_HEADER_TIMEOUT", tt.header)
			t.Setenv("GATEWAY_HTTP_READ_TIMEOUT", tt.read)

			headerTimeout, readTimeout := gatewayHTTPReadTimeouts()
			if headerTimeout != 10*time.Second || readTimeout != 5*time.Minute {
				t.Fatalf("timeouts=%s/%s, want 10s/5m", headerTimeout, readTimeout)
			}
		})
	}
}
