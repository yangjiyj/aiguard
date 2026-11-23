package main

import (
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/handler"
)

func TestRegisterMCPRoutesValidatesOriginBeforeAuthentication(t *testing.T) {
	proxy := handler.NewMCPProxyHandler(nil, nil, false)
	proxy.SetAllowedOrigins([]string{"https://trusted.example"})
	authHits := 0
	authMiddleware := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authHits++
			next.ServeHTTP(w, r)
		})
	}
	router := chi.NewRouter()
	registerMCPRoutes(router, authMiddleware, proxy)

	untrustedReq := httptest.NewRequest(http.MethodPost, "/mcp/server-1", nil)
	untrustedReq.Header.Set("Origin", "https://attacker.invalid")
	untrusted := httptest.NewRecorder()
	router.ServeHTTP(untrusted, untrustedReq)
	if untrusted.Code != http.StatusForbidden || authHits != 0 {
		t.Fatalf("untrusted status=%d authHits=%d", untrusted.Code, authHits)
	}

	preflightReq := httptest.NewRequest(http.MethodOptions, "/mcp/server-1", nil)
	preflightReq.Header.Set("Origin", "https://trusted.example")
	preflight := httptest.NewRecorder()
	router.ServeHTTP(preflight, preflightReq)
	if preflight.Code != http.StatusNoContent || authHits != 0 {
		t.Fatalf("preflight status=%d authHits=%d", preflight.Code, authHits)
	}

	native := httptest.NewRecorder()
	router.ServeHTTP(native, httptest.NewRequest(http.MethodPost, "/mcp/server-1", nil))
	if authHits != 1 {
		t.Fatalf("native request authHits=%d", authHits)
	}
}

func TestRegisterMCPRoutesValidatesOriginBeforeCombinedAuthentication(t *testing.T) {
	for _, tc := range []struct {
		name       string
		method     string
		origin     string
		denyAuth   bool
		wantStatus int
		wantCalls  []string
	}{
		{name: "untrusted origin bypasses neither wrapper", method: http.MethodPost, origin: "https://attacker.invalid", wantStatus: http.StatusForbidden},
		{name: "trusted preflight precedes both wrappers", method: http.MethodOptions, origin: "https://trusted.example", denyAuth: true, wantStatus: http.StatusNoContent},
		{name: "preflight without origin precedes both wrappers", method: http.MethodOptions, wantStatus: http.StatusBadRequest},
		{name: "authentication denial prevents policy", method: http.MethodPost, denyAuth: true, wantStatus: http.StatusUnauthorized, wantCalls: []string{"authentication"}},
		{name: "native authorized request reaches policy once", method: http.MethodPost, wantStatus: http.StatusNoContent, wantCalls: []string{"authentication", "integration"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			proxy := handler.NewMCPProxyHandler(nil, nil, false)
			proxy.SetAllowedOrigins([]string{"https://trusted.example"})
			var calls []string
			authMiddleware := func(next http.Handler) http.Handler {
				return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					calls = append(calls, "authentication")
					if tc.denyAuth {
						w.WriteHeader(http.StatusUnauthorized)
						return
					}
					next.ServeHTTP(w, r)
				})
			}
			// A terminal policy fixture observes routing without using a database or upstream.
			integrationMiddleware := func(http.Handler) http.Handler {
				return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					calls = append(calls, "integration")
					w.WriteHeader(http.StatusNoContent)
				})
			}
			dataPlaneAuth := func(next http.Handler) http.Handler {
				return authMiddleware(integrationMiddleware(next))
			}
			router := chi.NewRouter()
			registerMCPRoutes(router, dataPlaneAuth, proxy)
			request := httptest.NewRequest(tc.method, "/mcp/server-1", nil)
			if tc.origin != "" {
				request.Header.Set("Origin", tc.origin)
			}
			response := httptest.NewRecorder()
			router.ServeHTTP(response, request)
			if response.Code != tc.wantStatus || !reflect.DeepEqual(calls, tc.wantCalls) {
				t.Fatalf("status=%d calls=%v want status=%d calls=%v", response.Code, calls, tc.wantStatus, tc.wantCalls)
			}
		})
	}
}
