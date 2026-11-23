package auth_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	auth "github.com/yangjiyj/aiguard/apps/gateway-core/internal/auth"
)

func TestLegacyMiddlewareFailsClosed(t *testing.T) {
	nextCalled := false
	handler := auth.Middleware(nil)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/v1/chat/completions", nil)
	req.Header.Set("Authorization", "Bearer na_test_1234567890abcdef")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if nextCalled {
		t.Fatal("legacy middleware should not call next handler")
	}
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected status %d, got %d", http.StatusUnauthorized, rec.Code)
	}
	body := rec.Body.String()
	if body == "" {
		t.Fatal("expected error response body")
	}
	if want := "auth_misconfigured"; !strings.Contains(body, want) {
		t.Fatalf("expected response body to contain %q, got %q", want, body)
	}
}
