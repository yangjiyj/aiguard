package handler

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestInternalAPIMiddlewareRequiresSharedSecret(t *testing.T) {
	nextCalled := false
	mw := InternalAPIMiddleware("secret-token", &Dependencies{})
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusNoContent)
	}))

	req := httptest.NewRequest(http.MethodGet, "/admin/v1/internal/tools/config", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if nextCalled {
		t.Fatal("next handler should not be called without internal token")
	}
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusUnauthorized)
	}
}

func TestInternalAPIMiddlewareAllowsMatchingSharedSecret(t *testing.T) {
	mw := InternalAPIMiddleware("secret-token", &Dependencies{})
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	req := httptest.NewRequest(http.MethodGet, "/admin/v1/internal/tools/config", nil)
	req.Header.Set(InternalAPISecretHeader, "secret-token")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusNoContent)
	}
}

func TestInternalAPIMiddlewareAcceptsLegacyHeaderDuringCompatibilityWindow(t *testing.T) {
	mw := InternalAPIMiddleware("secret-token", &Dependencies{})
	h := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	req := httptest.NewRequest(http.MethodGet, "/admin/v1/internal/tools/config", nil)
	req.Header.Set(LegacyInternalAPISecretHeader, "secret-token")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusNoContent {
		t.Fatalf("status=%d", w.Code)
	}
}
