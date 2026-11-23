package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
)

func TestRegisterAgentAuthorizationRoutesReachesControlPlane(t *testing.T) {
	var got []string
	cp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = append(got, r.Method+" "+r.URL.Path)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer cp.Close()
	router := chi.NewRouter()
	registerAgentAuthorizationRoutes(router, cp.URL)
	router.Handle("/admin/v1/eval-integration/*", http.NotFoundHandler())
	for _, path := range []string{"/admin/v1/agent/authorize", "/admin/v1/agent/approval-requests", "/admin/v1/agent/approval-claims"} {
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, path, strings.NewReader(`{}`)))
		if rec.Code != http.StatusAccepted {
			t.Fatalf("%s status=%d", path, rec.Code)
		}
	}
	for _, path := range []string{"/admin/v1/agent/approvals", "/admin/v1/agent/exceptions/x/revoke"} {
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, path, strings.NewReader(`{}`)))
		if rec.Code == http.StatusAccepted {
			t.Fatalf("%s leaked to control plane", path)
		}
	}
	if len(got) != 3 {
		t.Fatalf("control plane hits=%v", got)
	}
}
