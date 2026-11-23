package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
)

func TestRegisterRuntimeRoutesIncludesImagesGenerationEndpoint(t *testing.T) {
	router := chi.NewRouter()
	authHits := 0
	authMiddleware := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authHits++
			next.ServeHTTP(w, r)
		})
	}
	hit := ""
	endpoint := func(name string) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			hit = name
			w.WriteHeader(http.StatusNoContent)
		}
	}

	registerRuntimeRoutes(
		router,
		authMiddleware,
		nil,
		endpoint("messages"),
		endpoint("chat"),
		endpoint("responses"),
		endpoint("embeddings"),
		endpoint("images"),
		endpoint("models"),
	)

	req := httptest.NewRequest(http.MethodPost, "/v1/images/generations", nil)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, req)

	if response.Code != http.StatusNoContent || hit != "images" {
		t.Fatalf("images route status=%d hit=%q", response.Code, hit)
	}
	if authHits != 1 {
		t.Fatalf("images route auth hits=%d, want 1", authHits)
	}
}

func TestRetentionRuntimeGuardBlocksOnlyFailClosed(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	for _, tc := range []struct {
		name, status, mode string
		want               int
	}{
		{name: "healthy closed", status: "ok", mode: "close", want: http.StatusNoContent},
		{name: "failed open", status: "error", mode: "open", want: http.StatusNoContent},
		{name: "failed closed", status: "error", mode: "close", want: http.StatusServiceUnavailable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			mode := tc.mode
			retentionRuntimeGuard(tc.status, func() string { return mode }, nil)(next).ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil))
			if recorder.Code != tc.want {
				t.Fatalf("status=%d want=%d body=%s", recorder.Code, tc.want, recorder.Body.String())
			}
		})
	}
}

// 2.9.22：日志留存失败模式按请求读取（控制台改了不用重启）；放行时记一条运行告警。
func TestRetentionRuntimeGuardReadsModePerRequest(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	mode := "open"
	releases := 0
	guard := retentionRuntimeGuard("error", func() string { return mode }, func(context.Context) { releases++ })(next)
	recorder := httptest.NewRecorder()
	guard.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil))
	if recorder.Code != http.StatusNoContent || releases != 1 {
		t.Fatalf("open 应放行并记运行告警：status=%d releases=%d", recorder.Code, releases)
	}
	mode = "close"
	recorder = httptest.NewRecorder()
	guard.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil))
	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("切到 close 后应立即拦截：status=%d", recorder.Code)
	}
}
