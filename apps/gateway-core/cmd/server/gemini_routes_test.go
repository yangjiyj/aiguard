package main

import (
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/handler"
	"github.com/go-chi/chi/v5"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type noReadBeforeAuth struct{ reads int }

func (r *noReadBeforeAuth) Read([]byte) (int, error) { r.reads++; return 0, io.EOF }
func (r *noReadBeforeAuth) Close() error             { return nil }
func TestGeminiRoutesAuthenticateBeforeBodyAndKeepExistingModels(t *testing.T) {
	r := chi.NewRouter()
	r.Use(handler.GeminiURLCredentialGuard)
	auth := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Authorization") != "Bearer fixture" {
				w.WriteHeader(401)
				io.WriteString(w, `{"error":{"message":"missing authorization"}}`)
				return
			}
			if r.URL.Path != "/v1/chat/completions" && r.URL.Path != "/v1/models" {
				t.Fatal("scope path bypassed")
			}
			next.ServeHTTP(w, r)
		})
	}
	noop := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, `{"object":"list","data":[]}`) })
	registerRuntimeRoutes(r, auth, nil, noop, noop, noop, noop, noop, noop)
	chat := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"id":"c","model":"m","choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":2,"total_tokens":3}}`)
	})
	registerGeminiRuntimeRoutes(r, auth, nil, chat, noop, nil)
	body := &noReadBeforeAuth{}
	request := httptest.NewRequest("POST", "/v1beta/models/m:generateContent", body)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, request)
	if w.Code != 401 || body.reads != 0 || !strings.Contains(w.Body.String(), "UNAUTHENTICATED") {
		t.Fatalf("unauthenticated request parsed native body: status=%d reads=%d %s", w.Code, body.reads, w.Body.String())
	}
	for _, path := range []string{"/v1beta/models/m:generateContent", "/v1/models/m:generateContent"} {
		request := httptest.NewRequest("POST", path, strings.NewReader(`{"contents":[{"parts":[{"text":"hi"}]}]}`))
		request.Header.Set("X-Goog-Api-Key", "fixture")
		w := httptest.NewRecorder()
		r.ServeHTTP(w, request)
		if w.Code != 200 || !strings.Contains(w.Body.String(), "candidates") {
			t.Fatalf("Google route %s status=%d %s", path, w.Code, w.Body.String())
		}
	}
	request = httptest.NewRequest("GET", "/v1/models", nil)
	request.Header.Set("Authorization", "Bearer fixture")
	w = httptest.NewRecorder()
	r.ServeHTTP(w, request)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"object":"list"`) {
		t.Fatal("existing OpenAI model list changed")
	}
	request = httptest.NewRequest("GET", "/v1beta/models", nil)
	request.Header.Set("X-Goog-Api-Key", "fixture")
	w = httptest.NewRecorder()
	r.ServeHTTP(w, request)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"models":`) {
		t.Fatalf("Google list route %d %s", w.Code, w.Body.String())
	}
	request = httptest.NewRequest("GET", "/v1beta/models/unknown", nil)
	w = httptest.NewRecorder()
	r.ServeHTTP(w, request)
	if w.Code != 404 || !strings.Contains(w.Body.String(), "NOT_FOUND") {
		t.Fatal("unsupported Google API returned success")
	}
}
