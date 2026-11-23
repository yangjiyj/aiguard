package catalog

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAnthropicCatalogPathsHeadersAndFormats(t *testing.T) {
	for _, suffix := range []string{"", "/", "/v1", "/v1/", "/relay/v1"} {
		for _, native := range []bool{true, false} {
			t.Run(fmt.Sprintf("%s/native=%v", suffix, native), func(t *testing.T) {
				server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					want := "/v1/models"
					if suffix == "/relay/v1" {
						want = "/relay/v1/models"
					}
					if r.URL.Path != want || r.Method != "GET" {
						t.Errorf("path/method %s %s", r.Method, r.URL.Path)
					}
					if r.Header.Get("x-api-key") != "fixture-key" || r.Header.Get("anthropic-version") != "2023-06-01" || r.Header.Get("Authorization") != "" {
						t.Errorf("incorrect authentication headers")
					}
					w.Header().Set("Content-Type", "application/json")
					if native {
						fmt.Fprint(w, `{"data":[{"id":"claude-fixture","type":"model","display_name":"Fixture Claude"}],"has_more":false,"last_id":"claude-fixture"}`)
					} else {
						fmt.Fprint(w, `{"object":"list","data":[{"id":"claude-fixture","object":"model","name":"Fixture Claude"}]}`)
					}
				}))
				defer server.Close()
				c := &AnthropicClient{testHTTPClient: server.Client()}
				got, err := c.FetchModels(context.Background(), server.URL+suffix, "fixture-key")
				if err != nil || len(got) != 1 || got[0].ID != "claude-fixture" || got[0].Object != "model" || got[0].Name != "Fixture Claude" {
					t.Fatalf("models=%+v err=%v", got, err)
				}
			})
		}
	}
}
func TestAnthropicCatalogPagination(t *testing.T) {
	calls := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.Header().Set("Content-Type", "application/json")
		if calls == 1 {
			fmt.Fprint(w, `{"data":[{"id":"claude-first","type":"model"}],"has_more":true,"last_id":"claude-first"}`)
			return
		}
		if r.URL.Query().Get("after_id") != "claude-first" {
			t.Errorf("missing cursor")
		}
		fmt.Fprint(w, `{"data":[{"id":"claude-second","type":"model"}],"has_more":false,"last_id":"claude-second"}`)
	}))
	defer server.Close()
	got, err := (&AnthropicClient{testHTTPClient: server.Client()}).FetchModels(context.Background(), server.URL, "fixture-key")
	if err != nil || len(got) != 2 || calls != 2 {
		t.Fatalf("calls=%d models=%+v err=%v", calls, got, err)
	}
}
func TestAnthropicCatalogRejectsInvalidSnapshots(t *testing.T) {
	cases := []string{`{"data":[{"id":"claude","type":"model"}],"has_more":null,"last_id":null}`, `{"data":[{"id":"claude","type":"model"}],"has_more":false,"last_id":"wrong"}`, `{"data":[{"id":"claude","type":"model"}]}`, `{"data":[{"id":"claude","type":"model"}],"has_more":false}`, `{}`, `{"data":null}`, `{"data":[] ,"error":{"message":"fixture-key"}}`, `{"data":[],"has_more":true}`, `{"data":[{"id":""}]}`, `{"data":[{"id":"claude","type":"message"}]}`, `{"data":[]} trailing`, `{"data":[],"has_more":"false"}`, `{"data":[],"object":"error"}`, `{"data":[],"next_cursor":"unverified"}`, `{"data":[{"id":"claude","name":"a"},{"id":"claude","name":"b"}]}`}
	for i, body := range cases {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, body) }))
			defer server.Close()
			got, err := (&AnthropicClient{testHTTPClient: server.Client()}).FetchModels(context.Background(), server.URL, "fixture-key")
			if err == nil || got != nil {
				t.Fatalf("unsafe snapshot accepted %+v err=%v", got, err)
			}
			if strings.Contains(err.Error(), "fixture-key") {
				t.Fatal("secret in error")
			}
		})
	}
}
func TestAnthropicCatalogErrorsAndRedirects(t *testing.T) {
	for _, status := range []int{401, 403, 404, 429, 500, 302} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			redirected := false
			destination := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { redirected = true }))
			defer destination.Close()
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Location", destination.URL)
				w.WriteHeader(status)
				fmt.Fprint(w, "fixture-key")
			}))
			defer server.Close()
			got, err := (&AnthropicClient{testHTTPClient: server.Client()}).FetchModels(context.Background(), server.URL, "fixture-key")
			if err == nil || got != nil || redirected {
				t.Fatalf("status=%d err=%v redirected=%v", status, err, redirected)
			}
			if strings.Contains(err.Error(), "fixture-key") {
				t.Fatal("secret in error")
			}
		})
	}
}
func TestAnthropicCatalogRejectsPaginationLoopAndPartialFailure(t *testing.T) {
	for _, failSecond := range []bool{false, true} {
		t.Run(fmt.Sprint(failSecond), func(t *testing.T) {
			calls := 0
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				if failSecond && calls > 1 {
					w.WriteHeader(401)
					return
				}
				fmt.Fprint(w, `{"data":[{"id":"claude-first","type":"model"}],"has_more":true,"last_id":"claude-first"}`)
			}))
			defer server.Close()
			got, err := (&AnthropicClient{testHTTPClient: server.Client()}).FetchModels(context.Background(), server.URL, "fixture-key")
			if err == nil || got != nil || calls > 3 {
				t.Fatalf("partial catalog returned: %+v err=%v calls=%d", got, err, calls)
			}
		})
	}
}
func TestAnthropicCatalogProductionRejectsPrivateTargets(t *testing.T) {
	for _, target := range []string{"https://127.0.0.1", "https://169.254.169.254", "https://localhost", "https://example.com?key=secret", "https://user:pass@example.com", "https://example.com#secret"} {
		got, err := NewAnthropicClient().FetchModels(context.Background(), target, "fixture-key")
		if err == nil || got != nil {
			t.Fatalf("unsafe target accepted: %s", target)
		}
	}
}
func TestAnthropicCatalogRejectsOversizedResponse(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, strings.Repeat(" ", 2*1024*1024+1)) }))
	defer server.Close()
	got, err := (&AnthropicClient{testHTTPClient: server.Client()}).FetchModels(context.Background(), server.URL, "fixture-key")
	if err == nil || got != nil {
		t.Fatal("oversized response accepted")
	}
}
