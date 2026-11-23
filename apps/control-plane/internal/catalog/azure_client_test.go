package catalog

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/types"
)

func TestAzureCatalogClientRejectsUnsafeTargetsWithoutRequest(t *testing.T) {
	var hits atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client, err := NewFactory().GetClient("azure")
	if err != nil {
		t.Fatal(err)
	}
	tests := []string{
		server.URL,
		"http://10.0.0.1",
		"http://169.254.169.254",
		"http://metadata.azure.internal",
		"http://user:pass@example.com",
		"https://example.com?api-version=secret",
		" https://example.com ",
	}
	for _, baseURL := range tests {
		if _, err := client.FetchModels(context.Background(), baseURL, "secret-key"); err == nil {
			t.Fatalf("FetchModels(%q) succeeded", baseURL)
		} else if strings.Contains(err.Error(), baseURL) || strings.Contains(err.Error(), "secret-key") {
			t.Fatalf("error leaked target or key: %v", err)
		}
	}
	if hits.Load() != 0 {
		t.Fatalf("unsafe targets reached handler %d times", hits.Load())
	}
}

func TestAzureCatalogClientRejectsHTTPBeforeRequest(t *testing.T) {
	var hits atomic.Int32
	client := newAzureClientWithHTTPClient(&http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		hits.Add(1)
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(`{"data":[]}`)),
			Header:     make(http.Header),
		}, nil
	})})
	if _, err := client.FetchModels(context.Background(), "http://example.com", "secret-key"); err == nil {
		t.Fatal("cleartext HTTP catalog target unexpectedly succeeded")
	}
	if got := hits.Load(); got != 0 {
		t.Fatalf("cleartext HTTP target received %d requests, want 0", got)
	}
}

func TestAzureCatalogClientDoesNotFollowRedirects(t *testing.T) {
	var redirectedHits atomic.Int32
	destination := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		redirectedHits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer destination.Close()
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, destination.URL, http.StatusFound)
	}))
	defer origin.Close()

	client := newAzureClientWithHTTPClient(origin.Client())
	if _, err := client.FetchModels(context.Background(), origin.URL, "secret-key"); err == nil {
		t.Fatal("redirect unexpectedly succeeded")
	}
	if redirectedHits.Load() != 0 {
		t.Fatalf("redirect destination reached %d times", redirectedHits.Load())
	}
}

func TestAzureCatalogClientEnforcesDecompressedBodyLimit(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Encoding", "gzip")
		writer := gzip.NewWriter(w)
		_, _ = writer.Write(bytes.Repeat([]byte("x"), azureCatalogBodyMaxBytes+1))
		_ = writer.Close()
	}))
	defer server.Close()

	client := newAzureClientWithHTTPClient(server.Client())
	if _, err := client.FetchModels(context.Background(), server.URL, "secret-key"); err == nil || !strings.Contains(err.Error(), "response_too_large") {
		t.Fatalf("oversized decompressed response error=%v", err)
	}
}

func TestAzureCatalogClientEnforcesModelCountLimit(t *testing.T) {
	models := make([]types.ProviderCatalogModel, azureCatalogModelMaxItems+1)
	for i := range models {
		models[i] = types.ProviderCatalogModel{ID: "model"}
	}
	server := azureCatalogServer(t, models)
	defer server.Close()

	client := newAzureClientWithHTTPClient(server.Client())
	if _, err := client.FetchModels(context.Background(), server.URL, "secret-key"); err == nil || !strings.Contains(err.Error(), "too_many_models") {
		t.Fatalf("oversized catalog error=%v", err)
	}
}

func TestAzureCatalogClientParsesNormalAnd338Responses(t *testing.T) {
	for _, count := range []int{2, 338} {
		t.Run(string(rune('a'+count%20)), func(t *testing.T) {
			models := make([]types.ProviderCatalogModel, count)
			for i := range models {
				models[i] = types.ProviderCatalogModel{ID: "model-" + string(rune(0x100+i)), Object: "model"}
			}
			server := azureCatalogServer(t, models)
			defer server.Close()
			client := newAzureClientWithHTTPClient(server.Client())
			got, err := client.FetchModels(context.Background(), server.URL, "secret-key")
			if err != nil || len(got) != count {
				t.Fatalf("count=%d got=%d err=%v", count, len(got), err)
			}
		})
	}
}

func TestAzureCatalogClientJoinsCompatibleModelPaths(t *testing.T) {
	tests := []struct {
		name     string
		basePath string
		wantPath string
	}{
		{name: "root", basePath: "", wantPath: "/v1/models"},
		{name: "root trailing slash", basePath: "/", wantPath: "/v1/models"},
		{name: "v1", basePath: "/v1", wantPath: "/v1/models"},
		{name: "v1 trailing slash", basePath: "/v1/", wantPath: "/v1/models"},
		{name: "prefix v1", basePath: "/prefix/v1", wantPath: "/prefix/v1/models"},
		{name: "prefix v1 trailing slash", basePath: "/prefix/v1/", wantPath: "/prefix/v1/models"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var gotPath string
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				gotPath = r.URL.Path
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"data":[]}`))
			}))
			defer server.Close()

			client := newAzureClientWithHTTPClient(server.Client())
			if _, err := client.FetchModels(context.Background(), server.URL+tt.basePath, "secret-key"); err != nil {
				t.Fatalf("FetchModels() error=%v", err)
			}
			if gotPath != tt.wantPath {
				t.Fatalf("request path=%q want=%q", gotPath, tt.wantPath)
			}
		})
	}
}

func TestAzureCatalogFactoryUsesDedicatedSafeClientOnlyForAzure(t *testing.T) {
	factory := NewFactory()
	azure, err := factory.GetClient("azure")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := azure.(*azureClient); !ok {
		t.Fatalf("azure client type=%T", azure)
	}
	for _, providerType := range []string{"openai", "custom", "deepseek"} {
		client, err := factory.GetClient(providerType)
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := client.(*OpenAIClient); !ok {
			t.Fatalf("%s client type=%T", providerType, client)
		}
	}
}

func azureCatalogServer(t *testing.T, models []types.ProviderCatalogModel) *httptest.Server {
	t.Helper()
	return httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/v1/models" {
			t.Errorf("request=%s %s", r.Method, r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer secret-key" {
			t.Errorf("authorization header missing")
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"data": models})
	}))
}
