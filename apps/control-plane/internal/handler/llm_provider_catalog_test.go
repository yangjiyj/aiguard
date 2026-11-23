package handler

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestListLLMProviderCatalogReturnsBroadPublicCatalog(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/admin/v1/llm-provider-catalog", nil)
	w := httptest.NewRecorder()

	ListLLMProviderCatalog().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp struct {
		Data []struct {
			ID          string   `json:"id"`
			Provider    string   `json:"provider"`
			ProviderCN  string   `json:"provider_cn"`
			Product     string   `json:"product"`
			ProductCN   string   `json:"product_cn"`
			Domains     []string `json:"domains"`
			RetainLevel string   `json:"retain_level"`
		} `json:"data"`
		Providers []struct {
			Value string `json:"value"`
			Label string `json:"label"`
		} `json:"providers"`
	}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(resp.Data) < 40 {
		t.Fatalf("catalog should cover broad public LLM pages, got %d entries", len(resp.Data))
	}
	wantProviders := map[string]bool{"openai": false, "deepseek": false, "alibaba": false, "bytedance": false, "tencent": false, "google": false}
	for _, item := range resp.Data {
		if _, ok := wantProviders[item.Provider]; ok {
			wantProviders[item.Provider] = true
		}
		if item.Product == "" || len(item.Domains) == 0 || item.RetainLevel == "" {
			t.Fatalf("catalog item missing customer-facing fields: %+v", item)
		}
	}
	for provider, found := range wantProviders {
		if !found {
			t.Fatalf("expected provider %s in catalog", provider)
		}
	}
	if len(resp.Providers) < 20 {
		t.Fatalf("provider options should be broad, got %d", len(resp.Providers))
	}
}

func TestMatchLLMProviderCatalog(t *testing.T) {
	body := bytes.NewBufferString(`{"host":"api.deepseek.com","path":"/v1/chat/completions"}`)
	req := httptest.NewRequest(http.MethodPost, "/admin/v1/llm-provider-catalog/test-match", body)
	w := httptest.NewRecorder()

	MatchLLMProviderCatalog().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp struct {
		Known       bool   `json:"known"`
		Provider    string `json:"provider"`
		Product     string `json:"product"`
		ProductCN   string `json:"product_cn"`
		Endpoint    string `json:"endpoint_kind"`
		RetainLevel string `json:"retain_level"`
	}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !resp.Known || resp.Provider != "deepseek" || resp.Product != "deepseek_api" || resp.ProductCN != "DeepSeek API" || resp.Endpoint != "api" || resp.RetainLevel != "content" {
		t.Fatalf("unexpected match: %+v", resp)
	}
}
