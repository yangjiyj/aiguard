package handler

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/yangjiyj/aiguard/packages/shared-go/llmcatalog"
)

type llmProviderOptionInfo struct {
	Value string `json:"value"`
	Label string `json:"label"`
	Count int    `json:"count"`
}

type llmCatalogResponse struct {
	Data      []llmcatalog.Entry      `json:"data"`
	Providers []llmProviderOptionInfo `json:"providers"`
}

type llmCatalogMatchRequest struct {
	Host string `json:"host"`
	Path string `json:"path"`
}

type llmCatalogMatchResponse struct {
	Known        bool   `json:"known"`
	Provider     string `json:"provider"`
	ProviderCN   string `json:"provider_cn"`
	Product      string `json:"product"`
	ProductCN    string `json:"product_cn"`
	Category     string `json:"category"`
	EndpointKind string `json:"endpoint_kind"`
	RetainLevel  string `json:"retain_level"`
	RiskProfile  string `json:"risk_profile"`
}

func ListLLMProviderCatalog() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		entries := llmcatalog.Catalog()
		providerOptions := llmcatalog.ProviderOptions()
		providers := make([]llmProviderOptionInfo, 0, len(providerOptions))
		for _, option := range providerOptions {
			providers = append(providers, llmProviderOptionInfo{
				Value: option.Provider,
				Label: option.ProviderCN,
				Count: option.Count,
			})
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(llmCatalogResponse{Data: entries, Providers: providers})
	}
}

func MatchLLMProviderCatalog() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req llmCatalogMatchRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "invalid JSON format")
			return
		}
		match := llmcatalog.Match(strings.TrimSpace(req.Host), strings.TrimSpace(req.Path))
		resp := llmCatalogMatchResponse{Known: match.Known, Provider: match.Provider, ProviderCN: match.ProviderCN, Product: match.Product, ProductCN: match.ProductCN, Category: match.Category, EndpointKind: match.EndpointKind, RetainLevel: match.RetainLevel, RiskProfile: match.RiskProfile}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}
}
