package handler

import (
	"github.com/yangjiyj/aiguard/packages/shared-go/aiadapters"
	"github.com/yangjiyj/aiguard/packages/shared-go/llmcatalog"
)

type LLMProviderMatch = llmcatalog.MatchResult

func containsDefaultHostPattern(pattern string) bool {
	for _, item := range llmcatalog.Catalog() {
		for _, domain := range item.Domains {
			if domain == pattern {
				return true
			}
		}
	}
	return false
}

func containsCatalogProvider(provider string) bool {
	for _, item := range llmcatalog.Catalog() {
		if item.Provider == provider {
			return true
		}
	}
	return false
}

func detectLLMProvider(host, path string) LLMProviderMatch {
	return llmcatalog.Match(host, path)
}

func detectLLMDecoders(host, path string) (string, string) {
	entry, ok := aiadapters.MatchCatalog(host, path)
	if !ok {
		return "", ""
	}
	return entry.RequestDecoder, entry.ResponseDecoder
}

func normalizeHost(host string) string {
	return llmcatalog.NormalizeHost(host)
}
