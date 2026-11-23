package llmcatalog

import "github.com/yangjiyj/aiguard/packages/shared-go/aiadapters"

type Entry = aiadapters.CatalogEntry

type MatchResult = aiadapters.MatchResult

type ProviderOption struct {
	Provider   string `json:"provider"`
	ProviderCN string `json:"provider_cn"`
	Count      int    `json:"count"`
}

func Catalog() []Entry {
	return aiadapters.CatalogEntries()
}

func ProviderOptions() []ProviderOption {
	seen := map[string]ProviderOption{}
	for _, item := range Catalog() {
		opt := seen[item.Provider]
		opt.Provider = item.Provider
		opt.ProviderCN = item.ProviderCN
		opt.Count++
		seen[item.Provider] = opt
	}
	out := make([]ProviderOption, 0, len(seen))
	for _, item := range seen {
		out = append(out, item)
	}
	for i := 0; i < len(out); i++ {
		for j := i + 1; j < len(out); j++ {
			if out[j].Provider < out[i].Provider {
				out[i], out[j] = out[j], out[i]
			}
		}
	}
	return out
}

func Match(host, path string) MatchResult {
	return aiadapters.Match(host, path)
}

func NormalizeHost(host string) string {
	return aiadapters.NormalizeHost(host)
}
