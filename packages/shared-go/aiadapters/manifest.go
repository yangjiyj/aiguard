package aiadapters

import (
	"embed"
	"encoding/json"
	"fmt"
	"net"
	"path"
	"sort"
	"strings"
	"sync"
)

//go:embed adapters/*.json
var adapterFS embed.FS

type CatalogEntry struct {
	ID              string   `json:"id"`
	Provider        string   `json:"provider"`
	ProviderCN      string   `json:"provider_cn"`
	Product         string   `json:"product"`
	ProductCN       string   `json:"product_cn"`
	Category        string   `json:"category"`
	Region          string   `json:"region"`
	Domains         []string `json:"domains"`
	PathRules       []string `json:"path_rules"`
	RequestDecoder  string   `json:"request_decoder"`
	ResponseDecoder string   `json:"response_decoder"`
	RetainLevel     string   `json:"retain_level"`
	RiskProfile     string   `json:"risk_profile"`
	Enabled         bool     `json:"enabled"`
	Priority        int      `json:"priority"`
	SourceURL       string   `json:"source_url"`
}

type AgentDefinition struct {
	Type     string   `json:"type"`
	Label    string   `json:"label"`
	Vendor   string   `json:"vendor"`
	Color    string   `json:"color"`
	Aliases  []string `json:"aliases"`
	Patterns []string `json:"patterns"`
}

type AgentRule struct {
	Type     string
	Aliases  []string
	Patterns []string
}

type MatchResult struct {
	Provider     string
	ProviderCN   string
	Product      string
	ProductCN    string
	Category     string
	EndpointKind string
	RetainLevel  string
	RiskProfile  string
	Known        bool
}

type Manifest struct {
	ID               string            `json:"id"`
	Name             string            `json:"name"`
	Vendor           string            `json:"vendor"`
	CatalogEntries   []CatalogEntry    `json:"catalog_entries"`
	AgentDefinitions []AgentDefinition `json:"agent_definitions"`
}

var (
	loadOnce sync.Once
	loaded   loadedAdapters
	loadErr  error
)

type loadedAdapters struct {
	Manifests []Manifest
	Catalog   []CatalogEntry
	Agents    []AgentDefinition
	Labels    map[string]string
}

func Manifests() []Manifest {
	data := mustLoad()
	out := make([]Manifest, len(data.Manifests))
	copy(out, data.Manifests)
	return out
}

func CatalogEntries() []CatalogEntry {
	data := mustLoad()
	out := make([]CatalogEntry, len(data.Catalog))
	copy(out, data.Catalog)
	return out
}

func AgentDefinitions() []AgentDefinition {
	data := mustLoad()
	out := make([]AgentDefinition, len(data.Agents))
	copy(out, data.Agents)
	return out
}

func AgentRules() []AgentRule {
	agents := AgentDefinitions()
	out := make([]AgentRule, 0, len(agents))
	for _, agent := range agents {
		out = append(out, AgentRule{Type: agent.Type, Aliases: cloneStrings(agent.Aliases), Patterns: cloneStrings(agent.Patterns)})
	}
	return out
}

func AgentLabels() map[string]string {
	data := mustLoad()
	out := make(map[string]string, len(data.Labels))
	for key, value := range data.Labels {
		out[key] = value
	}
	return out
}

func Label(agentType string) string {
	data := mustLoad()
	if name, ok := data.Labels[agentType]; ok {
		return name
	}
	return agentType
}

func MatchCatalog(host, requestPath string) (CatalogEntry, bool) {
	normalizedHost := NormalizeHost(host)
	normalizedPath := strings.TrimSpace(requestPath)
	if normalizedPath == "" {
		normalizedPath = "/"
	}
	for _, item := range CatalogEntries() {
		if !item.Enabled || !matchesAnyHost(item.Domains, normalizedHost) {
			continue
		}
		if matchesAnyPath(item.PathRules, normalizedPath) {
			return item, true
		}
	}
	return CatalogEntry{}, false
}

func Match(host, requestPath string) MatchResult {
	item, ok := MatchCatalog(host, requestPath)
	if !ok {
		return MatchResult{}
	}
	return MatchResult{Provider: item.Provider, ProviderCN: item.ProviderCN, Product: item.Product, ProductCN: item.ProductCN, Category: item.Category, EndpointKind: ClassifyEndpointKind(item.Category, requestPath), RetainLevel: item.RetainLevel, RiskProfile: item.RiskProfile, Known: true}
}

func mustLoad() loadedAdapters {
	loadOnce.Do(func() { loaded, loadErr = loadBuiltInAdapters() })
	if loadErr != nil {
		panic(loadErr)
	}
	return loaded
}

func loadBuiltInAdapters() (loadedAdapters, error) {
	files, err := adapterFS.ReadDir("adapters")
	if err != nil {
		return loadedAdapters{}, fmt.Errorf("read embedded adapters: %w", err)
	}
	out := loadedAdapters{Labels: map[string]string{}}
	seenManifest := map[string]bool{}
	seenCatalog := map[string]bool{}
	seenAgent := map[string]bool{}
	for _, file := range files {
		if file.IsDir() || !strings.HasSuffix(file.Name(), ".json") {
			continue
		}
		raw, err := adapterFS.ReadFile("adapters/" + file.Name())
		if err != nil {
			return loadedAdapters{}, fmt.Errorf("read %s: %w", file.Name(), err)
		}
		var manifest Manifest
		if err := json.Unmarshal(raw, &manifest); err != nil {
			return loadedAdapters{}, fmt.Errorf("parse %s: %w", file.Name(), err)
		}
		if strings.TrimSpace(manifest.ID) == "" {
			return loadedAdapters{}, fmt.Errorf("%s: manifest id is required", file.Name())
		}
		if seenManifest[manifest.ID] {
			return loadedAdapters{}, fmt.Errorf("duplicate manifest id %q", manifest.ID)
		}
		seenManifest[manifest.ID] = true
		for _, entry := range manifest.CatalogEntries {
			if err := validateCatalogEntry(file.Name(), entry); err != nil {
				return loadedAdapters{}, err
			}
			if seenCatalog[entry.ID] {
				return loadedAdapters{}, fmt.Errorf("duplicate catalog entry id %q", entry.ID)
			}
			seenCatalog[entry.ID] = true
			out.Catalog = append(out.Catalog, entry)
		}
		for _, agent := range manifest.AgentDefinitions {
			if err := validateAgentDefinition(file.Name(), agent); err != nil {
				return loadedAdapters{}, err
			}
			if seenAgent[agent.Type] {
				return loadedAdapters{}, fmt.Errorf("duplicate agent type %q", agent.Type)
			}
			seenAgent[agent.Type] = true
			out.Agents = append(out.Agents, agent)
			out.Labels[agent.Type] = agent.Label
		}
		out.Manifests = append(out.Manifests, manifest)
	}
	sort.SliceStable(out.Catalog, func(i, j int) bool { return out.Catalog[i].Priority > out.Catalog[j].Priority })
	return out, nil
}

func validateCatalogEntry(filename string, entry CatalogEntry) error {
	if entry.ID == "" || entry.Provider == "" || entry.Product == "" || entry.RetainLevel == "" || entry.RiskProfile == "" {
		return fmt.Errorf("%s: catalog entry missing required field: %+v", filename, entry)
	}
	if len(entry.Domains) == 0 {
		return fmt.Errorf("%s: catalog entry %q has no domains", filename, entry.ID)
	}
	return nil
}

func validateAgentDefinition(filename string, agent AgentDefinition) error {
	if agent.Type == "" || agent.Label == "" || len(agent.Patterns) == 0 {
		return fmt.Errorf("%s: agent definition missing required field: %+v", filename, agent)
	}
	return nil
}

func NormalizeHost(host string) string {
	host = strings.TrimSpace(strings.ToLower(host))
	if host == "" {
		return ""
	}
	if h, _, err := net.SplitHostPort(host); err == nil {
		return strings.Trim(h, "[]")
	}
	if idx := strings.Index(host, ":"); idx > 0 && !strings.Contains(host[:idx], "]") {
		return host[:idx]
	}
	return strings.Trim(host, "[]")
}

func matchesAnyHost(patterns []string, host string) bool {
	for _, pattern := range patterns {
		if hostMatchesPattern(pattern, host) {
			return true
		}
	}
	return false
}

func hostMatchesPattern(pattern, host string) bool {
	pattern = strings.ToLower(strings.TrimSpace(pattern))
	host = NormalizeHost(host)
	if pattern == host {
		return true
	}
	if strings.HasPrefix(pattern, "*.") {
		domain := strings.TrimPrefix(pattern, "*.")
		return host == domain || strings.HasSuffix(host, "."+domain)
	}
	if strings.Contains(pattern, "*") {
		matched, err := path.Match(pattern, host)
		return err == nil && matched
	}
	return false
}

func matchesAnyPath(patterns []string, requestPath string) bool {
	if len(patterns) == 0 {
		return true
	}
	normalizedPath := strings.TrimSpace(requestPath)
	lowerPath := strings.ToLower(normalizedPath)
	for _, rawPattern := range patterns {
		pattern := strings.TrimSpace(rawPattern)
		if pattern == "" {
			continue
		}
		lowerPattern := strings.ToLower(pattern)
		switch {
		case lowerPattern == "/":
			if normalizedPath == "/" {
				return true
			}
		case strings.HasPrefix(lowerPattern, "contains:"):
			needle := strings.TrimPrefix(lowerPattern, "contains:")
			if needle != "" && strings.Contains(lowerPath, needle) {
				return true
			}
		case strings.HasPrefix(lowerPattern, "suffix:"):
			suffix := strings.TrimPrefix(lowerPattern, "suffix:")
			if suffix != "" && strings.HasSuffix(lowerPath, suffix) {
				return true
			}
		case strings.HasPrefix(lowerPattern, "glob:"):
			globPattern := strings.TrimPrefix(pattern, "glob:")
			matched, err := path.Match(globPattern, normalizedPath)
			if err == nil && matched {
				return true
			}
		default:
			if strings.HasPrefix(lowerPath, lowerPattern) {
				return true
			}
		}
	}
	return false
}

func ClassifyEndpointKind(category, requestPath string) string {
	lower := strings.ToLower(requestPath)
	switch {
	case strings.Contains(lower, "file") || strings.Contains(lower, "upload"):
		return "file"
	case strings.Contains(lower, "image") || strings.Contains(lower, "vision") || strings.Contains(lower, "multimodal") || category == "image":
		return "multimodal"
	case strings.Contains(lower, "embedding"):
		return "embedding"
	case category == "api":
		return "api"
	case category == "chat" || strings.Contains(lower, "chat") || strings.Contains(lower, "messages") || strings.Contains(lower, "responses") || strings.Contains(lower, "generation"):
		return "chat"
	case category != "":
		return category
	default:
		return "api"
	}
}

func cloneStrings(in []string) []string {
	out := make([]string, len(in))
	copy(out, in)
	return out
}
