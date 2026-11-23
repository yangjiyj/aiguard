package aiadapters

import "testing"

func TestBuiltInAdapterManifestsLoadCatalogAndAgents(t *testing.T) {
	catalog := CatalogEntries()
	if len(catalog) < 80 {
		t.Fatalf("CatalogEntries() len = %d, want migrated built-in catalog", len(catalog))
	}
	agents := AgentDefinitions()
	if len(agents) < 30 {
		t.Fatalf("AgentDefinitions() len = %d, want migrated agent registry", len(agents))
	}
}

func TestAdapterCatalogIDsAndAgentTypesAreUnique(t *testing.T) {
	seenCatalog := map[string]bool{}
	for _, entry := range CatalogEntries() {
		if entry.ID == "" || entry.Provider == "" || entry.Product == "" || entry.RetainLevel == "" {
			t.Fatalf("catalog entry has required field missing: %+v", entry)
		}
		if seenCatalog[entry.ID] {
			t.Fatalf("duplicate catalog entry id %q", entry.ID)
		}
		seenCatalog[entry.ID] = true
	}

	seenAgents := map[string]bool{}
	for _, agent := range AgentDefinitions() {
		if agent.Type == "" || agent.Label == "" || len(agent.Patterns) == 0 {
			t.Fatalf("agent definition has required field missing: %+v", agent)
		}
		if seenAgents[agent.Type] {
			t.Fatalf("duplicate agent type %q", agent.Type)
		}
		seenAgents[agent.Type] = true
	}
}

func TestCodeBuddyAdapterCoversObservedStudioEndpoints(t *testing.T) {
	cases := []struct {
		host       string
		path       string
		wantRetain string
	}{
		{"copilot.tencent.com", "/v2/chat/completions", "content"},
		{"copilot.tencent.com", "/v2/chat/prediction", "summary"},
		{"copilot.tencent.com", "/v1/traces", "summary"},
		{"copilot.tencent.com", "/portal/abc/message/summary", "summary"},
		{"download.codebuddy.cn", "/releases/stable/win32-x64/CodeBuddySetup.exe", "summary"},
		{"ride-3-live-webapp.azurewebsites.net", "/api/invoke", "content"},
		{"ride-3-live-webapp.azurewebsites.net", "//api/invoke", "content"},
		{"ride-3-live-webapp.azurewebsites.net", "/api/stream", "content"},
	}
	for _, tt := range cases {
		got, ok := MatchCatalog(tt.host, tt.path)
		if !ok {
			t.Fatalf("MatchCatalog(%q, %q) not known", tt.host, tt.path)
		}
		if got.Provider != "tencent" || got.Product != "codebuddy" || got.RiskProfile != "ai_ide_agent" || got.RetainLevel != tt.wantRetain {
			t.Fatalf("MatchCatalog(%q, %q) = provider=%q product=%q retain=%q risk=%q, want tencent/codebuddy/%s/ai_ide_agent", tt.host, tt.path, got.Provider, got.Product, got.RetainLevel, got.RiskProfile, tt.wantRetain)
		}
	}
}

func TestMatchCatalogCopilotTelemetryHostsUseTelemetryDecoder(t *testing.T) {
	cases := []struct {
		host string
		path string
	}{
		{"telemetry.individual.githubcopilot.com", "/telemetry"},
		// path_rules=null 全路径承接:telemetry 子域即便路径形似对话端点,也不该
		// 跌回 support/copilot entry(priority 96 > 93/92/80)。
		{"telemetry.individual.githubcopilot.com", "/responses"},
		{"telemetry.business.githubcopilot.com", "/chat/completions"},
	}
	for _, tt := range cases {
		entry, ok := MatchCatalog(tt.host, tt.path)
		if !ok {
			t.Fatalf("MatchCatalog(%q, %q) not known", tt.host, tt.path)
		}
		if entry.ID != "github_copilot_telemetry" {
			t.Fatalf("MatchCatalog(%q, %q) entry = %q, want github_copilot_telemetry", tt.host, tt.path, entry.ID)
		}
		if entry.RequestDecoder != "telemetry" {
			t.Fatalf("MatchCatalog(%q, %q) request_decoder = %q, want telemetry", tt.host, tt.path, entry.RequestDecoder)
		}
	}
}
