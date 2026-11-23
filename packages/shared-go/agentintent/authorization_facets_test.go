package agentintent

import (
	"strings"
	"testing"
)

func TestDeriveT16AuthorizationFacetsFiniteMCPContract(t *testing.T) {
	cases := []struct {
		suffix               string
		args                 map[string]any
		action, resourceType string
	}{
		{"read_file", map[string]any{"path": "/repo/a.txt"}, "file.read", "file"},
		{"write_file", map[string]any{"file_path": "/repo/a.txt", "content": "safe"}, "file.write", "file"},
		{"list_files", map[string]any{"paths": []any{"/repo"}, "limit": 10}, "directory.list", "directory"},
		{"web_fetch", map[string]any{"url": "https://example.test/a"}, "network.connect", "domain"},
	}
	for _, tc := range cases {
		name := "mcp__docs__" + tc.suffix
		toolType := "file"
		if tc.action == "network.connect" {
			toolType = "network"
		}
		effect, facets, err := DeriveT16AuthorizationFacets("openclaw", name, toolType, "docs", tc.args)
		if err != nil || effect.Action != tc.action || effect.ResourceType != tc.resourceType || len(facets) != 3 || facets[0].Action != "tool_execute" || facets[1].Action != "mcp_invoke" {
			t.Errorf("%s effect=%+v facets=%+v err=%v", name, effect, facets, err)
		}
	}
}

func TestDeriveT16AuthorizationFacetsRejectsAmbiguousMCP(t *testing.T) {
	cases := []struct {
		name, server string
		args         map[string]any
	}{
		{"mcp__docs__read_file", "different", map[string]any{"path": "/repo/a"}},
		{"mcp__docs__unknown", "docs", map[string]any{"path": "/repo/a"}},
		{"mcp__docs__read_file", "docs", map[string]any{"path": "/repo/a", "file_path": "/repo/a"}},
		{"mcp__docs__read_file", "docs", map[string]any{"path": "relative"}},
		{"mcp__docs__write_file", "docs", map[string]any{"path": "/repo/a"}},
		{"mcp__docs__web_fetch", "docs", map[string]any{"url": "file:///etc/passwd"}},
	}
	for _, tc := range cases {
		if _, _, err := DeriveT16AuthorizationFacets("openclaw", tc.name, "mcp", tc.server, tc.args); err == nil {
			t.Errorf("expected unsupported/ambiguous input rejected: %s", tc.name)
		}
	}
}

func TestDeriveT16AuthorizationFacetsMatchesT14WireTypes(t *testing.T) {
	cases := []struct {
		name, product, tool, toolType, server string
		args                                  map[string]any
		wantAction, wantType, wantResource    string
	}{
		{"mcp file read wire type", "claude-code", "mcp__files__read_file", "file", "files",
			map[string]any{"filePath": "/workspace/a.txt"}, "file.read", "file", "/workspace/a.txt"},
		{"mcp network wire type", "opencode", "mcp__web__fetch_url", "network", "web",
			map[string]any{"url": "https://example.test/path"}, "network.connect", "domain", "example.test"},
		{"claude ls", "claude-code", "LS", "file", "",
			map[string]any{"path": "/workspace"}, "directory.list", "directory", "/workspace"},
		{"opencode list", "opencode", "list", "file", "",
			map[string]any{"filePath": "/workspace"}, "directory.list", "directory", "/workspace"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			effect, facets, err := DeriveT16AuthorizationFacets(tc.product, tc.tool, tc.toolType, tc.server, tc.args)
			if err != nil {
				t.Fatalf("derive: %v", err)
			}
			if effect.Action != tc.wantAction || effect.ResourceType != tc.wantType || effect.ResourceID != tc.wantResource {
				t.Fatalf("effect=%+v", effect)
			}
			wantFacetCount := 2
			if tc.server != "" {
				wantFacetCount = 3
				if len(facets) == wantFacetCount && facets[1].Action != "mcp_invoke" {
					t.Fatalf("facets=%+v", facets)
				}
			}
			if len(facets) != wantFacetCount {
				t.Fatalf("facets=%+v", facets)
			}
		})
	}
}

func TestDeriveT16AuthorizationFacetsRejectsMismatchedMCPMetadataAndAmbiguousPayload(t *testing.T) {
	if _, _, err := DeriveT16AuthorizationFacets("claude-code", "mcp__files__read_file", "file", "other",
		map[string]any{"path": "/workspace/a"}); err == nil {
		t.Fatal("mismatched MCP server metadata was accepted")
	}
	if _, _, err := DeriveT16AuthorizationFacets("claude-code", "mcp__files__write_file", "file", "files",
		map[string]any{"path": "/workspace/a", "content": "x", "text": "y"}); err == nil {
		t.Fatal("ambiguous write payload aliases were accepted")
	}
}

func TestDeriveT16AuthorizationFacetsRejectsMCPTypeMismatch(t *testing.T) {
	cases := []struct {
		name, toolType, server string
		args                   map[string]any
	}{
		{"mcp__web__fetch_url", "file", "web", map[string]any{"url": "https://example.test/a"}},
		{"mcp__files__read_file", "network", "files", map[string]any{"path": "/workspace/a"}},
		{"mcp__files__read_file", "browser", "files", map[string]any{"path": "/workspace/a"}},
	}
	for _, tc := range cases {
		if _, _, err := DeriveT16AuthorizationFacets("opencode", tc.name, tc.toolType, tc.server, tc.args); err == nil {
			t.Errorf("MCP effect with inconsistent T14 tool type was accepted: name=%s type=%s", tc.name, tc.toolType)
		}
	}
}

// T16-DEV-20260928 hookd alignment
func TestDeriveT16AuthorizationFacetsMatchesHookdDirectNetworkContract(t *testing.T) {
	accepted := []struct{ product, tool, url, host string }{
		{"claude-code", "WebFetch", "https://Docs.Example.test/a?q=1", "docs.example.test"},
		{"openclaw", "web_fetch", "https://docs.example.test/a", "docs.example.test"},
		{"opencode", "webfetch", "http://10.0.0.8:8080/x", "10.0.0.8"},
	}
	for _, tc := range accepted {
		effect, facets, err := DeriveT16AuthorizationFacets(tc.product, tc.tool, "network", "", map[string]any{"url": tc.url})
		if err != nil || effect.ResourceID != tc.host || len(facets) != 2 || facets[1].Action != "network_connect" || facets[1].ResourceID != tc.host {
			t.Errorf("%s/%s url=%s effect=%+v facets=%+v err=%v", tc.product, tc.tool, tc.url, effect, facets, err)
		}
	}
	rejected := []struct{ product, tool, url string }{
		{"openclaw", "webfetch", "https://docs.example.test/a"},
		{"opencode", "web_fetch", "https://docs.example.test/a"},
		{"claude-code", "WebFetch", "https://user@docs.example.test/a"},
		{"claude-code", "WebFetch", "https://bad_host.example.test/a"},
		{"claude-code", "WebFetch", "ftp://docs.example.test/a"},
	}
	for _, tc := range rejected {
		if _, _, err := DeriveT16AuthorizationFacets(tc.product, tc.tool, "network", "", map[string]any{"url": tc.url}); err == nil {
			t.Errorf("hookd would not authorize %s/%s url=%s but T16 derived facets", tc.product, tc.tool, tc.url)
		}
	}
}

func TestDeriveT16AuthorizationFacetsRespectsT13ResourceIDBound(t *testing.T) {
	long := "/" + strings.Repeat("a", 256)
	if _, _, err := DeriveT16AuthorizationFacets("claude-code", "Read", "file", "", map[string]any{"file_path": long}); err == nil {
		t.Fatal("path longer than the T13 256-byte resource bound was accepted")
	}
	ok := "/" + strings.Repeat("a", 255)
	if _, _, err := DeriveT16AuthorizationFacets("claude-code", "Read", "file", "", map[string]any{"file_path": ok}); err != nil {
		t.Fatalf("256-byte path rejected: %v", err)
	}
}
