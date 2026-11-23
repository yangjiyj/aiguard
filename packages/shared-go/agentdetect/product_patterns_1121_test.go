package agentdetect

import (
	"encoding/json"
	"net/http"
	"testing"
)

func TestProductPatternsComeFromRegistry(t *testing.T) {
	patterns := ProductPatterns("openai-codex")
	want := map[string]bool{"codex-tui/": false, "codex_vscode/": false, "codex_exec/": false, "codex desktop": false, "codex_cli_rs/": false}
	for _, p := range patterns {
		if _, ok := want[p]; ok {
			want[p] = true
		}
		if p != toLowerASCII(p) {
			t.Fatalf("pattern %q must be lower case for SQL strpos(lower(ua), p)", p)
		}
	}
	for p, seen := range want {
		if !seen {
			t.Fatalf("ProductPatterns(openai-codex) missing %q: %v", p, patterns)
		}
	}
	if len(ProductPatterns("no-such-product")) != 0 {
		t.Fatal("unknown product must have no patterns")
	}
	patterns[0] = "mutated"
	if ProductPatterns("openai-codex")[0] == "mutated" {
		t.Fatal("ProductPatterns must return a copy")
	}
}

func TestIdentityHeadersKeepsCodexOriginator(t *testing.T) {
	raw := IdentityHeaders(http.Header{"User-Agent": {"node"}, "Originator": {"codex_vscode"}})
	var got map[string]string
	if err := json.Unmarshal([]byte(raw), &got); err != nil {
		t.Fatal(err)
	}
	if got["originator"] != "codex_vscode" || got["header_product"] != "openai-codex" {
		t.Fatalf("originator not retained for later re-detection: %s", raw)
	}
	without := IdentityHeaders(http.Header{"User-Agent": {"codex_exec/1.0"}})
	plain := map[string]string{}
	if err := json.Unmarshal([]byte(without), &plain); err != nil || len(plain) != 6 {
		t.Fatalf("no originator header must keep the old 6-key shape: %s", without)
	}
}

func toLowerASCII(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + 32
		}
	}
	return string(b)
}
