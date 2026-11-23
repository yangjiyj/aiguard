package handler

import "testing"

func TestNormalizeRequestedKeyScopesSupportsMCPAndDefaultsToModelOnly(t *testing.T) {
	scopes, err := normalizeRequestedKeyScopes([]string{"mcp"})
	if err != nil {
		t.Fatalf("mcp scope rejected: %v", err)
	}
	if len(scopes) != 1 || scopes[0] != "mcp" {
		t.Fatalf("mcp scopes=%v", scopes)
	}

	defaults, err := normalizeRequestedKeyScopes(nil)
	if err != nil {
		t.Fatalf("default scopes rejected: %v", err)
	}
	want := map[string]bool{"chat": true, "responses": true, "embeddings": true, "models": true}
	if len(defaults) != len(want) {
		t.Fatalf("default scopes=%v want model-only scopes", defaults)
	}
	for _, scope := range defaults {
		if scope == "mcp" || !want[scope] {
			t.Fatalf("default scopes contain unexpected privilege %q: %v", scope, defaults)
		}
		delete(want, scope)
	}
	if len(want) != 0 {
		t.Fatalf("missing default model scopes: %v", want)
	}
}
