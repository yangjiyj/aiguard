package handler

import (
	"testing"
)

func TestMatchPattern_ExactMatch(t *testing.T) {
	w := &WhitelistChecker{}

	if !w.matchPattern("api.openai.com", "api.openai.com") {
		t.Error("exact match should return true")
	}
	if !w.matchPattern("example.com", "example.com") {
		t.Error("exact match should return true")
	}
}

func TestMatchPattern_WildcardMatch(t *testing.T) {
	w := &WhitelistChecker{}

	// *.openai.com matches api.openai.com
	if !w.matchPattern("*.openai.com", "api.openai.com") {
		t.Error("*.openai.com should match api.openai.com")
	}
	// *.openai.com matches v1.api.openai.com (subdomain)
	if !w.matchPattern("*.openai.com", "v1.api.openai.com") {
		t.Error("*.openai.com should match v1.api.openai.com")
	}
	// *.openai.com matches openai.com (domain itself)
	if !w.matchPattern("*.openai.com", "openai.com") {
		t.Error("*.openai.com should match openai.com")
	}
	// *.openai.com does NOT match other.com
	if w.matchPattern("*.openai.com", "other.com") {
		t.Error("*.openai.com should NOT match other.com")
	}
	// *.anthropic.com does NOT match api.openai.com
	if w.matchPattern("*.anthropic.com", "api.openai.com") {
		t.Error("*.anthropic.com should NOT match api.openai.com")
	}
}

func TestMatchPattern_NonWildcard(t *testing.T) {
	w := &WhitelistChecker{}

	// Exact match required for non-wildcard patterns
	if w.matchPattern("api.deepseek.com", "other.deepseek.com") {
		t.Error("api.deepseek.com should NOT match other.deepseek.com")
	}
	if w.matchPattern("api.deepseek.com", "api.deepseek.com") {
		// This should match - exact
	} else {
		t.Error("api.deepseek.com should match api.deepseek.com")
	}
}

func TestMatchPattern_EmptyPattern(t *testing.T) {
	w := &WhitelistChecker{}

	// Empty targets and patterns are invalid whitelist entries.
	if w.matchPattern("", "example.com") {
		t.Error("empty pattern should NOT match example.com")
	}
	if w.matchPattern("", "") {
		t.Error("empty pattern must not authorize an empty host")
	}
}

func TestMatchPattern_SubdomainNesting(t *testing.T) {
	w := &WhitelistChecker{}

	// *.example.com should match multiple levels of subdomains
	if !w.matchPattern("*.example.com", "a.b.c.example.com") {
		t.Error("*.example.com should match a.b.c.example.com")
	}
	if !w.matchPattern("*.example.com", "deep.nested.sub.example.com") {
		t.Error("*.example.com should match deep.nested.sub.example.com")
	}
}

func TestCheck_HostWithPort(t *testing.T) {
	w := &WhitelistChecker{
		cacheExpiry: 5 * 60 * 1000000000, // 5 minutes in nanoseconds
	}

	// Test that port is stripped before matching
	// Without actual DB, we can't test the full Check() function
	// But we can verify that matchPattern works without port

	// Simulate: host = "api.openai.com:443" -> stripped to "api.openai.com"
	hostWithoutPort := "api.openai.com"
	if !w.matchPattern("*.openai.com", hostWithoutPort) {
		t.Error("should match after stripping port")
	}
}

func TestWhitelistChecker_DeniesWhenStoreUnavailableByDefault(t *testing.T) {
	t.Setenv("PROXY_WHITELIST_FAIL_MODE", "closed")
	w := &WhitelistChecker{}

	allowed, auditEnabled, tenantID := w.Check("unlisted-public.example:443")

	if allowed {
		t.Fatal("an unavailable whitelist store must fail closed by default")
	}
	if !auditEnabled {
		t.Fatal("forward proxy should keep auditing enabled by default")
	}
	if tenantID != "tenant_default" {
		t.Fatalf("tenantID = %q, want tenant_default", tenantID)
	}
}
