package repository

import (
	"strings"
	"testing"
)

// T07/T08 TDD: these unit tests cover the pure helper functions in
// agent_destination_approval.go — rule id syntax, origin normalization, and
// create-input validation — before any database-backed behavior is tested.

func TestValidDestinationApprovalRuleID(t *testing.T) {
	valid := []string{"a", "official-anthropic-1", "relay_rule.1", strings.Repeat("a", 64)}
	for _, id := range valid {
		if !validDestinationApprovalRuleID(id) {
			t.Errorf("expected %q to be a valid rule id", id)
		}
	}
	invalid := []string{"", "-leading-dash", ".leading-dot", "_leading-underscore", "has a space", "has/slash", strings.Repeat("a", 65)}
	for _, id := range invalid {
		if validDestinationApprovalRuleID(id) {
			t.Errorf("expected %q to be an invalid rule id", id)
		}
	}
}

func TestNormalizeDestinationOrigin(t *testing.T) {
	cases := []struct {
		raw, scheme, host string
		ok                bool
	}{
		{"https://api.anthropic.com", "https", "api.anthropic.com", true},
		{"https://API.Anthropic.COM", "https", "api.anthropic.com", true},
		{"https://api.anthropic.com:443", "https", "api.anthropic.com", true},
		{"http://relay.example.test:80", "http", "relay.example.test", true},
		{"https://relay.example.test:8443", "https", "relay.example.test:8443", true},
		{"not-a-url", "", "", false},
		{"https://", "", "", false},
		{"", "", "", false},
	}
	for _, c := range cases {
		scheme, host, ok := normalizeDestinationOrigin(c.raw)
		if ok != c.ok || scheme != c.scheme || host != c.host {
			t.Errorf("normalizeDestinationOrigin(%q) = (%q,%q,%v), want (%q,%q,%v)", c.raw, scheme, host, ok, c.scheme, c.host, c.ok)
		}
	}
}

func TestValidDestinationApprovalRuleCreate(t *testing.T) {
	base := func() DestinationApprovalRuleCreate {
		return DestinationApprovalRuleCreate{RuleID: "rule-1", MatchType: "host", MatchValue: "api.anthropic.com", Category: "official"}
	}

	if !validDestinationApprovalRuleCreate(base()) {
		t.Fatal("expected baseline host rule to be valid")
	}

	baseURL := base()
	baseURL.MatchType = "base_url_prefix"
	baseURL.MatchValue = "https://relay.example.test"
	baseURL.Category = "relay"
	if !validDestinationApprovalRuleCreate(baseURL) {
		t.Fatal("expected baseline base_url_prefix rule to be valid")
	}

	badRuleID := base()
	badRuleID.RuleID = "has a space"
	if validDestinationApprovalRuleCreate(badRuleID) {
		t.Fatal("expected invalid rule_id to be rejected")
	}

	badMatchType := base()
	badMatchType.MatchType = "path_prefix"
	if validDestinationApprovalRuleCreate(badMatchType) {
		t.Fatal("expected unknown match_type to be rejected")
	}

	badCategory := base()
	badCategory.Category = "internal"
	if validDestinationApprovalRuleCreate(badCategory) {
		t.Fatal("expected unknown category to be rejected")
	}

	emptyValue := base()
	emptyValue.MatchValue = "   "
	if validDestinationApprovalRuleCreate(emptyValue) {
		t.Fatal("expected blank match_value to be rejected")
	}

	// A "host" rule must be a bare hostname — no scheme, no path, no query —
	// so it cannot smuggle in path/query scope under a match_type that the
	// verification query treats as exact-hostname-only.
	hostWithScheme := base()
	hostWithScheme.MatchValue = "https://api.anthropic.com"
	if validDestinationApprovalRuleCreate(hostWithScheme) {
		t.Fatal("expected host match_type with a scheme to be rejected")
	}
	hostWithPath := base()
	hostWithPath.MatchValue = "api.anthropic.com/v1"
	if validDestinationApprovalRuleCreate(hostWithPath) {
		t.Fatal("expected host match_type with a path to be rejected")
	}

	// A base_url_prefix rule must parse as an origin (scheme+host); a bare
	// hostname is not acceptable there because verification always compares
	// against a normalized scheme://host string for this match_type.
	baseURLBareHost := base()
	baseURLBareHost.MatchType = "base_url_prefix"
	baseURLBareHost.MatchValue = "relay.example.test"
	if validDestinationApprovalRuleCreate(baseURLBareHost) {
		t.Fatal("expected base_url_prefix match_type without a scheme to be rejected")
	}

	tooLongDescription := base()
	tooLongDescription.Description = strings.Repeat("d", 1025)
	if validDestinationApprovalRuleCreate(tooLongDescription) {
		t.Fatal("expected overlong description to be rejected")
	}
}
