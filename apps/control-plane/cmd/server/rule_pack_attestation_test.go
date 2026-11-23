package main

import (
	"strings"
	"testing"
)

func TestParseRulePackAttestationTokensMergesAndOverrides(t *testing.T) {
	got, err := parseRulePackAttestationTokens(
		`{" tenant_a ":"json-value","tenant_b":"json-b"}`,
		" tenant_a ",
		"single-value",
	)
	if err != nil {
		t.Fatalf("parse tokens: %v", err)
	}
	want := map[string]string{
		"tenant_a": "single-value",
		"tenant_b": "json-b",
	}
	if len(got) != len(want) {
		t.Fatalf("got %d tokens, want %d", len(got), len(want))
	}
	for tenantID, token := range want {
		if got[tenantID] != token {
			t.Fatalf("token for %q = %q, want exact %q", tenantID, got[tenantID], token)
		}
	}
}

func TestParseRulePackAttestationTokensPreservesSafeTokenBytes(t *testing.T) {
	got, err := parseRulePackAttestationTokens(`{"tenant_a":"value.with-safe_chars~"}`, "", "")
	if err != nil {
		t.Fatalf("parse tokens: %v", err)
	}
	if got["tenant_a"] != "value.with-safe_chars~" {
		t.Fatalf("token was changed: %q", got["tenant_a"])
	}
}

func TestParseRulePackAttestationTokensUsesDefaultSingleTenant(t *testing.T) {
	got, err := parseRulePackAttestationTokens("", "", "single-value")
	if err != nil {
		t.Fatalf("parse tokens: %v", err)
	}
	if got["tenant_default"] != "single-value" {
		t.Fatalf("default tenant token = %q", got["tenant_default"])
	}
}

func TestParseRulePackAttestationTokensWithoutTokenReturnsEmptyMap(t *testing.T) {
	got, err := parseRulePackAttestationTokens("", "tenant_a", "")
	if err != nil {
		t.Fatalf("parse tokens: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("got invented tokens: %#v", got)
	}
}

func TestParseRulePackAttestationTokensRejectsUnsafeEntriesWithoutLeakingValues(t *testing.T) {
	tests := []struct {
		name         string
		jsonValue    string
		singleTenant string
		singleToken  string
	}{
		{name: "malformed json", jsonValue: `{"tenant_a":"sensitive-value-must-not-appear"`},
		{name: "blank json tenant", jsonValue: `{"   ":"sensitive-value-must-not-appear"}`},
		{name: "blank json token", jsonValue: `{"tenant_a":"   "}`},
		{name: "json token contains whitespace", jsonValue: `{"tenant_a":"unsafe token"}`},
		{name: "json token contains header separator", jsonValue: `{"tenant_a":"unsafe=value"}`},
		{name: "json token too long", jsonValue: `{"tenant_a":"` + strings.Repeat("x", 257) + `"}`},
		{name: "normalized tenant collision", jsonValue: `{" tenant_a":"first-value","tenant_a ":"second-value"}`},
		{name: "blank single token", singleTenant: "tenant_a", singleToken: "   "},
		{name: "single token contains control", singleTenant: "tenant_a", singleToken: "bad\r\ntoken"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parseRulePackAttestationTokens(tt.jsonValue, tt.singleTenant, tt.singleToken)
			if err == nil {
				t.Fatal("expected validation error")
			}
			for _, value := range []string{
				"sensitive-value-must-not-appear",
				"first-value",
				"second-value",
			} {
				if strings.Contains(err.Error(), value) {
					t.Fatalf("error leaked configured value: %v", err)
				}
			}
		})
	}
}
