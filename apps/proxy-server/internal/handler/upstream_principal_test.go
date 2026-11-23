package handler

import (
	"net/http"
	"strings"
	"testing"
)

// assertNoSecretLeak fails when any n-byte window of secret appears in haystack.
// A single fixed 8-byte assertion is not enough for short tokens, so the window
// shrinks for short secrets.
func assertNoSecretLeak(t *testing.T, haystack, secret string, n int) {
	t.Helper()
	if secret == "" {
		return
	}
	for size := n; size >= 4; size-- {
		if len(secret) < size {
			continue
		}
		for start := 0; start+size <= len(secret); start++ {
			if strings.Contains(haystack, secret[start:start+size]) {
				t.Fatalf("raw secret window %q leaked into %q", secret[start:start+size], haystack)
			}
		}
	}
}

func anthropicBody(userID string) []byte {
	return []byte(`{"model":"claude-sonnet-4","metadata":{"user_id":"` + userID + `"},"messages":[]}`)
}

const anthropicUserIDFixture = "user_0123456789abcdef0123456789abcdef_account_11111111-2222-3333-4444-555555555555_session_66666666-7777-8888-9999-aaaaaaaaaaaa"

func TestDeriveUpstreamPrincipalPrefersChatGPTAccountHeader(t *testing.T) {
	header := http.Header{}
	header.Set("chatgpt-account-id", " acct-abc123 ")
	header.Set("Authorization", "Bearer sk-should-not-win")

	got := deriveUpstreamPrincipal("tenant-a", header, anthropicBody(anthropicUserIDFixture), LLMProviderMatch{Known: true, Provider: "anthropic"})
	if got.Key != "upstream:openai_account:acct-abc123" {
		t.Fatalf("Key = %q, want the chatgpt account header to win", got.Key)
	}
	if got.Source != upstreamSourceChatGPTAccount || got.Session != "" {
		t.Fatalf("unexpected source/session: %+v", got)
	}
}

func TestDeriveUpstreamPrincipalReadsAnthropicMetadata(t *testing.T) {
	got := deriveUpstreamPrincipal("tenant-a", http.Header{"Authorization": []string{"Bearer sk-fallback"}},
		anthropicBody(anthropicUserIDFixture), LLMProviderMatch{Known: true, Provider: "anthropic"})
	if got.Key != "upstream:anthropic_account:11111111-2222-3333-4444-555555555555" {
		t.Fatalf("Key = %q", got.Key)
	}
	if got.Session != "66666666-7777-8888-9999-aaaaaaaaaaaa" {
		t.Fatalf("Session = %q", got.Session)
	}
	if got.Source != upstreamSourceAnthropicMeta {
		t.Fatalf("Source = %q", got.Source)
	}
}

func TestAnthropicMetadataDoesNotMatchForeignBodies(t *testing.T) {
	cases := map[string][]byte{
		"no metadata":        []byte(`{"model":"claude-sonnet-4","messages":[]}`),
		"plain user id":      anthropicBody("user_0123456789abcdef"),
		"wrong separator":    anthropicBody("user_0123456789abcdef-account-11111111-2222-3333-4444-555555555555-session-66666666-7777-8888-9999-aaaaaaaaaaaa"),
		"uppercase hex":      anthropicBody("user_0123456789ABCDEF_account_11111111-2222-3333-4444-555555555555_session_66666666-7777-8888-9999-aaaaaaaaaaaa"),
		"short account uuid": anthropicBody("user_0123456789abcdef_account_11111111_session_66666666-7777-8888-9999-aaaaaaaaaaaa"),
		"not json":           []byte("user_0123456789abcdef_account_11111111-2222-3333-4444-555555555555_session_66666666-7777-8888-9999-aaaaaaaaaaaa"),
		"empty body":         nil,
	}
	for name, body := range cases {
		header := http.Header{}
		if got := deriveUpstreamPrincipal("tenant-a", header, body, LLMProviderMatch{Known: true, Provider: "anthropic"}); got.Key != "" {
			t.Fatalf("%s: expected no principal, got %+v", name, got)
		}
	}
}

func TestAnthropicBodyParsingIsSkippedForOtherProviders(t *testing.T) {
	body := anthropicBody(anthropicUserIDFixture)
	if got := deriveUpstreamPrincipal("tenant-a", http.Header{}, body, LLMProviderMatch{Known: true, Provider: "openai"}); got.Key != "" {
		t.Fatalf("openai provider must not be parsed for anthropic metadata: %+v", got)
	}
	if got := deriveUpstreamPrincipal("tenant-a", http.Header{}, body, LLMProviderMatch{Known: true, Provider: "Claude-Web"}); got.Key == "" {
		t.Fatal("claude-family providers should still be parsed")
	}
	if got := deriveUpstreamPrincipal("tenant-a", http.Header{}, body, LLMProviderMatch{Known: false}); got.Key == "" {
		t.Fatal("unknown providers should still be parsed")
	}
}

func TestCredentialFingerprintIsStableShortAndTenantScoped(t *testing.T) {
	const token = "sk-live-abcdefghijklmnopqrstuvwxyz0123456789"
	first := credentialFingerprint("tenant-a", token)
	if first != credentialFingerprint("tenant-a", token) {
		t.Fatal("fingerprint must be deterministic")
	}
	if first == credentialFingerprint("tenant-b", token) {
		t.Fatal("fingerprint must be scoped to the tenant")
	}
	if len(first) != upstreamCredentialFingerprintLength {
		t.Fatalf("fingerprint length = %d, want %d", len(first), upstreamCredentialFingerprintLength)
	}
	if strings.Contains(first, token[:4]) && len(token) > 4 && strings.Contains(first, token[:8]) {
		t.Fatalf("fingerprint %q looks like plaintext prefix", first)
	}
	assertNoSecretLeak(t, first, token, 8)
}

func TestCredentialHeaderPriorityAndLeakSafety(t *testing.T) {
	const token = "sk-live-abcdefghijklmnopqrstuvwxyz0123456789"
	// Set() canonicalises the header name the same way net/http does when it parses
	// a real request, so these cases exercise the production lookup path.
	headerWith := func(pairs ...string) http.Header {
		header := http.Header{}
		for i := 0; i+1 < len(pairs); i += 2 {
			header.Set(pairs[i], pairs[i+1])
		}
		return header
	}
	cases := []struct {
		name   string
		header http.Header
		want   string
	}{
		{
			name:   "authorization first",
			header: headerWith("Authorization", "Bearer "+token, "X-Api-Key", "k-second"),
			want:   "Bearer " + token,
		},
		{
			name:   "x-api-key when no authorization",
			header: headerWith("x-api-key", token),
			want:   token,
		},
		{
			name:   "api-key next",
			header: headerWith("api-key", token),
			want:   token,
		},
		{
			name:   "x-goog-api-key last",
			header: headerWith("x-goog-api-key", token),
			want:   token,
		},
		{
			name:   "no credential header at all",
			header: headerWith("Content-Type", "application/json"),
			want:   "",
		},
		{
			name:   "blank value is not a credential",
			header: headerWith("Authorization", "   "),
			want:   "",
		},
	}
	for _, tc := range cases {
		if got := credentialFromHeader(tc.header); got != tc.want {
			t.Fatalf("%s: credentialFromHeader = %q, want %q", tc.name, got, tc.want)
		}
	}

	record := ProxyAuditRecord{AccessType: "llm", SourceIP: "192.168.56.1"}
	record = record.WithUpstreamPrincipal("tenant-a", headerWith("Authorization", "Bearer "+token), nil, LLMProviderMatch{Known: true, Provider: "deepseek"})
	if !strings.HasPrefix(record.UpstreamPrincipal, "upstream:credential:") {
		t.Fatalf("UpstreamPrincipal = %q", record.UpstreamPrincipal)
	}
	assertNoSecretLeak(t, record.UpstreamPrincipal, token, 8)

	payload := upstreamPrincipalContextJSON(record)
	assertNoSecretLeak(t, payload, token, 8)
	if !strings.Contains(payload, `"identity_source":"upstream_credential"`) {
		t.Fatalf("payload = %s", payload)
	}
	if !strings.Contains(payload, `"schema_version":1`) {
		t.Fatalf("payload = %s", payload)
	}
	if !strings.Contains(payload, `"source_ip":"192.168.56.1"`) {
		t.Fatalf("payload = %s", payload)
	}
}

func TestWithUpstreamPrincipalOnlyTouchesLLMAndAIDEgress(t *testing.T) {
	header := http.Header{"Authorization": []string{"Bearer whatever"}}
	for _, accessType := range []string{"llm", "ai_ide"} {
		record := ProxyAuditRecord{AccessType: accessType}
		record = record.WithUpstreamPrincipal("tenant-a", header, nil, LLMProviderMatch{})
		if record.UpstreamPrincipal == "" {
			t.Fatalf("access type %s should carry an upstream principal", accessType)
		}
	}
	for _, accessType := range []string{"normal_public", ""} {
		record := ProxyAuditRecord{AccessType: accessType}
		record = record.WithUpstreamPrincipal("tenant-a", header, nil, LLMProviderMatch{})
		if record.UpstreamPrincipal != "" {
			t.Fatalf("access type %q must not be attributed to an upstream account: %q", accessType, record.UpstreamPrincipal)
		}
	}
}

func TestUpstreamPrincipalContextJSONStaysEmptyWithoutPrincipal(t *testing.T) {
	if got := upstreamPrincipalContextJSON(ProxyAuditRecord{SourceIP: "10.0.0.1"}); got != "" {
		t.Fatalf("no upstream principal should keep the column NULL, got %q", got)
	}

	record := ProxyAuditRecord{
		UpstreamPrincipal: "upstream:anthropic_account:11111111-2222-3333-4444-555555555555",
		UpstreamSession:   "66666666-7777-8888-9999-aaaaaaaaaaaa",
		SourceIP:          "192.168.56.1",
	}
	payload := upstreamPrincipalContextJSON(record)
	for _, want := range []string{
		`"identity_source":"upstream_account"`,
		`"principal_key":"upstream:anthropic_account:11111111-2222-3333-4444-555555555555"`,
		`"upstream_session":"66666666-7777-8888-9999-aaaaaaaaaaaa"`,
		`"source_ip":"192.168.56.1"`,
	} {
		if !strings.Contains(payload, want) {
			t.Fatalf("payload %s is missing %s", payload, want)
		}
	}
}

func TestUpstreamIdentitySourceSplitsAccountsFromCredentials(t *testing.T) {
	if got := upstreamIdentitySource("upstream:credential:0011223344556677"); got != upstreamIdentitySourceCredential {
		t.Fatalf("identity source = %q", got)
	}
	for _, key := range []string{
		"upstream:openai_account:acct-1",
		"upstream:anthropic_account:11111111-2222-3333-4444-555555555555",
	} {
		if got := upstreamIdentitySource(key); got != upstreamIdentitySourceAccount {
			t.Fatalf("%s: identity source = %q", key, got)
		}
	}
}
