package agentintent

import (
	"strings"
	"testing"
)

func TestSanitizeApprovedPurposeRedactsAndBoundsBeforeHashing(t *testing.T) {
	got := SanitizeApprovedPurpose("Review Bearer abcdefghijklmnop, email user@example.test, and /home/alice/private", 2048)
	for _, forbidden := range []string{"abcdefghijklmnop", "user@example.test", "/home/alice"} {
		if strings.Contains(got, forbidden) {
			t.Fatalf("purpose leaked %q: %q", forbidden, got)
		}
	}
	if !strings.Contains(got, "<redacted:credential>") || !strings.Contains(got, "<redacted:email>") {
		t.Fatalf("redacted purpose=%q", got)
	}
	long := strings.Repeat("x", 2050)
	if got := SanitizeApprovedPurpose(long, 10); len([]rune(got)) != 11 || !strings.HasSuffix(got, "…") {
		t.Fatalf("bounded purpose=%q", got)
	}
}

func TestIntentSourceContentAssuranceRequiresApprovedOrAcceptedDigest(t *testing.T) {
	hash := DigestString("verified source bytes")
	preview := "sha256:" + hash
	cases := []struct {
		name, claim, preview string
		allowed              []string
		accepted, want       string
	}{
		{name: "accepted result bytes", claim: hash, preview: preview, accepted: hash, want: "accepted_result_digest_match"},
		{name: "admin approved bytes", claim: hash, preview: preview, allowed: []string{"sha256:" + hash}, want: "approved_scope_digest_match"},
		{name: "endpoint claim only", claim: hash, preview: preview, want: "endpoint_claimed_digest_match"},
		{name: "preview mismatch", claim: hash, preview: "sha256:" + strings.Repeat("a", 64), allowed: []string{hash}, want: "preview_digest_mismatch"},
		{name: "preview missing", claim: hash, want: "preview_missing"},
		{name: "invalid digest", claim: "sha256:bad", preview: preview, want: "digest_invalid"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := IntentSourceContentAssurance(tc.claim, tc.preview, tc.allowed, tc.accepted); got != tc.want {
				t.Fatalf("assurance=%q want %q", got, tc.want)
			}
		})
	}
}
