package agentintent

import (
	"regexp"
	"strings"
	"unicode/utf8"
)

var (
	approvedBearerPattern     = regexp.MustCompile(`(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{6,}`)
	approvedCredentialPattern = regexp.MustCompile(`(?i)\b(api[_-]?key|access[_-]?token|refresh[_-]?token|token|secret|password|credential|authorization|cookie)\b\s*[:=]\s*["']?[^\s"',;]+`)
	approvedCommonKeyPattern  = regexp.MustCompile(`(?i)\b(?:sk-[A-Za-z0-9_-]{12,}|sk-ant-[A-Za-z0-9_-]{12,}|gh[pousr]_[A-Za-z0-9]{12,}|glpat-[A-Za-z0-9_-]{12,}|AKIA[A-Z0-9]{16})\b`)
	approvedPrivateKeyPattern = regexp.MustCompile(`(?is)-----BEGIN [^-]*PRIVATE KEY-----.*?-----END [^-]*PRIVATE KEY-----`)
	approvedEmailPattern      = regexp.MustCompile(`(?i)\b[A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,}\b`)
	approvedPhonePattern      = regexp.MustCompile(`\b\+?[0-9][0-9 .()\-]{7,}[0-9]\b`)
	approvedSensitiveURLQuery = regexp.MustCompile(`(?i)([?&](?:token|access_token|api[_-]?key|secret|password|auth|key)=)[^&#\s]+`)
	approvedHomePathPattern   = regexp.MustCompile(`(?:/home/[^/\s]+|[A-Za-z]:\\Users\\[^\\\s]+|~[/\\][^/\\\s]+)`)
)

// SanitizeApprovedPurpose redacts common credentials and personal identifiers
// before a task purpose is stored or hashed. maxRunes also bounds persisted text.
func SanitizeApprovedPurpose(value string, maxRunes int) string {
	if !utf8.ValidString(value) || maxRunes <= 0 {
		return ""
	}
	redacted := approvedPrivateKeyPattern.ReplaceAllString(value, "<redacted:private-key>")
	redacted = approvedBearerPattern.ReplaceAllString(redacted, "Bearer <redacted:credential>")
	redacted = approvedCredentialPattern.ReplaceAllString(redacted, "$1=<redacted:credential>")
	redacted = approvedCommonKeyPattern.ReplaceAllString(redacted, "<redacted:credential>")
	redacted = approvedSensitiveURLQuery.ReplaceAllString(redacted, "$1<redacted:credential>")
	redacted = approvedEmailPattern.ReplaceAllString(redacted, "<redacted:email>")
	redacted = approvedPhonePattern.ReplaceAllString(redacted, "<redacted:number>")
	redacted = approvedHomePathPattern.ReplaceAllString(redacted, "<redacted:path>")
	if utf8.RuneCountInString(redacted) > maxRunes {
		redacted = string([]rune(redacted)[:maxRunes]) + "…"
	}
	return strings.TrimSpace(redacted)
}

// IntentSourceContentAssurance compares only digests. The preview itself stays
// transient; bytes are bound only to an administrator-approved digest or a
// server-accepted terminal result digest.
func IntentSourceContentAssurance(claimHash, previewHash string, allowedHashes []string, acceptedResultHash string) string {
	claim, claimOK := normalizeIntentSourceDigest(claimHash)
	if !claimOK {
		return "digest_invalid"
	}
	if strings.TrimSpace(previewHash) == "" {
		return "preview_missing"
	}
	preview, previewOK := normalizeIntentSourceDigest(previewHash)
	if !previewOK {
		return "digest_invalid"
	}
	if preview != claim {
		return "preview_digest_mismatch"
	}
	if accepted, ok := normalizeIntentSourceDigest(acceptedResultHash); ok && accepted == claim {
		return "accepted_result_digest_match"
	}
	for _, allowed := range allowedHashes {
		if normalized, ok := normalizeIntentSourceDigest(allowed); ok && normalized == claim {
			return "approved_scope_digest_match"
		}
	}
	return "endpoint_claimed_digest_match"
}

func ValidIntentSourceContentAssurance(value string) bool {
	switch value {
	case "digest_invalid", "preview_missing", "preview_digest_mismatch", "accepted_result_digest_match",
		"approved_scope_digest_match", "endpoint_claimed_digest_match":
		return true
	default:
		return false
	}
}

func normalizeIntentSourceDigest(value string) (string, bool) {
	value = strings.TrimSpace(value)
	if !resultHashPattern.MatchString(value) {
		return "", false
	}
	return strings.TrimPrefix(strings.ToLower(value), "sha256:"), true
}
