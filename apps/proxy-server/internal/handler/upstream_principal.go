package handler

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"regexp"
	"strings"
)

// upstreamPrincipal is the subject the forward-proxy path can actually attribute
// traffic to. Behind the gateway's NAT every request shares one source address,
// so the upstream account (or the credential fingerprint standing in for it) is
// the only stable, human-meaningful owner.
//
// Key shapes:
//
//	upstream:openai_account:<account-id>
//	upstream:anthropic_account:<uuid>
//	upstream:credential:<sha256(tenantID \x00 value)[:16]>
//
// SECURITY: raw credential values must never be logged, persisted, or surfaced
// in error strings. Only the truncated digest is allowed to leave this file.
type upstreamPrincipal struct {
	Key     string
	Session string
	Source  string
}

const (
	upstreamPrincipalPrefix = "upstream:"

	// identity_source values written into request_logs.principal_context_json.
	upstreamIdentitySourceAccount    = "upstream_account"
	upstreamIdentitySourceCredential = "upstream_credential"

	upstreamSourceChatGPTAccount = "chatgpt_account_id_header"
	upstreamSourceAnthropicMeta  = "anthropic_metadata_user_id"
	upstreamSourceCredential     = "authorization_credential"

	upstreamCredentialFingerprintLength = 16
)

// anthropicMetadataUserIDPattern matches the identifier Anthropic's own clients
// put in metadata.user_id, e.g.
// user_0123456789abcdef0123456789abcdef_account_<uuid>_session_<uuid>.
var anthropicMetadataUserIDPattern = regexp.MustCompile(`^user_[0-9a-f]+_account_([0-9a-f-]{36})_session_([0-9a-f-]{36})$`)

// credentialHeaders is ordered most-specific first: an explicit provider key
// beats a generic bearer token.
var credentialHeaders = []string{"Authorization", "x-api-key", "api-key", "x-goog-api-key"}

// deriveUpstreamPrincipal resolves the upstream subject for one proxied request.
// Priority: chatgpt-account-id header, then Anthropic metadata.user_id, then the
// first non-empty credential header. Returns the zero value when nothing is
// available, which makes the caller fall back to the source address.
func deriveUpstreamPrincipal(tenantID string, h http.Header, decodedBody []byte, provider LLMProviderMatch) upstreamPrincipal {
	if h != nil {
		if accountID := strings.TrimSpace(h.Get("chatgpt-account-id")); accountID != "" {
			return upstreamPrincipal{
				Key:    upstreamPrincipalPrefix + "openai_account:" + accountID,
				Source: upstreamSourceChatGPTAccount,
			}
		}
	}
	if anthropic := anthropicPrincipalFromBody(decodedBody, provider); anthropic.Key != "" {
		return anthropic
	}
	if credential := credentialFromHeader(h); credential != "" {
		return upstreamPrincipal{
			Key:    upstreamPrincipalPrefix + "credential:" + credentialFingerprint(tenantID, credential),
			Source: upstreamSourceCredential,
		}
	}
	return upstreamPrincipal{}
}

// anthropicPrincipalFromBody pulls the account/session pair out of an
// Anthropic-shaped body. The account id and session id are client-generated
// identifiers, not secrets, so they are kept verbatim; the surrounding raw
// string is discarded.
func anthropicPrincipalFromBody(body []byte, provider LLMProviderMatch) upstreamPrincipal {
	if len(body) == 0 || !anthropicBodyParsingAllowed(provider) {
		return upstreamPrincipal{}
	}
	var envelope struct {
		Metadata struct {
			UserID string `json:"user_id"`
		} `json:"metadata"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		return upstreamPrincipal{}
	}
	match := anthropicMetadataUserIDPattern.FindStringSubmatch(strings.TrimSpace(envelope.Metadata.UserID))
	if match == nil {
		return upstreamPrincipal{}
	}
	return upstreamPrincipal{
		Key:     upstreamPrincipalPrefix + "anthropic_account:" + match[1],
		Session: match[2],
		Source:  upstreamSourceAnthropicMeta,
	}
}

// anthropicBodyParsingAllowed keeps the strict body regex from being attempted
// against providers that cannot emit it, while still inspecting traffic whose
// provider could not be identified from the host/path.
func anthropicBodyParsingAllowed(provider LLMProviderMatch) bool {
	name := strings.ToLower(strings.TrimSpace(provider.Provider))
	if name == "" {
		return true
	}
	return strings.Contains(name, "anthropic") || strings.Contains(name, "claude")
}

func credentialFromHeader(h http.Header) string {
	if h == nil {
		return ""
	}
	for _, name := range credentialHeaders {
		if value := strings.TrimSpace(h.Get(name)); value != "" {
			return value
		}
	}
	return ""
}

// credentialFingerprint makes one credential groupable and stable per tenant
// without being reversible. The raw value only ever feeds sha256; only a short
// hexadecimal digest is returned.
func credentialFingerprint(tenantID, credential string) string {
	sum := sha256.Sum256([]byte(tenantID + "\x00" + credential))
	digest := hex.EncodeToString(sum[:])
	if len(digest) <= upstreamCredentialFingerprintLength {
		return digest
	}
	return digest[:upstreamCredentialFingerprintLength]
}

// upstreamIdentitySource maps a principal key back to the identity_source value
// persisted alongside it.
func upstreamIdentitySource(principalKey string) string {
	if strings.Contains(principalKey, ":credential:") {
		return upstreamIdentitySourceCredential
	}
	return upstreamIdentitySourceAccount
}

// WithUpstreamPrincipal fills the upstream subject, but only for targets that
// really are an LLM or AI-IDE egress. Plain public browsing is left untouched:
// its Authorization header belongs to some unrelated website.
func (r ProxyAuditRecord) WithUpstreamPrincipal(tenantID string, h http.Header, decodedBody []byte, match LLMProviderMatch) ProxyAuditRecord {
	if r.AccessType != "llm" && r.AccessType != "ai_ide" {
		return r
	}
	principal := deriveUpstreamPrincipal(tenantID, h, decodedBody, match)
	if principal.Key == "" {
		return r
	}
	r.UpstreamPrincipal = principal.Key
	r.UpstreamSession = principal.Session
	return r
}

// upstreamPrincipalContextJSON renders the principal_context_json payload for the
// forward-proxy request_logs row. Returns "" when there is nothing to attribute,
// so the column stays NULL instead of an empty object.
func upstreamPrincipalContextJSON(record ProxyAuditRecord) string {
	principalKey := strings.TrimSpace(record.UpstreamPrincipal)
	if principalKey == "" {
		return ""
	}
	payload := map[string]interface{}{
		"schema_version":  1,
		"identity_source": upstreamIdentitySource(principalKey),
		"principal_key":   principalKey,
	}
	if session := strings.TrimSpace(record.UpstreamSession); session != "" {
		payload["upstream_session"] = session
	}
	if sourceIP := strings.TrimSpace(record.SourceIP); sourceIP != "" {
		payload["source_ip"] = sourceIP
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return ""
	}
	return string(encoded)
}
