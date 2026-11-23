package main

import (
	"encoding/json"
	"errors"
	"os"
	"regexp"
	"strings"
)

const (
	rulePackAttestationTokensJSONEnv = "JJD_RULE_PACK_ATTESTATION_TOKENS_JSON"
	rulePackAttestationTenantEnv     = "JJD_RULE_PACK_ATTESTATION_TENANT"
	rulePackAttestationTokenEnv      = "JJD_RULE_PACK_ATTESTATION_TOKEN"
	defaultRulePackAttestationTenant = "tenant_default"
)

var rulePackAttestationTokenPattern = regexp.MustCompile(
	"^[A-Za-z0-9!#$%&'*+.^_`|~-]{1,256}$",
)

func validRulePackAttestationToken(token string) bool {
	return rulePackAttestationTokenPattern.MatchString(token)
}

func loadRulePackAttestationTokens() (map[string]string, error) {
	return parseRulePackAttestationTokens(
		os.Getenv(rulePackAttestationTokensJSONEnv),
		os.Getenv(rulePackAttestationTenantEnv),
		os.Getenv(rulePackAttestationTokenEnv),
	)
}

// parseRulePackAttestationTokens loads the optional multi-tenant map first,
// then lets the single-tenant setting override the same normalized tenant.
// Tenant IDs are normalized for lookup; token bytes are never trimmed.
func parseRulePackAttestationTokens(jsonValue, singleTenant, singleToken string) (map[string]string, error) {
	tokens := make(map[string]string)
	if strings.TrimSpace(jsonValue) != "" {
		var configured map[string]string
		if err := json.Unmarshal([]byte(jsonValue), &configured); err != nil || configured == nil {
			return nil, errors.New("rule-pack attestation token map must be a JSON object of tenant IDs to tokens")
		}
		for tenantID, token := range configured {
			normalizedTenantID := strings.TrimSpace(tenantID)
			if normalizedTenantID == "" {
				return nil, errors.New("rule-pack attestation token map contains an empty tenant ID")
			}
			if !validRulePackAttestationToken(token) {
				return nil, errors.New("rule-pack attestation token map contains an invalid token")
			}
			if _, exists := tokens[normalizedTenantID]; exists {
				return nil, errors.New("rule-pack attestation token map contains duplicate normalized tenant IDs")
			}
			tokens[normalizedTenantID] = token
		}
	}

	if singleToken == "" {
		return tokens, nil
	}
	if !validRulePackAttestationToken(singleToken) {
		return nil, errors.New("single-tenant rule-pack attestation token is invalid")
	}
	normalizedTenantID := strings.TrimSpace(singleTenant)
	if normalizedTenantID == "" {
		normalizedTenantID = defaultRulePackAttestationTenant
	}
	tokens[normalizedTenantID] = singleToken
	return tokens, nil
}
