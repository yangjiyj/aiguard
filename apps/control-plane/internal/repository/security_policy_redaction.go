package repository

import (
	"bytes"
	"encoding/json"
	"strings"
	"unicode/utf8"
)

// SecurityPolicyRedaction belongs to a policy; restoration secrets never enter
// this configuration. The gateway stores actual values only for one request.
type SecurityPolicyRedaction struct {
	Replacement     string `json:"replacement"`
	RestoreResponse bool   `json:"restore_response"`
}

func NormalizeSecurityPolicyRedaction(input *SecurityPolicyRedaction) (*SecurityPolicyRedaction, error) {
	if input == nil {
		return nil, nil
	}
	if strings.TrimSpace(input.Replacement) == "" || utf8.RuneCountInString(input.Replacement) > 128 || strings.ContainsAny(input.Replacement, "\r\n\x00") || strings.Contains(input.Replacement, "<JJD_") {
		return nil, invalidSecurityPolicy("redaction replacement must be 1-128 characters, without line breaks or reserved placeholders")
	}
	copy := *input
	return &copy, nil
}

func ParseSecurityPolicyRedaction(scopeJSON []byte) (*SecurityPolicyRedaction, bool) {
	var scope struct {
		Redaction json.RawMessage `json:"redaction"`
	}
	if len(scopeJSON) == 0 || string(scopeJSON) == "null" {
		return nil, true
	}
	if json.Unmarshal(scopeJSON, &scope) != nil {
		return nil, false
	}
	if len(scope.Redaction) == 0 || string(scope.Redaction) == "null" {
		return nil, true
	}
	var setting SecurityPolicyRedaction
	decoder := json.NewDecoder(bytes.NewReader(scope.Redaction))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&setting) != nil {
		return nil, false
	}
	normalized, err := NormalizeSecurityPolicyRedaction(&setting)
	return normalized, err == nil
}

func scopeWithRedaction(scopeJSON []byte, input *SecurityPolicyRedaction) ([]byte, error) {
	setting, err := NormalizeSecurityPolicyRedaction(input)
	if err != nil {
		return nil, err
	}
	var scope map[string]any
	if json.Unmarshal(scopeJSON, &scope) != nil {
		return nil, invalidSecurityPolicy("policy scope is invalid")
	}
	if scope == nil {
		scope = map[string]any{}
	}
	scope["redaction"] = setting
	return json.Marshal(scope)
}
