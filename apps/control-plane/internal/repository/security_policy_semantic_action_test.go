package repository

import (
	"encoding/json"
	"errors"
	"testing"
)

func TestNormalizeSecurityPolicySemanticAction(t *testing.T) {
	for raw, want := range map[string]string{"": "audit", " audit ": "audit", "block": "block", "observe": "observe"} {
		got, err := NormalizeSecurityPolicySemanticAction(raw)
		if err != nil || got != want {
			t.Fatalf("%q => %q,%v want %q", raw, got, err, want)
		}
	}
	for _, bad := range []string{"mask", "allow", "BLOCK", "alert"} {
		if _, err := NormalizeSecurityPolicySemanticAction(bad); !errors.Is(err, ErrInvalidSecurityPolicy) {
			t.Fatalf("%q must be rejected, got %v", bad, err)
		}
	}
}

func TestParseSecurityPolicySemanticActionDefaultsToAudit(t *testing.T) {
	for scope, want := range map[string]string{
		"":                                  "audit",
		"null":                              "audit",
		`{}`:                                "audit",
		`{"semantic_action":"block"}`:       "block",
		`{"semantic_action":"observe"}`:     "observe",
		`{"semantic_action":"mask"}`:        "audit",
		`{"semantic_action":1}`:             "audit",
		`not-json`:                          "audit",
		`{"redaction":{"replacement":"x"}}`: "audit",
	} {
		if got := ParseSecurityPolicySemanticAction([]byte(scope)); got != want {
			t.Fatalf("scope %q => %q want %q", scope, got, want)
		}
	}
}

func TestScopeWithSemanticActionKeepsOtherKeysAndDropsDefault(t *testing.T) {
	base := []byte(`{"scene":"prompt_injection","redaction":{"replacement":"***","restore_response":false}}`)
	blocked, err := scopeWithSemanticAction(base, "block")
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	_ = json.Unmarshal(blocked, &decoded)
	if decoded["semantic_action"] != "block" || decoded["scene"] != "prompt_injection" || decoded["redaction"] == nil {
		t.Fatalf("scope=%s", blocked)
	}
	reset, err := scopeWithSemanticAction(blocked, "audit")
	if err != nil {
		t.Fatal(err)
	}
	decoded = nil
	_ = json.Unmarshal(reset, &decoded)
	if _, present := decoded["semantic_action"]; present || decoded["scene"] != "prompt_injection" {
		t.Fatalf("audit must remove the key, scope=%s", reset)
	}
	if _, err := scopeWithSemanticAction(base, "mask"); err == nil {
		t.Fatal("invalid semantic action must be rejected")
	}
}

func TestValidateSemanticActionCapabilities(t *testing.T) {
	semantic := SecurityPolicyCapability{Category: "semantic_jailbreak", Component: SemanticJudgeComponent, AllowedActions: []string{"audit", "block"}}
	auditOnlySemantic := SecurityPolicyCapability{Category: "semantic_x", Component: SemanticJudgeComponent, AllowedActions: []string{"audit"}}
	static := SecurityPolicyCapability{Category: "keyword_roleplay", Component: "security-engine.static-detectors", AllowedActions: []string{"audit", "block"}}

	if err := validateSemanticActionCapabilities([]SecurityPolicyCapability{static}, "audit"); err != nil {
		t.Fatalf("audit is always valid: %v", err)
	}
	for _, action := range []string{"block", "observe"} {
		if err := validateSemanticActionCapabilities([]SecurityPolicyCapability{static}, action); !errors.Is(err, ErrInvalidSecurityPolicy) {
			t.Fatalf("%s without semantic capability must be rejected: %v", action, err)
		}
		if err := validateSemanticActionCapabilities([]SecurityPolicyCapability{static, semantic}, action); err != nil {
			t.Fatalf("%s with semantic capability must be accepted: %v", action, err)
		}
	}
	if err := validateSemanticActionCapabilities([]SecurityPolicyCapability{auditOnlySemantic}, "block"); !errors.Is(err, ErrInvalidSecurityPolicy) {
		t.Fatalf("block requires the semantic capability to allow block: %v", err)
	}
	if err := validateSemanticActionCapabilities([]SecurityPolicyCapability{auditOnlySemantic}, "observe"); err != nil {
		t.Fatalf("observe does not require block: %v", err)
	}
}
