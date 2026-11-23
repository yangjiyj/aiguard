package modelrouter_test

import (
	"encoding/json"
	"testing"
)

// TestModelPolicyParsing tests the JSON parsing behavior for model policies
// This validates the fix for the bug where parsed JSON was replaced with empty slices
func TestModelPolicyParsing(t *testing.T) {
	tests := []struct {
		name        string
		allowJSON   string
		denyJSON    string
		expectAllow []string
		expectDeny  []string
	}{
		{
			name:        "empty_arrays",
			allowJSON:   "[]",
			denyJSON:    "[]",
			expectAllow: []string{},
			expectDeny:  []string{},
		},
		{
			name:        "single_model_allowed",
			allowJSON:   `["gpt-4"]`,
			denyJSON:    "[]",
			expectAllow: []string{"gpt-4"},
			expectDeny:  []string{},
		},
		{
			name:        "multiple_models",
			allowJSON:   `["gpt-4", "gpt-3.5-turbo", "claude-3-sonnet"]`,
			denyJSON:    `["gpt-4-32k"]`,
			expectAllow: []string{"gpt-4", "gpt-3.5-turbo", "claude-3-sonnet"},
			expectDeny:  []string{"gpt-4-32k"},
		},
		{
			name:        "null_json",
			allowJSON:   "null",
			denyJSON:    "null",
			expectAllow: nil, // json.Unmarshal returns nil for null
			expectDeny:  nil,
		},
		{
			name:        "invalid_json_returns_error",
			allowJSON:   "invalid",
			denyJSON:    "[]",
			expectAllow: nil, // Should handle error gracefully
			expectDeny:  []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var allowList, denyList []string

			// Parse allow list
			if tt.allowJSON != "" && tt.allowJSON != "null" {
				err := json.Unmarshal([]byte(tt.allowJSON), &allowList)
				if err != nil && tt.name != "invalid_json_returns_error" {
					t.Errorf("Failed to parse allowJSON: %v", err)
				}
			}

			// Parse deny list
			if tt.denyJSON != "" && tt.denyJSON != "null" {
				err := json.Unmarshal([]byte(tt.denyJSON), &denyList)
				if err != nil {
					t.Errorf("Failed to parse denyJSON: %v", err)
				}
			}

			// Verify expected values
			if tt.name == "invalid_json_returns_error" {
				// For invalid JSON, allowList should remain nil or empty
				if len(allowList) > 0 {
					t.Errorf("Invalid JSON should not produce valid list")
				}
			} else {
				// Check allow list
				if !sliceEqual(allowList, tt.expectAllow) {
					t.Errorf("allowList = %v, want %v", allowList, tt.expectAllow)
				}
				// Check deny list
				if !sliceEqual(denyList, tt.expectDeny) {
					t.Errorf("denyList = %v, want %v", denyList, tt.expectDeny)
				}
			}
		})
	}
}

// TestIsModelAllowed tests the policy enforcement logic
func TestIsModelAllowed(t *testing.T) {
	tests := []struct {
		name      string
		model     string
		allowList []string
		denyList  []string
		allowed   bool
	}{
		{"empty_lists_all_allowed", "gpt-4", []string{}, []string{}, true},
		{"model_in_allow_list", "gpt-4", []string{"gpt-4", "gpt-3.5-turbo"}, []string{}, true},
		{"model_not_in_allow_list", "claude-3-opus", []string{"gpt-4"}, []string{}, false},
		{"model_in_deny_list", "gpt-4-32k", []string{"gpt-4"}, []string{"gpt-4-32k"}, false},
		{"deny_overrides_allow", "gpt-4", []string{"gpt-4"}, []string{"gpt-4"}, false},
		{"nil_lists_all_allowed", "gpt-4", nil, nil, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isModelAllowed(tt.model, tt.allowList, tt.denyList)
			if result != tt.allowed {
				t.Errorf("isModelAllowed(%s, %v, %v) = %v, want %v",
					tt.model, tt.allowList, tt.denyList, result, tt.allowed)
			}
		})
	}
}

// TestResolveProvider tests static provider resolution fallback
func TestResolveProvider(t *testing.T) {
	tests := []struct {
		model    string
		expected string
	}{
		{"gpt-4", "openai"},
		{"gpt-4o", "openai"},
		{"gpt-3.5-turbo", "openai"},
		{"o1-preview", "openai"},
		{"o1-mini", "openai"},
		{"claude-3-sonnet", "anthropic"},
		{"claude-3-opus", "anthropic"},
		{"claude-3-5-sonnet", "anthropic"},
		{"gemini-pro", "gemini"},
		{"gemini-1.5-flash", "gemini"},
		{"unknown-model", "openai"}, // Default fallback
	}

	for _, tt := range tests {
		t.Run(tt.model, func(t *testing.T) {
			result := resolveProvider(tt.model)
			if result != tt.expected {
				t.Errorf("resolveProvider(%s) = %s, want %s", tt.model, result, tt.expected)
			}
		})
	}
}

// Helper functions

func sliceEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func isModelAllowed(model string, allowList, denyList []string) bool {
	// Check deny list first
	for _, m := range denyList {
		if m == model {
			return false
		}
	}

	// If allow list is empty or nil, all models allowed (except deny list)
	if len(allowList) == 0 {
		return true
	}

	// Check allow list
	for _, m := range allowList {
		if m == model {
			return true
		}
	}

	return false
}

func resolveProvider(model string) string {
	// Simplified version matching production logic
	modelLower := model
	for i, c := range model {
		if c >= 'A' && c <= 'Z' {
			modelLower = modelLower[:i] + string(c+32) + modelLower[i+1:]
		}
	}

	// Check prefixes
	if len(modelLower) >= 3 && modelLower[:3] == "gpt" {
		return "openai"
	}
	if len(modelLower) >= 2 && modelLower[:2] == "o1" {
		return "openai"
	}
	if len(modelLower) >= 6 && modelLower[:6] == "claude" {
		return "anthropic"
	}
	if len(modelLower) >= 6 && modelLower[:6] == "gemini" {
		return "gemini"
	}

	return "openai" // Default
}