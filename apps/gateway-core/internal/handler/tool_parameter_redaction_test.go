package handler

import (
	"reflect"
	"testing"
)

func TestSanitizeToolCallParametersRedactsSensitiveKeysRecursively(t *testing.T) {
	input := map[string]interface{}{
		"password":      "ordinary-looking-value",
		"Authorization": "Bearer not-detected-by-value-scanner",
		"max_tokens":    float64(128),
		"nested": map[string]interface{}{
			"client_secret": "short",
			"private-key":   "short",
			"safe":          "visible",
		},
		"items": []interface{}{
			map[string]interface{}{"api_key": "tiny", "label": "kept"},
		},
	}

	got := sanitizeToolCallParameters(input)
	want := map[string]interface{}{
		"password":      "<redacted:sensitive-key>",
		"Authorization": "<redacted:sensitive-key>",
		"max_tokens":    float64(128),
		"nested": map[string]interface{}{
			"client_secret": "<redacted:sensitive-key>",
			"private-key":   "<redacted:sensitive-key>",
			"safe":          "visible",
		},
		"items": []interface{}{
			map[string]interface{}{"api_key": "<redacted:sensitive-key>", "label": "kept"},
		},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("sanitized parameters = %#v, want %#v", got, want)
	}
}

func TestSensitiveToolParameterKeyDoesNotTreatTokenBudgetAsCredential(t *testing.T) {
	for _, key := range []string{"max_tokens", "token_count", "prompt_tokens"} {
		if isSensitiveToolParameterKey(key) {
			t.Fatalf("%q must remain visible for useful audit evidence", key)
		}
	}
}
