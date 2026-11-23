package repository

import "testing"

func TestMergeVerifiedModelCapabilitiesPreservesManualAndVerifiedValues(t *testing.T) {
	existing := map[string]interface{}{
		"manual_route": "keep",
		"modality":     "verified-image",
		"protocols": map[string]interface{}{
			"responses_native": true,
			"chat_completions": false,
		},
	}
	desired := map[string]interface{}{
		"modality": "text",
		"protocols": map[string]interface{}{
			"responses_native": false,
			"chat_completions": true,
			"embeddings":       true,
		},
		"new_flag": true,
	}
	got := mergeVerifiedModelCapabilities(existing, desired)
	if got["manual_route"] != "keep" || got["modality"] != "verified-image" || got["new_flag"] != true {
		t.Fatalf("unexpected top-level merge: %#v", got)
	}
	protocols, ok := got["protocols"].(map[string]interface{})
	if !ok || protocols["responses_native"] != true || protocols["chat_completions"] != false || protocols["embeddings"] != true {
		t.Fatalf("unexpected protocol merge: %#v", got["protocols"])
	}
}
