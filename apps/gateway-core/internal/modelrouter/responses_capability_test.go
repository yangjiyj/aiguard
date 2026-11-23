package modelrouter

import "testing"

func TestResponsesNativeCapability(t *testing.T) {
	tests := []struct {
		name string
		raw  []byte
		want bool
	}{
		{name: "enabled", raw: []byte(`{"protocols":{"responses_native":true}}`), want: true},
		{name: "disabled", raw: []byte(`{"protocols":{"responses_native":false}}`), want: false},
		{name: "missing", raw: []byte(`{"modality":["text"]}`), want: false},
		{name: "invalid", raw: []byte(`{`), want: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := responsesNativeCapability(tc.raw); got != tc.want {
				t.Fatalf("responsesNativeCapability(%s)=%v want=%v", tc.raw, got, tc.want)
			}
		})
	}
}

func TestModelRecordCarriesResponsesNativeFlag(t *testing.T) {
	record := ModelRecord{ResponsesNative: true}
	if !record.ResponsesNative {
		t.Fatal("native Responses capability was lost")
	}
}

func TestResponsesNativeCapabilityDoesNotInspectModelNames(t *testing.T) {
	raw := []byte("{\"protocols\":{\"responses_native\":true}}")
	for _, modelName := range []string{"gpt-image-1", "gpt-image-2"} {
		if !responsesNativeCapability(raw) {
			t.Fatalf("%s must preserve explicit native Responses capability", modelName)
		}
	}
	if !responsesNativeCapability(raw) {
		t.Fatal("regular GPT model should preserve native Responses capability")
	}
}
