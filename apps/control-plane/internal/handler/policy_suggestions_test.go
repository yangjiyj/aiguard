package handler

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestDecodePolicySuggestionPayload(t *testing.T) {
	tests := []struct {
		name, payload string
		wantErr       bool
	}{
		{"regex accepted", `{"regex":"(?i)secret\\d+","examples":["secret1"]}`, false},
		{"keywords accepted", `{"keywords":["secret"]}`, false},
		{"unknown key rejected", `{"regex":"secret","unexpected":true}`, true},
		{"invalid regex rejected", `{"regex":"("}`, true},
		{"oversized regex rejected", `{"regex":"` + strings.Repeat("a", policySuggestionMaxRegexBytes+1) + `"}`, true},
		{"multiple matchers rejected", `{"regex":"secret","keywords":["secret"]}`, true},
		{"empty matcher rejected", `{"keywords":[]}`, true},
		{"empty object rejected", `null`, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var raw json.RawMessage = []byte(tt.payload)
			_, err := decodePolicySuggestionPayload(raw)
			if (err != nil) != tt.wantErr {
				t.Fatalf("err=%v wantErr=%v", err, tt.wantErr)
			}
		})
	}
}
