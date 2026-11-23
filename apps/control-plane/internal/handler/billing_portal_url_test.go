package handler

import "testing"

func TestNormalizePortalGatewayURL(t *testing.T) {
	tests := map[string]string{
		"http://gateway.test:8080":       "http://gateway.test:8080/v1",
		"http://gateway.test:8080/v1/":   "http://gateway.test:8080/v1",
		"http://gateway.test:8080/v1/v1": "http://gateway.test:8080/v1",
		"https://gateway.test/base":      "https://gateway.test/base/v1",
		"not-a-url":                      "",
		"":                               "",
	}
	for input, want := range tests {
		if got := normalizePortalGatewayURL(input); got != want {
			t.Errorf("normalizePortalGatewayURL(%q)=%q want %q", input, got, want)
		}
	}
}
