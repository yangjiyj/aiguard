package handler

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func TestRetainedProviderErrorMessageRedactsAndBounds(t *testing.T) {
	secret := "sk-" + strings.Repeat("x", 40)
	result := retainedProviderErrorMessage("provider capacity unavailable Authorization: Bearer " + secret + "\n" + strings.Repeat("中文", 600))
	if strings.Contains(result, secret) || strings.Contains(result, "\n") || !utf8.ValidString(result) || len([]rune(result)) > 515 {
		t.Fatalf("unsafe diagnostic: %q", result)
	}
	if !strings.Contains(result, "provider capacity unavailable") {
		t.Fatal("lost useful diagnostic")
	}
}
