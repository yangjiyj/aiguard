package repository

import (
	"regexp"
	"testing"
)

func TestNewToolCallLogIDUsesNinetySixBitsOfRandomness(t *testing.T) {
	t.Parallel()

	id := newToolCallLogID()
	if matched := regexp.MustCompile(`^tc_[0-9a-f]{24}$`).MatchString(id); !matched {
		t.Fatalf("tool call log ID must contain 24 lowercase hex characters, got %q", id)
	}
	if next := newToolCallLogID(); next == id {
		t.Fatalf("consecutive tool call log IDs must differ, got %q twice", id)
	}
}
