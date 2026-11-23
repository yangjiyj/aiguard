package notify

import (
	"testing"
)

func TestSendEmail_InvalidConfig(t *testing.T) {
	// host empty → error
	err := SendEmail(EmailConfig{To: []string{"test@example.com"}}, "subj", "body")
	if err == nil {
		t.Error("expected error for empty host")
	}

	// to empty → error
	err = SendEmail(EmailConfig{Host: "smtp.example.com"}, "subj", "body")
	if err == nil {
		t.Error("expected error for empty to list")
	}
}

func TestSendEmail_DefaultPort(t *testing.T) {
	// Default port should be set to 25 internally; the only way to verify
	// without actually connecting is that the function doesn't crash on
	// config validation. Real connection is not attempted in unit tests.
	cfg := EmailConfig{
		Host: "unreachable.invalid",
		// Port intentionally 0 → should default to 25
		To:   []string{"a@b.c"},
		From: "sender@b.c",
	}
	// We expect a dial error (not a config error)
	err := SendEmail(cfg, "test", "test")
	if err == nil {
		t.Fatal("expected connection error for unreachable host")
	}
	// Must not be the config-invalid error
	if err.Error() == "email config invalid: host and to are required" {
		t.Errorf("should have passed config validation, got: %v", err)
	}
}
