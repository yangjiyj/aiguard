package permission

import (
	"strings"
	"testing"
	"unicode/utf8"
)

// Regression (2026-10-01): permission.denied audit rows were silently lost
// because audit_operations.target_id is varchar(64) and deep evidence routes
// (e.g. /admin/v1/audit/access-retention/{id}/content) exceed 64 bytes.
func TestTruncateAuditTarget(t *testing.T) {
	tests := []struct {
		name string
		in   string
	}{
		{"short", "/admin/v1/login"},
		{"exactly64", "/" + strings.Repeat("a", 63)},
		{"long ascii route", "/admin/v1/audit/access-retention/1d68c306-8cb2-4c5e-beec-017772b79b2a/content"},
		{"long artifact route", "/admin/v1/audit/access-retention/{request_id}/artifacts/{artifact_id}/original"},
		{"long multibyte", "/admin/v1/audit/" + strings.Repeat("\u7559\u8bc1", 40)},
		{"empty", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := truncateAuditTarget(tt.in)
			if len(got) > 64 {
				t.Fatalf("len=%d exceeds 64 bytes", len(got))
			}
			if !utf8.ValidString(got) {
				t.Fatalf("result is not valid UTF-8: %q", got)
			}
			if len(tt.in) <= 64 && got != tt.in {
				t.Fatalf("short input must be returned unchanged: got %q want %q", got, tt.in)
			}
			if len(tt.in) > 64 {
				if !strings.HasPrefix(tt.in, got) {
					t.Fatalf("result must be a prefix of input: got %q", got)
				}
				if got == tt.in {
					t.Fatalf("long input must be truncated")
				}
			}
		})
	}
}
