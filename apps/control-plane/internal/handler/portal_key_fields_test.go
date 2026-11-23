package handler

import (
	"testing"
	"time"
)

func TestParseKeyExpiresAtAcceptsFutureRFC3339(t *testing.T) {
	future := time.Now().Add(24 * time.Hour).Format(time.RFC3339)
	got, err := parseKeyExpiresAt(future)
	if err != nil || got == nil {
		t.Fatalf("parseKeyExpiresAt(%q) = %v, %v; want future time, nil", future, got, err)
	}
}

func TestParseKeyExpiresAtRejectsPastAndGarbage(t *testing.T) {
	for _, raw := range []string{"2020-01-01T00:00:00Z", "not-a-time"} {
		if _, err := parseKeyExpiresAt(raw); err == nil {
			t.Fatalf("parseKeyExpiresAt(%q) should fail", raw)
		}
	}
}

func TestParseKeyExpiresAtEmptyMeansNil(t *testing.T) {
	got, err := parseKeyExpiresAt("")
	if err != nil || got != nil {
		t.Fatalf("empty expires_at should be (nil, nil), got %v, %v", got, err)
	}
}

func TestNormalizeKeyNameTrimsAndLimitsRunes(t *testing.T) {
	got, err := normalizeKeyName("  张三/研发部  ")
	if err != nil {
		t.Fatal("valid name rejected")
	}
	if got != "张三/研发部" {
		t.Fatalf("normalizeKeyName should trim spaces, got %q", got)
	}

	exact := make([]rune, 128)
	for i := range exact {
		exact[i] = '名'
	}
	if _, err := normalizeKeyName(string(exact)); err != nil {
		t.Fatal("128-rune name should pass (boundary)")
	}

	long := append(exact, '名')
	if _, err := normalizeKeyName(string(long)); err == nil {
		t.Fatal("129-rune name should fail")
	}
}

func TestNormalizeKeyNameRejectsControlChars(t *testing.T) {
	// name 会出现在 key 列表与审计追溯展示里，控制字符可伪造多行审计记录（日志注入式视觉混淆）
	for _, raw := range []string{"张三\n研发部", "tab\there", "bell\x07"} {
		if _, err := normalizeKeyName(raw); err == nil {
			t.Fatalf("normalizeKeyName(%q) should reject control chars", raw)
		}
	}
}
