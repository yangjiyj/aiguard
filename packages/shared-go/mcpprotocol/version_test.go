package mcpprotocol

import (
	"strings"
	"testing"
)

func TestSupportedVersionsOrderedNewestFirst(t *testing.T) {
	want := []string{"2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"}
	got := SupportedVersions()
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("supported=%v want=%v", got, want)
	}
	if Latest != want[0] || DefaultAssumedWhenHeaderAbsent != "2025-03-26" {
		t.Fatalf("latest=%q default=%q", Latest, DefaultAssumedWhenHeaderAbsent)
	}
	got[0] = "tampered"
	if SupportedVersions()[0] != Latest {
		t.Fatal("SupportedVersions must return a copy")
	}
}

func TestIsSupported(t *testing.T) {
	for _, v := range []string{"2025-11-25", " 2025-06-18 ", "2025-03-26", "2024-11-05"} {
		if !IsSupported(v) {
			t.Fatalf("%q must be supported", v)
		}
	}
	for _, v := range []string{"", "2023-01-01", "2099-01-01", "garbage"} {
		if IsSupported(v) {
			t.Fatalf("%q must be rejected", v)
		}
	}
}

func TestUnsupportedErrorMentionsBothSides(t *testing.T) {
	msg := UnsupportedError("2023-01-01").Error()
	want := "MCP 协议版本不受支持：服务端返回 \"2023-01-01\"，客户端支持 [2025-11-25, 2025-06-18, 2025-03-26, 2024-11-05]"
	if msg != want {
		t.Fatalf("got %q", msg)
	}
}

func TestAllowsBatch(t *testing.T) {
	if !AllowsBatch("2025-03-26") || AllowsBatch("2025-06-18") || AllowsBatch("2024-11-05") || AllowsBatch("2025-11-25") {
		t.Fatal("only 2025-03-26 allows batch")
	}
}

func TestNegotiate(t *testing.T) {
	cases := []struct {
		in      string
		wantEff string
		forward bool
		wantErr bool
	}{
		{"2025-11-25", "2025-11-25", false, false},
		{"2024-11-05", "2024-11-05", false, false},
		{" 2025-06-18 ", "2025-06-18", false, false},
		{"2099-01-01", Latest, true, false},
		{"2025-11-26", Latest, true, false},
		{"1999-01-01", "", false, true},
		{"2023-01-01", "", false, true},
		{"2025-01-15", "", false, true}, // 介于已知版本之间的未知版本：保持原有拒绝行为
		{"", "", false, true},
		{"2099-1-1", "", false, true},
		{"2099-13-01", "", false, true},
		{"garbage", "", false, true},
	}
	for _, c := range cases {
		got, err := Negotiate(c.in)
		if (err != nil) != c.wantErr {
			t.Fatalf("%q err=%v wantErr=%v", c.in, err, c.wantErr)
		}
		if err != nil {
			if !strings.Contains(err.Error(), "客户端支持") {
				t.Fatalf("%q error must list client versions: %v", c.in, err)
			}
			continue
		}
		if got.Effective != c.wantEff || got.Forward != c.forward || got.Raw != strings.TrimSpace(c.in) {
			t.Fatalf("%q => %+v", c.in, got)
		}
	}
}
