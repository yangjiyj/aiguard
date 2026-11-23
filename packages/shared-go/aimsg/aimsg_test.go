package aimsg

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

func TestContentSHA256HexMatchesStdlib(t *testing.T) {
	content := "GWTEST-P1C 用户正文"
	sum := sha256.Sum256([]byte(content))
	want := hex.EncodeToString(sum[:])
	if got := ContentSHA256Hex(content); got != want {
		t.Fatalf("ContentSHA256Hex = %q, want %q", got, want)
	}
}

func TestNewConvMessageFillsSHA(t *testing.T) {
	m := newConvMessage("user", SourceUser, "hello world")
	if m.Role != "user" || m.Source != SourceUser || m.Content != "hello world" {
		t.Fatalf("unexpected ConvMessage: %+v", m)
	}
	if m.ContentSHA256 != ContentSHA256Hex("hello world") {
		t.Fatalf("ContentSHA256 未按 Content 计算: %+v", m)
	}
}

func TestFlattenMessagesJoinsNonEmptyInOrder(t *testing.T) {
	msgs := []ConvMessage{
		newConvMessage("system", SourceSystemPrompt, "系统提示词"),
		newConvMessage("user", SourceUser, "  "),
		newConvMessage("user", SourceUser, "用户正文"),
	}
	if got := FlattenMessages(msgs); got != "系统提示词\n用户正文" {
		t.Fatalf("FlattenMessages = %q", got)
	}
}
