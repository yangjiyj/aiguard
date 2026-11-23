package aiconvo

import (
	"strings"
	"testing"
)

// claudeCodeSystemPrompt 拟真 Claude Code system prompt：指令正文 + 易变尾巴（日期/gitStatus/system-reminder）。
func claudeCodeSystemPrompt(date, branch, reminder string) string {
	return strings.Join([]string{
		"You are Claude Code, Anthropic's official CLI for Claude.",
		"You are an interactive CLI tool that helps users with software engineering tasks.",
		"<system-reminder>" + reminder + "</system-reminder>",
		"# Tone and style",
		"You should be concise, direct, and to the point.",
		"Today's date is " + date + ".",
		"gitStatus: This is the git status at the start of the conversation.",
		"Current branch: " + branch,
		"Status:\n(clean)",
		"Recent commits:\nabc1234 feat: something",
	}, "\n")
}

func TestSystemDigestStableAcrossVolatileLines(t *testing.T) {
	day1 := claudeCodeSystemPrompt("2026-07-04", "main", "今日技能列表 A")
	day2 := claudeCodeSystemPrompt("2026-07-05", "feature/x", "今日技能列表 B")
	if SystemDigest(day1) != SystemDigest(day2) {
		t.Fatalf("同一 Claude Code system prompt 跨日 digest 应稳定:\nday1=%s\nday2=%s\n归一化1=%q\n归一化2=%q",
			SystemDigest(day1), SystemDigest(day2), NormalizeSystemPrompt(day1), NormalizeSystemPrompt(day2))
	}
}

func TestSystemDigestChangesWhenInstructionsChange(t *testing.T) {
	a := claudeCodeSystemPrompt("2026-07-04", "main", "r")
	b := strings.Replace(a, "concise, direct", "verbose, indirect", 1)
	if SystemDigest(a) == SystemDigest(b) {
		t.Fatal("指令正文变化必须改变 digest")
	}
}

func TestNormalizeStripsSystemReminderAndGitStatus(t *testing.T) {
	got := NormalizeSystemPrompt(claudeCodeSystemPrompt("2026-07-04", "main", "秘密动态内容"))
	for _, banned := range []string{"秘密动态内容", "2026-07-04", "gitStatus:", "Current branch", "Recent commits"} {
		if strings.Contains(got, banned) {
			t.Fatalf("归一化结果不应含易变内容 %q，got=%q", banned, got)
		}
	}
	if !strings.Contains(got, "You are Claude Code") {
		t.Fatalf("归一化不应剥掉指令正文，got=%q", got)
	}
}

func TestContentSHA256KnownVector(t *testing.T) {
	// sha256("") 标准向量
	if got := ContentSHA256(""); got != "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" {
		t.Fatalf("ContentSHA256(\"\") = %s", got)
	}
}

func TestConversationKey(t *testing.T) {
	k1 := ConversationKey("t1", "key_a", "claude-code", "digest1", "usersha1")
	if !strings.HasPrefix(k1, "ck_") || len(k1) != 3+32 {
		t.Fatalf("键形态应为 ck_+32hex, got=%q", k1)
	}
	if k1 != ConversationKey("t1", "key_a", "claude-code", "digest1", "usersha1") {
		t.Fatal("同参必须稳定")
	}
	for _, k2 := range []string{
		ConversationKey("t2", "key_a", "claude-code", "digest1", "usersha1"),
		ConversationKey("t1", "key_b", "claude-code", "digest1", "usersha1"),
		ConversationKey("t1", "key_a", "opencode", "digest1", "usersha1"),
		ConversationKey("t1", "key_a", "claude-code", "digest2", "usersha1"),
		ConversationKey("t1", "key_a", "claude-code", "digest1", "usersha2"),
	} {
		if k1 == k2 {
			t.Fatalf("任一分量变化都应改变键, 撞上=%q", k2)
		}
	}
	if ConversationKey("", "key_a", "claude-code", "d", "u") != "" {
		t.Fatal("无租户返回空（不归组）")
	}
}
