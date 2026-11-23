package filerestrict

import (
	"strings"
	"testing"
	"unicode/utf8"
)

// 与网关 agentguard 的文件类防护项例外口径一致（批次 1）：按路径层级、不做 URL 解码、区分大小写。
func TestExceptionTargetMatchesFollowsPathHierarchy(t *testing.T) {
	for _, tc := range []struct {
		pattern, raw string
		want         bool
	}{
		{"", "/any/file", true},
		{"plan.docx", "/data/x/plan.docx", true},
		{"plan.docx", "/data/x/myplan.docx", false},
		{"Plan.docx", "/data/x/plan.docx", false},
		{"/data/x/", "/data/x/plan.docx", true},
		{"/data/x/", "/data/xy/plan.docx", false},
		{"x/", "/data/x/plan.docx", true},
		{"x/plan.docx", "/data/x/plan.docx", true},
		{"x/plan.docx", "/data/xx/plan.docx", false},
		{"/data/x/plan.docx", "/data/x/../x/plan.docx", true},
		{"/data/x/", "/data/x/../y/plan.docx", false},
		{"plan.docx", "/data/a%2fb/plan.docx", false},
		{"plan.docx", "../plan.docx", false},
		{"~/.ssh/", `~\.ssh\id_rsa`, true},
	} {
		if got := ExceptionTargetMatches(tc.pattern, ExceptionTarget(tc.raw)); got != tc.want {
			t.Errorf("pattern=%q raw=%q got %v want %v", tc.pattern, tc.raw, got, tc.want)
		}
	}
}

// 合流（批次 1 网关口径 + 2A 收尾）后的唯一实现，表驱动用例集中在这里；网关 agentguard 只留端到端用例。
// 只有写在开头的 ~/ 是家目录：~/ 下折叠，越过 ~ 的（~/../x）落不到确定文件；相对路径折叠后才变成
// ~/ 开头或等于 ~ 的（x/../~/a、./~/a）也落不到确定文件。含 %、越出根目录的同样返回空串。
func TestExceptionTargetTildeIsHomeOnlyAsLiteralPrefix(t *testing.T) {
	for raw, want := range map[string]string{
		"~/allowed/b.docx":        "~/allowed/b.docx",
		"~/a/../allowed/b.docx":   "~/allowed/b.docx",
		"~/a/../b":                "~/b",
		"~/./.ssh/id_rsa":         "~/.ssh/id_rsa",
		`~\.ssh\id_rsa`:           "~/.ssh/id_rsa",
		"~/../~/.ssh/id_rsa":      "",
		"~/..":                    "",
		"~/../x":                  "",
		"x/../~/allowed/b.docx":   "",
		"./~/allowed/b.docx":      "",
		`x\..\~\allowed\b.docx`:   "",
		"a/..":                    "",
		"a/../~":                  "",
		"/srv/app/./allowed/b.md": "/srv/app/allowed/b.md",
		"/data/a%2fb/plan.docx":   "",
		"../plan.docx":            "",
		"  ":                      "",
	} {
		if got := ExceptionTarget(raw); got != want {
			t.Errorf("ExceptionTarget(%q) = %q, want %q", raw, got, want)
		}
	}
}

// 目录型例外（/ 结尾）匹配目录本身（打包整个目录）和其下的路径，按路径段边界；相对目录匹配任意层级上的同名目录。
func TestExceptionTargetMatchesDirectoryItself(t *testing.T) {
	for _, tc := range []struct {
		pattern, target string
		want            bool
	}{
		{"~/.ssh/", "~/.ssh", true},
		{"~/.ssh/", "~/.ssh/id_rsa", true},
		{"~/.ssh/", "~/.sshx", false},
		{"/data/x/", "/data/x", true},
		{"/data/x/", "/data/xy", false},
		{"x/", "/srv/x", true},
		{"x/", "x", true},
		{"x/", "/srv/xx", false},
		{"x/", "/srv/x/a", true},
		{"/data/x/", "", false},
		{"", "", true},
	} {
		if got := ExceptionTargetMatches(tc.pattern, tc.target); got != tc.want {
			t.Errorf("ExceptionTargetMatches(%q, %q) = %v, want %v", tc.pattern, tc.target, got, tc.want)
		}
	}
}

// 证据里的字面写法：不解码、不折叠，截到 MaxLiteralPathBytes，不切断多字节字符。
func TestLiteralPathKeepsRawSpellingAndTruncatesOnRuneBoundary(t *testing.T) {
	if got := LiteralPath("  /srv/app/%2e%2e/.env "); got != "/srv/app/%2e%2e/.env" {
		t.Fatalf("literal=%q", got)
	}
	long := strings.Repeat("a", MaxLiteralPathBytes-1) + "密钥"
	got := LiteralPath(long)
	if len(got) != MaxLiteralPathBytes-1 || !utf8.ValidString(got) {
		t.Fatalf("truncated literal must stop before a split rune: len=%d valid=%v", len(got), utf8.ValidString(got))
	}
}
