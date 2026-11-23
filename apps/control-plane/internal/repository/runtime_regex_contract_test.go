package repository

import (
	"strings"
	"testing"
)

func TestIsSafeRuntimeRegexMatchesEngineContract(t *testing.T) {
	tests := []struct {
		name    string
		pattern string
		want    bool
	}{
		{name: "empty", pattern: "", want: false},
		{name: "at byte limit", pattern: strings.Repeat("a", MaxRuntimeRegexPatternBytes), want: true},
		{name: "over byte limit", pattern: strings.Repeat("a", MaxRuntimeRegexPatternBytes+1), want: false},
		{name: "nested quantifier", pattern: "(a+)+$", want: false},
		{name: "ambiguous repeated alternation", pattern: "(a|aa)+$", want: false},
		{name: "python lookahead", pattern: "(?=abc)abc", want: true},
		// 自定义正则大小写不敏感用内联标志，引擎（Python regex 库）按原样编译执行。
		{name: "inline ignorecase flag", pattern: `(?i)cus-\d{5}`, want: true},
		{name: "scoped ignorecase group", pattern: `(?i:cus)-\d{5}`, want: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsSafeRuntimeRegex(tc.pattern); got != tc.want {
				t.Fatalf("IsSafeRuntimeRegex(%q) = %v, want %v", tc.pattern, got, tc.want)
			}
		})
	}
}

func TestMaxRuntimeRegexPatternBytesIsEngineLimit(t *testing.T) {
	const engineMaxPatternLen = 1000
	if MaxRuntimeRegexPatternBytes != engineMaxPatternLen {
		t.Fatalf(
			"MaxRuntimeRegexPatternBytes = %d, want engine limit %d",
			MaxRuntimeRegexPatternBytes,
			engineMaxPatternLen,
		)
	}
}
