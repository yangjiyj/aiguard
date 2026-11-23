package agentguard

import "testing"

func TestExceptionTargetMatchesMCPServerAndToolExactly(t *testing.T) {
	for _, tc := range []struct {
		pattern, target string
		want            bool
	}{
		{"mcp:files/read", "mcp:files/read", true},
		{"mcp:files", "mcp:files/read", true},
		{"MCP:Files", "mcp:files/read", true},
		{"mcp:files/read", "mcp:files/readall", false},
		{"mcp:file", "mcp:files/read", false},
		{"mcp:files", "mcp:files2/read", false},
		{"mcp:files/read", "/data/mcp:files/read", false},
	} {
		if got := exceptionTargetMatches(tc.pattern, tc.target, ""); got != tc.want {
			t.Errorf("pattern %q target %q = %v, want %v", tc.pattern, tc.target, got, tc.want)
		}
	}
	if !exceptionTargetMatches("secret", "/home/u/secret.txt", "") {
		t.Fatal("non-MCP patterns keep substring matching")
	}
}
