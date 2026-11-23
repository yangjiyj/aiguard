package aimsg

import "testing"

func TestAgentRequestKindRecognizesClaudeCodeSecurityMonitor(t *testing.T) {
	monitor := []ConvMessage{
		{Role: "system", Source: SourceSystemPrompt, Content: "x-anthropic-billing-header: cc_version=2.1"},
		{Role: "system", Source: SourceSystemPrompt, Content: "\n You are a security monitor for autonomous AI coding agents. Decide ..."},
		{Role: "user", Source: SourceUser, Content: "<transcript>../../etc/passwd</transcript>"},
	}
	for _, agentType := range []string{"claude-code", "Claude_Code", " claude-code "} {
		if got := AgentRequestKind(agentType, monitor); got != AgentRequestKindClaudeCodeSecurityMonitor {
			t.Fatalf("agentType %q: got %q", agentType, got)
		}
	}
}

func TestAgentRequestKindRejectsOtherShapes(t *testing.T) {
	header := "You are a security monitor for autonomous AI coding agents."
	cases := map[string]struct {
		agentType string
		messages  []ConvMessage
	}{
		"other client":        {"cursor", []ConvMessage{{Source: SourceSystemPrompt, Content: header}}},
		"no client type":      {"", []ConvMessage{{Source: SourceSystemPrompt, Content: header}}},
		"header in user turn": {"claude-code", []ConvMessage{{Source: SourceUser, Content: header}}},
		"header not at start": {"claude-code", []ConvMessage{{Source: SourceSystemPrompt, Content: "Note. " + header}}},
		"plain session":       {"claude-code", []ConvMessage{{Source: SourceSystemPrompt, Content: "You are Claude Code."}}},
	}
	for name, tc := range cases {
		if got := AgentRequestKind(tc.agentType, tc.messages); got != "" {
			t.Fatalf("%s: got %q, want empty", name, got)
		}
	}
}
