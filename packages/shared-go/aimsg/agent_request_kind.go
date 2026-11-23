package aimsg

import "strings"

// AgentRequestKindClaudeCodeSecurityMonitor marks Claude Code's auto-mode
// security monitor request. Its user message replays the session transcript
// (already inspected when the session sent it) for a safety classification.
const AgentRequestKindClaudeCodeSecurityMonitor = "claude_code_security_monitor"

const claudeCodeSecurityMonitorHeader = "You are a security monitor for autonomous AI coding agents"

// AgentRequestKind recognizes agent-internal requests from the normalized
// client type and a fixed system prompt header. It never changes a message's
// source or inspection scope: the engine only treats keyword-combination
// findings in such a request as evidence. Unknown shapes return "".
func AgentRequestKind(agentType string, messages []ConvMessage) string {
	normalized := strings.ReplaceAll(strings.ToLower(strings.TrimSpace(agentType)), "_", "-")
	if normalized != "claude-code" {
		return ""
	}
	for _, message := range messages {
		if message.Source != SourceSystemPrompt {
			continue
		}
		if strings.HasPrefix(strings.TrimLeft(message.Content, " \t\r\n"), claudeCodeSecurityMonitorHeader) {
			return AgentRequestKindClaudeCodeSecurityMonitor
		}
	}
	return ""
}
