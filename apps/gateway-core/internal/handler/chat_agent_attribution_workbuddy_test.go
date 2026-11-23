package handler

import (
	"net/http"
	"testing"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/auth"
	"github.com/yangjiyj/aiguard/packages/shared-go/agentdetect"
)

func TestWorkBuddyUserAgentBeatsPromptContentInference(t *testing.T) {
	prompts := []string{
		"You are Claude Code, Anthropic's official CLI. Also compatible with Codex CLI.",
		"You are Codex CLI. Claude Code docs follow.",
		"Claude Code and Codex CLI are mentioned here.",
	}
	for _, role := range []string{"main", "auxiliary", "compaction"} {
		for _, prompt := range prompts {
			h := http.Header{"User-Agent": {"WorkBuddy/5.9.3 WorkBuddy/5.9.3 CLI/2.165.0"}, "X-Agent-Type": {role}}
			d, err := agentdetect.DetectFromHeaders(h)
			if err != nil {
				t.Fatal(err)
			}
			info := &auth.AuthInfo{AgentType: d.Product, AgentDetectionSource: d.Source, AgentDetectionConfidence: d.Confidence}
			refineChatAgentAttribution(info, []Message{{Role: "system", Content: jsonQuote(prompt)}, {Role: "user", Content: jsonQuote("hi")}})
			if info.AgentType != "workbuddy" || info.AgentDetectionSource != "user_agent" {
				t.Fatalf("role=%s prompt=%q -> %q/%q", role, prompt, info.AgentType, info.AgentDetectionSource)
			}
		}
	}
}

func TestGenericUserAgentStillUsesMessageProtocol(t *testing.T) {
	d, _ := agentdetect.DetectFromHeaders(http.Header{"User-Agent": {"Go-http-client/1.1"}, "X-Agent-Type": {"main"}})
	info := &auth.AuthInfo{AgentType: d.Product, AgentDetectionSource: d.Source}
	refineChatAgentAttribution(info, []Message{{Role: "system", Content: jsonQuote("You are Claude Code, Anthropic's official CLI for Claude.")}})
	if info.AgentType != "claude-code" || info.AgentDetectionSource != "message_protocol" {
		t.Fatalf("%q/%q", info.AgentType, info.AgentDetectionSource)
	}
}
