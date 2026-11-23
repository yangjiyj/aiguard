package handler

import (
	"testing"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/auth"
)

func TestRefineChatAgentAttributionRecognizesWorkBuddyGenericMain(t *testing.T) {
	info := &auth.AuthInfo{AgentType: "main", AgentDetectionSource: "client_header"}
	messages := []Message{{
		Role: "user",
		Content: jsonQuote(`<system-reminder data-role="user-context">
<user_info>Workspace Folder: /Users/test/WorkBuddy/task</user_info>
</system-reminder>
<user_query>真实问题</user_query>`),
	}}
	refineChatAgentAttribution(info, messages)
	if info.AgentType != "workbuddy" || info.AgentDetectionSource != "message_protocol" || info.AgentDetectionConfidence != protocolAgentDetectionConfidence {
		t.Fatalf("WorkBuddy attribution = %#v", info)
	}
}

func TestRefineChatAgentAttributionRecognizesCodeBuddyGenericMain(t *testing.T) {
	info := &auth.AuthInfo{AgentType: "main"}
	messages := []Message{{
		Role:    "system",
		Content: jsonQuote("You are Tencent Cloud CodeBuddy, the AI coding assistant."),
	}}
	refineChatAgentAttribution(info, messages)
	if info.AgentType != "codebuddy" {
		t.Fatalf("CodeBuddy attribution = %#v", info)
	}
}

func TestRefineChatAgentAttributionUsesTrustedSystemPrompt(t *testing.T) {
	info := &auth.AuthInfo{}
	messages := []Message{
		{Role: "system", Content: jsonQuote("You are Cline, an autonomous coding agent.")},
		{Role: "user", Content: jsonQuote("普通问题")},
	}
	refineChatAgentAttribution(info, messages)
	if info.AgentType != "cline" {
		t.Fatalf("Cline attribution = %#v", info)
	}
}

func TestRefineChatAgentAttributionUsesSpecificTrustedIdentityAndRejectsSubstring(t *testing.T) {
	for _, tc := range []struct {
		name, prompt, want string
	}{
		{
			name:   "decline is not cline",
			prompt: "You must decline unsafe requests and explain the policy.",
			want:   "main",
		},
		{
			name:   "codebuddy identity beats workbuddy and cline mentions",
			prompt: "You are Tencent Cloud CodeBuddy. WorkBuddy and Cline are other supported clients.",
			want:   "codebuddy",
		},
		{
			name:   "workbuddy identity beats codebuddy and vscode mentions",
			prompt: "You are WorkBuddy. Tencent Cloud CodeBuddy is separate, and the workspace may be open in Visual Studio Code.",
			want:   "workbuddy",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			info := &auth.AuthInfo{AgentType: "main"}
			refineChatAgentAttribution(info, []Message{{Role: "system", Content: jsonQuote(tc.prompt)}})
			if info.AgentType != tc.want {
				t.Fatalf("attribution = %#v, want %q", info, tc.want)
			}
		})
	}
}

func TestRefineChatAgentAttributionReadsOnlyMachinePartOfTrustedUserEnvelope(t *testing.T) {
	info := &auth.AuthInfo{AgentType: "main"}
	messages := []Message{{
		Role: "user",
		Content: jsonQuote(`<system-reminder data-role="user-context">
<user_info>Workspace Folder: /Users/test/WorkBuddy/task</user_info>
</system-reminder>
<user_query>Please compare CodeBuddy and Cline.</user_query>`),
	}}
	refineChatAgentAttribution(info, messages)
	if info.AgentType != "workbuddy" {
		t.Fatalf("human query overrode structured machine identity: %#v", info)
	}
}

func TestRefineChatAgentAttributionDoesNotOverrideExplicitOrTrustPlainUserText(t *testing.T) {
	explicit := &auth.AuthInfo{AgentType: "openai-codex", AgentDetectionSource: "explicit_header", AgentDetectionConfidence: 1}
	refineChatAgentAttribution(explicit, []Message{{Role: "system", Content: jsonQuote("You are Cline")}})
	if explicit.AgentType != "openai-codex" || explicit.AgentDetectionSource != "explicit_header" {
		t.Fatalf("explicit attribution was overwritten: %#v", explicit)
	}

	plain := &auth.AuthInfo{AgentType: "main"}
	refineChatAgentAttribution(plain, []Message{{Role: "user", Content: jsonQuote("请解释 WorkBuddy 是什么")}})
	if plain.AgentType != "main" {
		t.Fatalf("plain user text spoofed attribution: %#v", plain)
	}

	partialEnvelope := &auth.AuthInfo{AgentType: "main"}
	refineChatAgentAttribution(partialEnvelope, []Message{{
		Role:    "user",
		Content: jsonQuote(`<system-reminder data-role="user-context"><user_info>WorkBuddy</user_info></system-reminder>`),
	}})
	if partialEnvelope.AgentType != "main" {
		t.Fatalf("unrecognized partial user envelope spoofed attribution: %#v", partialEnvelope)
	}
}
