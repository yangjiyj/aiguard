package handler

import (
	"encoding/json"
	"testing"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
)

func ckMsg(role, text string) Message {
	quoted, _ := json.Marshal(text)
	return Message{Role: role, Content: json.RawMessage(quoted)}
}

func ckEnvelope() *modelrouter.RequestEnvelope {
	return &modelrouter.RequestEnvelope{TenantID: "tenant_default", ClientID: "key_abc", AgentType: "claude-code"}
}

func TestComputeConversationKeyStableAcrossVolatileSystemPrompt(t *testing.T) {
	day1 := &ChatCompletionRequest{Messages: []Message{
		ckMsg("system", "You are Claude Code.\nToday's date is 2026-07-04.\ngitStatus: xx\nCurrent branch: main"),
		ckMsg("user", "帮我修这个 bug"),
	}}
	day2 := &ChatCompletionRequest{Messages: []Message{
		ckMsg("system", "You are Claude Code.\nToday's date is 2026-07-05.\ngitStatus: yy\nCurrent branch: feat/z"),
		ckMsg("user", "帮我修这个 bug"),
	}}
	k1, k2 := computeConversationKey(ckEnvelope(), day1), computeConversationKey(ckEnvelope(), day2)
	if k1 == "" || k1 != k2 {
		t.Fatalf("同会话跨日键应稳定: %q vs %q", k1, k2)
	}
}

func TestComputeConversationKeyDiffersByFirstUserMessage(t *testing.T) {
	a := &ChatCompletionRequest{Messages: []Message{ckMsg("system", "S"), ckMsg("user", "问题A")}}
	b := &ChatCompletionRequest{Messages: []Message{ckMsg("system", "S"), ckMsg("user", "问题B")}}
	if computeConversationKey(ckEnvelope(), a) == computeConversationKey(ckEnvelope(), b) {
		t.Fatal("不同首条 user 消息必须产生不同键")
	}
}

func TestComputeConversationKeyEmptyWhenNoUserMessage(t *testing.T) {
	req := &ChatCompletionRequest{Messages: []Message{ckMsg("system", "only system")}}
	if got := computeConversationKey(ckEnvelope(), req); got != "" {
		t.Fatalf("无 user 消息应返回空（计数回退 request_id）, got=%q", got)
	}
	if got := computeConversationKey(nil, req); got != "" {
		t.Fatalf("nil envelope 应返回空, got=%q", got)
	}
}

func TestClineConversationKeyStableAndKeyScoped(t *testing.T) {
	envelope := ckEnvelope()
	envelope.AgentType = "cline"
	request := func(mode string) *ChatCompletionRequest {
		return &ChatCompletionRequest{Messages: []Message{ckMsg("user", "<task>检查项目</task>\n\n# task_progress RECOMMENDED\n<environment_details>\n"+mode+"\n</environment_details>")}}
	}
	first := computeConversationKey(envelope, request("ACT MODE"))
	if first != computeConversationKey(envelope, request("PLAN MODE")) {
		t.Fatal("dynamic context split")
	}
	envelope.ClientID = "another-api-key"
	if first == computeConversationKey(envelope, request("ACT MODE")) {
		t.Fatal("different API keys merged")
	}
}

func TestAgentAPIKeyConversationHistoryAndIsolation(t *testing.T) {
	for _, agent := range []string{"cline", "github-copilot"} {
		t.Run(agent, func(t *testing.T) {
			env := ckEnvelope()
			env.AgentType = agent
			first := &ChatCompletionRequest{Messages: []Message{ckMsg("user", "分析图片")}}
			later := &ChatCompletionRequest{Messages: []Message{ckMsg("user", "分析图片"), ckMsg("assistant", "图片说明"), ckMsg("user", "继续")}}
			key := computeConversationKey(env, first)
			if key == "" || key != computeConversationKey(env, later) {
				t.Fatal("history split")
			}
			env.ClientID = "different-key"
			if key == computeConversationKey(env, later) {
				t.Fatal("keys merged")
			}
		})
	}
}
