package handler

import (
	"github.com/yangjiyj/aiguard/packages/shared-go/aimsg"
	"testing"
)

func TestWorkBuddyForwardProxyPreservesTask(t *testing.T) {
	envelope := `<system-reminder data-role="user-context"><user_info>
Workspace Folder: /Users/test/WorkBuddy/task-one
</user_info><product_identity>You are WorkBuddy, a powerful AI assistant.</product_identity></system-reminder><user_query>first</user_query>`
	messages := []ConvMessage{{Source: aimsg.SourceSystemPrompt, Content: "You are Codex."}, {Source: aimsg.SourceUser, Content: envelope}}
	if got := inferStructuredAgentType(messages); got != "workbuddy" {
		t.Fatal(got)
	}
	first := workBuddyProxyTaskID("tenant-test", messages)
	if first == "" {
		t.Fatal("missing task")
	}
	messages = append(messages, ConvMessage{Source: aimsg.SourceUser, Content: "follow-up"})
	if workBuddyProxyTaskID("tenant-test", messages) != first {
		t.Fatal("task split")
	}
	if workBuddyProxyTaskID("another-tenant", messages) == first {
		t.Fatal("tenant isolation lost")
	}
	if workBuddyProxyTaskID("tenant-test", []ConvMessage{{Source: aimsg.SourceUser, Content: "I use WorkBuddy"}}) != "" {
		t.Fatal("ordinary query creates task")
	}
}
