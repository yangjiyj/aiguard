package aimsg

import (
	"github.com/yangjiyj/aiguard/packages/shared-go/inspectionscope"
	"testing"
)

func longAgentTask() []ConvMessage {
	messages := []ConvMessage{{Role: "user", Source: SourceUser, Content: "完成代码审查"}}
	for i := 0; i < 200; i++ {
		messages = append(messages, ConvMessage{Role: "assistant", Source: SourceAssistantHistory, Content: "tool call"}, ConvMessage{Role: "tool", Source: SourceToolResult, Content: "earlier result"})
	}
	messages = append(messages, ConvMessage{Role: "assistant", Source: SourceAssistantHistory, Content: "latest parallel tool calls"}, ConvMessage{Role: "tool", Source: SourceToolResult, Content: "current one"}, ConvMessage{Role: "tool", Source: SourceToolResult, Content: "current two"})
	return messages
}

func TestAgentTaskWithoutNewUserOnlyInspectsLatestToolBatch(t *testing.T) {
	messages := longAgentTask()
	selected := SelectInspectionMessages(messages, inspectionscope.Default())
	if len(selected) != 3 || selected[0].Source != SourceUser || selected[1].Content != "current one" || selected[2].Content != "current two" {
		t.Fatalf("wanted latest user and both current tool replies; got %#v", selected)
	}
	policy := inspectionscope.Default()
	policy.InspectHistory = true
	if got := len(SelectInspectionMessages(messages, policy)); got != len(messages) {
		t.Fatalf("history enabled: selected %d of %d", got, len(messages))
	}
	unknown := ConvMessage{Source: SourceUnknown, Content: "unrecognized input"}
	messages = append([]ConvMessage{unknown}, messages...)
	if SelectInspectionMessages(messages, inspectionscope.Default())[0].Source != SourceUnknown {
		t.Fatal("unknown provenance was dropped as history")
	}
}

func BenchmarkSelectLongAgentTask(b *testing.B) {
	messages := longAgentTask()
	policy := inspectionscope.Default()
	b.ReportMetric(float64(len(messages)), "messages/request")
	b.ReportMetric(float64(len(SelectInspectionMessages(messages, policy))), "inspection_targets/request")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		SelectInspectionMessages(messages, policy)
	}
}
