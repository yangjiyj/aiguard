package repository

import (
	"strings"
	"testing"
	"time"
)

func TestSummarizeEvidenceTimelineKeepsDistinctBehaviorTypes(t *testing.T) {
	base := time.Date(2026, 8, 5, 2, 40, 0, 0, time.UTC)
	input := []EvidenceTimelineEvent{
		{ID: "m1", Type: "model_call", Title: "模型调用", Detail: "gpt-5.6-sol", Timestamp: base},
		{ID: "m2", Type: "model_call", Title: "模型调用", Detail: "gpt-5.6-sol", Timestamp: base.Add(time.Second)},
		{ID: "t1", Type: "tool_action", Title: "执行命令", Timestamp: base.Add(2 * time.Second)},
		{ID: "m3", Type: "model_call", Title: "模型调用", Detail: "gpt-5.6-luna", Timestamp: base.Add(3 * time.Second)},
	}
	got := summarizeEvidenceTimeline(input)
	if len(got) != 2 {
		t.Fatalf("events=%+v", got)
	}
	if got[0].Type != "model_calls" || got[0].Count != 3 || got[0].Title != "模型交互" {
		t.Fatalf("first=%+v", got[0])
	}
	if got[1].Type != "tool_action" {
		t.Fatalf("tool behavior was lost: %+v", got)
	}
}

func TestSummarizeEvidenceTimelineSeparatesModelCallOutcomes(t *testing.T) {
	base := time.Date(2026, 8, 5, 2, 40, 0, 0, time.UTC)
	got := summarizeEvidenceTimeline([]EvidenceTimelineEvent{
		{ID: "m1", Type: "model_call", Title: "模型调用", Detail: "gpt-5.6-sol", Status: "success", Timestamp: base},
		{ID: "m2", Type: "model_call", Title: "模型调用", Detail: "gpt-5.6-sol", Status: "success", Timestamp: base.Add(time.Second)},
		{ID: "m3", Type: "model_call", Title: "模型调用", Detail: "gpt-5.6-sol", Status: "provider_error", Timestamp: base.Add(2 * time.Second)},
	})
	if len(got) != 2 {
		t.Fatalf("model outcomes were merged: %+v", got)
	}
	outcomes := map[string]int{}
	for _, event := range got {
		outcomes[event.Status] = event.Count
	}
	if outcomes["success"] != 2 || outcomes["failed"] != 1 {
		t.Fatalf("outcomes=%+v events=%+v", outcomes, got)
	}
}

func TestEvidenceTimelineStatusLabelsExecutionFactsConservatively(t *testing.T) {
	tests := []struct {
		event EvidenceTimelineEvent
		want  string
	}{
		{EvidenceTimelineEvent{Type: "tool_action", EventKind: "definition_exposed"}, "已暴露工具定义"},
		{EvidenceTimelineEvent{Type: "tool_action", EventKind: "invocation_proposed"}, "调用请求"},
		{EvidenceTimelineEvent{Type: "tool_action", EventKind: "execution_forwarded"}, "已转发执行"},
		{EvidenceTimelineEvent{Type: "tool_action", EventKind: "result_observed"}, "已观察结果"},
	}
	for _, tt := range tests {
		if got := evidenceTimelineFactLabel(tt.event); got != tt.want {
			t.Fatalf("kind=%s label=%q want=%q", tt.event.EventKind, got, tt.want)
		}
	}
}

func TestSummarizeEvidenceTimelineGroupsRepeatedBehavior(t *testing.T) {
	base := time.Date(2026, 8, 5, 7, 27, 0, 0, time.UTC)
	events := []EvidenceTimelineEvent{
		{ID: "m1", Type: "model_call", Title: "模型调用", Detail: "gpt-5.6-luna", Timestamp: base},
		{ID: "t1", Type: "tool_action", Title: "exec", Detail: "npm test", Status: "recorded", EventKind: "invocation_proposed", FactLabel: "调用请求", Timestamp: base.Add(time.Second)},
		{ID: "m2", Type: "model_call", Title: "模型调用", Detail: "gpt-5.6-luna", Timestamp: base.Add(2 * time.Second)},
		{ID: "t2", Type: "tool_action", Title: "exec", Detail: "npm run build", Status: "success", EventKind: "invocation_proposed", FactLabel: "调用请求", Timestamp: base.Add(3 * time.Second)},
	}

	got := summarizeEvidenceTimeline(events)
	if len(got) != 2 {
		t.Fatalf("summary=%+v", got)
	}
	if got[0].Type != "model_calls" || got[0].Count != 2 || got[0].Title != "模型交互" {
		t.Fatalf("model summary=%+v", got[0])
	}
	if got[1].Type != "tool_action" || got[1].Title != "exec" || got[1].Count != 2 {
		t.Fatalf("tool summary=%+v", got[1])
	}
	if !strings.Contains(got[1].Detail, "npm test") || !strings.Contains(got[1].Detail, "npm run build") {
		t.Fatalf("tool samples missing: %+v", got[1])
	}
	if got[1].Status != "" {
		t.Fatalf("request recording status must not imply execution: %+v", got[1])
	}
}

func TestCompactEvidenceToolInventoryKeepsWorkBuddyStyleInventoryReadable(t *testing.T) {
	names := []string{"Agent", "Bash", "Edit", "Glob", "Grep", "Read", "Write", "conversation_search", "one", "two", "three", "four", "five", "six"}
	got := compactEvidenceToolInventory(strings.Join(names, "、"), len(names))
	if !strings.Contains(got, "Agent") || !strings.Contains(got, "conversation_search") {
		t.Fatalf("visible tool names missing: %s", got)
	}
	if !strings.Contains(got, "另有 2 种工具已折叠") {
		t.Fatalf("folded tool count missing: %s", got)
	}
	if strings.Contains(got, "five") || strings.Contains(got, "six") {
		t.Fatalf("inventory was not compacted: %s", got)
	}
}

func TestEvidenceTimelineAttemptPredicateExcludesProtocolNoise(t *testing.T) {
	if !strings.Contains(evidenceTimelineAttemptPredicateSQL, "invocation_proposed") || !strings.Contains(evidenceTimelineAttemptPredicateSQL, "execution_forwarded") {
		t.Fatalf("attempt predicate missing execution facts: %s", evidenceTimelineAttemptPredicateSQL)
	}
	for _, noise := range []string{"result_observed", "definition_exposed"} {
		if strings.Contains(evidenceTimelineAttemptPredicateSQL, "= '"+noise+"'") {
			t.Fatalf("attempt predicate includes protocol noise %s: %s", noise, evidenceTimelineAttemptPredicateSQL)
		}
	}
}

func TestRetentionOutcomeDoesNotInventPolicyBlock(t *testing.T) {
	for _, tc := range []struct{ status, want string }{
		{"blocked", "请求被拒绝（具体原因未留存）"},
		{"egress_denied", "目标地址被访问控制拒绝"},
		{"target_resolution_failed", "目标域名解析失败或超时"},
		{"model_not_found", "请求的模型不存在或已停用"},
		{"success", ""}, {"in_progress", ""},
	} {
		if got := retentionOutcomeTitle(tc.status); got != tc.want {
			t.Fatalf("%s: %s", tc.status, got)
		}
	}
	events := summarizeEvidenceTimeline([]EvidenceTimelineEvent{
		{ID: "outcome:r1", RequestID: "r1", Type: "request_outcome", Title: "请求被拒绝", Count: 1},
		{ID: "outcome:r2", RequestID: "r2", Type: "request_outcome", Title: "请求被拒绝", Count: 1},
	})
	if len(events) != 2 {
		t.Fatal("exception request IDs must remain individually traceable")
	}
}
