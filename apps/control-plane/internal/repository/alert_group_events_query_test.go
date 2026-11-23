package repository

import (
	"reflect"
	"strings"
	"testing"
)

func TestBuildAlertGroupEventsQueriesGroupsByEffectiveConversation(t *testing.T) {
	countSQL, listSQL, countArgs, listArgs := buildAlertGroupEventsQueries("tenant_a", "group_a", AlertGroupEventListFilter{
		View:   AlertGroupEventViewConversations,
		Limit:  20,
		Offset: 40,
	})

	for _, fragment := range []string{
		"COUNT(DISTINCT COALESCE(NULLIF(conversation_key, ''), request_id))",
	} {
		if !strings.Contains(countSQL, fragment) {
			t.Fatalf("conversation count query missing %q:\n%s", fragment, countSQL)
		}
	}
	for _, fragment := range []string{
		"COALESCE(NULLIF(conversation_key, ''), request_id) AS row_key",
		"ROW_NUMBER() OVER",
		"COUNT(*) OVER",
		"MIN(created_at) OVER",
		"MAX(created_at) OVER",
		"WHEN 'security_blocked' THEN 4",
		"WHEN 'block' THEN 4",
		"WHEN 'deny' THEN 4",
		"WHEN 'security_replied' THEN 3",
		"WHEN 'mask' THEN 3",
		"WHEN 'redact' THEN 3",
		"WHEN 'rewrite' THEN 3",
		"WHEN 'audit' THEN 2",
		"WHEN 'allow' THEN 1",
		"WHEN 'critical' THEN 4",
	} {
		if !strings.Contains(listSQL, fragment) {
			t.Fatalf("conversation list query missing %q:\n%s", fragment, listSQL)
		}
	}
	if want := []any{"tenant_a", "group_a"}; !reflect.DeepEqual(countArgs, want) {
		t.Fatalf("unexpected count args: got %#v want %#v", countArgs, want)
	}
	if want := []any{"tenant_a", "group_a", 20, 40}; !reflect.DeepEqual(listArgs, want) {
		t.Fatalf("unexpected list args: got %#v want %#v", listArgs, want)
	}
}

func TestBuildAlertGroupEventsQueriesFiltersPhysicalEventsByConversation(t *testing.T) {
	countSQL, listSQL, countArgs, listArgs := buildAlertGroupEventsQueries("tenant_a", "group_a", AlertGroupEventListFilter{
		View:            AlertGroupEventViewEvents,
		ConversationKey: "ck_task_1",
		Limit:           10,
		Offset:          5,
	})

	for _, query := range []string{countSQL, listSQL} {
		if !strings.Contains(query, "conversation_key = $3") {
			t.Fatalf("physical event query must bind conversation_key:\n%s", query)
		}
	}
	if want := []any{"tenant_a", "group_a", "ck_task_1"}; !reflect.DeepEqual(countArgs, want) {
		t.Fatalf("unexpected count args: got %#v want %#v", countArgs, want)
	}
	if want := []any{"tenant_a", "group_a", "ck_task_1", 10, 5}; !reflect.DeepEqual(listArgs, want) {
		t.Fatalf("unexpected list args: got %#v want %#v", listArgs, want)
	}
}
