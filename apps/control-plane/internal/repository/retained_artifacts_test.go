package repository

import (
	"strings"
	"testing"
	"time"
)

func TestRetainedArtifactReadWindowScopesLinksAndRequestsNotOriginalCreation(t *testing.T) {
	start := time.Date(2026, 9, 3, 4, 25, 0, 0, time.UTC)
	end := start.Add(time.Minute)
	where, args := appendRetainedArtifactReadFilters(
		[]string{"l.tenant_id = $1", "l.request_id = $2"},
		[]interface{}{"tenant-a", "req-chat"},
		"customer", start, end,
	)
	joined := strings.Join(where, " AND ")
	for _, required := range []string{
		"l.environment_scope", "a.environment_scope", "rl.environment_scope",
		"l.created_at >=", "l.created_at <", "rl.created_at >=", "rl.created_at <",
	} {
		if !strings.Contains(joined, required) {
			t.Fatalf("scoped artifact filter missing %q: %s", required, joined)
		}
	}
	if strings.Contains(joined, "a.created_at") {
		t.Fatalf("original upload time must not hide a later authorized reference: %s", joined)
	}
	if len(args) != 5 {
		t.Fatalf("args=%#v", args)
	}
}

func TestRetainedArtifactBatchOrderUsesReferenceTimeBeforeOpaqueIDs(t *testing.T) {
	order := strings.ToLower(retainedArtifactsChronologicalOrder)
	requiredInOrder := []string{
		"rl.created_at asc",
		"l.created_at asc",
		"l.direction asc",
		"l.ordinal asc",
		"a.id asc",
		"l.request_id asc",
	}
	last := -1
	for _, fragment := range requiredInOrder {
		index := strings.Index(order, fragment)
		if index < 0 || index <= last {
			t.Fatalf("artifact order must use actual reference time before stable ids: %q", order)
		}
		last = index
	}
	if strings.HasPrefix(strings.TrimSpace(order), "order by l.request_id") {
		t.Fatalf("opaque request id must not determine artifact chronology: %q", order)
	}
}
