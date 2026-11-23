package repository

import (
	"strings"
	"testing"
	"time"
)

func TestSecurityEventAgentSnapshotFilterUsesBoundParameters(t *testing.T) {
	start := time.Date(2026, 10, 6, 0, 0, 0, 0, time.UTC)
	end := start.Add(time.Minute)
	join, where, args := buildSecurityEventsWhere("tenant1", SecurityEventFilter{AgentInstanceID: "agent1", StartTime: &start, EndTime: &end})
	if join != "" || len(args) != 4 || args[0] != "tenant1" || args[1] != "agent1" {
		t.Fatalf("join=%q where=%q args=%v", join, where, args)
	}
	for _, expected := range []string{"se.agent_instance_id = $2", "se.created_at >= $3", "se.created_at <= $4"} {
		if !strings.Contains(where, expected) {
			t.Fatalf("missing %s in %s", expected, where)
		}
	}
	if strings.Contains(where, "agent1") || strings.Contains(where, "tenant1") {
		t.Fatal("unbound identity in SQL")
	}
}
