package auditpipe

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/yangjiyj/aiguard/packages/shared-go/eventbus"
)

func TestSinkRetainsAgentIdentityFromDurableSnapshot(t *testing.T) {
	snapshot := testRequestLogSnapshot()
	snapshot.AgentInstanceID = "agent-before-rotation"
	for _, kind := range []string{"content", "security"} {
		t.Run(kind, func(t *testing.T) {
			db := &fakeExecutor{}
			sink := NewSink(db, "customer")
			var err error
			if kind == "content" {
				err = sink.writeContentLog(context.Background(), eventbus.AuditContentLogPayload{RequestLog: snapshot, LogID: "content1", Role: "user", Content: "normal request", CreatedAt: time.Now()})
			} else {
				err = sink.writeSecurityEvent(context.Background(), eventbus.AuditSecurityEventPayload{RequestLog: snapshot, EventID: "event1", EventType: "security_check", Severity: "high", ActionTaken: "audit", CreatedAt: time.Now()})
			}
			if err != nil {
				t.Fatal(err)
			}
			if len(db.calls) == 0 || !strings.Contains(db.calls[0].query, "agent_instance_id") {
				t.Fatal("snapshot identity column omitted")
			}
			args := db.calls[0].args
			if args[len(args)-1] != "agent-before-rotation" {
				t.Fatal("snapshot identity replaced or lost")
			}
		})
	}
}
