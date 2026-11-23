package permission

import (
	"testing"
)

func TestBuiltinPermissionIDBoundedAndDeterministic(t *testing.T) {
	longID := builtinPermissionID("platform_admin", "agent_operation_policy", "write")
	if len(longID) > 50 {
		t.Fatalf("permission id length = %d, want <= 50", len(longID))
	}
	if again := builtinPermissionID("platform_admin", "agent_operation_policy", "write"); again != longID {
		t.Fatalf("permission id is not deterministic: %q != %q", again, longID)
	}
	if other := builtinPermissionID("platform_admin", "agent_operation_event", "write"); other == longID {
		t.Fatal("distinct permissions must not share a primary key")
	}
}
