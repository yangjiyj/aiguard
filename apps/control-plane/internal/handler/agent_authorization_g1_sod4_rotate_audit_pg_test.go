package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
)

// Rotation revokes pre-rotation authorization and records it in one audit row with counts and
// ids only (never a credential).
func TestG1SoD4HandlerRotateInvalidatesAndAudits(t *testing.T) {
	f := newT15SoDHandlerFixture(t)
	approved := f.pending(t)
	if rr := f.resolve("approver-c", "tenant_admin", approved.ID, "approved"); rr.Code != http.StatusOK {
		t.Fatalf("approve: %d %s", rr.Code, rr.Body.String())
	}
	pending := f.pending(t)
	if rr := f.createException("approver-c", "tenant_admin", "e"); rr.Code != http.StatusCreated {
		t.Fatalf("exception: %d %s", rr.Code, rr.Body.String())
	}
	credential := f.rotateAs(t, "admin-b", "tenant_admin")
	if got := f.status(t, approved.ID); got != "revoked" {
		t.Fatalf("approved ticket after rotate: %s", got)
	}
	if got := f.status(t, pending.ID); got != "pending" {
		t.Fatalf("pending ticket after rotate: %s", got)
	}
	var active int
	if err := f.db.QueryRow(context.Background(), `SELECT count(*) FROM agent_authorization_approval_exceptions WHERE revoked_at IS NULL`).Scan(&active); err != nil || active != 0 {
		t.Fatalf("active exceptions after rotate: %d %v", active, err)
	}
	ops := f.audit.find("agent_authorization_principal.rotate_invalidated")
	if len(ops) != 1 || ops[0].UserID != "admin-b" || ops[0].TargetID != f.principal.ID {
		t.Fatalf("rotate_invalidated audit: %+v", ops)
	}
	d := ops[0].ActionDetail
	raw, _ := json.Marshal(d)
	if d["revoked_exception_count"] != 1 || d["revoked_approval_count"] != 1 {
		t.Fatalf("rotate_invalidated detail: %s", raw)
	}
	t15AuditHasNoSecret(t, ops[0], credential)
	// A rotation with nothing to invalidate writes no rotate_invalidated row.
	f.rotateAs(t, "admin-d", "tenant_admin")
	if n := len(f.audit.find("agent_authorization_principal.rotate_invalidated")); n != 1 {
		t.Fatalf("empty rotation audited invalidation: %d", n)
	}
}
