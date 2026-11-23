package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

// G1 batch 3 handler-level checks over real PostgreSQL. They drive the real admin
// routes (register / revoke / rotate-token / resolve), so they compile against the
// pre-fix tree too and document the red state there.

func (f *t15SoDHandlerFixture) principalAPI() *AgentAuthorizationAPI {
	return NewAgentAuthorizationAPI(f.repo, &Dependencies{SystemRepo: f.audit})
}

func (f *t15SoDHandlerFixture) rotateAs(t *testing.T, userID, role string) string {
	t.Helper()
	rr := httptest.NewRecorder()
	f.principalAPI().RotatePrincipalCredential(rr, t15SoDAdminRequest(userID, role,
		"/admin/v1/agent/principals/"+f.principal.ID+"/rotate-token", f.principal.ID, ""))
	if rr.Code != http.StatusOK {
		t.Fatalf("rotate as %s: %d %s", userID, rr.Code, rr.Body.String())
	}
	var body struct {
		Credential string `json:"credential"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil || body.Credential == "" {
		t.Fatalf("rotate body %q: %v", rr.Body.String(), err)
	}
	principal, err := f.repo.ResolvePrincipalCredential(context.Background(), repository.HashAgentToken(body.Credential))
	if err != nil || principal == nil {
		t.Fatalf("resolve rotated credential: %v %v", principal, err)
	}
	f.principal = *principal
	return body.Credential
}

func t15AuditHasNoSecret(t *testing.T, op *repository.AuditOperation, secret string) {
	t.Helper()
	raw, _ := json.Marshal(op.ActionDetail)
	if secret != "" && strings.Contains(string(raw), secret) {
		t.Fatalf("audit %s leaked credential: %s", op.ActionType, raw)
	}
	if strings.Contains(strings.ToLower(string(raw)), "credential\"") {
		t.Fatalf("audit %s carries a credential field: %s", op.ActionType, raw)
	}
}

// F1 (ported from g1-review TestG1RRotateThenSelfApproveByNonCreator): a non-creator admin
// who rotates the credential holds the agent identity and must not approve its requests.
func TestG1SoD3HandlerRotatorCannotResolveOwnRequest(t *testing.T) {
	f := newT15SoDHandlerFixture(t)
	f.rotateAs(t, "reviewer-b", "tenant_admin")
	for _, decision := range []string{"approved", "rejected"} {
		approval := f.pending(t)
		rr := f.resolve("reviewer-b", "platform_admin", approval.ID, decision)
		if rr.Code != http.StatusForbidden || t15SoDErrorCode(t, rr) != "approval_self_resolution_forbidden" {
			t.Fatalf("rotator %s: status=%d body=%s", decision, rr.Code, rr.Body.String())
		}
		if got := f.status(t, approval.ID); got != "pending" {
			t.Fatalf("rotator %s changed status to %s", decision, got)
		}
	}
	if rr := f.createException("reviewer-b", "tenant_admin", "7"); rr.Code != http.StatusForbidden || t15SoDErrorCode(t, rr) != "approval_self_resolution_forbidden" {
		t.Fatalf("rotator exception: %d %s", rr.Code, rr.Body.String())
	}
	if rr := f.resolve("creator-a", "tenant_admin", f.pending(t).ID, "approved"); rr.Code != http.StatusForbidden {
		t.Fatalf("creator after rotation: %d %s", rr.Code, rr.Body.String())
	}
	approval := f.pending(t)
	if rr := f.resolve("approver-c", "tenant_admin", approval.ID, "approved"); rr.Code != http.StatusOK || f.status(t, approval.ID) != "approved" {
		t.Fatalf("independent approver after rotation: %d %s", rr.Code, rr.Body.String())
	}
	denied := f.audit.find("agent_authorization_approval.resolve_denied")
	if len(denied) != 3 {
		t.Fatalf("resolve_denied audit count=%d", len(denied))
	}
	for _, op := range denied {
		if op.ActionDetail["reason"] != "self_resolution" {
			t.Fatalf("denied reason: %+v", op.ActionDetail)
		}
	}
}

// F3: a principal whose created_by is blank has no provable requester, so every
// resolution and exception fails closed with 403 and an audited denial.
func TestG1SoD3HandlerBlankCreatorFailsClosed(t *testing.T) {
	f := newT15SoDHandlerFixture(t)
	ctx := context.Background()
	for i, blank := range []string{"", "   ", "\t"} {
		approval := f.pending(t)
		if _, err := f.db.Exec(ctx, `UPDATE agent_authorization_principals SET created_by=$1 WHERE id=$2`, blank, f.principal.ID); err != nil {
			t.Fatal(err)
		}
		rr := f.resolve("reviewer-b", "tenant_admin", approval.ID, "approved")
		if rr.Code != http.StatusForbidden || t15SoDErrorCode(t, rr) != "approval_separation_unverifiable" {
			t.Fatalf("blank creator %q resolve: %d %s", blank, rr.Code, rr.Body.String())
		}
		if got := f.status(t, approval.ID); got != "pending" {
			t.Fatalf("blank creator %q changed status to %s", blank, got)
		}
		if rr := f.createException("reviewer-b", "tenant_admin", string(rune('a'+i))); rr.Code != http.StatusForbidden || t15SoDErrorCode(t, rr) != "approval_separation_unverifiable" {
			t.Fatalf("blank creator %q exception: %d %s", blank, rr.Code, rr.Body.String())
		}
		if _, err := f.db.Exec(ctx, `UPDATE agent_authorization_principals SET created_by='creator-a' WHERE id=$1`, f.principal.ID); err != nil {
			t.Fatal(err)
		}
	}
	var exceptions int
	if err := f.db.QueryRow(ctx, `SELECT count(*) FROM agent_authorization_approval_exceptions`).Scan(&exceptions); err != nil || exceptions != 0 {
		t.Fatalf("exception persisted for blank creator: %d %v", exceptions, err)
	}
	for _, action := range []string{"agent_authorization_approval.resolve_denied", "agent_authorization_approval_exception.create_denied"} {
		ops := f.audit.find(action)
		if len(ops) != 3 {
			t.Fatalf("%s count=%d", action, len(ops))
		}
		for _, op := range ops {
			if op.ActionDetail["reason"] != "credential_holder_unknown" || op.UserID != "reviewer-b" {
				t.Fatalf("%s shape: %+v", action, op)
			}
		}
	}
}

// F2: register, revoke and rotate-token write audit_operations with actor and target,
// never the one-time credential.
func TestG1SoD3HandlerPrincipalLifecycleAudited(t *testing.T) {
	f := newT15SoDHandlerFixture(t)
	api := f.principalAPI()
	expires := time.Now().UTC().Add(6 * time.Hour).Format(time.RFC3339)
	body := `{"name":"g1-sod3-audit","expires_at":"` + expires + `","grants":[{"action":"file_read","resource_type":"file","resource_id":"/tmp/a.txt","expires_at":"` +
		expires + `","quota_max":10,"quota_window_seconds":60}]}`
	rr := httptest.NewRecorder()
	api.RegisterPrincipal(rr, t15SoDAdminRequest("registrar-r", "tenant_admin", "/admin/v1/agent/principals", "", body))
	if rr.Code != http.StatusCreated {
		t.Fatalf("register: %d %s", rr.Code, rr.Body.String())
	}
	var created repository.AgentAuthorizationPrincipalCreated
	if err := json.Unmarshal(rr.Body.Bytes(), &created); err != nil || created.Credential == "" {
		t.Fatalf("register body: %v", err)
	}
	id := created.Principal.ID
	registered := f.audit.find("agent_authorization_principal.register")
	if len(registered) != 1 || registered[0].UserID != "registrar-r" || registered[0].TargetType != "agent_authorization_principal" ||
		registered[0].TargetID != id || registered[0].ActionDetail["created_by"] != "registrar-r" {
		t.Fatalf("register audit: %+v", registered)
	}
	t15AuditHasNoSecret(t, registered[0], created.Credential)

	rr = httptest.NewRecorder()
	api.RotatePrincipalCredential(rr, t15SoDAdminRequest("rotator-s", "tenant_admin", "/admin/v1/agent/principals/"+id+"/rotate-token", id, ""))
	if rr.Code != http.StatusOK {
		t.Fatalf("rotate: %d %s", rr.Code, rr.Body.String())
	}
	var rotated struct {
		Credential string `json:"credential"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &rotated)
	ops := f.audit.find("agent_authorization_principal.rotate")
	if len(ops) != 1 || ops[0].UserID != "rotator-s" || ops[0].TargetID != id || ops[0].ActionDetail["rotated_by"] != "rotator-s" {
		t.Fatalf("rotate audit: %+v", ops)
	}
	t15AuditHasNoSecret(t, ops[0], rotated.Credential)

	rr = httptest.NewRecorder()
	api.RevokePrincipal(rr, t15SoDAdminRequest("revoker-t", "tenant_admin", "/admin/v1/agent/principals/"+id+"/revoke", id, ""))
	if rr.Code != http.StatusNoContent {
		t.Fatalf("revoke: %d %s", rr.Code, rr.Body.String())
	}
	ops = f.audit.find("agent_authorization_principal.revoke")
	if len(ops) != 1 || ops[0].UserID != "revoker-t" || ops[0].TargetID != id {
		t.Fatalf("revoke audit: %+v", ops)
	}
	// Failed operations are not audited as successes.
	missing := "00000000-0000-4000-8000-000000000000"
	rr = httptest.NewRecorder()
	api.RotatePrincipalCredential(rr, t15SoDAdminRequest("rotator-s", "tenant_admin", "/admin/v1/agent/principals/"+missing+"/rotate-token", missing, ""))
	if rr.Code != http.StatusNotFound || len(f.audit.find("agent_authorization_principal.rotate")) != 1 {
		t.Fatalf("missing rotate: %d audits=%d", rr.Code, len(f.audit.find("agent_authorization_principal.rotate")))
	}
}
