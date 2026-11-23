package repository

// T22IR-M01 regression: T16 intent-authorization resolve must hash delegated
// T13 records with the same project binding Authorize uses, and must fail
// closed (explicit deny) when the delegation chain is no longer valid.
// Gate: AGENT_DELEGATION_TEST_DATABASE_URL (setupDelegationPGTest).

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/yangjiyj/aiguard/packages/shared-go/agentintent"
	"github.com/jackc/pgx/v5/pgxpool"
)

const m01Endpoint = "m01-endpoint"

type m01Env struct {
	db              *pgxpool.Pool
	tenant          string
	auth            *AgentAuthorizationRepository
	deleg           *AgentDelegationRepository
	root, mid, leaf TrustedAgentPrincipal
	midDel          string
	leafGrants      []AgentAuthorizationGrant
}

func m01Grant(action, resourceType, resourceID string, expiry time.Time) AgentAuthorizationGrant {
	return AgentAuthorizationGrant{Action: action, ResourceType: resourceType, ResourceID: resourceID,
		Conditions: map[string]any{"project_id": "project-a"}, ExpiresAt: expiry, QuotaMax: 100, QuotaWindowSeconds: 3600}
}

// m01Chain builds root -> mid -> leaf in project-a through the real Authorize + Create path.
func m01Chain(t *testing.T) *m01Env {
	t.Helper()
	db, tenant := setupDelegationPGTest(t)
	t.Cleanup(func() { cleanupT16ChainTenant(t, db, tenant) })
	ctx, now := context.Background(), time.Now().UTC()
	e := &m01Env{db: db, tenant: tenant, auth: NewAgentAuthorizationRepository(db), deleg: NewAgentDelegationRepository(db)}
	files := func(exp time.Time) []AgentAuthorizationGrant {
		return []AgentAuthorizationGrant{m01Grant("agents.delegate", "project", "project-a", exp),
			m01Grant("file_write", "file", "/tmp/m01.txt", exp), m01Grant("tool_execute", "tool", "web_fetch", exp),
			m01Grant("network_connect", "domain", "allowed.example", exp)}
	}
	e.root, _ = registerDelegationTestPrincipal(t, ctx, e.auth, tenant, "m01-root", now.Add(2*time.Hour), files(now.Add(time.Hour)))
	mid, err := delegateChild(ctx, e.auth, e.deleg, e.root, "project-a", "m01-auth-mid-0001", "m01-create-mid-1", "m01-mid",
		now.Add(55*time.Minute), files(now.Add(50*time.Minute)))
	if err != nil {
		t.Fatalf("mid delegation: %v", err)
	}
	e.mid = TrustedAgentPrincipal{ID: mid.Delegation.ChildPrincipalID, TenantID: tenant, CredentialHash: HashAgentToken(mid.Credential), ExpiresAt: mid.Delegation.ExpiresAt}
	e.midDel = mid.Delegation.ID
	leaf, err := delegateChild(ctx, e.auth, e.deleg, e.mid, "project-a", "m01-auth-leaf-001", "m01-create-leaf1", "m01-leaf",
		now.Add(45*time.Minute), files(now.Add(40 * time.Minute))[1:])
	if err != nil {
		t.Fatalf("leaf delegation: %v", err)
	}
	e.leafGrants = leaf.Grants
	e.leaf = TrustedAgentPrincipal{ID: leaf.Delegation.ChildPrincipalID, TenantID: tenant, CredentialHash: HashAgentToken(leaf.Credential), ExpiresAt: leaf.Delegation.ExpiresAt}
	return e
}

// m01Store persists a T16-shaped T13 decision for p (no client context, like hookd)
// and returns the matching resolve request.
func (e *m01Env) m01Store(t *testing.T, p TrustedAgentPrincipal, useID string, facet agentintent.AuthorizationFacet) (agentintent.AuthorizationResolveRequest, *AgentAuthorizationDecision) {
	t.Helper()
	req := agentintent.AuthorizationResolveRequest{Product: "claude-code", SessionID: "m01-sess", ToolUseID: useID,
		ArgumentsHash: "sha256:" + strings.Repeat("c", 64), ToolName: "Write", Facets: []agentintent.AuthorizationFacet{facet}}
	key, err := agentintent.AuthorizationIdempotencyKey(req.Product, m01Endpoint, req.SessionID, useID, req.ArgumentsHash, req.ToolName, facet)
	if err != nil {
		t.Fatal(err)
	}
	d, err := e.auth.Authorize(context.Background(), p, AgentAuthorizationRequest{Action: facet.Action,
		ResourceType: facet.ResourceType, ResourceID: facet.ResourceID, IdempotencyKey: key})
	if err != nil || d == nil {
		t.Fatalf("store T13 %s: %+v err=%v", useID, d, err)
	}
	return req, d
}

// m01Outcome classifies a resolve result: resolved-allow, resolved-deny:<reason>, unresolved:<err>.
func m01Outcome(res []agentintent.AuthorizationResolution, err error) string {
	switch {
	case err != nil:
		return "unresolved:" + err.Error()
	case len(res) == 1 && res[0].Allowed && res[0].GrantID != "":
		return "resolved-allow"
	case len(res) == 1 && !res[0].Allowed && res[0].GrantID == "":
		return "resolved-deny:" + res[0].Reason
	}
	return fmt.Sprintf("other:%+v", res)
}

var (
	m01Granted   = agentintent.AuthorizationFacet{Action: "file_write", ResourceType: "file", ResourceID: "/tmp/m01.txt"}
	m01Ungranted = agentintent.AuthorizationFacet{Action: "file_write", ResourceType: "file", ResourceID: "/tmp/m01-not-granted.txt"}
)

// xi (review T22IR-M01): a stored T13 deny must resolve as a deny for a delegated
// leaf exactly as for a root, so gateway-core keeps the t13 block floor. The leaf
// allow must also resolve (previously every delegated record was unresolved).
func TestT22M01XI_DelegatedT13DenyResolvesAsDeny(t *testing.T) {
	e := m01Chain(t)
	ctx := context.Background()
	got := map[string]string{}
	for _, c := range []struct {
		name  string
		p     TrustedAgentPrincipal
		facet agentintent.AuthorizationFacet
	}{{"root-deny", e.root, m01Ungranted}, {"leaf-deny", e.leaf, m01Ungranted}, {"leaf-allow", e.leaf, m01Granted}} {
		req, d := e.m01Store(t, c.p, "m01-xi-"+c.name, c.facet)
		res, err := e.auth.ResolveIntentAuthorizations(ctx, e.tenant, m01Endpoint, req)
		got[c.name] = m01Outcome(res, err)
		t.Logf("%s: stored allowed=%v reason=%s -> resolve=%s", c.name, d.Allowed, d.Reason, got[c.name])
	}
	for name, want := range map[string]string{"root-deny": "resolved-deny:no_matching_grant",
		"leaf-deny": "resolved-deny:no_matching_grant", "leaf-allow": "resolved-allow"} {
		if got[name] != want {
			t.Errorf("%s: resolve=%s want %s", name, got[name], want)
		}
	}
}

// m01Exec runs a fixture mutation that simulates a damaged/changed delegation chain.
func (e *m01Env) m01Exec(t *testing.T, sql string, args ...any) {
	t.Helper()
	if _, err := e.db.Exec(context.Background(), sql, args...); err != nil {
		t.Fatalf("fixture %q: %v", sql, err)
	}
}

// m01AddAncestors hangs n synthetic active ancestors above root (depth fixture).
func (e *m01Env) m01AddAncestors(t *testing.T, n int) {
	t.Helper()
	child := e.root.ID
	for i := 0; i < n; i++ {
		var id string
		if err := e.db.QueryRow(context.Background(), `INSERT INTO agent_authorization_principals
			(id,tenant_id,name,credential_hash,credential_prefix,status,expires_at,created_by)
			VALUES (gen_random_uuid(),$1,$2,$3,'m01anc00','active',clock_timestamp()+interval '2 hours','m01-fixture')
			RETURNING id::text`, e.tenant, fmt.Sprintf("m01-anc-%d", i), HashAgentToken(fmt.Sprintf("%s-m01-anc-%d", e.tenant, i))).Scan(&id); err != nil {
			t.Fatalf("ancestor %d: %v", i, err)
		}
		e.m01Exec(t, `INSERT INTO agent_delegations (id,tenant_id,parent_principal_id,child_principal_id,project_id,idempotency_key,
			authorization_idempotency_key,request_hash,expires_at) VALUES (gen_random_uuid(),$1,$2,$3,'project-a',$4,$4,
			repeat('d',64),clock_timestamp()+interval '1 hour')`, e.tenant, id, child, fmt.Sprintf("m01-anc-edge-%d", i))
		child = id
	}
}

// Fail-closed: once the leaf's delegation chain is broken, cyclic, too deep,
// cross-project, revoked/expired, or no longer covered by an ancestor grant, a
// stored leaf decision (allow or deny) must resolve as an explicit deny, never
// as an allow and never as unresolved (which drops the gateway block floor).
func TestT22M01_ResolveFailsClosedOnBrokenDelegationChain(t *testing.T) {
	want := "resolved-deny:" + "delegation_parent_inactive"
	for name, damage := range map[string]func(*testing.T, *m01Env){
		"ancestor edge revoked": func(t *testing.T, e *m01Env) {
			e.m01Exec(t, `UPDATE agent_delegations SET revoked_at=clock_timestamp() WHERE tenant_id=$1 AND id=$2`, e.tenant, e.midDel)
		},
		"ancestor edge expired": func(t *testing.T, e *m01Env) {
			e.m01Exec(t, `UPDATE agent_delegations SET expires_at=created_at+interval '1 microsecond' WHERE tenant_id=$1 AND id=$2`, e.tenant, e.midDel)
		},
		"root principal revoked": func(t *testing.T, e *m01Env) {
			e.m01Exec(t, `UPDATE agent_authorization_principals SET status='revoked',revoked_at=clock_timestamp() WHERE tenant_id=$1 AND id=$2`, e.tenant, e.root.ID)
		},
		"chain cycle": func(t *testing.T, e *m01Env) {
			e.m01Exec(t, `INSERT INTO agent_delegations (id,tenant_id,parent_principal_id,child_principal_id,project_id,idempotency_key,
				authorization_idempotency_key,request_hash,expires_at) VALUES (gen_random_uuid(),$1,$2,$3,'project-a','m01-cycle-edge',
				'm01-cycle-edge',repeat('a',64),clock_timestamp()+interval '1 hour')`, e.tenant, e.leaf.ID, e.root.ID)
		},
		"chain too deep": func(t *testing.T, e *m01Env) { e.m01AddAncestors(t, AgentDelegationMaxDepth) },
		"root grant expired (allow only)": func(t *testing.T, e *m01Env) {
			e.m01Exec(t, `UPDATE agent_authorization_grants SET expires_at=clock_timestamp() WHERE tenant_id=$1 AND principal_id=$2 AND action='file_write'`, e.tenant, e.root.ID)
		},
		"cross-project binding": func(t *testing.T, e *m01Env) {
			e.m01Exec(t, `UPDATE agent_delegations SET project_id='project-b' WHERE tenant_id=$1 AND id=$2`, e.tenant, e.midDel)
		},
	} {
		t.Run(name, func(t *testing.T) {
			e := m01Chain(t)
			allowReq, allowD := e.m01Store(t, e.leaf, "m01-fc-allow", m01Granted)
			denyReq, denyD := e.m01Store(t, e.leaf, "m01-fc-deny", m01Ungranted)
			if !allowD.Allowed || denyD.Allowed {
				t.Fatalf("fixture: stored allow=%v deny=%v", allowD.Allowed, denyD.Allowed)
			}
			damage(t, e)
			for label, req := range map[string]agentintent.AuthorizationResolveRequest{"allow": allowReq, "deny": denyReq} {
				res, err := e.auth.ResolveIntentAuthorizations(context.Background(), e.tenant, m01Endpoint, req)
				expect := want
				if label == "deny" && strings.HasPrefix(name, "root grant expired") {
					expect = "resolved-deny:no_matching_grant" // ancestor grants are only rechecked for stored allows
				}
				if got := m01Outcome(res, err); got != expect {
					t.Errorf("stored %s after %s: resolve=%s want %s", label, name, got, expect)
				}
			}
		})
	}
}

// Caller 1 (handler path): ResolveIntentAuthorizationContext must report the
// delegated deny as resolved, and a broken chain as a resolved deny.
func TestT22M01_ResolveIntentAuthorizationContextDelegated(t *testing.T) {
	e := m01Chain(t)
	ctx := context.Background()
	denyReq, _ := e.m01Store(t, e.leaf, "m01-ctx-deny", m01Ungranted)
	allowReq, _ := e.m01Store(t, e.leaf, "m01-ctx-allow", m01Granted)
	check := func(label string, req agentintent.AuthorizationResolveRequest, want string) {
		t.Helper()
		out, err := e.auth.ResolveIntentAuthorizationContext(ctx, e.tenant, m01Endpoint, req)
		got := out.AuthorizationStatus + "/" + m01Outcome(out.Resolutions, err)
		t.Logf("%s: %s", label, got)
		if got != want {
			t.Errorf("%s: got %s want %s", label, got, want)
		}
	}
	check("leaf deny", denyReq, "resolved/resolved-deny:no_matching_grant")
	check("leaf allow", allowReq, "resolved/resolved-allow")
	e.m01Exec(t, `UPDATE agent_delegations SET project_id='project-b' WHERE tenant_id=$1 AND id=$2`, e.tenant, e.midDel)
	check("leaf allow, cross-project chain", allowReq, "resolved/resolved-deny:delegation_parent_inactive")
}

// Caller 2 (T16 step ledger, agent_intent_task_steps.go): a delegated leaf's
// in-scope T13 allow must be recorded as "allowed" (not "unresolved"), and after
// the ancestry breaks the same stored allow must be recorded as "denied".
func TestT22M01_IntentTaskStepDelegatedAuthorizationState(t *testing.T) {
	e := m01Chain(t)
	ctx := context.Background()
	endpointID, sessionID := "ep-m01-"+e.tenant, "sess-m01"
	e.m01Exec(t, `INSERT INTO agent_endpoints(id,tenant_id,machine_id,hostname,os,arch,agent_product,token_hash)
		VALUES($1,$2,'m-'||$1,'h-'||$1,'linux','amd64','openclaw',repeat('f',64))`, endpointID, e.tenant)
	inputs := []AgentIntentTaskGrantInput{}
	for _, g := range e.leafGrants {
		if g.Action == "tool_execute" || g.Action == "network_connect" {
			inputs = append(inputs, AgentIntentTaskGrantInput{GrantID: g.ID})
		}
	}
	// CreateIntentTask only accepts unconditioned grants, while delegated grants must
	// bind project_id; relax the leaf rows for task creation only, then restore them.
	e.m01Exec(t, `UPDATE agent_authorization_grants SET conditions_json='{}' WHERE tenant_id=$1 AND principal_id=$2`, e.tenant, e.leaf.ID)
	task, err := e.auth.CreateIntentTask(ctx, e.tenant, "m01-admin", AgentIntentTaskCreate{EndpointID: endpointID,
		PrincipalID: e.leaf.ID, Purpose: "fetch the approved example page", ExpiresAt: time.Now().Add(30 * time.Minute),
		Grants: inputs, AllowedSourceKinds: []string{"tool_result", "user_prompt"}})
	if err != nil {
		t.Fatalf("create intent task: %v", err)
	}
	e.m01Exec(t, `UPDATE agent_authorization_grants SET conditions_json='{"project_id":"project-a"}' WHERE tenant_id=$1 AND principal_id=$2`, e.tenant, e.leaf.ID)
	logs := NewToolCallLogRepository(e.db)
	authorize := func(useID string) string {
		t.Helper()
		args := map[string]any{"url": "https://allowed.example/page"}
		argsHash, _ := agentintent.ArgumentsHash(args)
		_, facets, err := agentintent.DeriveT16AuthorizationFacets("openclaw", "web_fetch", "network", "", args)
		if err != nil {
			t.Fatal(err)
		}
		for _, f := range facets {
			key, _ := agentintent.AuthorizationIdempotencyKey("openclaw", endpointID, sessionID, useID, argsHash, "web_fetch", f)
			if d, err := e.auth.Authorize(ctx, e.leaf, AgentAuthorizationRequest{Action: f.Action, ResourceType: f.ResourceType,
				ResourceID: f.ResourceID, IdempotencyKey: key}); err != nil || !d.Allowed {
				t.Fatalf("leaf authorize %s: %+v err=%v", f.Action, d, err)
			}
		}
		return useID
	}
	propose := func(useID string) string {
		t.Helper()
		log := &ToolCallLog{TenantID: e.tenant, EndpointID: endpointID, SessionID: sessionID, PromptID: "prompt-m01",
			ToolCallID: useID, ToolName: "web_fetch", ToolType: "network", Parameters: map[string]any{"url": "https://allowed.example/page"},
			AttributionMode: "endpoint_hook", AttributionConfidence: 1, Provenance: "agent_endpoint",
			EventKind: "invocation_proposed", Status: "audited", IntentTaskID: task.ID}
		if err := logs.UpsertEndpointToolProposal(ctx, log); err != nil {
			t.Fatalf("proposal %s: %v", useID, err)
		}
		var state string
		if err := e.db.QueryRow(ctx, `SELECT authorization_state FROM agent_intent_task_steps WHERE tenant_id=$1 AND tool_call_log_id=$2`,
			e.tenant, log.ID).Scan(&state); err != nil {
			t.Fatalf("read step %s: %v", useID, err)
		}
		return state
	}
	if got := propose(authorize("m01-step-1")); got != "allowed" {
		t.Errorf("delegated in-scope step: authorization_state=%s want allowed", got)
	}
	second := authorize("m01-step-2")
	e.m01Exec(t, `UPDATE agent_delegations SET project_id='project-b' WHERE tenant_id=$1 AND id=$2`, e.tenant, e.midDel)
	if got := propose(second); got != "denied" {
		t.Errorf("delegated step after cross-project chain: authorization_state=%s want denied", got)
	}
}

// Non-delegated principals: resolve output must be byte-identical before and
// after the fix. IDs are replaced by stable placeholders and the JSON is pinned
// to a golden string; the same test passes unchanged on 6f625d82.
func TestT22M01_RootResolveOutputUnchanged(t *testing.T) {
	e := m01Chain(t)
	ctx, now := context.Background(), time.Now().UTC()
	plain := func(id string) AgentAuthorizationGrant {
		return AgentAuthorizationGrant{Action: "file_write", ResourceType: "file", ResourceID: id, ExpiresAt: now.Add(time.Hour), QuotaMax: 100, QuotaWindowSeconds: 3600}
	}
	e.root, _ = registerDelegationTestPrincipal(t, ctx, e.auth, e.tenant, "m01-plain-root", now.Add(2*time.Hour), []AgentAuthorizationGrant{plain("/tmp/m01.txt")})
	var lines []string
	record := func(label string, req agentintent.AuthorizationResolveRequest) {
		res, err := e.auth.ResolveIntentAuthorizations(ctx, e.tenant, m01Endpoint, req)
		raw, _ := json.Marshal(res)
		out := strings.ReplaceAll(string(raw), e.root.ID, "<root>")
		for _, g := range res {
			if g.GrantID != "" {
				out = strings.ReplaceAll(out, g.GrantID, "<grant>")
			}
			out = strings.ReplaceAll(out, g.IdempotencyKey, "<key>")
		}
		lines = append(lines, fmt.Sprintf("%s err=%v unresolved=%v %s", label, err, errors.Is(err, ErrAgentIntentAuthorizationUnresolved), out))
	}
	allowReq, _ := e.m01Store(t, e.root, "m01-root-allow", m01Granted)
	denyReq, _ := e.m01Store(t, e.root, "m01-root-deny", m01Ungranted)
	record("allow", allowReq)
	record("deny", denyReq)
	missing := denyReq
	missing.ToolUseID = "m01-root-never-authorized"
	record("missing", missing)
	e.m01Exec(t, `UPDATE agent_authorization_grants SET expires_at=clock_timestamp() WHERE tenant_id=$1 AND principal_id=$2 AND resource_id='/tmp/m01.txt'`, e.tenant, e.root.ID)
	record("allow-grant-expired", allowReq)
	e.m01Exec(t, `UPDATE agent_authorization_principals SET status='revoked',revoked_at=clock_timestamp() WHERE tenant_id=$1 AND id=$2`, e.tenant, e.root.ID)
	record("deny-principal-revoked", denyReq)
	got := strings.Join(lines, "\n")
	t.Logf("root resolve golden:/n%s", got)
	want := strings.Join([]string{
		`allow err=<nil> unresolved=false [{"facet":{"action":"file_write","resource_type":"file","resource_id":"/tmp/m01.txt"},"idempotency_key":"<key>","allowed":true,"reason":"allowed","principal_id":"<root>","grant_id":"<grant>"}]`,
		`deny err=<nil> unresolved=false [{"facet":{"action":"file_write","resource_type":"file","resource_id":"/tmp/m01-not-granted.txt"},"idempotency_key":"<key>","allowed":false,"reason":"no_matching_grant","principal_id":"<root>"}]`,
		`missing err=agent intent authorization is unresolved unresolved=true null`,
		`allow-grant-expired err=agent intent authorization is unresolved unresolved=true null`,
		`deny-principal-revoked err=agent intent authorization is unresolved unresolved=true null`,
	}, "\n")
	if got != want {
		t.Errorf("root resolve output changed:/n got:/n%s/nwant:/n%s", got, want)
	}
}
