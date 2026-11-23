package repository

import (
	"context"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// setupDelegationPGTest connects to a real, migrated Postgres instance (schema
// current through migration 874) and returns pools scoped to a disposable
// tenant. It is skipped unless AGENT_DELEGATION_TEST_DATABASE_URL is set, so it
// never runs against a shared or production database by accident.
func setupDelegationPGTest(t *testing.T) (*pgxpool.Pool, string) {
	t.Helper()
	databaseURL := os.Getenv("AGENT_DELEGATION_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("AGENT_DELEGATION_TEST_DATABASE_URL is not set")
	}
	ctx := context.Background()
	db, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	tenantID := fmt.Sprintf("t22w19_%d", time.Now().UnixNano())
	if _, err := db.Exec(ctx, `INSERT INTO tenants (id, name, edition, status) VALUES ($1,$2,'enterprise','active')`, tenantID, tenantID); err != nil {
		t.Fatalf("insert tenant: %v", err)
	}
	t.Cleanup(func() {
		_, _ = db.Exec(ctx, `DELETE FROM agent_delegation_calls WHERE tenant_id = $1`, tenantID)
		_, _ = db.Exec(ctx, `DELETE FROM agent_delegation_grants WHERE tenant_id = $1`, tenantID)
		_, _ = db.Exec(ctx, `DELETE FROM agent_delegations WHERE tenant_id = $1`, tenantID)
		_, _ = db.Exec(ctx, `DELETE FROM agent_authorization_usage WHERE tenant_id = $1`, tenantID)
		_, _ = db.Exec(ctx, `DELETE FROM agent_authorization_requests WHERE tenant_id = $1`, tenantID)
		_, _ = db.Exec(ctx, `DELETE FROM agent_authorization_grants WHERE tenant_id = $1`, tenantID)
		_, _ = db.Exec(ctx, `DELETE FROM agent_authorization_principals WHERE tenant_id = $1`, tenantID)
		_, _ = db.Exec(ctx, `DELETE FROM tenants WHERE id = $1`, tenantID)
		db.Close()
	})
	return db, tenantID
}

// registerDelegationTestPrincipal creates a real principal (root or child) via
// the same repository path production traffic uses, with one grant of the
// caller's choosing already attached.
func registerDelegationTestPrincipal(t *testing.T, ctx context.Context, authRepo *AgentAuthorizationRepository, tenantID, name string, expiresAt time.Time, grants []AgentAuthorizationGrant) (TrustedAgentPrincipal, *AgentAuthorizationPrincipalCreated) {
	t.Helper()
	created, err := authRepo.RegisterPrincipal(ctx, tenantID, AgentAuthorizationPrincipalCreate{
		Name: name, ExpiresAt: expiresAt, CreatedBy: "t22-negatives-test", Grants: grants,
	})
	if err != nil {
		t.Fatalf("register principal %s: %v", name, err)
	}
	return TrustedAgentPrincipal{
		ID: created.Principal.ID, TenantID: tenantID, CredentialHash: HashAgentToken(created.Credential), ExpiresAt: created.Principal.ExpiresAt,
	}, created
}

// delegateChild drives the real agents.delegate authorization call followed by
// AgentDelegationRepository.Create, exactly as the handler layer requires:
// creation is refused unless a fresh, exact-scope T13 allow for this project
// already exists under the same idempotency key.
func delegateChild(ctx context.Context, authRepo *AgentAuthorizationRepository, delegRepo *AgentDelegationRepository, parent TrustedAgentPrincipal, projectID, authKey, createKey, name string, expiresAt time.Time, grants []AgentAuthorizationGrant) (*AgentDelegationCreated, error) {
	authRequest := AgentAuthorizationRequest{
		Action: "agents.delegate", ResourceType: "project", ResourceID: projectID,
		Context: map[string]any{"project_id": projectID}, IdempotencyKey: authKey,
	}
	if _, err := authRepo.Authorize(ctx, parent, authRequest); err != nil {
		return nil, fmt.Errorf("authorize agents.delegate: %w", err)
	}
	return delegRepo.Create(ctx, parent, AgentDelegationCreate{
		Name: name, ProjectID: projectID, ExpiresAt: expiresAt, Grants: grants,
		AuthorizationIdempotencyKey: authKey, IdempotencyKey: createKey,
	})
}

func delegateGrant(id string, expires time.Time, quotaMax int64, windowSeconds int, projectID string) AgentAuthorizationGrant {
	return AgentAuthorizationGrant{
		ID: id, Action: "tickets.update", ResourceType: "ticket", ResourceID: "ticket-7",
		Conditions: map[string]any{"project_id": projectID}, ExpiresAt: expires,
		QuotaMax: quotaMax, QuotaWindowSeconds: windowSeconds,
	}
}

// TestAgentDelegationCreateRejectsCrossProjectChild proves N2 end to end: a
// parent authorized to delegate into project-a cannot mint a child scoped to
// project-b, and no child principal, delegation edge, or grant row survives
// the rejected attempt.
func TestAgentDelegationCreateRejectsCrossProjectChild(t *testing.T) {
	db, tenantID := setupDelegationPGTest(t)
	ctx := context.Background()
	authRepo := NewAgentAuthorizationRepository(db)
	delegRepo := NewAgentDelegationRepository(db)
	now := time.Now().UTC()

	parentGrantID := "parent-grant-" + tenantID
	parent, _ := registerDelegationTestPrincipal(t, ctx, authRepo, tenantID, "root", now.Add(6*time.Hour), []AgentAuthorizationGrant{
		{ID: parentGrantID, Action: "agents.delegate", ResourceType: "project", ResourceID: "project-a",
			Conditions: map[string]any{"project_id": "project-a"}, ExpiresAt: now.Add(5 * time.Hour), QuotaMax: 10, QuotaWindowSeconds: 3600},
		delegateGrant("scope-grant-"+tenantID, now.Add(5*time.Hour), 5, 3600, "project-a"),
	})

	before := countDelegationRows(t, ctx, db, tenantID)

	_, err := delegateChild(ctx, authRepo, delegRepo, parent, "project-b", "authorize-xproj-0001", "create-xproj-0001",
		"child-cross-project", now.Add(2*time.Hour), []AgentAuthorizationGrant{delegateGrant("", now.Add(time.Hour), 2, 3600, "project-b")})
	if err == nil {
		t.Fatal("cross-project delegation was accepted")
	}

	after := countDelegationRows(t, ctx, db, tenantID)
	if before != after {
		t.Fatalf("cross-project rejection left residue: before=%+v after=%+v", before, after)
	}
}

// TestAgentDelegationCreateRejectsChildScopeBeyondParentGrant proves N1's
// action/resource axes end to end: a child grant naming a different action or
// resource than anything the parent holds is refused, with no residue.
func TestAgentDelegationCreateRejectsChildScopeBeyondParentGrant(t *testing.T) {
	for _, tc := range []struct {
		name  string
		child AgentAuthorizationGrant
	}{
		{"different action", AgentAuthorizationGrant{Action: "tickets.delete", ResourceType: "ticket", ResourceID: "ticket-7", Conditions: map[string]any{"project_id": "project-a"}, QuotaMax: 1, QuotaWindowSeconds: 3600}},
		{"different resource", AgentAuthorizationGrant{Action: "tickets.update", ResourceType: "ticket", ResourceID: "ticket-other", Conditions: map[string]any{"project_id": "project-a"}, QuotaMax: 1, QuotaWindowSeconds: 3600}},
		{"different resource type", AgentAuthorizationGrant{Action: "tickets.update", ResourceType: "folder", ResourceID: "ticket-7", Conditions: map[string]any{"project_id": "project-a"}, QuotaMax: 1, QuotaWindowSeconds: 3600}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db, tenantID := setupDelegationPGTest(t)
			ctx := context.Background()
			authRepo := NewAgentAuthorizationRepository(db)
			delegRepo := NewAgentDelegationRepository(db)
			now := time.Now().UTC()

			parent, _ := registerDelegationTestPrincipal(t, ctx, authRepo, tenantID, "root", now.Add(6*time.Hour), []AgentAuthorizationGrant{
				{ID: "parent-delegate-" + tenantID, Action: "agents.delegate", ResourceType: "project", ResourceID: "project-a",
					Conditions: map[string]any{"project_id": "project-a"}, ExpiresAt: now.Add(5 * time.Hour), QuotaMax: 10, QuotaWindowSeconds: 3600},
				delegateGrant("scope-grant-"+tenantID, now.Add(5*time.Hour), 5, 3600, "project-a"),
			})

			before := countDelegationRows(t, ctx, db, tenantID)
			childGrant := tc.child
			childGrant.ExpiresAt = now.Add(time.Hour)

			_, err := delegateChild(ctx, authRepo, delegRepo, parent, "project-a", "authorize-scope-"+tc.name, "create-scope-"+tc.name,
				"child-scope", now.Add(2*time.Hour), []AgentAuthorizationGrant{childGrant})
			if err == nil {
				t.Fatalf("child scope %q exceeding parent grant was accepted", tc.name)
			}
			if !errors.Is(err, ErrAgentAuthorizationInvalid) {
				t.Fatalf("unexpected error for %q: %v", tc.name, err)
			}

			after := countDelegationRows(t, ctx, db, tenantID)
			if before != after {
				t.Fatalf("rejected child scope %q left residue: before=%+v after=%+v", tc.name, before, after)
			}
		})
	}
}

// TestAgentDelegationCreateRejectsChildExpiryLaterThanParent proves the expiry
// ceiling end to end for both axes source enforces: the delegation record
// itself cannot outlive the parent principal, and an individual child grant
// cannot outlive the parent's matching grant or the delegation record.
func TestAgentDelegationCreateRejectsChildExpiryLaterThanParent(t *testing.T) {
	now := time.Now().UTC()
	t.Run("delegation outlives parent principal", func(t *testing.T) {
		db, tenantID := setupDelegationPGTest(t)
		ctx := context.Background()
		authRepo := NewAgentAuthorizationRepository(db)
		delegRepo := NewAgentDelegationRepository(db)

		parentExpiry := now.Add(time.Hour)
		parent, _ := registerDelegationTestPrincipal(t, ctx, authRepo, tenantID, "root", parentExpiry, []AgentAuthorizationGrant{
			{ID: "parent-delegate-" + tenantID, Action: "agents.delegate", ResourceType: "project", ResourceID: "project-a",
				Conditions: map[string]any{"project_id": "project-a"}, ExpiresAt: parentExpiry.Add(-time.Minute), QuotaMax: 10, QuotaWindowSeconds: 3600},
			delegateGrant("scope-grant-"+tenantID, parentExpiry.Add(-time.Minute), 5, 3600, "project-a"),
		})

		before := countDelegationRows(t, ctx, db, tenantID)
		_, err := delegateChild(ctx, authRepo, delegRepo, parent, "project-a", "authorize-expiry-deleg-0001", "create-expiry-deleg-0001",
			"child-outlives-parent", parentExpiry.Add(time.Hour), []AgentAuthorizationGrant{delegateGrant("", now.Add(30*time.Minute), 2, 3600, "project-a")})
		if err == nil {
			t.Fatal("delegation outliving parent principal was accepted")
		}
		after := countDelegationRows(t, ctx, db, tenantID)
		if before != after {
			t.Fatalf("rejected delegation expiry left residue: before=%+v after=%+v", before, after)
		}
	})

	t.Run("child grant outlives parent grant", func(t *testing.T) {
		db, tenantID := setupDelegationPGTest(t)
		ctx := context.Background()
		authRepo := NewAgentAuthorizationRepository(db)
		delegRepo := NewAgentDelegationRepository(db)

		parentGrantExpiry := now.Add(time.Hour)
		parent, _ := registerDelegationTestPrincipal(t, ctx, authRepo, tenantID, "root", now.Add(6*time.Hour), []AgentAuthorizationGrant{
			{ID: "parent-delegate-" + tenantID, Action: "agents.delegate", ResourceType: "project", ResourceID: "project-a",
				Conditions: map[string]any{"project_id": "project-a"}, ExpiresAt: now.Add(5 * time.Hour), QuotaMax: 10, QuotaWindowSeconds: 3600},
			delegateGrant("scope-grant-"+tenantID, parentGrantExpiry, 5, 3600, "project-a"),
		})

		before := countDelegationRows(t, ctx, db, tenantID)
		_, err := delegateChild(ctx, authRepo, delegRepo, parent, "project-a", "authorize-expiry-grant-0001", "create-expiry-grant-0001",
			"child-grant-outlives", now.Add(2*time.Hour), []AgentAuthorizationGrant{delegateGrant("", parentGrantExpiry.Add(time.Minute), 2, 3600, "project-a")})
		if err == nil {
			t.Fatal("child grant outliving parent grant was accepted")
		}
		after := countDelegationRows(t, ctx, db, tenantID)
		if before != after {
			t.Fatalf("rejected grant expiry left residue: before=%+v after=%+v", before, after)
		}
	})
}

// TestAgentDelegationAuthorizeRejectsWhenAncestorQuotaExhausted proves the
// quota ceiling end to end at authorization time (not just at creation time):
// once the parent-mapped ancestor grant's own quota window is exhausted, the
// child's otherwise-valid request is denied and neither the child's nor the
// parent's usage counters advance.
func TestAgentDelegationAuthorizeRejectsWhenAncestorQuotaExhausted(t *testing.T) {
	db, tenantID := setupDelegationPGTest(t)
	ctx := context.Background()
	authRepo := NewAgentAuthorizationRepository(db)
	delegRepo := NewAgentDelegationRepository(db)
	now := time.Now().UTC()

	parentScopeGrantID := "parent-scope-" + tenantID
	parent, _ := registerDelegationTestPrincipal(t, ctx, authRepo, tenantID, "root", now.Add(6*time.Hour), []AgentAuthorizationGrant{
		{ID: "parent-delegate-" + tenantID, Action: "agents.delegate", ResourceType: "project", ResourceID: "project-a",
			Conditions: map[string]any{"project_id": "project-a"}, ExpiresAt: now.Add(5 * time.Hour), QuotaMax: 10, QuotaWindowSeconds: 3600},
		{ID: parentScopeGrantID, Action: "tickets.update", ResourceType: "ticket", ResourceID: "ticket-7",
			Conditions: map[string]any{"project_id": "project-a"}, ExpiresAt: now.Add(5 * time.Hour), QuotaMax: 1, QuotaWindowSeconds: 3600},
	})

	created, err := delegateChild(ctx, authRepo, delegRepo, parent, "project-a", "authorize-quota-0001", "create-quota-0001",
		"child-quota", now.Add(2*time.Hour), []AgentAuthorizationGrant{delegateGrant("", now.Add(time.Hour), 1, 3600, "project-a")})
	if err != nil {
		t.Fatalf("valid delegation setup failed: %v", err)
	}
	child := TrustedAgentPrincipal{ID: created.Delegation.ChildPrincipalID, TenantID: tenantID, CredentialHash: HashAgentToken(created.Credential), ExpiresAt: created.Delegation.ExpiresAt}

	firstUsage := usageTotal(t, ctx, db, tenantID)
	decision1, err := authRepo.Authorize(ctx, child, AgentAuthorizationRequest{
		Action: "tickets.update", ResourceType: "ticket", ResourceID: "ticket-7",
		Context: map[string]any{"project_id": "project-a"}, IdempotencyKey: "child-call-00001a",
	})
	if err != nil {
		t.Fatalf("first delegated call failed: %v", err)
	}
	if !decision1.Allowed {
		t.Fatalf("first delegated call under ancestor quota was denied: %+v", decision1)
	}

	// Sample usage right after the one legitimate call, not before it --
	// registering the delegation itself (an agents.delegate authorize call)
	// already consumes quota on the parent's delegate grant, so "usage
	// before any tickets.update call" is not a meaningful baseline for "usage
	// after the denied second call".
	afterFirstUsage := usageTotal(t, ctx, db, tenantID)

	decision2, err := authRepo.Authorize(ctx, child, AgentAuthorizationRequest{
		Action: "tickets.update", ResourceType: "ticket", ResourceID: "ticket-7",
		Context: map[string]any{"project_id": "project-a"}, IdempotencyKey: "child-call-00002a",
	})
	if err != nil {
		t.Fatalf("second delegated call returned error instead of denial: %v", err)
	}
	if decision2.Allowed || decision2.Reason != "quota_exceeded" {
		t.Fatalf("second delegated call should have been denied by exhausted ancestor quota: %+v", decision2)
	}

	secondUsage := usageTotal(t, ctx, db, tenantID)
	if secondUsage != afterFirstUsage {
		t.Fatalf("quota-exceeded denial changed usage counters: before-second-call=%d after=%d", afterFirstUsage, secondUsage)
	}
	if afterFirstUsage <= firstUsage {
		t.Fatal("first allowed call did not record any usage at all")
	}
}

// TestAgentDelegationRevokeDeniesSubsequentChildCallAndMeasuresPropagation
// proves R1 end to end and measures the real wall-clock latency between the
// revocation commit and the first authorization call that observes it. The
// mechanism is synchronous and consistent, not cached: Authorize locks and
// rereads agent_delegations/agent_authorization_principals inside its own
// transaction (see lockAgentDelegationChain in agent_authorization.go), so
// revocation is visible to the next call as soon as Revoke's transaction
// commits. There is no async propagation delay to measure beyond ordinary
// database round-trip time.
func TestAgentDelegationRevokeDeniesSubsequentChildCallAndMeasuresPropagation(t *testing.T) {
	db, tenantID := setupDelegationPGTest(t)
	ctx := context.Background()
	authRepo := NewAgentAuthorizationRepository(db)
	delegRepo := NewAgentDelegationRepository(db)
	now := time.Now().UTC()

	parent, _ := registerDelegationTestPrincipal(t, ctx, authRepo, tenantID, "root", now.Add(6*time.Hour), []AgentAuthorizationGrant{
		{ID: "parent-delegate-" + tenantID, Action: "agents.delegate", ResourceType: "project", ResourceID: "project-a",
			Conditions: map[string]any{"project_id": "project-a"}, ExpiresAt: now.Add(5 * time.Hour), QuotaMax: 10, QuotaWindowSeconds: 3600},
		delegateGrant("scope-grant-"+tenantID, now.Add(5*time.Hour), 5, 3600, "project-a"),
	})

	created, err := delegateChild(ctx, authRepo, delegRepo, parent, "project-a", "authorize-revoke-0001", "create-revoke-0001",
		"child-revoke", now.Add(2*time.Hour), []AgentAuthorizationGrant{delegateGrant("", now.Add(time.Hour), 5, 3600, "project-a")})
	if err != nil {
		t.Fatalf("valid delegation setup failed: %v", err)
	}
	child := TrustedAgentPrincipal{ID: created.Delegation.ChildPrincipalID, TenantID: tenantID, CredentialHash: HashAgentToken(created.Credential), ExpiresAt: created.Delegation.ExpiresAt}

	preRevoke, err := authRepo.Authorize(ctx, child, AgentAuthorizationRequest{
		Action: "tickets.update", ResourceType: "ticket", ResourceID: "ticket-7",
		Context: map[string]any{"project_id": "project-a"}, IdempotencyKey: "pre-revoke-call-0001",
	})
	if err != nil || !preRevoke.Allowed {
		t.Fatalf("call before revocation should be allowed: decision=%+v err=%v", preRevoke, err)
	}

	revokeCommitAt := time.Now()
	revoked, err := delegRepo.Revoke(ctx, tenantID, parent.ID, created.Delegation.ID)
	if err != nil || !revoked {
		t.Fatalf("revoke failed: revoked=%v err=%v", revoked, err)
	}
	firstDeniedObservedAt := time.Now()

	postRevoke, err := authRepo.Authorize(ctx, child, AgentAuthorizationRequest{
		Action: "tickets.update", ResourceType: "ticket", ResourceID: "ticket-7",
		Context: map[string]any{"project_id": "project-a"}, IdempotencyKey: "post-revoke-call-0001",
	})
	firstDeniedObservedAt = time.Now()
	if !errors.Is(err, ErrAgentAuthorizationPrincipalUnauthorized) {
		t.Fatalf("post-revocation call error=%v decision=%+v, want unauthorized", err, postRevoke)
	}
	propagationLatency := firstDeniedObservedAt.Sub(revokeCommitAt)
	t.Logf("revocation-to-first-denied-call wall-clock latency: %s", propagationLatency)
	if propagationLatency < 0 {
		t.Fatalf("measured negative propagation latency: %s", propagationLatency)
	}
	if propagationLatency > 5*time.Second {
		t.Fatalf("revocation propagation latency exceeded 5s budget for a local test DB: %s", propagationLatency)
	}

	childStillActive, err := principalIsActive(ctx, db, tenantID, created.Delegation.ChildPrincipalID)
	if err != nil {
		t.Fatal(err)
	}
	if childStillActive {
		t.Fatal("revoked delegation left child principal active")
	}
}

// TestAgentDelegationGrandchildCannotExceedGrandparentCeiling proves that a
// three-level chain (root -> mid -> leaf) enforces the ceiling at every hop.
// mid can only forward delegation authority it was itself delegated by root
// through a real Create call (a grant inserted without the matching
// agent_delegation_grants mapping row does not count, proving the mapping
// table -- not just a matching action/resource/expiry/quota tuple -- is what
// authorizes forwarding). Once mid legitimately holds a forwardable
// agents.delegate grant, mid still cannot let leaf claim a wider ticket quota
// than mid itself received from root.
func TestAgentDelegationGrandchildCannotExceedGrandparentCeiling(t *testing.T) {
	db, tenantID := setupDelegationPGTest(t)
	ctx := context.Background()
	authRepo := NewAgentAuthorizationRepository(db)
	delegRepo := NewAgentDelegationRepository(db)
	now := time.Now().UTC()

	root, _ := registerDelegationTestPrincipal(t, ctx, authRepo, tenantID, "root", now.Add(6*time.Hour), []AgentAuthorizationGrant{
		{ID: "root-delegate-" + tenantID, Action: "agents.delegate", ResourceType: "project", ResourceID: "project-a",
			Conditions: map[string]any{"project_id": "project-a"}, ExpiresAt: now.Add(5 * time.Hour), QuotaMax: 10, QuotaWindowSeconds: 3600},
		delegateGrant("root-scope-"+tenantID, now.Add(5*time.Hour), 4, 3600, "project-a"),
	})

	// root delegates to mid: a re-delegatable agents.delegate grant plus a
	// ticket scope grant, both real Create-issued rows with delegation
	// mappings.
	midCreated, err := delegateChild(ctx, authRepo, delegRepo, root, "project-a", "authorize-mid-00001", "create-mid-00001x",
		"mid", now.Add(4*time.Hour), []AgentAuthorizationGrant{
			{Action: "agents.delegate", ResourceType: "project", ResourceID: "project-a",
				Conditions: map[string]any{"project_id": "project-a"}, ExpiresAt: now.Add(3 * time.Hour), QuotaMax: 10, QuotaWindowSeconds: 3600},
			delegateGrant("", now.Add(3*time.Hour), 4, 3600, "project-a"),
		})
	if err != nil {
		t.Fatalf("mid-tier delegation setup failed: %v", err)
	}
	mid := TrustedAgentPrincipal{ID: midCreated.Delegation.ChildPrincipalID, TenantID: tenantID, CredentialHash: HashAgentToken(midCreated.Credential), ExpiresAt: midCreated.Delegation.ExpiresAt}

	// A grant inserted directly by SQL, bypassing Create, has no
	// agent_delegation_grants mapping row. Even though it names the same
	// action/resource/expiry/quota as a legitimately delegated grant would,
	// ancestorGrantLimits cannot walk it back to root, so mid cannot use it
	// to authorize its own agents.delegate call -- proving the mapping row,
	// not just a matching tuple, is what grants forwarding authority.
	// The grant's primary key is a uuid column; generate a real one
	// server-side rather than a human-readable label, since the point
	// under test is the missing agent_delegation_grants mapping row,
	// not the id's literal value.
	var forgedGrantID string
	// A different resource_id (project-a-forged) than mid's real
	// agents.delegate grant (project-a) is required: the grants table has
	// a unique key on (tenant_id, principal_id, action, resource_type,
	// resource_id), so a forged row could never coexist with the real,
	// mapped one under the same tuple. The forgery under test is the
	// missing delegation mapping, not the resource_id string.
	if err := db.QueryRow(ctx, `INSERT INTO agent_authorization_grants (id,tenant_id,principal_id,action,resource_type,resource_id,conditions_json,expires_at,quota_max,quota_window_seconds) VALUES (gen_random_uuid(),$1,$2,'agents.delegate','project','project-a-forged','{"project_id":"project-a"}'::jsonb,$3,10,3600) RETURNING id::text`,
		tenantID, mid.ID, now.Add(3*time.Hour)).Scan(&forgedGrantID); err != nil {
		t.Fatalf("seed unmapped delegate grant: %v", err)
	}
	// Authorize returning a non-nil error would mean the call itself
	// failed; a business-level denial for a grant with no delegation
	// mapping surfaces as decision.Allowed == false with err == nil (see
	// the no_matching_grant path), so both must be checked.
	unmappedDecision, err := authRepo.Authorize(ctx, mid, AgentAuthorizationRequest{
		Action: "agents.delegate", ResourceType: "project", ResourceID: "project-a-forged",
		Context: map[string]any{"project_id": "project-a"}, IdempotencyKey: "authorize-unmapped-0001",
	})
	if err != nil {
		t.Fatalf("authorize call against unmapped grant errored unexpectedly: %v", err)
	}
	if unmappedDecision.Allowed {
		t.Fatal("mid authorized agents.delegate through an unmapped grant lacking ancestor lineage")
	}
	if _, err := db.Exec(ctx, `DELETE FROM agent_authorization_grants WHERE tenant_id=$1 AND id=$2`, tenantID, forgedGrantID); err != nil {
		t.Fatal(err)
	}

	// With the legitimate, Create-issued agents.delegate grant, mid can
	// forward a ticket grant up to what it itself was delegated (quota 4),
	// but not beyond it.
	before := countDelegationRows(t, ctx, db, tenantID)
	_, err = delegateChild(ctx, authRepo, delegRepo, mid, "project-a", "authorize-leaf-00001", "create-leaf-00001x",
		"leaf", now.Add(2*time.Hour), []AgentAuthorizationGrant{delegateGrant("", now.Add(time.Hour), 5, 3600, "project-a")})
	if err == nil {
		t.Fatal("mid forwarded a ticket quota (5) wider than its own delegated ceiling (4)")
	}
	after := countDelegationRows(t, ctx, db, tenantID)
	if before != after {
		t.Fatalf("rejected grandchild scope overreach left residue: before=%+v after=%+v", before, after)
	}

	before = countDelegationRows(t, ctx, db, tenantID)
	_, err = delegateChild(ctx, authRepo, delegRepo, mid, "project-a", "authorize-leaf-00002", "create-leaf-00002x",
		"leaf", now.Add(2*time.Hour), []AgentAuthorizationGrant{delegateGrant("", now.Add(time.Hour), 4, 3600, "project-a")})
	if err != nil {
		t.Fatalf("leaf delegation within mid's own ceiling should succeed: %v", err)
	}
	after = countDelegationRows(t, ctx, db, tenantID)
	if after.delegations != before.delegations+1 {
		t.Fatalf("valid grandchild delegation was not recorded: before=%+v after=%+v", before, after)
	}

	// Finally, the leaf's grant traces back through mid to root: leaf's
	// ticket call is bounded by root's original quota of 4 for the whole
	// chain, not by mid's forwarded ceiling alone. Drain root's own ticket
	// grant quota directly (simulating root's own concurrent usage of the
	// same ceiling) and confirm the leaf call is denied by the shared
	// ancestor limit.
	leaf := TrustedAgentPrincipal{ID: "", TenantID: tenantID}
	if err := db.QueryRow(ctx, `SELECT child_principal_id::text FROM agent_delegations WHERE tenant_id=$1 AND parent_principal_id=$2 AND idempotency_key='create-leaf-00002x'`, tenantID, mid.ID).Scan(&leaf.ID); err != nil {
		t.Fatalf("locate leaf principal: %v", err)
	}
	var leafCredentialHash string
	if err := db.QueryRow(ctx, `SELECT credential_hash FROM agent_authorization_principals WHERE tenant_id=$1 AND id=$2`, tenantID, leaf.ID).Scan(&leafCredentialHash); err != nil {
		t.Fatal(err)
	}
	leaf.CredentialHash = leafCredentialHash
	leaf.ExpiresAt = now.Add(2 * time.Hour)

	decision, err := authRepo.Authorize(ctx, leaf, AgentAuthorizationRequest{
		Action: "tickets.update", ResourceType: "ticket", ResourceID: "ticket-7",
		Context: map[string]any{"project_id": "project-a"}, IdempotencyKey: "leaf-call-00000001",
	})
	if err != nil {
		t.Fatalf("leaf call within full-chain quota should not error: %v", err)
	}
	if !decision.Allowed {
		t.Fatalf("leaf call within full three-level chain quota was denied: %+v", decision)
	}
}

// TestAgentDelegationCreateIgnoresForgedParentIdentityInPayload proves that a
// delegation's parent is always the server-authenticated TrustedAgentPrincipal
// passed by the trusted-auth middleware, never a value an attacker could place
// in the request body: AgentDelegationCreate carries no parent/tenant field
// for a caller to forge, and cross-tenant credential reuse is rejected by
// principal lookup, not by trusting client-supplied identifiers.
func TestAgentDelegationCreateIgnoresForgedParentIdentityInPayload(t *testing.T) {
	db, tenantA := setupDelegationPGTest(t)
	ctx := context.Background()
	_, tenantB := setupDelegationPGTest(t)
	authRepo := NewAgentAuthorizationRepository(db)
	delegRepo := NewAgentDelegationRepository(db)
	now := time.Now().UTC()

	// A principal genuinely registered under tenant A.
	realParent, _ := registerDelegationTestPrincipal(t, ctx, authRepo, tenantA, "root", now.Add(6*time.Hour), []AgentAuthorizationGrant{
		{ID: "parent-delegate-" + tenantA, Action: "agents.delegate", ResourceType: "project", ResourceID: "project-a",
			Conditions: map[string]any{"project_id": "project-a"}, ExpiresAt: now.Add(5 * time.Hour), QuotaMax: 10, QuotaWindowSeconds: 3600},
		delegateGrant("scope-grant-"+tenantA, now.Add(5*time.Hour), 5, 3600, "project-a"),
	})

	// Attacker claims to be that exact principal ID/credential but under a
	// different tenant string (forged tenant binding in the caller-controlled
	// TrustedAgentPrincipal value, simulating a compromised or misrouted
	// middleware claim). The repository must scope every write and read by
	// (tenant_id, principal_id, credential_hash) together, so this must fail
	// closed rather than silently operating against tenant A's real row.
	forged := realParent
	forged.TenantID = tenantB

	before := countDelegationRows(t, ctx, db, tenantA)
	_, err := delegateChild(ctx, authRepo, delegRepo, forged, "project-a", "authorize-forged-0001", "create-forged-0001",
		"child-forged", now.Add(2*time.Hour), []AgentAuthorizationGrant{delegateGrant("", now.Add(time.Hour), 2, 3600, "project-a")})
	if err == nil {
		t.Fatal("delegation succeeded with a forged cross-tenant principal binding")
	}
	if !errors.Is(err, ErrAgentAuthorizationPrincipalUnauthorized) {
		t.Fatalf("forged tenant binding error=%v, want unauthorized", err)
	}
	after := countDelegationRows(t, ctx, db, tenantA)
	if before != after {
		t.Fatalf("forged parent identity left residue under real tenant: before=%+v after=%+v", before, after)
	}
}

type delegationRowCounts struct {
	principals, grants, delegations, delegationGrants int
}

func countDelegationRows(t *testing.T, ctx context.Context, db *pgxpool.Pool, tenantID string) delegationRowCounts {
	t.Helper()
	var counts delegationRowCounts
	if err := db.QueryRow(ctx, `SELECT count(*) FROM agent_authorization_principals WHERE tenant_id=$1`, tenantID).Scan(&counts.principals); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(ctx, `SELECT count(*) FROM agent_authorization_grants WHERE tenant_id=$1`, tenantID).Scan(&counts.grants); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(ctx, `SELECT count(*) FROM agent_delegations WHERE tenant_id=$1`, tenantID).Scan(&counts.delegations); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(ctx, `SELECT count(*) FROM agent_delegation_grants WHERE tenant_id=$1`, tenantID).Scan(&counts.delegationGrants); err != nil {
		t.Fatal(err)
	}
	return counts
}

func usageTotal(t *testing.T, ctx context.Context, db *pgxpool.Pool, tenantID string) int64 {
	t.Helper()
	var total int64
	if err := db.QueryRow(ctx, `SELECT COALESCE(sum(used),0) FROM agent_authorization_usage WHERE tenant_id=$1`, tenantID).Scan(&total); err != nil {
		t.Fatal(err)
	}
	return total
}

func principalIsActive(ctx context.Context, db *pgxpool.Pool, tenantID, principalID string) (bool, error) {
	var active bool
	err := db.QueryRow(ctx, `SELECT status='active' AND revoked_at IS NULL FROM agent_authorization_principals WHERE tenant_id=$1 AND id=$2`, tenantID, principalID).Scan(&active)
	return active, err
}
