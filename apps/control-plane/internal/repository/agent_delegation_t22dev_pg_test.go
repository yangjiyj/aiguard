package repository

// T22.dev (2026-09-28) real-PostgreSQL lifecycle tests. They use the same
// AGENT_DELEGATION_TEST_DATABASE_URL gate as agent_delegation_negatives_pg_test.go
// and never run against a shared database by accident. Timings are measured
// with the real wall clock and the real database clock; nothing is mocked.

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"
)

func t22DevRoot(t *testing.T, ctx context.Context, authRepo *AgentAuthorizationRepository, tenantID string, now time.Time, ticketExpiry time.Time) TrustedAgentPrincipal {
	t.Helper()
	root, _ := registerDelegationTestPrincipal(t, ctx, authRepo, tenantID, "t22dev-root", now.Add(2*time.Hour), []AgentAuthorizationGrant{
		{Action: "agents.delegate", ResourceType: "project", ResourceID: "project-a",
			Conditions: map[string]any{"project_id": "project-a"}, ExpiresAt: now.Add(time.Hour), QuotaMax: 100, QuotaWindowSeconds: 3600},
		delegateGrant("", ticketExpiry, 1000, 3600, "project-a"),
	})
	return root
}

// t22DevChain builds root -> mid -> leaf through the real authorize + Create
// path and returns mid, leaf and the two delegation ids.
func t22DevChain(t *testing.T, ctx context.Context, authRepo *AgentAuthorizationRepository, delegRepo *AgentDelegationRepository, root TrustedAgentPrincipal, now time.Time, tag string) (TrustedAgentPrincipal, TrustedAgentPrincipal, string, string) {
	t.Helper()
	midCreated, err := delegateChild(ctx, authRepo, delegRepo, root, "project-a", "t22dev-auth-mid-"+tag, "t22dev-create-mid-"+tag,
		"t22dev-mid", now.Add(50*time.Minute), []AgentAuthorizationGrant{
			{Action: "agents.delegate", ResourceType: "project", ResourceID: "project-a",
				Conditions: map[string]any{"project_id": "project-a"}, ExpiresAt: now.Add(45 * time.Minute), QuotaMax: 100, QuotaWindowSeconds: 3600},
			delegateGrant("", now.Add(45*time.Minute), 1000, 3600, "project-a"),
		})
	if err != nil {
		t.Fatalf("mid delegation: %v", err)
	}
	mid := TrustedAgentPrincipal{ID: midCreated.Delegation.ChildPrincipalID, TenantID: root.TenantID, CredentialHash: HashAgentToken(midCreated.Credential), ExpiresAt: midCreated.Delegation.ExpiresAt}
	leafCreated, err := delegateChild(ctx, authRepo, delegRepo, mid, "project-a", "t22dev-auth-leaf-"+tag, "t22dev-create-leaf-"+tag,
		"t22dev-leaf", now.Add(40*time.Minute), []AgentAuthorizationGrant{delegateGrant("", now.Add(35*time.Minute), 1000, 3600, "project-a")})
	if err != nil {
		t.Fatalf("leaf delegation: %v", err)
	}
	leaf := TrustedAgentPrincipal{ID: leafCreated.Delegation.ChildPrincipalID, TenantID: root.TenantID, CredentialHash: HashAgentToken(leafCreated.Credential), ExpiresAt: leafCreated.Delegation.ExpiresAt}
	return mid, leaf, midCreated.Delegation.ID, leafCreated.Delegation.ID
}

func t22DevTicketCall(ctx context.Context, authRepo *AgentAuthorizationRepository, principal TrustedAgentPrincipal, key string) (bool, error) {
	decision, err := authRepo.Authorize(ctx, principal, AgentAuthorizationRequest{
		Action: "tickets.update", ResourceType: "ticket", ResourceID: "ticket-7",
		Context:        map[string]any{"project_id": "project-a", "run_id": "run-" + key, "instance_id": "inst-t22dev", "tool_call_id": "tool-" + key},
		IdempotencyKey: key,
	})
	if err != nil {
		return false, err
	}
	return decision.Allowed, nil
}

// Requirement: ancestor expiry propagates to every descendant, measured with
// the real clock. Descendant expiries are nested by construction at create
// time, so to isolate propagation the root's ticket grant is shortened in the
// database to expire ~2s from now while mid/leaf keep their own 1h grants.
func TestT22DevRealClockAncestorGrantExpiryDeniesGrandchild(t *testing.T) {
	db, tenantID := setupDelegationPGTest(t)
	ctx := context.Background()
	authRepo := NewAgentAuthorizationRepository(db)
	delegRepo := NewAgentDelegationRepository(db)
	now := time.Now().UTC()
	root := t22DevRoot(t, ctx, authRepo, tenantID, now, now.Add(time.Hour))
	_, leaf, _, _ := t22DevChain(t, ctx, authRepo, delegRepo, root, now, "expiry")

	if allowed, err := t22DevTicketCall(ctx, authRepo, leaf, "t22dev-expiry-pre-0001"); err != nil || !allowed {
		t.Fatalf("leaf call before ancestor expiry: allowed=%v err=%v", allowed, err)
	}
	var rootExpiry time.Time
	if err := db.QueryRow(ctx, `UPDATE agent_authorization_grants SET expires_at=clock_timestamp()+interval '2 seconds'
		WHERE tenant_id=$1 AND principal_id=$2 AND action='tickets.update' RETURNING expires_at`, tenantID, root.ID).Scan(&rootExpiry); err != nil {
		t.Fatalf("shorten root grant: %v", err)
	}
	var leafOwnExpiry time.Time
	if err := db.QueryRow(ctx, `SELECT expires_at FROM agent_authorization_grants WHERE tenant_id=$1 AND principal_id=$2 AND action='tickets.update'`, tenantID, leaf.ID).Scan(&leafOwnExpiry); err != nil {
		t.Fatal(err)
	}
	if !leafOwnExpiry.After(rootExpiry.Add(time.Minute)) {
		t.Fatalf("test setup: leaf grant %s must outlive root grant %s", leafOwnExpiry, rootExpiry)
	}
	var lastAllowed, firstDenied time.Time
	deadline := time.Now().Add(10 * time.Second)
	for i := 0; time.Now().Before(deadline); i++ {
		callStart := time.Now()
		allowed, err := t22DevTicketCall(ctx, authRepo, leaf, fmt.Sprintf("t22dev-expiry-poll-%05d", i))
		observed := time.Now()
		if err == nil && allowed {
			lastAllowed = callStart
			time.Sleep(20 * time.Millisecond)
			continue
		}
		firstDenied = observed
		break
	}
	if firstDenied.IsZero() {
		t.Fatal("grandchild was never denied after its root grant expired")
	}
	if !lastAllowed.IsZero() && lastAllowed.After(rootExpiry) {
		t.Fatalf("grandchild allowed at %s after root grant expired at %s", lastAllowed, rootExpiry)
	}
	lag := firstDenied.Sub(rootExpiry)
	t.Logf("T22DEV_MEASURE ancestor_grant_expiry_to_grandchild_denial=%s poll_interval=20ms last_allow_before_expiry=%s", lag, rootExpiry.Sub(lastAllowed))
	if lag > time.Second {
		t.Fatalf("ancestor expiry propagation %s exceeds the 1s contract bound", lag)
	}
	// After expiry nothing may be allowed through any replayed idempotency key either.
	if allowed, err := t22DevTicketCall(ctx, authRepo, leaf, "t22dev-expiry-pre-0001"); err == nil && allowed {
		t.Fatal("replayed pre-expiry allow was returned after ancestor expiry")
	}
}

// Requirement: an administrator revoking the root principal cascades to every
// descendant in the same transaction; measure revoke-return -> first denial.
func TestT22DevAdminRootRevokeCascadesToGrandchildAndReplay(t *testing.T) {
	db, tenantID := setupDelegationPGTest(t)
	ctx := context.Background()
	authRepo := NewAgentAuthorizationRepository(db)
	delegRepo := NewAgentDelegationRepository(db)
	now := time.Now().UTC()
	root := t22DevRoot(t, ctx, authRepo, tenantID, now, now.Add(time.Hour))
	mid, leaf, _, _ := t22DevChain(t, ctx, authRepo, delegRepo, root, now, "adminrevoke")
	if allowed, err := t22DevTicketCall(ctx, authRepo, leaf, "t22dev-admrev-pre-001"); err != nil || !allowed {
		t.Fatalf("leaf call before revoke: allowed=%v err=%v", allowed, err)
	}
	start := time.Now()
	found, err := authRepo.RevokePrincipal(ctx, tenantID, root.ID)
	returned := time.Now()
	if err != nil || !found {
		t.Fatalf("admin revoke root: found=%v err=%v", found, err)
	}
	_, err = t22DevTicketCall(ctx, authRepo, leaf, "t22dev-admrev-post-01")
	denied := time.Now()
	if !errors.Is(err, ErrAgentAuthorizationPrincipalUnauthorized) {
		t.Fatalf("grandchild after root revoke: err=%v, want unauthorized", err)
	}
	if _, err := t22DevTicketCall(ctx, authRepo, leaf, "t22dev-admrev-pre-001"); !errors.Is(err, ErrAgentAuthorizationPrincipalUnauthorized) {
		t.Fatalf("replayed pre-revoke allow after root revoke: err=%v", err)
	}
	for name, id := range map[string]string{"mid": mid.ID, "leaf": leaf.ID} {
		active, err := principalIsActive(ctx, db, tenantID, id)
		if err != nil || active {
			t.Fatalf("%s principal still active after root revoke: active=%v err=%v", name, active, err)
		}
	}
	var liveEdges int
	if err := db.QueryRow(ctx, `SELECT count(*) FROM agent_delegations WHERE tenant_id=$1 AND revoked_at IS NULL`, tenantID).Scan(&liveEdges); err != nil || liveEdges != 0 {
		t.Fatalf("live delegation edges after root revoke: %d err=%v", liveEdges, err)
	}
	t.Logf("T22DEV_MEASURE admin_root_revoke_txn=%s revoke_return_to_grandchild_denial=%s", returned.Sub(start), denied.Sub(returned))
}

// Requirement: under concurrency no descendant call that starts after the
// revoke transaction commits can be allowed. A worker hammers the leaf while
// the root's direct child delegation is revoked.
func TestT22DevConcurrentRevokeNeverAllowsAfterCommit(t *testing.T) {
	db, tenantID := setupDelegationPGTest(t)
	ctx := context.Background()
	authRepo := NewAgentAuthorizationRepository(db)
	delegRepo := NewAgentDelegationRepository(db)
	now := time.Now().UTC()
	root := t22DevRoot(t, ctx, authRepo, tenantID, now, now.Add(time.Hour))
	_, leaf, midDelegationID, _ := t22DevChain(t, ctx, authRepo, delegRepo, root, now, "concurrent")

	type sample struct {
		start, end time.Time
		allowed    bool
		err        error
	}
	var (
		mu      sync.Mutex
		samples []sample
		stop    = make(chan struct{})
		wg      sync.WaitGroup
	)
	for worker := 0; worker < 4; worker++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			for i := 0; ; i++ {
				select {
				case <-stop:
					return
				default:
				}
				s := sample{start: time.Now()}
				s.allowed, s.err = t22DevTicketCall(ctx, authRepo, leaf, fmt.Sprintf("t22dev-conc-%d-%05d", worker, i))
				s.end = time.Now()
				mu.Lock()
				samples = append(samples, s)
				mu.Unlock()
			}
		}(worker)
	}
	time.Sleep(300 * time.Millisecond)
	found, err := delegRepo.Revoke(ctx, tenantID, root.ID, midDelegationID)
	committed := time.Now()
	if err != nil || !found {
		close(stop)
		wg.Wait()
		t.Fatalf("revoke mid delegation: found=%v err=%v", found, err)
	}
	time.Sleep(300 * time.Millisecond)
	close(stop)
	wg.Wait()

	var before, after, allowedAfter, unexpected int
	var firstDeniedAfter time.Duration = -1
	for _, s := range samples {
		if s.err != nil && !errors.Is(s.err, ErrAgentAuthorizationPrincipalUnauthorized) {
			unexpected++
			t.Logf("unexpected error: %v", s.err)
		}
		if s.start.After(committed) {
			after++
			if s.allowed {
				allowedAfter++
			}
			continue
		}
		if s.allowed {
			before++
		}
		if !s.allowed && s.end.After(committed) {
			if d := s.end.Sub(committed); firstDeniedAfter < 0 || d < firstDeniedAfter {
				firstDeniedAfter = d
			}
		}
	}
	t.Logf("T22DEV_MEASURE concurrent_revoke samples=%d allowed_before=%d started_after_commit=%d allowed_after_commit=%d unexpected_errors=%d commit_to_inflight_denial=%s", len(samples), before, after, allowedAfter, unexpected, firstDeniedAfter)
	if before == 0 || after == 0 {
		t.Fatalf("concurrency window not exercised: allowed_before=%d started_after=%d", before, after)
	}
	if allowedAfter != 0 || unexpected != 0 {
		t.Fatalf("calls started after revoke commit were allowed=%d or failed unexpectedly=%d", allowedAfter, unexpected)
	}
}

// Requirement: cross-tenant isolation for every delegation surface.
func TestT22DevCrossTenantDelegationSurfacesAreInvisible(t *testing.T) {
	db, tenantA := setupDelegationPGTest(t)
	_, tenantB := setupDelegationPGTest(t)
	ctx := context.Background()
	authRepo := NewAgentAuthorizationRepository(db)
	delegRepo := NewAgentDelegationRepository(db)
	now := time.Now().UTC()
	rootA := t22DevRoot(t, ctx, authRepo, tenantA, now, now.Add(time.Hour))
	_, leafA, midDelegationID, leafDelegationID := t22DevChain(t, ctx, authRepo, delegRepo, rootA, now, "xtenant")
	if allowed, err := t22DevTicketCall(ctx, authRepo, leafA, "t22dev-xt-leafcall-01"); err != nil || !allowed {
		t.Fatalf("leaf A call: allowed=%v err=%v", allowed, err)
	}
	rootB := t22DevRoot(t, ctx, authRepo, tenantB, now, now.Add(time.Hour))

	// Tenant B's agent cannot revoke or read tenant A's delegations.
	if found, err := delegRepo.Revoke(ctx, tenantB, rootB.ID, midDelegationID); err != nil || found {
		t.Fatalf("tenant B revoked tenant A delegation: found=%v err=%v", found, err)
	}
	if calls, err := delegRepo.ListCalls(ctx, tenantB, rootB.ID, midDelegationID, 50); err != nil || len(calls) != 0 {
		t.Fatalf("tenant B read tenant A calls: n=%d err=%v", len(calls), err)
	}
	// Tenant A's root reads its own subtree (mid's agents.delegate call that
	// created the leaf, plus the leaf's ticket call) but not via a forged tenant.
	if calls, err := delegRepo.ListCalls(ctx, tenantA, rootA.ID, midDelegationID, 50); err != nil || len(calls) != 2 {
		t.Fatalf("tenant A root subtree calls: n=%d err=%v", len(calls), err)
	}
	// The leaf's credential replayed under tenant B is unauthorized.
	forged := leafA
	forged.TenantID = tenantB
	if _, err := t22DevTicketCall(ctx, authRepo, forged, "t22dev-xt-forged-001"); !errors.Is(err, ErrAgentAuthorizationPrincipalUnauthorized) {
		t.Fatalf("leaf credential under tenant B: err=%v", err)
	}
	// Tenant B admin investigation of tenant A's root finds nothing.
	if _, err := delegRepo.InvestigateTree(ctx, tenantB, rootA.ID, 50); !errors.Is(err, ErrAgentDelegationRootNotFound) {
		t.Fatalf("tenant B investigated tenant A root: err=%v", err)
	}
	if active, err := principalIsActive(ctx, db, tenantA, leafA.ID); err != nil || !active {
		t.Fatalf("cross-tenant attempts changed tenant A leaf: active=%v err=%v", active, err)
	}
	_ = leafDelegationID
}

// Requirement: a delegated child cannot use a request context to reach a
// different project; the denial is still recorded for investigation.
func TestT22DevDelegatedCallCannotSwitchProjectAndIsRecorded(t *testing.T) {
	db, tenantID := setupDelegationPGTest(t)
	ctx := context.Background()
	authRepo := NewAgentAuthorizationRepository(db)
	delegRepo := NewAgentDelegationRepository(db)
	now := time.Now().UTC()
	root := t22DevRoot(t, ctx, authRepo, tenantID, now, now.Add(time.Hour))
	_, leaf, _, leafDelegationID := t22DevChain(t, ctx, authRepo, delegRepo, root, now, "project")
	before := usageTotal(t, ctx, db, tenantID)
	decision, err := authRepo.Authorize(ctx, leaf, AgentAuthorizationRequest{
		Action: "tickets.update", ResourceType: "ticket", ResourceID: "ticket-7",
		Context: map[string]any{"project_id": "project-b"}, IdempotencyKey: "t22dev-proj-switch-01",
	})
	if err == nil && decision.Allowed {
		t.Fatal("delegated leaf was allowed into project-b")
	}
	if after := usageTotal(t, ctx, db, tenantID); after != before {
		t.Fatalf("cross-project denial consumed quota: %d -> %d", before, after)
	}
	var recorded, allowedRows int
	if err := db.QueryRow(ctx, `SELECT count(*), count(*) FILTER (WHERE allowed) FROM agent_delegation_calls WHERE tenant_id=$1 AND delegation_id=$2 AND authorization_idempotency_key='t22dev-proj-switch-01'`,
		tenantID, leafDelegationID).Scan(&recorded, &allowedRows); err != nil {
		t.Fatal(err)
	}
	if recorded != 1 || allowedRows != 0 {
		t.Fatalf("cross-project attempt investigation rows=%d allowed=%d, want 1/0", recorded, allowedRows)
	}
}

// Requirement: a T15 approval that was approved while the delegation was live
// cannot be claimed once an ancestor revokes the delegation.
func TestT22DevApprovedClaimRejectedAfterParentRevoke(t *testing.T) {
	db, tenantID := setupDelegationPGTest(t)
	ctx := context.Background()
	authRepo := NewAgentAuthorizationRepository(db)
	delegRepo := NewAgentDelegationRepository(db)
	now := time.Now().UTC()
	fileGrant := func(expiry time.Time) AgentAuthorizationGrant {
		return AgentAuthorizationGrant{Action: "file_write", ResourceType: "file", ResourceID: "/tmp/t22dev.txt",
			Conditions: map[string]any{"project_id": "project-a"}, ExpiresAt: expiry, QuotaMax: 100, QuotaWindowSeconds: 3600}
	}
	root, _ := registerDelegationTestPrincipal(t, ctx, authRepo, tenantID, "t22dev-root-t15", now.Add(2*time.Hour), []AgentAuthorizationGrant{
		{Action: "agents.delegate", ResourceType: "project", ResourceID: "project-a",
			Conditions: map[string]any{"project_id": "project-a"}, ExpiresAt: now.Add(time.Hour), QuotaMax: 100, QuotaWindowSeconds: 3600},
		fileGrant(now.Add(time.Hour)),
	})
	created, err := delegateChild(ctx, authRepo, delegRepo, root, "project-a", "t22dev-auth-t15-0001", "t22dev-create-t15-001",
		"t22dev-child-t15", now.Add(50*time.Minute), []AgentAuthorizationGrant{fileGrant(now.Add(45 * time.Minute))})
	if err != nil {
		t.Fatalf("delegate: %v", err)
	}
	child := TrustedAgentPrincipal{ID: created.Delegation.ChildPrincipalID, TenantID: tenantID, CredentialHash: HashAgentToken(created.Credential), ExpiresAt: created.Delegation.ExpiresAt}
	t13Key := "t22dev-t15-call-000001"
	decision, err := authRepo.Authorize(ctx, child, AgentAuthorizationRequest{Action: "file_write", ResourceType: "file", ResourceID: "/tmp/t22dev.txt",
		Context: map[string]any{"project_id": "project-a"}, IdempotencyKey: t13Key})
	if err != nil || !decision.Allowed {
		t.Fatalf("child T13: %+v %v", decision, err)
	}
	digest := t15DevDigest("t22dev")
	approval, _, err := authRepo.CreateAgentAuthorizationApproval(ctx, child, decision.GrantID, AgentAuthorizationApprovalInput{
		Action: "file_write", ResourceType: "file", ResourceID: "/tmp/t22dev.txt", ArgumentsSHA256: digest,
		AuthorizationIdempotencyKey: t13Key, ApprovalIdempotencyKey: t15DevKey("t15:req:", "t22dev-req")})
	if err != nil || approval.Status != "pending" {
		t.Fatalf("child approval request: %+v %v", approval, err)
	}
	if _, changed, err := authRepo.ResolveAgentAuthorizationApproval(ctx, tenantID, approval.ID, "approved", "admin-t22dev", "ok"); err != nil || !changed {
		t.Fatalf("approve: changed=%v err=%v", changed, err)
	}
	if found, err := delegRepo.Revoke(ctx, tenantID, root.ID, created.Delegation.ID); err != nil || !found {
		t.Fatalf("parent revoke: %v %v", found, err)
	}
	if _, err := authRepo.Authorize(ctx, child, AgentAuthorizationRequest{Action: "file_write", ResourceType: "file", ResourceID: "/tmp/t22dev.txt",
		Context: map[string]any{"project_id": "project-a"}, IdempotencyKey: t13Key}); !errors.Is(err, ErrAgentAuthorizationPrincipalUnauthorized) {
		t.Fatalf("T13 re-check after revoke: %v", err)
	}
	claim, err := authRepo.ClaimAgentAuthorizationApproval(ctx, child, decision.GrantID, approval.ID, AgentAuthorizationApprovalClaimInput{
		Action: "file_write", ResourceType: "file", ResourceID: "/tmp/t22dev.txt", ArgumentsSHA256: digest,
		AuthorizationIdempotencyKey: t13Key, ClaimIdempotencyKey: t15DevKey("t15:claim:", "t22dev-claim")})
	if !errors.Is(err, ErrAgentAuthorizationPrincipalUnauthorized) || (claim != nil && claim.Allowed) {
		t.Fatalf("approved claim after parent revoke: claim=%+v err=%v", claim, err)
	}
}

// Requirement: complete parent/child call investigation for a tenant admin.
func TestT22DevInvestigateTreeReturnsFullChainAndEffectiveStatus(t *testing.T) {
	db, tenantID := setupDelegationPGTest(t)
	ctx := context.Background()
	authRepo := NewAgentAuthorizationRepository(db)
	delegRepo := NewAgentDelegationRepository(db)
	now := time.Now().UTC()
	root := t22DevRoot(t, ctx, authRepo, tenantID, now, now.Add(time.Hour))
	mid, leaf, midDelegationID, leafDelegationID := t22DevChain(t, ctx, authRepo, delegRepo, root, now, "invest")
	if allowed, err := t22DevTicketCall(ctx, authRepo, mid, "t22dev-inv-mid-00001"); err != nil || !allowed {
		t.Fatalf("mid call: %v %v", allowed, err)
	}
	if allowed, err := t22DevTicketCall(ctx, authRepo, leaf, "t22dev-inv-leaf-0001"); err != nil || !allowed {
		t.Fatalf("leaf call: %v %v", allowed, err)
	}
	// An out-of-scope leaf call is denied and must also be visible.
	if d, err := authRepo.Authorize(ctx, leaf, AgentAuthorizationRequest{Action: "tickets.delete", ResourceType: "ticket", ResourceID: "ticket-7",
		Context: map[string]any{"project_id": "project-a"}, IdempotencyKey: "t22dev-inv-leaf-deny1"}); err != nil || d.Allowed {
		t.Fatalf("out-of-scope leaf call: %+v %v", d, err)
	}

	got, err := delegRepo.InvestigateTree(ctx, tenantID, root.ID, 50)
	if err != nil {
		t.Fatal(err)
	}
	if got.RootPrincipalID != root.ID || len(got.Delegations) != 2 {
		t.Fatalf("tree: %+v", got)
	}
	if n := got.Delegations[0]; n.DelegationID != midDelegationID || n.Depth != 1 || n.ParentPrincipalID != root.ID || n.ChildPrincipalID != mid.ID || n.EffectiveStatus != "active" {
		t.Fatalf("depth-1 node: %+v", n)
	}
	if n := got.Delegations[1]; n.DelegationID != leafDelegationID || n.Depth != 2 || n.ParentPrincipalID != mid.ID || n.ChildPrincipalID != leaf.ID || n.EffectiveStatus != "active" {
		t.Fatalf("depth-2 node: %+v", n)
	}
	if len(got.Calls) != 4 {
		t.Fatalf("calls: want 4 (mid agents.delegate, mid allow, leaf allow, leaf deny) once each, got %d: %+v", len(got.Calls), got.Calls)
	}
	byKey := map[string]AgentDelegationInvestigationCall{}
	for _, call := range got.Calls {
		byKey[call.AuthorizationIdempotencyKey] = call
	}
	leafCall := byKey["t22dev-inv-leaf-0001"]
	if !leafCall.Allowed || leafCall.Depth != 2 || leafCall.DelegationID != leafDelegationID || leafCall.CallingPrincipalID != leaf.ID ||
		fmt.Sprint(leafCall.PrincipalChain) != fmt.Sprint([]string{root.ID, mid.ID, leaf.ID}) ||
		leafCall.RunID != "run-t22dev-inv-leaf-0001" || leafCall.ToolCallID != "tool-t22dev-inv-leaf-0001" || leafCall.InstanceID != "inst-t22dev" {
		t.Fatalf("leaf call investigation row: %+v", leafCall)
	}
	if deny := byKey["t22dev-inv-leaf-deny1"]; deny.Allowed || deny.Reason == "" || deny.Action != "tickets.delete" || deny.Depth != 2 {
		t.Fatalf("leaf denial investigation row: %+v", deny)
	}
	if midCall := byKey["t22dev-inv-mid-00001"]; !midCall.Allowed || midCall.Depth != 1 || fmt.Sprint(midCall.PrincipalChain) != fmt.Sprint([]string{root.ID, mid.ID}) {
		t.Fatalf("mid call investigation row: %+v", midCall)
	}
	// A mid-level subtree investigation only sees the leaf.
	sub, err := delegRepo.InvestigateTree(ctx, tenantID, mid.ID, 50)
	if err != nil || len(sub.Delegations) != 1 || len(sub.Calls) != 2 {
		t.Fatalf("mid subtree: %+v %v", sub, err)
	}

	// After revoking root -> mid, the tree reports both edges revoked and the
	// history remains queryable.
	if found, err := delegRepo.Revoke(ctx, tenantID, root.ID, midDelegationID); err != nil || !found {
		t.Fatalf("revoke: %v %v", found, err)
	}
	after, err := delegRepo.InvestigateTree(ctx, tenantID, root.ID, 50)
	if err != nil || len(after.Delegations) != 2 || len(after.Calls) != 4 {
		t.Fatalf("after revoke: %+v %v", after, err)
	}
	for _, n := range after.Delegations {
		if n.Status != "revoked" || n.EffectiveStatus != "revoked" || n.RevokedAt == nil {
			t.Fatalf("node after revoke: %+v", n)
		}
	}
	if _, err := delegRepo.InvestigateTree(ctx, tenantID, "not-a-uuid", 50); !errors.Is(err, ErrAgentAuthorizationInvalid) {
		t.Fatalf("invalid root id: %v", err)
	}
}

// Ancestor revoked outside the cascade (e.g. a partially applied repair) must
// be reported as ancestor_inactive for still-active descendants.
func TestT22DevInvestigateTreeFlagsDescendantsOfInactiveAncestor(t *testing.T) {
	db, tenantID := setupDelegationPGTest(t)
	ctx := context.Background()
	authRepo := NewAgentAuthorizationRepository(db)
	delegRepo := NewAgentDelegationRepository(db)
	now := time.Now().UTC()
	root := t22DevRoot(t, ctx, authRepo, tenantID, now, now.Add(time.Hour))
	mid, _, midDelegationID, _ := t22DevChain(t, ctx, authRepo, delegRepo, root, now, "ancestor")
	if _, err := db.Exec(ctx, `UPDATE agent_delegations SET revoked_at=clock_timestamp() WHERE tenant_id=$1 AND id=$2`, tenantID, midDelegationID); err != nil {
		t.Fatal(err)
	}
	got, err := delegRepo.InvestigateTree(ctx, tenantID, root.ID, 10)
	if err != nil || len(got.Delegations) != 2 {
		t.Fatalf("tree: %+v %v", got, err)
	}
	if got.Delegations[0].Status != "revoked" || got.Delegations[1].Status != "active" || got.Delegations[1].EffectiveStatus != "ancestor_inactive" {
		t.Fatalf("effective status: %+v", got.Delegations)
	}
	if _, err := t22DevTicketCall(ctx, authRepo, mid, "t22dev-anc-mid-00001"); !errors.Is(err, ErrAgentAuthorizationPrincipalUnauthorized) {
		t.Fatalf("mid call under revoked edge: %v", err)
	}
}

// Requirement: the T15 approval repository itself (not only the HTTP handler's
// preceding T13 call) re-checks the full delegation ancestry. An ancestor grant
// that expires after approval must stop both new approval requests and claims.
func TestT22DevApprovalRepositoryRechecksAncestorGrantExpiry(t *testing.T) {
	db, tenantID := setupDelegationPGTest(t)
	ctx := context.Background()
	authRepo := NewAgentAuthorizationRepository(db)
	delegRepo := NewAgentDelegationRepository(db)
	now := time.Now().UTC()
	fileGrant := func(expiry time.Time) AgentAuthorizationGrant {
		return AgentAuthorizationGrant{Action: "file_write", ResourceType: "file", ResourceID: "/tmp/t22dev-anc.txt",
			Conditions: map[string]any{"project_id": "project-a"}, ExpiresAt: expiry, QuotaMax: 100, QuotaWindowSeconds: 3600}
	}
	root, _ := registerDelegationTestPrincipal(t, ctx, authRepo, tenantID, "t22dev-root-anc", now.Add(2*time.Hour), []AgentAuthorizationGrant{
		{Action: "agents.delegate", ResourceType: "project", ResourceID: "project-a",
			Conditions: map[string]any{"project_id": "project-a"}, ExpiresAt: now.Add(time.Hour), QuotaMax: 100, QuotaWindowSeconds: 3600},
		fileGrant(now.Add(time.Hour)),
	})
	created, err := delegateChild(ctx, authRepo, delegRepo, root, "project-a", "t22dev-auth-anc-0001", "t22dev-create-anc-001",
		"t22dev-child-anc", now.Add(50*time.Minute), []AgentAuthorizationGrant{fileGrant(now.Add(45 * time.Minute))})
	if err != nil {
		t.Fatalf("delegate: %v", err)
	}
	child := TrustedAgentPrincipal{ID: created.Delegation.ChildPrincipalID, TenantID: tenantID, CredentialHash: HashAgentToken(created.Credential), ExpiresAt: created.Delegation.ExpiresAt}
	t13Key := "t22dev-anc-call-000001"
	decision, err := authRepo.Authorize(ctx, child, AgentAuthorizationRequest{Action: "file_write", ResourceType: "file", ResourceID: "/tmp/t22dev-anc.txt",
		Context: map[string]any{"project_id": "project-a"}, IdempotencyKey: t13Key})
	if err != nil || !decision.Allowed {
		t.Fatalf("child T13: %+v %v", decision, err)
	}
	digest := t15DevDigest("t22dev-anc")
	approval, _, err := authRepo.CreateAgentAuthorizationApproval(ctx, child, decision.GrantID, AgentAuthorizationApprovalInput{
		Action: "file_write", ResourceType: "file", ResourceID: "/tmp/t22dev-anc.txt", ArgumentsSHA256: digest,
		AuthorizationIdempotencyKey: t13Key, ApprovalIdempotencyKey: t15DevKey("t15:req:", "t22dev-anc-req")})
	if err != nil {
		t.Fatalf("child approval request: %v", err)
	}
	if _, changed, err := authRepo.ResolveAgentAuthorizationApproval(ctx, tenantID, approval.ID, "approved", "admin-t22dev", "ok"); err != nil || !changed {
		t.Fatalf("approve: changed=%v err=%v", changed, err)
	}
	if _, err := db.Exec(ctx, `UPDATE agent_authorization_grants SET expires_at=clock_timestamp() WHERE tenant_id=$1 AND principal_id=$2 AND action='file_write'`, tenantID, root.ID); err != nil {
		t.Fatal(err)
	}
	claim, err := authRepo.ClaimAgentAuthorizationApproval(ctx, child, decision.GrantID, approval.ID, AgentAuthorizationApprovalClaimInput{
		Action: "file_write", ResourceType: "file", ResourceID: "/tmp/t22dev-anc.txt", ArgumentsSHA256: digest,
		AuthorizationIdempotencyKey: t13Key, ClaimIdempotencyKey: t15DevKey("t15:claim:", "t22dev-anc-claim")})
	if err == nil && claim != nil && claim.Allowed {
		t.Fatalf("approved claim succeeded after the ancestor grant expired: %+v", claim)
	}
	if !errors.Is(err, ErrAgentAuthorizationPrincipalUnauthorized) {
		t.Fatalf("claim after ancestor expiry: err=%v claim=%+v, want unauthorized", err, claim)
	}
	if _, _, err := authRepo.CreateAgentAuthorizationApproval(ctx, child, decision.GrantID, AgentAuthorizationApprovalInput{
		Action: "file_write", ResourceType: "file", ResourceID: "/tmp/t22dev-anc.txt", ArgumentsSHA256: t15DevDigest("t22dev-anc-2"),
		AuthorizationIdempotencyKey: t13Key, ApprovalIdempotencyKey: t15DevKey("t15:req:", "t22dev-anc-req-2")}); !errors.Is(err, ErrAgentAuthorizationPrincipalUnauthorized) {
		t.Fatalf("new approval request after ancestor expiry: err=%v, want unauthorized", err)
	}
	var claimed bool
	if err := db.QueryRow(ctx, `SELECT agent_authorization_claimed_at IS NOT NULL FROM agentguard_confirmations WHERE tenant_id=$1 AND id=$2`, tenantID, approval.ID).Scan(&claimed); err != nil || claimed {
		t.Fatalf("approval consumed after ancestor expiry: claimed=%v err=%v", claimed, err)
	}
}

// Regression (found by the T22.dev PREPARE sweep): the T13 retention cleanup
// compared window_start with "$1 - interval", which PostgreSQL typed as
// interval-interval and rejected, so quota buckets were never pruned.
func TestT22DevAgentAuthorizationPruneRunsOnPostgres(t *testing.T) {
	db, tenantID := setupDelegationPGTest(t)
	ctx := context.Background()
	authRepo := NewAgentAuthorizationRepository(db)
	now := time.Now().UTC()
	root := t22DevRoot(t, ctx, authRepo, tenantID, now, now.Add(time.Hour))
	if allowed, err := t22DevTicketCall(ctx, authRepo, root, "t22dev-prune-call-01"); err != nil || !allowed {
		t.Fatalf("seed call: %v %v", allowed, err)
	}
	if _, err := db.Exec(ctx, `UPDATE agent_authorization_usage SET window_start=window_start - interval '400 days' WHERE tenant_id=$1`, tenantID); err != nil {
		t.Fatal(err)
	}
	result, err := authRepo.PruneExpiredData(ctx)
	if err != nil {
		t.Fatalf("PruneExpiredData on PostgreSQL: %+v %v", result, err)
	}
	var remaining int
	if err := db.QueryRow(ctx, `SELECT count(*) FROM agent_authorization_usage WHERE tenant_id=$1`, tenantID).Scan(&remaining); err != nil || remaining != 0 || result.DeletedUsage < 1 {
		t.Fatalf("stale usage not pruned: remaining=%d result=%+v err=%v", remaining, result, err)
	}
}
