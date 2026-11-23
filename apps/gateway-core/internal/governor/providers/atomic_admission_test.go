package providers

import (
	"context"
	"errors"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/governor"
	"github.com/redis/go-redis/v9"
)

type staticAdmissionQuotaProvider struct {
	quotas []governor.ScopedQuota
	err    error
}

func (p staticAdmissionQuotaProvider) ScopedQuotas(context.Context, governor.ScopeRef) ([]governor.ScopedQuota, error) {
	return append([]governor.ScopedQuota(nil), p.quotas...), p.err
}

func atomicAdmissionRedis(t *testing.T) *redis.Client {
	t.Helper()
	rawURL := os.Getenv("ATOMIC_QUOTA_TEST_REDIS_URL")
	if rawURL == "" {
		t.Skip("ATOMIC_QUOTA_TEST_REDIS_URL is not set")
	}
	options, err := redis.ParseURL(rawURL)
	if err != nil {
		t.Fatal(err)
	}
	client := redis.NewClient(options)
	t.Cleanup(func() {
		_ = client.FlushDB(context.Background()).Err()
		_ = client.Close()
	})
	if err := client.FlushDB(context.Background()).Err(); err != nil {
		t.Fatal(err)
	}
	return client
}

func TestAtomicAdmissionReservesAllTrustedScopesAndReturnsLimitFacts(t *testing.T) {
	client := atomicAdmissionRedis(t)
	provider := staticAdmissionQuotaProvider{quotas: []governor.ScopedQuota{
		{Scope: "tenant", ID: "tenant-a", EnforcementMode: "enforce", Limits: governor.EffectiveQuotaInput{RPMLimit: 2, TPMLimit: 50, ConcurrencyLimit: 2}},
		{Scope: "project", ID: "project-a", EnforcementMode: "enforce", Limits: governor.EffectiveQuotaInput{RPMLimit: 10, TPMLimit: 100, ConcurrencyLimit: 5}},
		{Scope: "key", ID: "key-a", EnforcementMode: "enforce", Limits: governor.EffectiveQuotaInput{TPMLimit: 100}},
		// There is no trusted actor in the ref. A key-owner-derived user policy must stay inert.
		{Scope: "user", ID: "key-owner-user", EnforcementMode: "enforce", Limits: governor.EffectiveQuotaInput{TPMLimit: 1}},
	}}
	admission := NewAtomicAdmission(client, provider)
	ref := governor.ScopeRef{TenantID: "tenant-a", ProjectID: "project-a", KeyID: "key-a"}

	first, err := admission.Admit(context.Background(), governor.AdmissionRequest{Ref: ref, RequestID: "request-1", EstimatedTokens: 30})
	if err != nil {
		t.Fatalf("first admission: %v", err)
	}
	if duplicate, err := admission.Admit(context.Background(), governor.AdmissionRequest{Ref: ref, RequestID: "request-1", EstimatedTokens: 30}); err != nil || duplicate.RequestID != first.RequestID {
		t.Fatalf("idempotent duplicate admission lease=%+v err=%v", duplicate, err)
	}
	if _, err := admission.Admit(context.Background(), governor.AdmissionRequest{Ref: ref, RequestID: "request-1", EstimatedTokens: 31}); err == nil {
		t.Fatal("same request id with a different estimate must not return a fabricated lease")
	}
	provider.quotas[0].Limits.TPMLimit = 51
	if _, err := admission.Admit(context.Background(), governor.AdmissionRequest{Ref: ref, RequestID: "request-1", EstimatedTokens: 30}); err == nil {
		t.Fatal("same request id with a changed policy snapshot must fail idempotency validation")
	}
	provider.quotas[0].Limits.TPMLimit = 50

	_, err = admission.Admit(context.Background(), governor.AdmissionRequest{Ref: ref, RequestID: "request-2", EstimatedTokens: 25})
	var limitErr *governor.AdmissionLimitError
	if !errors.As(err, &limitErr) {
		t.Fatalf("second admission error=%v, want limit facts", err)
	}
	if limitErr.Metric != "tpm" || limitErr.Scope != "tenant" || limitErr.ScopeID != "tenant-a" ||
		limitErr.Limit != 50 || limitErr.Used != 0 || limitErr.Reserved != 30 || limitErr.Requested != 25 ||
		limitErr.RetryAfter <= 0 || limitErr.RequestID != "request-2" {
		t.Fatalf("unexpected limit facts: %+v", limitErr)
	}

	if err := admission.Settle(context.Background(), first, 20, 0, false); err != nil {
		t.Fatalf("settle first lease: %v", err)
	}
	if err := admission.Settle(context.Background(), first, 20, 0, false); err != nil {
		t.Fatalf("idempotent settle: %v", err)
	}
	if _, err := admission.Admit(context.Background(), governor.AdmissionRequest{Ref: ref, RequestID: "request-1", EstimatedTokens: 30}); err == nil {
		t.Fatal("a settled request must not be admitted again inside the idempotency window")
	}
	tenantScope := governor.AdmissionScope{Scope: "tenant", ID: "tenant-a"}
	if got := client.Get(context.Background(), atomicTPMKey("tenant-a", tenantScope, first.MinuteBucket)).Val(); got != "20" {
		t.Fatalf("settled TPM counter=%q, want 20", got)
	}
	second, err := admission.Admit(context.Background(), governor.AdmissionRequest{Ref: ref, RequestID: "request-2", EstimatedTokens: 25})
	if err != nil {
		t.Fatalf("second admission after settlement: %v", err)
	}
	if err := admission.Release(context.Background(), second, 10, 0); err != nil {
		t.Fatalf("release second lease: %v", err)
	}
	if err := admission.Release(context.Background(), second, 10, 0); err != nil {
		t.Fatalf("idempotent release: %v", err)
	}
	if got := client.Get(context.Background(), atomicTPMKey("tenant-a", tenantScope, first.MinuteBucket)).Val(); got != "30" {
		t.Fatalf("released TPM counter=%q, want settled 20 + failed actual 10", got)
	}
}

func TestAtomicAdmissionRejectsConcurrentRequestsSharingClientIdempotencyKey(t *testing.T) {
	client := atomicAdmissionRedis(t)
	admission := NewAtomicAdmission(client, staticAdmissionQuotaProvider{quotas: []governor.ScopedQuota{{
		Scope: "tenant", ID: "tenant-a", EnforcementMode: "enforce",
		Limits: governor.EffectiveQuotaInput{ConcurrencyLimit: 2},
	}}})
	ref := governor.ScopeRef{TenantID: "tenant-a"}

	type result struct {
		requestID string
		lease     *governor.AdmissionLease
		err       error
	}
	start := make(chan struct{})
	results := make(chan result, 2)
	var ready sync.WaitGroup
	ready.Add(2)
	for _, requestID := range []string{"server-request-1", "server-request-2"} {
		go func(requestID string) {
			ready.Done()
			<-start
			lease, err := admission.Admit(context.Background(), governor.AdmissionRequest{
				Ref: ref, RequestID: requestID, IdempotencyKey: "client-retry-key", EstimatedTokens: 10,
			})
			results <- result{requestID: requestID, lease: lease, err: err}
		}(requestID)
	}
	ready.Wait()
	close(start)

	var winner *governor.AdmissionLease
	var loserRequestID string
	for range 2 {
		outcome := <-results
		if outcome.err == nil {
			if winner != nil {
				t.Fatal("the same client idempotency key admitted two upstream requests")
			}
			winner = outcome.lease
			continue
		}
		var conflict *governor.AdmissionIdempotencyError
		if !errors.As(outcome.err, &conflict) || conflict.RequestID != outcome.requestID || conflict.State != "acquired" {
			t.Fatalf("duplicate request error=%#v, want acquired idempotency conflict", outcome.err)
		}
		loserRequestID = outcome.requestID
	}
	if winner == nil || loserRequestID == "" || winner.RequestID == loserRequestID {
		t.Fatalf("unexpected concurrent outcomes: winner=%+v loser=%q", winner, loserRequestID)
	}

	if err := admission.Settle(context.Background(), winner, 8, 0, false); err != nil {
		t.Fatalf("settle winner: %v", err)
	}
	_, err := admission.Admit(context.Background(), governor.AdmissionRequest{
		Ref: ref, RequestID: loserRequestID, IdempotencyKey: "client-retry-key", EstimatedTokens: 10,
	})
	var conflict *governor.AdmissionIdempotencyError
	if !errors.As(err, &conflict) || conflict.RequestID != loserRequestID || conflict.State != "settled" {
		t.Fatalf("settled duplicate error=%#v, want settled idempotency conflict", err)
	}

	released, err := admission.Admit(context.Background(), governor.AdmissionRequest{
		Ref: ref, RequestID: "release-owner", IdempotencyKey: "released-client-key", EstimatedTokens: 10,
	})
	if err != nil {
		t.Fatalf("admit release owner: %v", err)
	}
	if err := admission.Release(context.Background(), released, 0, 0); err != nil {
		t.Fatalf("release owner: %v", err)
	}
	_, err = admission.Admit(context.Background(), governor.AdmissionRequest{
		Ref: ref, RequestID: "release-contender", IdempotencyKey: "released-client-key", EstimatedTokens: 10,
	})
	if !errors.As(err, &conflict) || conflict.RequestID != "release-contender" || conflict.State != "released" {
		t.Fatalf("released duplicate error=%#v, want released idempotency conflict", err)
	}
}

func TestAtomicAdmissionCorruptStoredLeaseIsRuntimeFault(t *testing.T) {
	client := atomicAdmissionRedis(t)
	admission := NewAtomicAdmission(client, staticAdmissionQuotaProvider{})
	if err := client.Set(context.Background(), atomicLeaseKey("tenant-a", "corrupt-key"), "{not-json", time.Minute).Err(); err != nil {
		t.Fatal(err)
	}
	_, err := admission.Admit(context.Background(), governor.AdmissionRequest{
		Ref: governor.ScopeRef{TenantID: "tenant-a"}, RequestID: "request-a",
		IdempotencyKey: "corrupt-key", EstimatedTokens: 1,
	})
	var runtimeErr *governor.AdmissionRuntimeError
	if !errors.As(err, &runtimeErr) || runtimeErr.Metric != "runtime_fault" {
		t.Fatalf("corrupt lease error=%#v, want runtime fault", err)
	}
}

func TestAtomicAdmissionRecoversExpiredConcurrencyLease(t *testing.T) {
	client := atomicAdmissionRedis(t)
	admission := NewAtomicAdmission(client, staticAdmissionQuotaProvider{quotas: []governor.ScopedQuota{{
		Scope: "tenant", ID: "tenant-a", EnforcementMode: "enforce",
		Limits: governor.EffectiveQuotaInput{ConcurrencyLimit: 1},
	}}})
	admission.leaseTTL = 500 * time.Millisecond
	ref := governor.ScopeRef{TenantID: "tenant-a"}
	crashed, err := admission.Admit(context.Background(), governor.AdmissionRequest{Ref: ref, RequestID: "crashed", EstimatedTokens: 1})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := admission.Admit(context.Background(), governor.AdmissionRequest{Ref: ref, RequestID: "blocked", EstimatedTokens: 1}); err == nil {
		t.Fatal("active concurrency lease must block")
	}
	time.Sleep(100 * time.Millisecond)
	if err := admission.Heartbeat(context.Background(), crashed); err != nil {
		t.Fatalf("heartbeat: %v", err)
	}
	time.Sleep(100 * time.Millisecond)
	if _, err := admission.Admit(context.Background(), governor.AdmissionRequest{Ref: ref, RequestID: "still-blocked", EstimatedTokens: 1}); err == nil {
		t.Fatal("heartbeat must extend the active lease")
	}
	time.Sleep(500 * time.Millisecond)
	if _, err := admission.Admit(context.Background(), governor.AdmissionRequest{Ref: ref, RequestID: "recovered", EstimatedTokens: 1}); err != nil {
		t.Fatalf("expired lease did not recover: %v", err)
	}
}

func TestAtomicAdmissionUsesRedisTimeAndDoesNotReclaimActiveOwner(t *testing.T) {
	client := atomicAdmissionRedis(t)
	quota := staticAdmissionQuotaProvider{quotas: []governor.ScopedQuota{{
		Scope: "tenant", ID: "tenant-a", EnforcementMode: "enforce",
		Limits: governor.EffectiveQuotaInput{ConcurrencyLimit: 1, DailyTokenLimit: 100, OverageAction: "rate_limit"},
	}}}
	ahead := NewAtomicAdmission(client, quota)
	ahead.leaseTTL = time.Second
	ahead.now = func() time.Time { return time.Now().Add(48 * time.Hour) }
	lease, err := ahead.Admit(context.Background(), governor.AdmissionRequest{
		Ref: governor.ScopeRef{TenantID: "tenant-a"}, RequestID: "active-owner", EstimatedTokens: 10,
	})
	if err != nil {
		t.Fatal(err)
	}
	redisNow, err := client.Time(context.Background()).Result()
	if err != nil {
		t.Fatal(err)
	}
	if delta := lease.ExpiresAt.Sub(redisNow); delta < 500*time.Millisecond || delta > 2*time.Second {
		t.Fatalf("lease expiry used skewed gateway clock: redis_now=%s expires=%s delta=%s", redisNow, lease.ExpiresAt, delta)
	}

	scope := governor.AdmissionScope{Scope: "tenant", ID: "tenant-a"}
	// Simulate a stale index written by an old/skewed node. The logical lease
	// key and fingerprint remain authoritative and must prevent reclamation.
	if err := client.ZAdd(context.Background(), atomicReservationExpiryKey("tenant-a", scope), redis.Z{Score: 0, Member: lease.LeaseID}).Err(); err != nil {
		t.Fatal(err)
	}
	if err := client.ZAdd(context.Background(), atomicConcurrencyKey("tenant-a", scope), redis.Z{Score: 0, Member: lease.LeaseID}).Err(); err != nil {
		t.Fatal(err)
	}
	behind := NewAtomicAdmission(client, quota)
	behind.now = func() time.Time { return time.Now().Add(-48 * time.Hour) }
	_, err = behind.Admit(context.Background(), governor.AdmissionRequest{
		Ref: governor.ScopeRef{TenantID: "tenant-a"}, RequestID: "contender", EstimatedTokens: 1,
	})
	var limitErr *governor.AdmissionLimitError
	if !errors.As(err, &limitErr) || limitErr.Metric != "concurrency" {
		t.Fatalf("active owner was reclaimed after stale score: %v", err)
	}
	if got := client.Get(context.Background(), atomicDayReservationKey("tenant-a", scope, lease.DayBucket)).Val(); got != "10" {
		t.Fatalf("active token reservation was reclaimed: %q", got)
	}
}

func TestAtomicAdmissionLeaseCoversConfiguredRequestDuration(t *testing.T) {
	admission := NewAtomicAdmission(nil, staticAdmissionQuotaProvider{})
	admission.SetMaxRequestDuration(2 * time.Hour)
	if admission.leaseTTL < 2*time.Hour+admissionLeaseMargin {
		t.Fatalf("lease TTL=%s does not cover request duration and margin", admission.leaseTTL)
	}
}

func TestAtomicAdmissionReclaimsExpiredTokenReservations(t *testing.T) {
	client := atomicAdmissionRedis(t)
	admission := NewAtomicAdmission(client, staticAdmissionQuotaProvider{quotas: []governor.ScopedQuota{{
		Scope: "tenant", ID: "tenant-a", EnforcementMode: "enforce",
		Limits: governor.EffectiveQuotaInput{TPMLimit: 20, DailyTokenLimit: 20, MonthlyTokenLimit: 20, OverageAction: "rate_limit"},
	}}})
	admission.leaseTTL = 200 * time.Millisecond
	ref := governor.ScopeRef{TenantID: "tenant-a"}
	first, err := admission.Admit(context.Background(), governor.AdmissionRequest{
		Ref: ref, RequestID: "server-request-1", IdempotencyKey: "client-retry", EstimatedTokens: 15,
	})
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(350 * time.Millisecond)
	second, err := admission.Admit(context.Background(), governor.AdmissionRequest{
		Ref: ref, RequestID: "server-request-2", IdempotencyKey: "client-retry", EstimatedTokens: 15,
	})
	if err != nil {
		t.Fatalf("expired process lease kept token reservations: %v", err)
	}
	scope := governor.AdmissionScope{Scope: "tenant", ID: "tenant-a"}
	for name, key := range map[string]string{
		"tpm":   atomicTPMReservationKey("tenant-a", scope, second.MinuteBucket),
		"day":   atomicDayReservationKey("tenant-a", scope, second.DayBucket),
		"month": atomicMonthReservationKey("tenant-a", scope, second.MonthBucket),
	} {
		if got := client.Get(context.Background(), key).Val(); got != "15" {
			t.Fatalf("%s reservation=%q, want only the new lease amount", name, got)
		}
	}
	var conflict *governor.AdmissionIdempotencyError
	if err := admission.Settle(context.Background(), first, 10, 0, false); !errors.As(err, &conflict) {
		t.Fatalf("expired owner finalized replacement lease: %v", err)
	}
	if err := admission.Release(context.Background(), second, 0, 0); err != nil {
		t.Fatal(err)
	}
}

func TestAtomicAdmissionSoftBypassAndExplicitBlockSemantics(t *testing.T) {
	client := atomicAdmissionRedis(t)
	ref := governor.ScopeRef{TenantID: "tenant-a"}
	soft := NewAtomicAdmission(client, staticAdmissionQuotaProvider{quotas: []governor.ScopedQuota{{
		Scope: "tenant", ID: "tenant-a", EnforcementMode: "soft", Limits: governor.EffectiveQuotaInput{TPMConfigured: true, TPMLimit: 5},
	}}})
	lease, err := soft.Admit(context.Background(), governor.AdmissionRequest{Ref: ref, RequestID: "soft", EstimatedTokens: 6})
	if err != nil || len(lease.Observations) != 1 || lease.Observations[0].Metric != "tpm" {
		t.Fatalf("soft overage must be observed without blocking: lease=%+v err=%v", lease, err)
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	lease, err = soft.Admit(context.Background(), governor.AdmissionRequest{Ref: ref, RequestID: "soft-fault", EstimatedTokens: 1})
	if err != nil || lease.State != "observation_unavailable" {
		t.Fatalf("soft Redis fault must fail open visibly: lease=%+v err=%v", lease, err)
	}

	client = atomicAdmissionRedis(t)
	bypass := NewAtomicAdmission(client, staticAdmissionQuotaProvider{quotas: []governor.ScopedQuota{{
		Scope: "tenant", ID: "tenant-a", EnforcementMode: "bypass", Limits: governor.EffectiveQuotaInput{RPMLimit: 1},
	}}})
	lease, err = bypass.Admit(context.Background(), governor.AdmissionRequest{Ref: ref, RequestID: "bypass", EstimatedTokens: 3})
	if err != nil || lease.State != "acquired" {
		t.Fatalf("bypass accounting admission: lease=%+v err=%v", lease, err)
	}
	if err := bypass.Settle(context.Background(), lease, 2, 0, false); err != nil {
		t.Fatal(err)
	}
	if got := client.HGet(context.Background(), BudgetKey("tenant", "tenant-a", lease.MonthBucket), "tokens").Val(); got != "2" {
		t.Fatalf("bypass usage was not accounted: %q", got)
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	lease, err = bypass.Admit(context.Background(), governor.AdmissionRequest{Ref: ref, RequestID: "bypass-fault", EstimatedTokens: 1})
	if err != nil || lease.State != "observation_unavailable" {
		t.Fatalf("bypass accounting Redis fault must fail open visibly: lease=%+v err=%v", lease, err)
	}

	client = atomicAdmissionRedis(t)
	blocked := NewAtomicAdmission(client, staticAdmissionQuotaProvider{quotas: []governor.ScopedQuota{{
		Scope: "tenant", ID: "tenant-a", EnforcementMode: "enforce",
		Limits: governor.EffectiveQuotaInput{TPMBlocked: true},
	}}})
	_, err = blocked.Admit(context.Background(), governor.AdmissionRequest{Ref: ref, RequestID: "blocked", EstimatedTokens: 10})
	var limitErr *governor.AdmissionLimitError
	if !errors.As(err, &limitErr) || limitErr.Metric != "tpm" || limitErr.Limit != 0 || limitErr.Reserved != 0 || limitErr.Requested != 10 {
		t.Fatalf("explicit TPM block error=%#v", err)
	}
}

func TestAtomicAdmissionSafelyRejectsUnsupportedEnforcedTokenActions(t *testing.T) {
	tests := []struct {
		mode        string
		action      string
		wantBlocked bool
	}{
		{mode: "soft", action: "notify"},
		{mode: "soft", action: "rate_limit"},
		{mode: "soft", action: "pause_key"},
		{mode: "soft", action: "downgrade_model"},
		{mode: "enforce", action: "notify"},
		{mode: "enforce", action: "rate_limit", wantBlocked: true},
		{mode: "enforce", action: "pause_key", wantBlocked: true},
		{mode: "enforce", action: "downgrade_model", wantBlocked: true},
	}
	for _, tc := range tests {
		t.Run(tc.mode+"/"+tc.action, func(t *testing.T) {
			client := atomicAdmissionRedis(t)
			admission := NewAtomicAdmission(client, staticAdmissionQuotaProvider{quotas: []governor.ScopedQuota{{
				Scope: "tenant", ID: "tenant-a", EnforcementMode: tc.mode,
				Limits: governor.EffectiveQuotaInput{DailyTokenLimit: 5, OverageAction: tc.action},
			}}})
			lease, err := admission.Admit(context.Background(), governor.AdmissionRequest{
				Ref: governor.ScopeRef{TenantID: "tenant-a"}, RequestID: tc.mode + "-" + tc.action, EstimatedTokens: 6,
			})
			var limitErr *governor.AdmissionLimitError
			if tc.wantBlocked {
				if !errors.As(err, &limitErr) || limitErr.Metric != "day_tokens" {
					t.Fatalf("error=%#v, want atomic day-token rejection", err)
				}
				if (tc.action == "pause_key" || tc.action == "downgrade_model") && limitErr.ConfiguredAction != tc.action {
					t.Fatalf("configured action=%q, want explicit legacy action %q", limitErr.ConfiguredAction, tc.action)
				}
				return
			}
			if err != nil || lease == nil || len(lease.Observations) != 1 || lease.Observations[0].Metric != "day_tokens" {
				t.Fatalf("lease=%+v err=%v, want non-blocking observation", lease, err)
			}
		})
	}
}

func TestAtomicAdmissionReportsSettlementOverrunAfterAccountingActualTokens(t *testing.T) {
	client := atomicAdmissionRedis(t)
	admission := NewAtomicAdmission(client, staticAdmissionQuotaProvider{quotas: []governor.ScopedQuota{{
		Scope: "tenant", ID: "tenant-a", EnforcementMode: "enforce",
		Limits: governor.EffectiveQuotaInput{TPMConfigured: true, TPMLimit: 100},
	}}})
	lease, err := admission.Admit(context.Background(), governor.AdmissionRequest{Ref: governor.ScopeRef{TenantID: "tenant-a"}, RequestID: "overrun", EstimatedTokens: 10})
	if err != nil {
		t.Fatal(err)
	}
	err = admission.Settle(context.Background(), lease, 15, 0, false)
	var overrun *governor.AdmissionOverrunError
	if !errors.As(err, &overrun) || overrun.ActualTokens != 15 || overrun.EstimatedTokens != 10 {
		t.Fatalf("settlement overrun error=%#v", err)
	}
	scope := governor.AdmissionScope{Scope: "tenant", ID: "tenant-a"}
	if got := client.Get(context.Background(), atomicTPMKey("tenant-a", scope, lease.MinuteBucket)).Val(); got != "15" {
		t.Fatalf("overrun actual usage was not accounted: %q", got)
	}
}

func TestAtomicAdmissionIncludesDailyAndMonthlyReservations(t *testing.T) {
	client := atomicAdmissionRedis(t)
	admission := NewAtomicAdmission(client, staticAdmissionQuotaProvider{quotas: []governor.ScopedQuota{{
		Scope: "tenant", ID: "tenant-a", EnforcementMode: "enforce",
		Limits: governor.EffectiveQuotaInput{DailyTokenLimit: 40, MonthlyTokenLimit: 100, OverageAction: "rate_limit"},
	}}})
	ref := governor.ScopeRef{TenantID: "tenant-a"}
	first, err := admission.Admit(context.Background(), governor.AdmissionRequest{Ref: ref, RequestID: "period-1", EstimatedTokens: 30})
	if err != nil {
		t.Fatal(err)
	}
	_, err = admission.Admit(context.Background(), governor.AdmissionRequest{Ref: ref, RequestID: "period-2", EstimatedTokens: 15})
	var limitErr *governor.AdmissionLimitError
	if !errors.As(err, &limitErr) || limitErr.Metric != "day_tokens" || limitErr.Used != 0 || limitErr.Reserved != 30 || limitErr.Requested != 15 || limitErr.Limit != 40 {
		t.Fatalf("daily reservation facts=%#v", err)
	}

	scope := governor.AdmissionScope{Scope: "tenant", ID: "tenant-a"}
	if err := admission.Settle(context.Background(), first, 10, 0, false); err != nil {
		t.Fatal(err)
	}
	if day := client.HGet(context.Background(), BudgetKeyDay(scope.Scope, scope.ID, first.DayBucket), "tokens").Val(); day != "10" {
		t.Fatalf("atomic finalize day usage=%q, want 10", day)
	}
	if month := client.HGet(context.Background(), BudgetKey(scope.Scope, scope.ID, first.MonthBucket), "tokens").Val(); month != "10" {
		t.Fatalf("atomic finalize month usage=%q, want 10", month)
	}
	if _, err := admission.Admit(context.Background(), governor.AdmissionRequest{Ref: ref, RequestID: "period-2", EstimatedTokens: 15}); err != nil {
		t.Fatalf("released period reservations should allow next request: %v", err)
	}
}

func TestAtomicAdmissionEnforcesAndAccountsApplicationTeamAncestors(t *testing.T) {
	client := atomicAdmissionRedis(t)
	admission := NewAtomicAdmission(client, staticAdmissionQuotaProvider{quotas: []governor.ScopedQuota{
		{Scope: "team", ID: "team-root", EnforcementMode: "enforce", Limits: governor.EffectiveQuotaInput{DailyTokenLimit: 10, OverageAction: "rate_limit"}},
		{Scope: "team", ID: "team-child", EnforcementMode: "accounting"},
	}})
	ref := governor.ScopeRef{TenantID: "tenant-a", TeamID: "team-child", ProjectID: "project-a"}
	first, err := admission.Admit(context.Background(), governor.AdmissionRequest{Ref: ref, RequestID: "ancestor-1", EstimatedTokens: 7})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := admission.Admit(context.Background(), governor.AdmissionRequest{Ref: ref, RequestID: "ancestor-2", EstimatedTokens: 4}); err == nil {
		t.Fatal("parent team pool did not constrain the child application")
	}
	if err := admission.Settle(context.Background(), first, 6, 0, false); err != nil {
		t.Fatal(err)
	}
	for _, teamID := range []string{"team-root", "team-child"} {
		if got := client.HGet(context.Background(), BudgetKeyDay("team", teamID, first.DayBucket), "tokens").Val(); got != "6" {
			t.Fatalf("team %s tokens=%q, want 6", teamID, got)
		}
	}
}

func TestAtomicAdmissionAccountsWithoutCurrentPolicyAndFailsOpenWithoutRedis(t *testing.T) {
	client := atomicAdmissionRedis(t)
	provider := staticAdmissionQuotaProvider{}
	admission := NewAtomicAdmission(client, provider)
	ref := governor.ScopeRef{TenantID: "tenant-a", ProjectID: "project-a", KeyID: "key-a"}
	lease, err := admission.Admit(context.Background(), governor.AdmissionRequest{Ref: ref, RequestID: "accounting", EstimatedTokens: 10})
	if err != nil || lease.State != "acquired" {
		t.Fatalf("best-effort accounting admission lease=%+v err=%v", lease, err)
	}
	if err := admission.Settle(context.Background(), lease, 7, 0, false); err != nil {
		t.Fatal(err)
	}
	for _, scope := range []governor.AdmissionScope{{Scope: "tenant", ID: "tenant-a"}, {Scope: "project", ID: "project-a"}, {Scope: "key", ID: "key-a"}} {
		if got := client.HGet(context.Background(), BudgetKey(scope.Scope, scope.ID, lease.MonthBucket), "tokens").Val(); got != "7" {
			t.Fatalf("%s accounting tokens=%q, want 7", scope.Scope, got)
		}
	}

	withoutRedis := NewAtomicAdmission(nil, provider)
	lease, err = withoutRedis.Admit(context.Background(), governor.AdmissionRequest{Ref: ref, RequestID: "accounting-fault", EstimatedTokens: 10})
	if err != nil || lease.State != "observation_unavailable" {
		t.Fatalf("accounting-only Redis fault must not block: lease=%+v err=%v", lease, err)
	}
}

func TestAtomicAdmissionReturnsRuntimeFaultOnQuotaOrRedisFailure(t *testing.T) {
	client := atomicAdmissionRedis(t)
	ref := governor.ScopeRef{TenantID: "tenant-a"}
	admission := NewAtomicAdmission(client, staticAdmissionQuotaProvider{err: errors.New("database unavailable")})
	_, err := admission.Admit(context.Background(), governor.AdmissionRequest{Ref: ref, RequestID: "quota-fault", EstimatedTokens: 1})
	var runtimeErr *governor.AdmissionRuntimeError
	if !errors.As(err, &runtimeErr) || runtimeErr.Metric != "runtime_fault" || runtimeErr.RequestID != "quota-fault" {
		t.Fatalf("quota fault = %#v", err)
	}

	admission = NewAtomicAdmission(client, staticAdmissionQuotaProvider{quotas: []governor.ScopedQuota{{
		Scope: "tenant", ID: "tenant-a", EnforcementMode: "enforce",
		Limits: governor.EffectiveQuotaInput{RPMLimit: 1},
	}}})
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	_, err = admission.Admit(context.Background(), governor.AdmissionRequest{Ref: ref, RequestID: "redis-fault", EstimatedTokens: 1})
	if !errors.As(err, &runtimeErr) || runtimeErr.Metric != "runtime_fault" || runtimeErr.RequestID != "redis-fault" {
		t.Fatalf("redis fault = %#v", err)
	}
}

func TestAtomicAdmissionReservesAndSettlesBillableMicros(t *testing.T) {
	client := atomicAdmissionRedis(t)
	admission := NewAtomicAdmission(client, staticAdmissionQuotaProvider{quotas: []governor.ScopedQuota{{
		Scope: "tenant", ID: "tenant-a", EnforcementMode: "enforce",
		Limits: governor.EffectiveQuotaInput{
			DailyBudgetMicros: 100, MonthlyBudgetMicros: 200,
			OverageAction: "rate_limit", QuotaTimezone: "UTC",
		},
	}}})
	ref := governor.ScopeRef{TenantID: "tenant-a"}
	first, err := admission.Admit(context.Background(), governor.AdmissionRequest{
		Ref: ref, RequestID: "cost-1", EstimatedTokens: 5,
		EstimatedCostMicros: 60, CostEstimateAvailable: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = admission.Admit(context.Background(), governor.AdmissionRequest{
		Ref: ref, RequestID: "cost-2", EstimatedTokens: 5,
		EstimatedCostMicros: 50, CostEstimateAvailable: true,
	})
	var limitErr *governor.AdmissionLimitError
	if !errors.As(err, &limitErr) || limitErr.Metric != "day_cost_micros" ||
		limitErr.Limit != 100 || limitErr.Used != 0 || limitErr.Reserved != 60 || limitErr.Requested != 50 {
		t.Fatalf("money quota facts=%#v", err)
	}
	if err := admission.Settle(context.Background(), first, 4, 40, true); err != nil {
		t.Fatal(err)
	}
	scope := first.Scopes[0]
	if got := client.HGet(context.Background(), BudgetKeyDay(scope.Scope, scope.ID, scope.DayBucket), "cost_micros").Val(); got != "40" {
		t.Fatalf("settled day cost=%q, want 40", got)
	}
	if got := client.Get(context.Background(), atomicDayCostReservationKey("tenant-a", scope, scope.DayBucket)).Val(); got != "0" {
		t.Fatalf("day cost reservation=%q, want 0", got)
	}
	second, err := admission.Admit(context.Background(), governor.AdmissionRequest{
		Ref: ref, RequestID: "cost-2", EstimatedTokens: 5,
		EstimatedCostMicros: 50, CostEstimateAvailable: true,
	})
	if err != nil {
		t.Fatalf("settlement did not release unused cost reservation: %v", err)
	}
	if err := admission.Release(context.Background(), second, 0, 0); err != nil {
		t.Fatal(err)
	}
}

func TestAtomicAdmissionCostEstimateFailureModeIsExplicit(t *testing.T) {
	client := atomicAdmissionRedis(t)
	ref := governor.ScopeRef{TenantID: "tenant-a"}
	enforced := NewAtomicAdmission(client, staticAdmissionQuotaProvider{quotas: []governor.ScopedQuota{{
		Scope: "tenant", ID: "tenant-a", EnforcementMode: "enforce",
		Limits: governor.EffectiveQuotaInput{DailyBudgetMicros: 100, OverageAction: "rate_limit"},
	}}})
	_, err := enforced.Admit(context.Background(), governor.AdmissionRequest{Ref: ref, RequestID: "missing-cost", EstimatedTokens: 1})
	var runtimeErr *governor.AdmissionRuntimeError
	if !errors.As(err, &runtimeErr) {
		t.Fatalf("enforced money quota accepted an unavailable estimate: %v", err)
	}

	soft := NewAtomicAdmission(client, staticAdmissionQuotaProvider{quotas: []governor.ScopedQuota{{
		Scope: "tenant", ID: "tenant-a", EnforcementMode: "soft",
		Limits: governor.EffectiveQuotaInput{DailyBudgetMicros: 100, OverageAction: "notify"},
	}}})
	lease, err := soft.Admit(context.Background(), governor.AdmissionRequest{Ref: ref, RequestID: "soft-missing-cost", EstimatedTokens: 1})
	if err != nil || lease == nil || len(lease.Observations) == 0 || lease.Observations[0].Metric != "cost_estimate_unavailable" {
		t.Fatalf("soft missing estimate was not surfaced: lease=%+v err=%v", lease, err)
	}
	if err := soft.Settle(context.Background(), lease, 1, 0, false); err != nil {
		t.Fatal(err)
	}
	if got := client.HGet(context.Background(), BudgetKeyDay("tenant", "tenant-a", lease.Scopes[0].DayBucket), "cost_unpriced_requests").Val(); got != "1" {
		t.Fatalf("unpriced settlement quality=%q, want 1", got)
	}
	withEstimate := NewAtomicAdmission(client, staticAdmissionQuotaProvider{quotas: []governor.ScopedQuota{{
		Scope: "tenant", ID: "tenant-a", EnforcementMode: "enforce",
		Limits: governor.EffectiveQuotaInput{DailyBudgetMicros: 100, OverageAction: "rate_limit"},
	}}})
	observed, err := withEstimate.Admit(context.Background(), governor.AdmissionRequest{
		Ref: ref, RequestID: "priced-after-unpriced", EstimatedTokens: 1,
		EstimatedCostMicros: 1, CostEstimateAvailable: true,
	})
	if err != nil || len(observed.Observations) == 0 || observed.Observations[0].Metric != "day_cost_usage_incomplete" {
		t.Fatalf("historical unpriced usage was not surfaced as an observation: lease=%+v err=%v", observed, err)
	}
	if err := withEstimate.Release(context.Background(), observed, 0, 0); err != nil {
		t.Fatal(err)
	}
}

func TestAtomicAdmissionHonorsCanonicalBlockedDimensions(t *testing.T) {
	tests := []struct {
		name   string
		metric string
		limits governor.EffectiveQuotaInput
	}{
		{name: "rpm", metric: "rpm", limits: governor.EffectiveQuotaInput{RPMBlocked: true}},
		{name: "tpm", metric: "tpm", limits: governor.EffectiveQuotaInput{TPMBlocked: true}},
		{name: "concurrency", metric: "concurrency", limits: governor.EffectiveQuotaInput{ConcurrencyBlocked: true}},
		{name: "day tokens", metric: "day_tokens", limits: governor.EffectiveQuotaInput{DailyTokenBlocked: true}},
		{name: "month tokens", metric: "month_tokens", limits: governor.EffectiveQuotaInput{MonthlyTokenBlocked: true}},
		{name: "day cost", metric: "day_cost_micros", limits: governor.EffectiveQuotaInput{DailyBudgetBlocked: true}},
		{name: "month cost", metric: "month_cost_micros", limits: governor.EffectiveQuotaInput{MonthlyBudgetBlocked: true}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			admission := NewAtomicAdmission(nil, staticAdmissionQuotaProvider{quotas: []governor.ScopedQuota{{
				Scope: "tenant", ID: "tenant-a", EnforcementMode: "enforce", Limits: tc.limits,
			}}})
			_, err := admission.Admit(context.Background(), governor.AdmissionRequest{
				Ref: governor.ScopeRef{TenantID: "tenant-a"}, RequestID: tc.name,
				EstimatedTokens: 1, EstimatedCostMicros: 1, CostEstimateAvailable: true,
			})
			var limitErr *governor.AdmissionLimitError
			if !errors.As(err, &limitErr) || limitErr.Metric != tc.metric || limitErr.Limit != 0 {
				t.Fatalf("blocked dimension error=%#v", err)
			}
		})
	}
}

func TestAdmissionPeriodsRespectEachPolicyTimezone(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 30, 0, 0, time.UTC)
	utcMonth, utcDay, _, _, err := admissionPeriodsForTimezone(now, "UTC")
	if err != nil {
		t.Fatal(err)
	}
	laMonth, laDay, _, _, err := admissionPeriodsForTimezone(now, "America/Los_Angeles")
	if err != nil {
		t.Fatal(err)
	}
	if utcMonth != "2026-01" || utcDay != "2026-01-01" || laMonth != "2025-12" || laDay != "2025-12-31" {
		t.Fatalf("timezone buckets UTC=%s/%s LA=%s/%s", utcMonth, utcDay, laMonth, laDay)
	}
	if got := quotaPeriodBucket("Asia/Shanghai", "2026-01-01"); got != "2026-01-01" {
		t.Fatalf("default timezone key changed: %q", got)
	}
	if utcKey, laKey := quotaPeriodBucket("UTC", utcDay), quotaPeriodBucket("America/Los_Angeles", laDay); utcKey == utcDay || laKey == laDay || utcKey == laKey {
		t.Fatalf("custom timezone keys are not isolated: UTC=%q LA=%q", utcKey, laKey)
	}
	if _, _, _, _, err := admissionPeriodsForTimezone(now, "Not/A_Zone"); err == nil {
		t.Fatal("invalid quota timezone was accepted")
	}
}

func TestAdmissionPeriodTTLRespectsDSTDayLength(t *testing.T) {
	tests := []struct {
		name string
		now  time.Time
		want time.Duration
	}{
		{name: "spring forward", now: time.Date(2026, 3, 8, 5, 30, 0, 0, time.UTC), want: 22*time.Hour + 30*time.Minute},
		{name: "fall back", now: time.Date(2026, 11, 1, 4, 30, 0, 0, time.UTC), want: 24*time.Hour + 30*time.Minute},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, _, _, dayTTL, err := admissionPeriodsForTimezone(tc.now, "America/New_York")
			if err != nil {
				t.Fatal(err)
			}
			if untilReset := dayTTL - 24*time.Hour; untilReset != tc.want {
				t.Fatalf("time until local day reset=%s, want %s", untilReset, tc.want)
			}
		})
	}
}

// D6 (7.4): a model without a configured price is refused with an explicit
// price-missing error instead of a generic quota runtime fault.
func TestAtomicAdmissionAllowsUnpricedModel(t *testing.T) {
	client := atomicAdmissionRedis(t)
	ref := governor.ScopeRef{TenantID: "tenant-a", ModelName: "unpriced-model"}
	admission := NewAtomicAdmission(client, staticAdmissionQuotaProvider{quotas: []governor.ScopedQuota{{
		Scope: "tenant", ID: "tenant-a", EnforcementMode: "enforce",
		Limits: governor.EffectiveQuotaInput{DailyBudgetMicros: 100, OverageAction: "rate_limit"},
	}}})
	lease, err := admission.Admit(context.Background(), governor.AdmissionRequest{Ref: ref, RequestID: "unpriced", EstimatedTokens: 1, CostEstimateMissingPrice: true})
	if err != nil || lease == nil {
		t.Fatalf("unpriced must bypass money quota: %v", err)
	}
	if err := admission.Release(context.Background(), lease, 0, 0); err != nil {
		t.Fatal(err)
	}

}
