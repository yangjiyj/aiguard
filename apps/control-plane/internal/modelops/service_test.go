package modelops

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestConfigLimitsDefaultAndProtocolValidation(t *testing.T) {
	c := DefaultConfig()
	if c.Enabled || c.MaxOutputTokens != 128 || len(c.Protocols) != 3 {
		t.Fatalf("default %+v", c)
	}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*Config){func(c *Config) { c.IntervalSeconds = 59 }, func(c *Config) { c.Concurrency = 6 }, func(c *Config) { c.TimeoutSeconds = 61 }, func(c *Config) { c.MaxTargets = 101 }, func(c *Config) { c.MaxOutputTokens = 1025 }, func(c *Config) { c.FailureThreshold = 0 }, func(c *Config) { c.Protocols = []string{"chat", "chat"} }, func(c *Config) { c.Protocols = []string{"bogus"} }} {
		bad := DefaultConfig()
		change(&bad)
		if bad.Validate() == nil {
			t.Fatalf("invalid config accepted %+v", bad)
		}
	}
	for _, h := range []int{0, 6, 24, 72, 168} {
		if _, err := (ReadFilter{WindowHours: h}).validated(); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := (ReadFilter{WindowHours: 7}).validated(); !errors.Is(err, ErrInvalid) {
		t.Fatal("unbounded window")
	}
}
func TestOutcomeSanitizesSecretsAndRequiresValidatedPayload(t *testing.T) {
	o := Outcome{Success: true, HTTPStatus: 200, BodyValidated: false, ErrorKind: "Bearer secret-raw-response"}.sanitized()
	if o.Success || o.ErrorKind != "invalid_body" {
		t.Fatal(o)
	}
	o = Outcome{HTTPStatus: 900, LatencyMS: -1, ErrorKind: "raw-url?apikey=secret"}.sanitized()
	if o.ErrorKind != "upstream_error" || o.LatencyMS != 0 || o.HTTPStatus != 0 {
		t.Fatal(o)
	}
}
func TestTargetDigestBindsExactCredentialDeploymentAndStatus(t *testing.T) {
	fields := []string{"openai", "https://example.invalid", "api_key", "cred", "cipher", "model", "provider", "public", "deployment", "active", "active"}
	digest := func(v []string) string {
		return DigestTargetIdentity(v[0], v[1], v[2], v[3], v[4], v[5], v[6], v[7], v[8], v[9], v[10])
	}
	base := digest(fields)
	if len(base) != 64 {
		t.Fatal(base)
	}
	for i := range fields {
		copyFields := append([]string(nil), fields...)
		copyFields[i] += "changed"
		if digest(copyFields) == base {
			t.Fatalf("unbound identity field %d", i)
		}
	}
}

type fakeStore struct {
	Store
	mu        sync.Mutex
	cfg       Config
	targets   []Target
	records   []ProbeRecord
	claims    map[string]bool
	recordErr error
	renewErr  error
	released  string
}

func (f *fakeStore) GetConfig(context.Context, string) (Config, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.cfg, nil
}
func (f *fakeStore) ListManualTargets(ctx context.Context, tenant string, protocols []string) ([]Target, error) {
	return f.ListTargets(ctx, tenant, protocols)
}
func (f *fakeStore) ListTargets(_ context.Context, _ string, protocols []string) ([]Target, error) {
	if len(protocols) == 0 {
		return preferredTargets(f.targets), nil
	}
	out := []Target{}
	for _, t := range f.targets {
		for _, p := range protocols {
			if p == t.Protocol {
				out = append(out, t)
			}
		}
	}
	return out, nil
}
func (f *fakeStore) RecordManual(ctx context.Context, _, actor string, t Target, o Outcome) (ProbeRecord, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.recordErr != nil {
		return ProbeRecord{}, f.recordErr
	}
	if err := ctx.Err(); err != nil {
		return ProbeRecord{}, err
	}
	if t.ConfigVersion != f.cfg.Version {
		return ProbeRecord{}, ErrConflict
	}
	r := ProbeRecord{Target: t, Outcome: o, Actor: actor, Source: "manual", InvocationID: invocationID(ctx)}
	f.records = append(f.records, r)
	return r, nil
}
func (f *fakeStore) BeginManualTarget(ctx context.Context, _, _ string, t Target) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if ctx.Err() != nil {
		return false, ctx.Err()
	}
	if f.claims == nil {
		f.claims = map[string]bool{}
	}
	key := invocationID(ctx) + "/" + t.Key()
	if f.claims[key] {
		return false, nil
	}
	f.claims[key] = true
	return true, nil
}
func (f *fakeStore) RenewLease(context.Context, *Lease) error { return f.renewErr }
func (f *fakeStore) ReleaseLease(_ context.Context, _ *Lease, cursor string) error {
	f.released = cursor
	return nil
}
func (f *fakeStore) ClaimTarget(_ context.Context, _ *Lease, t Target) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.claims == nil {
		f.claims = map[string]bool{}
	}
	if f.claims[t.Key()] {
		return false, nil
	}
	f.claims[t.Key()] = true
	return true, nil
}
func (f *fakeStore) BeginScheduledDispatch(ctx context.Context, _ *Lease, _ Target) error {
	return ctx.Err()
}
func (f *fakeStore) Complete(ctx context.Context, _ *Lease, t Target, o Outcome) (ProbeRecord, error) {
	if ctx.Err() != nil {
		return ProbeRecord{}, ErrLeaseLost
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	r := ProbeRecord{Target: t, Outcome: o, Source: "scheduled", InvocationID: invocationID(ctx)}
	f.records = append(f.records, r)
	return r, nil
}
func testTarget(id, provider, protocol string) Target {
	return Target{ModelID: id, ProviderID: provider, Protocol: protocol, PreferredProtocol: protocol, ProviderType: "openai", Supported: true}
}

func TestManualCostVersionAndLimitsRejectBeforeNetwork(t *testing.T) {
	f := &fakeStore{cfg: DefaultConfig(), targets: []Target{testTarget("a", "p", "chat")}}
	var calls int
	s := NewService(f, ExecutorFunc(func(context.Context, string, Target) Outcome { calls++; return Outcome{} }))
	requests := []TestRequest{{ModelIDs: []string{"a"}, ExpectedConfigVersion: 1}, {ModelIDs: []string{"a"}, ConfirmCost: true, ExpectedConfigVersion: 99}, {ModelIDs: []string{"foreign"}, ConfirmCost: true, ExpectedConfigVersion: 1}, {ModelIDs: []string{"a", "a"}, ConfirmCost: true, ExpectedConfigVersion: 1}, {ModelIDs: []string{"a"}, Protocols: []string{"unknown"}, ConfirmCost: true, ExpectedConfigVersion: 1}}
	for _, req := range requests {
		if _, err := s.Test(context.Background(), "tenant", "actor", req); err == nil {
			t.Fatalf("unsafe test accepted %+v", req)
		}
	}
	if calls != 0 {
		t.Fatal("network called before validation")
	}
}
func TestManualRegisteredProtocolBudgetInvocationAndProviderAuthStop(t *testing.T) {
	f := &fakeStore{cfg: DefaultConfig(), targets: []Target{testTarget("a", "p", "messages"), testTarget("b", "p", "messages"), testTarget("c", "other", "chat")}}
	f.cfg.MaxOutputTokens = 137
	s := NewService(f, ExecutorFunc(func(ctx context.Context, _ string, target Target) Outcome {
		if target.MaxOutputTokens != 137 || target.TimeoutSeconds != 15 {
			t.Error("budget not frozen")
		}
		if _, ok := ctx.Deadline(); !ok {
			t.Error("probe has no timeout")
		}
		if target.ProviderID == "p" {
			return Outcome{HTTPStatus: 401, ErrorKind: "unauthorized"}
		}
		return Outcome{Success: true, HTTPStatus: 200, BodyValidated: true, LatencyMS: 17}
	}))
	r, err := s.Test(WithInvocation(context.Background(), "this-job"), "tenant", "actor", TestRequest{ModelIDs: []string{"a", "b", "c"}, ConfirmCost: true, ExpectedConfigVersion: 1})
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Items) != 2 || len(r.Skipped) != 1 || r.Skipped[0].ModelID != "b" || r.Skipped[0].Reason != "provider_auth_failed" {
		t.Fatalf("auth failure did not stop provider: %+v", r)
	}
	for _, x := range r.Items {
		if x.InvocationID != "this-job" {
			t.Fatal("reused invocation evidence")
		}
		if x.ModelID == "a" && x.Protocol != "messages" {
			t.Fatal("Claude wrong protocol")
		}
	}
}
func TestManualPersistenceFailureNeverReportsSuccess(t *testing.T) {
	f := &fakeStore{cfg: DefaultConfig(), targets: []Target{testTarget("a", "p", "chat")}, recordErr: errors.New("disk failure")}
	s := NewService(f, ExecutorFunc(func(context.Context, string, Target) Outcome {
		return Outcome{Success: true, HTTPStatus: 200, BodyValidated: true}
	}))
	r, err := s.Test(context.Background(), "tenant", "actor", TestRequest{ModelIDs: []string{"a"}, ConfirmCost: true, ExpectedConfigVersion: 1})
	if err == nil || !strings.Contains(err.Error(), "disk failure") {
		t.Fatal("false durable success")
	}
	if len(r.Skipped) != 1 || r.Skipped[0].Reason != "unknown_after_interruption" {
		t.Fatal("sent result fabricated as unsent")
	}
}
func TestManualConfigChangesCancelUnsentAndRejectOldResult(t *testing.T) {
	f := &fakeStore{cfg: DefaultConfig(), targets: []Target{testTarget("a", "p", "chat"), testTarget("b", "p", "chat")}}
	var calls int
	s := NewService(f, ExecutorFunc(func(context.Context, string, Target) Outcome {
		calls++
		f.mu.Lock()
		f.cfg.Version++
		f.mu.Unlock()
		return Outcome{Success: true, HTTPStatus: 200, BodyValidated: true}
	}))
	r, err := s.Test(context.Background(), "tenant", "actor", TestRequest{ModelIDs: []string{"a", "b"}, ConfirmCost: true, ExpectedConfigVersion: 1})
	if !errors.Is(err, ErrConflict) || calls != 1 || len(f.records) != 0 {
		t.Fatalf("changed configuration writes: calls=%d records=%d err=%v", calls, len(f.records), err)
	}
	if len(r.Skipped) != 2 || r.Skipped[0].Reason != "unknown_after_interruption" || r.Skipped[1].Reason != "configuration_changed" {
		t.Fatalf("terminal states misclassify actual sends %+v", r)
	}
}
func TestManualFrozenIdentityRejectsQueuedCredentialChangesBeforeNetwork(t *testing.T) {
	target := testTarget("a", "p", "chat")
	target.IdentityDigest = "new-credential"
	f := &fakeStore{cfg: DefaultConfig(), targets: []Target{target}}
	var calls int
	s := NewService(f, ExecutorFunc(func(context.Context, string, Target) Outcome { calls++; return Outcome{} }))
	ctx := WithTargetIdentities(context.Background(), map[string]string{"a": "old-credential"})
	_, err := s.Test(ctx, "tenant", "actor", TestRequest{ModelIDs: []string{"a"}, ConfirmCost: true, ExpectedConfigVersion: 1})
	if !errors.Is(err, ErrIdentityChanged) || calls != 0 || len(f.records) != 0 {
		t.Fatalf("queued job accepted new identity: calls=%d err=%v", calls, err)
	}
}
func TestSchedulerFairRotationSingleProtocolAndTargetCap(t *testing.T) {
	targets := []Target{testTarget("a", "p", "chat"), testTarget("b", "p", "chat"), testTarget("c", "p", "chat")}
	rotated := rotateTargets(targets, targets[0].Key())
	if rotated[0].ModelID != "b" || rotated[2].ModelID != "a" {
		t.Fatal("unfair rotation")
	}
	f := &fakeStore{cfg: DefaultConfig(), targets: append(targets, Target{ModelID: "a", ProviderID: "p", Protocol: "messages", PreferredProtocol: "chat"})}
	f.cfg.MaxTargets = 2
	s := NewService(f, ExecutorFunc(func(context.Context, string, Target) Outcome {
		return Outcome{Success: true, HTTPStatus: 200, BodyValidated: true}
	}))
	l := &Lease{TenantID: "tenant", Token: "batch", Epoch: 4, Config: f.cfg, Cursor: targets[0].Key()}
	if err := s.RunLease(context.Background(), l); err != nil {
		t.Fatal(err)
	}
	if len(f.records) != 2 || f.records[0].ModelID != "b" || f.records[1].ModelID != "c" || f.released != targets[2].Key() {
		t.Fatalf("unfair capped schedule %+v cursor=%s", f.records, f.released)
	}
	for _, r := range f.records {
		if r.InvocationID != "batch" {
			t.Fatal("scheduled invocation not isolated")
		}
	}
}
func TestSchedulerConcurrencyBoundAndLeaseLossAborts(t *testing.T) {
	f := &fakeStore{cfg: DefaultConfig()}
	for i := 0; i < 6; i++ {
		f.targets = append(f.targets, testTarget(fmt.Sprint(i), fmt.Sprint(i), "chat"))
	}
	f.cfg.Concurrency = 2
	var active, peak atomic.Int64
	s := NewService(f, ExecutorFunc(func(context.Context, string, Target) Outcome {
		n := active.Add(1)
		for {
			p := peak.Load()
			if n <= p || peak.CompareAndSwap(p, n) {
				break
			}
		}
		time.Sleep(5 * time.Millisecond)
		active.Add(-1)
		return Outcome{Success: true, HTTPStatus: 200, BodyValidated: true}
	}))
	if err := s.RunLease(context.Background(), &Lease{TenantID: "t", Token: "batch", Config: f.cfg}); err != nil {
		t.Fatal(err)
	}
	if peak.Load() > 2 || len(f.records) != 6 {
		t.Fatalf("concurrency=%d records=%d", peak.Load(), len(f.records))
	}
	lost := &fakeStore{cfg: DefaultConfig(), targets: []Target{testTarget("a", "p", "chat")}, renewErr: ErrLeaseLost}
	s = NewService(lost, ExecutorFunc(func(ctx context.Context, _ string, _ Target) Outcome {
		<-ctx.Done()
		return Outcome{ErrorKind: "cancelled"}
	}))
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	started := time.Now()
	err := s.RunLease(ctx, &Lease{TenantID: "t", Token: "lease", Config: lost.cfg})
	if !errors.Is(err, ErrLeaseLost) || time.Since(started) > 4*time.Second || len(lost.records) != 0 {
		t.Fatalf("lost lease did not abort: elapsed=%s result=%v records=%d", time.Since(started), err, len(lost.records))
	}
}
func TestUnsupportedNativeProtocolsRemainUnknownWithoutProbesOrAlerts(t *testing.T) {
	for _, typ := range []string{"future-native"} {
		target := testTarget("a", "p", "chat")
		target.ProviderType = typ
		target.Supported = false
		f := &fakeStore{cfg: DefaultConfig(), targets: []Target{target}}
		var calls int
		s := NewService(f, ExecutorFunc(func(context.Context, string, Target) Outcome {
			calls++
			return Outcome{Success: true, HTTPStatus: 200, BodyValidated: true}
		}))
		r, err := s.Test(context.Background(), "tenant", "actor", TestRequest{ModelIDs: []string{"a"}, ConfirmCost: true, ExpectedConfigVersion: 1})
		if err != nil || calls != 0 || len(r.Items) != 0 || len(r.Skipped) != 1 || r.Skipped[0].Reason != "unsupported" || len(f.claims) != 0 {
			t.Fatalf("native %s fabricated probe evidence %+v %v", typ, r, err)
		}
		if err = s.RunLease(context.Background(), &Lease{TenantID: "tenant", Token: "batch", Config: f.cfg}); err != nil || calls != 0 || len(f.claims) != 0 {
			t.Fatalf("native %s scheduler dispatched %v", typ, err)
		}
	}
}
func TestManualInventoryAndMessagesIgnoreSchedulerProtocolRestriction(t *testing.T) {
	target := testTarget("claude", "p", "messages")
	target.ProviderType = " Anthropic "
	f := &fakeStore{cfg: DefaultConfig(), targets: []Target{target}}
	f.cfg.Protocols = []string{"chat"}
	var calls int
	s := NewService(f, ExecutorFunc(func(_ context.Context, _ string, t Target) Outcome {
		calls++
		if t.Protocol != "messages" {
			return Outcome{ErrorKind: "invalid_request"}
		}
		return Outcome{Success: true, HTTPStatus: 200, BodyValidated: true}
	}))
	targets, err := s.Targets(context.Background(), "tenant")
	if err != nil || len(targets) != 1 {
		t.Fatalf("manual model disappeared with chat-only scheduler %+v %v", targets, err)
	}
	r, err := s.Test(context.Background(), "tenant", "actor", TestRequest{ModelIDs: []string{"claude"}, Protocols: []string{"messages"}, ConfirmCost: true, ExpectedConfigVersion: 1})
	if err != nil || len(r.Items) != 1 || calls != 1 {
		t.Fatalf("native messages blocked by scheduler config %+v %v", r, err)
	}
}

func TestNativeChatProtocolsDispatchWithoutAdvertisingOtherNativeInterfaces(t *testing.T) {
	for _, typ := range []string{"gemini", "vertex", "bedrock"} {
		if !ProtocolSupported(typ, "chat") || ProtocolSupported(typ, "responses") || ProtocolSupported(typ, "messages") {
			t.Fatalf("native protocol registry wrong: %s", typ)
		}
		target := testTarget("native", "provider", "chat")
		target.ProviderType = typ
		target.Supported = true
		f := &fakeStore{cfg: DefaultConfig(), targets: []Target{target}}
		calls := 0
		s := NewService(f, ExecutorFunc(func(context.Context, string, Target) Outcome {
			calls++
			return Outcome{Success: true, HTTPStatus: 200, BodyValidated: true}
		}))
		result, err := s.Test(context.Background(), "tenant", "actor", TestRequest{ModelIDs: []string{"native"}, ConfirmCost: true, ExpectedConfigVersion: 1})
		if err != nil || calls != 1 || len(result.Items) != 1 || len(result.Skipped) != 0 {
			t.Fatalf("native %s not executed %+v err=%v", typ, result, err)
		}
	}
}
