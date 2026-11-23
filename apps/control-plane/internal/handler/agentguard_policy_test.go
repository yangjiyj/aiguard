package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
	"github.com/yangjiyj/aiguard/packages/shared-go/secrets"
)

type fakeAgentGuardPolicyRepo struct {
	policies            map[string]*repository.AgentGuardPolicy
	versions            map[string][]*repository.AgentGuardPolicyVersion
	exceptions          []*repository.AgentGuardException
	confirmations       map[string]*repository.AgentGuardConfirmation
	mcpExecutions       map[string]*repository.MCPConfirmationExecution
	stats               *repository.AgentGuardGovernanceStats
	suggestion          *repository.AgentGuardExceptionSuggestion
	simulation          *repository.AgentGuardPolicySimulationResult
	baseline            *repository.AgentGuardBehaviorBaseline
	rollouts            []*repository.AgentGuardRollout
	suggestedID         string
	suggestReason       string
	atomicCreateErr     error
	atomicUpdateErr     error
	atomicCreateCalls   int
	atomicUpdateCalls   int
	confirmationMu      sync.Mutex
	markConfirmationErr error
	mcpCiphertext       string
	mcpContextHash      string
}

func newFakeAgentGuardPolicyRepo() *fakeAgentGuardPolicyRepo {
	return &fakeAgentGuardPolicyRepo{
		policies:      map[string]*repository.AgentGuardPolicy{},
		versions:      map[string][]*repository.AgentGuardPolicyVersion{},
		confirmations: map[string]*repository.AgentGuardConfirmation{},
		mcpExecutions: map[string]*repository.MCPConfirmationExecution{},
	}
}

func (f *fakeAgentGuardPolicyRepo) CreatePolicy(_ context.Context, p *repository.AgentGuardPolicy) error {
	p.ID = "agp_fake"
	f.policies[p.ID] = p
	return nil
}
func (f *fakeAgentGuardPolicyRepo) UpdatePolicy(_ context.Context, p *repository.AgentGuardPolicy) (bool, error) {
	existing := f.policies[p.ID]
	if existing == nil || existing.TenantID != p.TenantID {
		return false, nil
	}
	createdAt, createdBy := existing.CreatedAt, existing.CreatedBy
	*existing = *p
	existing.CreatedAt = createdAt
	existing.CreatedBy = createdBy
	return true, nil
}
func (f *fakeAgentGuardPolicyRepo) ListPolicies(_ context.Context, tenantID string) ([]*repository.AgentGuardPolicy, error) {
	var out []*repository.AgentGuardPolicy
	for _, p := range f.policies {
		if p.TenantID == tenantID {
			out = append(out, p)
		}
	}
	return out, nil
}
func (f *fakeAgentGuardPolicyRepo) GetPolicy(_ context.Context, tenantID, id string) (*repository.AgentGuardPolicy, error) {
	p := f.policies[id]
	if p == nil || p.TenantID != tenantID {
		return nil, nil
	}
	return p, nil
}
func (f *fakeAgentGuardPolicyRepo) CreateVersion(_ context.Context, p *repository.AgentGuardPolicy, createdBy string) (*repository.AgentGuardPolicyVersion, error) {
	v, err := repository.NewAgentGuardPolicyVersion(p, createdBy)
	if err != nil {
		return nil, err
	}
	f.versions[p.ID] = append([]*repository.AgentGuardPolicyVersion{v}, f.versions[p.ID]...)
	return v, nil
}
func (f *fakeAgentGuardPolicyRepo) CreatePolicyWithVersion(ctx context.Context, p *repository.AgentGuardPolicy, createdBy string) (*repository.AgentGuardPolicy, *repository.AgentGuardPolicyVersion, error) {
	f.atomicCreateCalls++
	if f.atomicCreateErr != nil {
		return nil, nil, f.atomicCreateErr
	}
	if err := f.CreatePolicy(ctx, p); err != nil {
		return nil, nil, err
	}
	version, err := f.CreateVersion(ctx, p, createdBy)
	if err != nil {
		return nil, nil, err
	}
	return p, version, nil
}
func (f *fakeAgentGuardPolicyRepo) UpdatePolicyWithVersion(ctx context.Context, p *repository.AgentGuardPolicy, createdBy string) (*repository.AgentGuardPolicy, *repository.AgentGuardPolicyVersion, bool, error) {
	f.atomicUpdateCalls++
	if f.atomicUpdateErr != nil {
		return nil, nil, false, f.atomicUpdateErr
	}
	updated, err := f.UpdatePolicy(ctx, p)
	if err != nil || !updated {
		return nil, nil, updated, err
	}
	stored, err := f.GetPolicy(ctx, p.TenantID, p.ID)
	if err != nil {
		return nil, nil, false, err
	}
	version, err := f.CreateVersion(ctx, stored, createdBy)
	if err != nil {
		return nil, nil, false, err
	}
	return stored, version, true, nil
}
func (f *fakeAgentGuardPolicyRepo) ListVersions(_ context.Context, tenantID, policyID string) ([]*repository.AgentGuardPolicyVersion, error) {
	return f.versions[policyID], nil
}
func (f *fakeAgentGuardPolicyRepo) RollbackPolicy(_ context.Context, tenantID, policyID, versionID, actorID string) (*repository.AgentGuardPolicy, error) {
	versions := f.versions[policyID]
	for _, v := range versions {
		if v.ID == versionID && v.TenantID == tenantID {
			p := f.policies[policyID]
			p.Mode, _ = v.SnapshotJSON["mode"].(string)
			p.FailPolicy, _ = v.SnapshotJSON["fail_policy"].(string)
			p.UpdatedBy = actorID
			return p, nil
		}
	}
	return nil, nil
}
func (f *fakeAgentGuardPolicyRepo) CreateException(_ context.Context, e *repository.AgentGuardException) error {
	if err := repository.ValidateAgentGuardException(e); err != nil {
		return err
	}
	if e.ID == "" {
		e.ID = "agex_fake"
	}
	f.exceptions = append(f.exceptions, e)
	return nil
}
func (f *fakeAgentGuardPolicyRepo) ListActiveExceptions(_ context.Context, tenantID string, now time.Time) ([]*repository.AgentGuardException, error) {
	var out []*repository.AgentGuardException
	for _, e := range f.exceptions {
		if e.TenantID == tenantID && e.Enabled && e.ExpiresAt.After(now) {
			out = append(out, e)
		}
	}
	return out, nil
}
func (f *fakeAgentGuardPolicyRepo) DeleteException(_ context.Context, tenantID, id string) (bool, error) {
	for _, e := range f.exceptions {
		if e.TenantID == tenantID && e.ID == id {
			e.Enabled = false
			return true, nil
		}
	}
	return false, nil
}
func (f *fakeAgentGuardPolicyRepo) CreateConfirmation(_ context.Context, c *repository.AgentGuardConfirmation) error {
	f.confirmationMu.Lock()
	defer f.confirmationMu.Unlock()
	if c.ID == "" {
		c.ID = "agcf_fake"
	}
	c.Status = "pending"
	if c.ReplayStatus == "" {
		c.ReplayStatus = "pending"
	}
	f.confirmations[c.ID] = c
	return nil
}
func (f *fakeAgentGuardPolicyRepo) CreateMCPConfirmation(ctx context.Context, c *repository.AgentGuardConfirmation, ciphertext, contextHash string) error {
	f.mcpCiphertext = ciphertext
	f.mcpContextHash = contextHash
	c.ToolCallArguments = ""
	c.Source = "mcp"
	if err := f.CreateConfirmation(ctx, c); err != nil {
		return err
	}
	f.confirmationMu.Lock()
	defer f.confirmationMu.Unlock()
	f.mcpExecutions[c.ID] = &repository.MCPConfirmationExecution{ConfirmationID: c.ID, TenantID: c.TenantID, ExecutionStatus: "pending"}
	return nil
}
func (f *fakeAgentGuardPolicyRepo) CreateMCPConfirmationDeduplicated(ctx context.Context, c *repository.AgentGuardConfirmation, identity repository.MCPConfirmationIdentity, ciphertext, contextHash string) (*repository.MCPConfirmationExecution, bool, error) {
	if err := f.CreateMCPConfirmation(ctx, c, ciphertext, contextHash); err != nil {
		return nil, false, err
	}
	f.confirmationMu.Lock()
	defer f.confirmationMu.Unlock()
	state := f.mcpExecutions[c.ID]
	state.InvocationID = "mcpinv-fake"
	state.ConfirmationStatus = "pending"
	state.ScopeKey = identity.ScopeKey
	state.CanonicalRequestHash = identity.CanonicalRequestHash
	state.PrincipalHash = identity.PrincipalHash
	state.ExpiresAt = c.ExpiresAt
	copy := *state
	return &copy, true, nil
}
func (f *fakeAgentGuardPolicyRepo) GetMCPConfirmationExecution(_ context.Context, tenantID, confirmationID string) (*repository.MCPConfirmationExecution, error) {
	f.confirmationMu.Lock()
	defer f.confirmationMu.Unlock()
	state := f.mcpExecutions[confirmationID]
	if state == nil || state.TenantID != tenantID {
		return nil, nil
	}
	copy := *state
	return &copy, nil
}
func (f *fakeAgentGuardPolicyRepo) ClaimMCPConfirmationExecution(_ context.Context, tenantID, confirmationID string) (*repository.MCPConfirmationExecution, bool, error) {
	f.confirmationMu.Lock()
	defer f.confirmationMu.Unlock()
	state := f.mcpExecutions[confirmationID]
	confirmation := f.confirmations[confirmationID]
	if state == nil || confirmation == nil || state.TenantID != tenantID {
		return nil, false, nil
	}
	claimed := false
	if confirmation.Status == "approved" && state.ExecutionStatus == "pending" {
		state.ExecutionStatus = "executing"
		state.AttemptID = "attempt-" + confirmationID
		claimed = true
	}
	copy := *state
	return &copy, claimed, nil
}
func (f *fakeAgentGuardPolicyRepo) MarkMCPConfirmationUnknown(_ context.Context, tenantID, confirmationID, attemptID, errorCode string) error {
	f.confirmationMu.Lock()
	defer f.confirmationMu.Unlock()
	state := f.mcpExecutions[confirmationID]
	if state != nil && state.TenantID == tenantID && state.AttemptID == attemptID && state.ExecutionStatus == "executing" {
		state.ExecutionStatus = "unknown"
		state.ErrorCode = errorCode
	}
	return nil
}
func (f *fakeAgentGuardPolicyRepo) ListMCPConfirmationExecutions(_ context.Context, tenantID string, confirmationIDs []string) (map[string]*repository.MCPConfirmationExecution, error) {
	f.confirmationMu.Lock()
	defer f.confirmationMu.Unlock()
	out := map[string]*repository.MCPConfirmationExecution{}
	for _, id := range confirmationIDs {
		if state := f.mcpExecutions[id]; state != nil && state.TenantID == tenantID {
			copy := *state
			out[id] = &copy
		}
	}
	return out, nil
}
func (f *fakeAgentGuardPolicyRepo) ListConfirmations(_ context.Context, tenantID, status, source string) ([]*repository.AgentGuardConfirmation, error) {
	f.confirmationMu.Lock()
	defer f.confirmationMu.Unlock()
	var out []*repository.AgentGuardConfirmation
	for _, c := range f.confirmations {
		if c.TenantID == tenantID && (status == "" || c.Status == status) && (source == "" || c.Source == source) {
			out = append(out, c)
		}
	}
	return out, nil
}
func (f *fakeAgentGuardPolicyRepo) ResolveConfirmation(_ context.Context, tenantID, id, status, actorID, note string) (*repository.AgentGuardConfirmation, error) {
	f.confirmationMu.Lock()
	defer f.confirmationMu.Unlock()
	c := f.confirmations[id]
	if c == nil || c.TenantID != tenantID {
		return nil, nil
	}
	result := func(applied bool) *repository.AgentGuardConfirmation {
		copy := *c
		copy.ResolutionApplied = applied
		return &copy
	}
	if c.Status == status {
		return result(false), nil
	}
	if c.Status == "expired" {
		return result(false), repository.ErrAgentGuardConfirmationExpired
	}
	if c.Status != "pending" {
		return result(false), repository.ErrAgentGuardConfirmationResolutionConflict
	}
	if !c.ExpiresAt.After(time.Now()) {
		c.Status = "expired"
		now := time.Now()
		c.ResolvedAt = &now
		return result(false), repository.ErrAgentGuardConfirmationExpired
	}
	c.Status = status
	c.ResolvedBy = actorID
	c.ResolutionNote = note
	now := time.Now()
	c.ResolvedAt = &now
	return result(true), nil
}
func (f *fakeAgentGuardPolicyRepo) GetFalsePositiveStats(_ context.Context, tenantID string, _ int) (*repository.AgentGuardGovernanceStats, error) {
	if f.stats != nil {
		return f.stats, nil
	}
	return &repository.AgentGuardGovernanceStats{TotalHits: 0}, nil
}
func (f *fakeAgentGuardPolicyRepo) SuggestException(_ context.Context, tenantID, toolCallID, reason, actorID string, now time.Time) (*repository.AgentGuardExceptionSuggestion, error) {
	f.suggestedID = toolCallID
	f.suggestReason = reason
	if f.suggestion != nil {
		f.suggestion.Exception.TenantID = tenantID
		f.suggestion.Exception.CreatedBy = actorID
		return f.suggestion, nil
	}
	log := repository.ToolCallLog{ID: toolCallID, TenantID: tenantID, ToolName: "network.upload", EffectiveDecision: "block", EvidenceJSON: []byte(`[{"rule_id":"argument_tainted"}]`)}
	return repository.SuggestAgentGuardExceptionFromToolCall(log, reason, now)
}
func (f *fakeAgentGuardPolicyRepo) SimulatePolicy(_ context.Context, _ string, req repository.AgentGuardPolicySimulationRequest) (*repository.AgentGuardPolicySimulationResult, error) {
	if f.simulation != nil {
		return f.simulation, nil
	}
	return &repository.AgentGuardPolicySimulationResult{PolicyID: req.PolicyID, TotalEvaluated: 3, WouldBlockCount: 1}, nil
}
func (f *fakeAgentGuardPolicyRepo) GetBehaviorBaseline(_ context.Context, _ string, _ int) (*repository.AgentGuardBehaviorBaseline, error) {
	if f.baseline != nil {
		return f.baseline, nil
	}
	return &repository.AgentGuardBehaviorBaseline{Profiles: []repository.AgentGuardActorProfile{{ActorID: "agent-user-1", TotalCalls: 3}}}, nil
}
func (f *fakeAgentGuardPolicyRepo) CreateRollout(_ context.Context, rollout *repository.AgentGuardRollout) error {
	if err := repository.ValidateAgentGuardRollout(rollout); err != nil {
		return err
	}
	if rollout.ID == "" {
		rollout.ID = "agro_fake"
	}
	rollout.SimulationOnly = true
	f.rollouts = append(f.rollouts, rollout)
	return nil
}
func (f *fakeAgentGuardPolicyRepo) ListRollouts(_ context.Context, tenantID, status string) ([]*repository.AgentGuardRollout, error) {
	var out []*repository.AgentGuardRollout
	for _, rollout := range f.rollouts {
		if rollout.TenantID == tenantID && (status == "" || rollout.Status == status) {
			out = append(out, rollout)
		}
	}
	return out, nil
}

type agentGuardAuditSystemRepo struct {
	mu    sync.Mutex
	count int
}

func (r *agentGuardAuditSystemRepo) Get(_ context.Context, _ string) (*repository.SystemSetting, error) {
	return nil, nil
}
func (r *agentGuardAuditSystemRepo) GetAll(_ context.Context) ([]*repository.SystemSetting, error) {
	return nil, nil
}
func (r *agentGuardAuditSystemRepo) Set(_ context.Context, _, _ string) error { return nil }
func (r *agentGuardAuditSystemRepo) SetMultiple(_ context.Context, _ map[string]string) error {
	return nil
}
func (r *agentGuardAuditSystemRepo) CreateAuditOperation(_ context.Context, _ *repository.AuditOperation) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.count++
	return nil
}
func (r *agentGuardAuditSystemRepo) auditCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.count
}
func (r *agentGuardAuditSystemRepo) ListAuditOperations(_ context.Context, _, _ int, _ string) ([]*repository.AuditOperation, int, error) {
	return nil, 0, nil
}
func (r *agentGuardAuditSystemRepo) GetBool(_ context.Context, _ string) (bool, error) {
	return false, nil
}

func withAgentGuardUser(r *http.Request) *http.Request {
	user := &repository.User{ID: "user-1", TenantID: "tenant-a", Role: "platform_admin", Status: "active"}
	return r.WithContext(context.WithValue(r.Context(), auth.UserKey, user))
}

func TestCreateAgentGuardPolicyCreatesVersionAndAudit(t *testing.T) {
	repo := newFakeAgentGuardPolicyRepo()
	auditRepo := &agentGuardAuditSystemRepo{}
	deps := &Dependencies{AgentGuardPolicyRepo: repo, SystemRepo: auditRepo}
	body := []byte(`{"name":"生产严格策略","scope_type":"project","scope_ref":"proj-1","mode":"strict","default_action":"audit","fail_policy":"fail_closed","enabled":true}`)
	req := withAgentGuardUser(httptest.NewRequest(http.MethodPost, "/admin/v1/agentguard/policies", bytes.NewReader(body)))
	rr := httptest.NewRecorder()

	CreateAgentGuardPolicy(deps)(rr, req)

	if rr.Code != http.StatusCreated {
		t.Fatalf("status = %d, body = %s", rr.Code, rr.Body.String())
	}
	versionCount := 0
	for _, versions := range repo.versions {
		versionCount += len(versions)
	}
	if len(repo.policies) != 1 || versionCount != 1 {
		t.Fatalf("policy/version not persisted: policies=%d versions=%d", len(repo.policies), versionCount)
	}
	if auditRepo.count == 0 {
		t.Fatal("expected operation audit to be written")
	}
}
func TestResolveAgentGuardConfirmation(t *testing.T) {
	repo := newFakeAgentGuardPolicyRepo()
	_ = repo.CreateConfirmation(context.Background(), &repository.AgentGuardConfirmation{TenantID: "tenant-a", TraceID: "trace-1", ToolName: "network.upload", ExpiresAt: time.Now().Add(time.Minute)})
	deps := &Dependencies{AgentGuardPolicyRepo: repo, SystemRepo: &agentGuardAuditSystemRepo{}}
	body := []byte(`{"status":"approved","note":"确认是内部上传"}`)
	req := withAgentGuardUser(httptest.NewRequest(http.MethodPost, "/admin/v1/agentguard/confirmations/agcf_fake/resolve", bytes.NewReader(body)))
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", "agcf_fake")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	rr := httptest.NewRecorder()

	ResolveAgentGuardConfirmation(deps)(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", rr.Code, rr.Body.String())
	}
	if repo.confirmations["agcf_fake"].Status != "approved" || repo.confirmations["agcf_fake"].ResolvedBy != "user-1" {
		t.Fatalf("confirmation was not resolved: %#v", repo.confirmations["agcf_fake"])
	}
}

func TestListAgentGuardTemplates(t *testing.T) {
	deps := &Dependencies{AgentGuardPolicyRepo: newFakeAgentGuardPolicyRepo()}
	req := withAgentGuardUser(httptest.NewRequest(http.MethodGet, "/admin/v1/agentguard/templates", nil))
	rr := httptest.NewRecorder()

	ListAgentGuardTemplates(deps)(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rr.Code, rr.Body.String())
	}
	if !bytes.Contains(rr.Body.Bytes(), []byte("标准治理模板")) || !bytes.Contains(rr.Body.Bytes(), []byte("strict")) {
		t.Fatalf("template response missing standard/strict templates: %s", rr.Body.String())
	}
}

func TestGetAgentGuardFalsePositiveStats(t *testing.T) {
	repo := newFakeAgentGuardPolicyRepo()
	repo.stats = &repository.AgentGuardGovernanceStats{
		TotalHits:          10,
		FalsePositiveCount: 2,
		ByRule:             []repository.AgentGuardStatsGroup{{Key: "argument_tainted", FalsePositiveRate: 0.5}},
	}
	deps := &Dependencies{AgentGuardPolicyRepo: repo}
	req := withAgentGuardUser(httptest.NewRequest(http.MethodGet, "/admin/v1/agentguard/governance/stats?days=7", nil))
	rr := httptest.NewRecorder()

	GetAgentGuardFalsePositiveStats(deps)(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rr.Code, rr.Body.String())
	}
	if !bytes.Contains(rr.Body.Bytes(), []byte("argument_tainted")) {
		t.Fatalf("stats response missing rule group: %s", rr.Body.String())
	}
}

func TestSuggestAgentGuardException(t *testing.T) {
	repo := newFakeAgentGuardPolicyRepo()
	repo.suggestion = &repository.AgentGuardExceptionSuggestion{
		SourceToolCallID: "tc_fp",
		Exception: &repository.AgentGuardException{
			ScopeType:     "tenant",
			RuleID:        "argument_tainted",
			TargetPattern: "https://files.partner.example/upload",
			Decision:      "audit",
			Reason:        "已确认合作方上传",
			ExpiresAt:     time.Now().Add(7 * 24 * time.Hour),
			Enabled:       true,
		},
	}
	deps := &Dependencies{AgentGuardPolicyRepo: repo, MCPConfirmationScopeSecret: "internal-test-secret"}
	body := []byte(`{"tool_call_id":"tc_fp","reason":"已确认合作方上传"}`)
	req := withAgentGuardUser(httptest.NewRequest(http.MethodPost, "/admin/v1/agentguard/exceptions/suggest", bytes.NewReader(body)))
	rr := httptest.NewRecorder()

	SuggestAgentGuardException(deps)(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rr.Code, rr.Body.String())
	}
	if repo.suggestedID != "tc_fp" || repo.suggestReason != "已确认合作方上传" {
		t.Fatalf("suggestion repo not called with expected args: id=%s reason=%s", repo.suggestedID, repo.suggestReason)
	}
	if !bytes.Contains(rr.Body.Bytes(), []byte("files.partner.example")) {
		t.Fatalf("suggestion response missing target: %s", rr.Body.String())
	}
}

func TestSimulateAgentGuardPolicyHandler(t *testing.T) {
	repo := newFakeAgentGuardPolicyRepo()
	deps := &Dependencies{AgentGuardPolicyRepo: repo}
	body := []byte(`{"policy_id":"agp_1","days":7,"limit":100}`)
	req := withAgentGuardUser(httptest.NewRequest(http.MethodPost, "/admin/v1/agentguard/policies/simulate", bytes.NewReader(body)))
	rr := httptest.NewRecorder()

	SimulateAgentGuardPolicy(deps)(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rr.Code, rr.Body.String())
	}
	var resp repository.AgentGuardPolicySimulationResult
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.TotalEvaluated != 3 || resp.WouldBlockCount != 1 {
		t.Fatalf("unexpected simulation response: %#v", resp)
	}
}

func TestCreateAgentGuardRolloutAuditsOperation(t *testing.T) {
	repo := newFakeAgentGuardPolicyRepo()
	auditRepo := &agentGuardAuditSystemRepo{}
	deps := &Dependencies{AgentGuardPolicyRepo: repo, SystemRepo: auditRepo}
	body := []byte(`{"policy_id":"agp_1","scope_type":"project","scope_ref":"proj-1","rollout_mode":"audit","traffic_percent":20,"status":"active","expires_at":"2030-01-01T00:00:00Z"}`)
	req := withAgentGuardUser(httptest.NewRequest(http.MethodPost, "/admin/v1/agentguard/rollouts", bytes.NewReader(body)))
	rr := httptest.NewRecorder()

	CreateAgentGuardRollout(deps)(rr, req)

	if rr.Code != http.StatusCreated {
		t.Fatalf("status = %d, body = %s", rr.Code, rr.Body.String())
	}
	if !bytes.Contains(rr.Body.Bytes(), []byte("\"simulation_only\":true")) {
		t.Fatalf("rollout must be marked simulation-only until gateway enforcement exists: %s", rr.Body.String())
	}
	if len(repo.rollouts) != 1 || repo.rollouts[0].TenantID != "tenant-a" || repo.rollouts[0].CreatedBy != "user-1" {
		t.Fatalf("rollout not persisted with tenant/user context: %#v", repo.rollouts)
	}
	if auditRepo.count == 0 {
		t.Fatal("expected rollout creation to write operation audit")
	}
}

func TestDeleteAgentGuardExceptionDisablesScopedRule(t *testing.T) {
	repo := newFakeAgentGuardPolicyRepo()
	repo.exceptions = []*repository.AgentGuardException{{
		ID:        "agex_delete",
		TenantID:  "tenant-a",
		ScopeType: "project",
		ScopeRef:  "proj-1",
		Decision:  "audit",
		Reason:    "误报",
		ExpiresAt: time.Now().Add(time.Hour),
		Enabled:   true,
	}}
	deps := &Dependencies{AgentGuardPolicyRepo: repo, SystemRepo: &agentGuardAuditSystemRepo{}}
	req := withAgentGuardUser(httptest.NewRequest(http.MethodDelete, "/admin/v1/agentguard/exceptions/agex_delete", nil))
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", "agex_delete")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	rr := httptest.NewRecorder()

	DeleteAgentGuardException(deps).ServeHTTP(rr, req)

	if rr.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204; body=%s", rr.Code, rr.Body.String())
	}
	if repo.exceptions[0].Enabled {
		t.Fatalf("exception should be disabled after delete")
	}
}

func TestAgentGuardBehaviorAndDLPFromJSON(t *testing.T) {
	// 保守：nil / 空 map → nil（不编造默认基线，缺啥就是没有）
	if got := agentGuardBehaviorFromJSON(nil); got != nil {
		t.Fatalf("nil behavior json should map to nil, got %#v", got)
	}
	if got := agentGuardBehaviorFromJSON(map[string]any{}); got != nil {
		t.Fatalf("empty behavior json should map to nil, got %#v", got)
	}
	if got := agentGuardDLPFromJSON(nil); got != nil {
		t.Fatalf("nil dlp json should map to nil, got %#v", got)
	}
	if got := agentGuardDLPFromJSON(map[string]any{}); got != nil {
		t.Fatalf("empty dlp json should map to nil, got %#v", got)
	}

	behavior := agentGuardBehaviorFromJSON(map[string]any{
		"file_read_burst_10s":       float64(50),
		"network_egress_burst_10s":  float64(40),
		"command_execute_burst_10s": float64(20),
	})
	if behavior == nil {
		t.Fatalf("expected behavior map, got nil")
	}
	if behavior["file_read_burst_10s"] != float64(50) ||
		behavior["network_egress_burst_10s"] != float64(40) ||
		behavior["command_execute_burst_10s"] != float64(20) {
		t.Fatalf("behavior passthrough mismatch: %#v", behavior)
	}

	dlp := agentGuardDLPFromJSON(map[string]any{"high_confidence_secret_egress": "block"})
	if dlp == nil {
		t.Fatalf("expected dlp map, got nil")
	}
	if dlp["high_confidence_secret_egress"] != "block" {
		t.Fatalf("dlp passthrough mismatch: %#v", dlp)
	}
}

func TestGetInternalAgentGuardEffectivePolicyEmitsBehaviorAndDLP(t *testing.T) {
	repo := newFakeAgentGuardPolicyRepo()
	repo.policies["agp_x"] = &repository.AgentGuardPolicy{
		ID:            "agp_x",
		TenantID:      "tenant-a",
		Name:          "strict",
		ScopeType:     "tenant",
		Mode:          "strict",
		DefaultAction: "audit",
		FailPolicy:    "fail_closed",
		Enabled:       true,
		RulesJSON:     map[string]any{},
		BehaviorJSON: map[string]any{
			"file_read_burst_10s":       float64(50),
			"network_egress_burst_10s":  float64(50),
			"command_execute_burst_10s": float64(20),
		},
		DLPJSON: map[string]any{"high_confidence_secret_egress": "block"},
	}
	repo.versions["agp_x"] = []*repository.AgentGuardPolicyVersion{{PolicyVersion: "v1", Active: true}}

	auditRepo := &agentGuardAuditSystemRepo{}
	deps := &Dependencies{AgentGuardPolicyRepo: repo, SystemRepo: auditRepo}
	req := withAgentGuardUser(httptest.NewRequest(http.MethodGet, "/admin/v1/internal/agentguard/effective-policy", nil))
	req.Header.Set("X-Tenant-ID", "tenant-a")
	rr := httptest.NewRecorder()

	GetInternalAgentGuardEffectivePolicy(deps)(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d (body=%s)", rr.Code, rr.Body.String())
	}
	var resp struct {
		Data struct {
			Behavior map[string]any `json:"behavior"`
			DLP      map[string]any `json:"dlp"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v (body=%s)", err, rr.Body.String())
	}
	if resp.Data.Behavior == nil {
		t.Fatalf("expected behavior in emitted policy, body=%s", rr.Body.String())
	}
	if resp.Data.Behavior["file_read_burst_10s"] != float64(50) ||
		resp.Data.Behavior["network_egress_burst_10s"] != float64(50) ||
		resp.Data.Behavior["command_execute_burst_10s"] != float64(20) {
		t.Fatalf("emitted behavior mismatch: %#v", resp.Data.Behavior)
	}
	if resp.Data.DLP == nil {
		t.Fatalf("expected dlp in emitted policy, body=%s", rr.Body.String())
	}
	if resp.Data.DLP["high_confidence_secret_egress"] != "block" {
		t.Fatalf("emitted dlp mismatch: %#v", resp.Data.DLP)
	}
}

type fakeGatewayMCPExecutor struct {
	mu    sync.Mutex
	calls int
	repo  *fakeAgentGuardPolicyRepo
}

func (e *fakeGatewayMCPExecutor) ExecuteMCPConfirmation(_ context.Context, tenantID, confirmationID, attemptID string) error {
	e.mu.Lock()
	e.calls++
	e.mu.Unlock()
	e.repo.confirmationMu.Lock()
	defer e.repo.confirmationMu.Unlock()
	state := e.repo.mcpExecutions[confirmationID]
	if state != nil && state.TenantID == tenantID && state.AttemptID == attemptID {
		state.ExecutionStatus = "executed"
		state.ResponseSummary = map[string]any{"outcome": "executed"}
	}
	return nil
}

func (e *fakeGatewayMCPExecutor) callCount() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.calls
}

func TestCreateMCPConfirmationInternalEncryptsContextAndNeverReturnsArguments(t *testing.T) {
	t.Setenv("JJD_PROVIDER_SECRET_KEY", "mcp-confirmation-test-key")
	repo := newFakeAgentGuardPolicyRepo()
	deps := &Dependencies{AgentGuardPolicyRepo: repo, MCPConfirmationScopeSecret: "internal-test-secret"}
	body := []byte(`{
		"request_id":"req-1","trace_id":"trace-1","tool_name":"demo__write",
		"tool_call_id":"number:9","raw_decision":"confirm","effective_decision":"confirm",
		"source":"mcp","expires_at":"2099-01-01T00:00:00Z",
		"mcp_replay_context":{
			"version":2,"tenant_id":"tenant-a","operation_id":"op-control-plane-original","server_id":"server-a","tool_name":"write",
			"tool_call_id":"number:9","protocol_version":"2025-11-25",
			"tool_id":"tool-a","supply_chain_revision":"revision-a",
			"approved_schema_hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			"server_route_hash":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
			"request_body":{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"write","arguments":{"secret":"never-plain"}}}
		}
	}`)
	request := httptest.NewRequest(http.MethodPost, "/admin/v1/internal/agentguard/confirmations", bytes.NewReader(body))
	request.Header.Set("X-Tenant-ID", "tenant-a")
	response := httptest.NewRecorder()
	CreateAgentGuardConfirmationInternal(deps)(response, request)
	if response.Code != http.StatusCreated {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	if !strings.HasPrefix(repo.mcpCiphertext, "enc:v1:") || strings.Contains(repo.mcpCiphertext, "never-plain") || len(repo.mcpContextHash) != 64 {
		t.Fatalf("ciphertext=%q hash=%q", repo.mcpCiphertext, repo.mcpContextHash)
	}
	plaintext, err := secrets.DecryptProviderSecret(repo.mcpCiphertext)
	if err != nil || !strings.Contains(plaintext, "never-plain") || !strings.Contains(plaintext, `"operation_id":"op-control-plane-original"`) {
		t.Fatalf("decrypt err=%v plaintext=%q", err, plaintext)
	}
	if strings.Contains(response.Body.String(), "never-plain") || strings.Contains(response.Body.String(), "enc:v1:") ||
		strings.Contains(response.Body.String(), "tool_call_arguments") {
		t.Fatalf("response leaked replay context: %s", response.Body.String())
	}

	listRequest := withAgentGuardUser(httptest.NewRequest(http.MethodGet, "/admin/v1/agentguard/confirmations?source=mcp", nil))
	listResponse := httptest.NewRecorder()
	ListAgentGuardConfirmations(deps)(listResponse, listRequest)
	if listResponse.Code != http.StatusOK || strings.Contains(listResponse.Body.String(), "never-plain") ||
		strings.Contains(listResponse.Body.String(), "enc:v1:") || strings.Contains(listResponse.Body.String(), "attempt-") {
		t.Fatalf("list leaked execution secret: %s", listResponse.Body.String())
	}
}

func TestResolveMCPConfirmationExecutesOnceWhileLocalReplayBoundaryStaysSeparate(t *testing.T) {
	repo := newFakeAgentGuardPolicyRepo()
	confirmation := &repository.AgentGuardConfirmation{
		ID: "agcf_mcp", TenantID: "tenant-a", RequestID: "req", TraceID: "trace",
		ToolName: "demo__write", ToolCallID: "number:9", RawDecision: "confirm",
		EffectiveDecision: "confirm", Source: "mcp", ExpiresAt: time.Now().Add(time.Minute),
	}
	if err := repo.CreateMCPConfirmation(context.Background(), confirmation, "enc:v1:test", strings.Repeat("a", 64)); err != nil {
		t.Fatal(err)
	}
	executor := &fakeGatewayMCPExecutor{repo: repo}
	deps := &Dependencies{AgentGuardPolicyRepo: repo, MCPConfirmationExecutor: executor, SystemRepo: &agentGuardAuditSystemRepo{}}
	for i := 0; i < 2; i++ {
		request := withAgentGuardUser(httptest.NewRequest(http.MethodPost, "/admin/v1/agentguard/confirmations/agcf_mcp/resolve", bytes.NewReader([]byte(`{"status":"approved"}`))))
		routeContext := chi.NewRouteContext()
		routeContext.URLParams.Add("id", "agcf_mcp")
		request = request.WithContext(context.WithValue(request.Context(), chi.RouteCtxKey, routeContext))
		response := httptest.NewRecorder()
		ResolveAgentGuardConfirmation(deps)(response, request)
		if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"execution_status":"executed"`) {
			t.Fatalf("attempt %d status=%d body=%s", i, response.Code, response.Body.String())
		}
	}
	if executor.callCount() != 1 {
		t.Fatalf("gateway executions=%d", executor.callCount())
	}
}

type failingGatewayMCPExecutor struct {
	calls int
}

func (e *failingGatewayMCPExecutor) ExecuteMCPConfirmation(context.Context, string, string, string) error {
	e.calls++
	return context.DeadlineExceeded
}

func TestResolveMCPConfirmationNetworkUncertaintyBecomesTerminalUnknown(t *testing.T) {
	repo := newFakeAgentGuardPolicyRepo()
	confirmation := &repository.AgentGuardConfirmation{
		ID: "agcf_unknown", TenantID: "tenant-a", RequestID: "req", TraceID: "trace",
		ToolName: "demo__write", ToolCallID: "number:9", RawDecision: "confirm",
		EffectiveDecision: "confirm", Source: "mcp", ExpiresAt: time.Now().Add(time.Minute),
	}
	if err := repo.CreateMCPConfirmation(context.Background(), confirmation, "enc:v1:test", strings.Repeat("b", 64)); err != nil {
		t.Fatal(err)
	}
	executor := &failingGatewayMCPExecutor{}
	deps := &Dependencies{AgentGuardPolicyRepo: repo, MCPConfirmationExecutor: executor, SystemRepo: &agentGuardAuditSystemRepo{}}
	for i := 0; i < 2; i++ {
		request := withAgentGuardUser(httptest.NewRequest(http.MethodPost, "/resolve", bytes.NewReader([]byte(`{"status":"approved"}`))))
		routeContext := chi.NewRouteContext()
		routeContext.URLParams.Add("id", "agcf_unknown")
		request = request.WithContext(context.WithValue(request.Context(), chi.RouteCtxKey, routeContext))
		response := httptest.NewRecorder()
		ResolveAgentGuardConfirmation(deps)(response, request)
		if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"execution_status":"unknown"`) {
			t.Fatalf("attempt %d status=%d body=%s", i, response.Code, response.Body.String())
		}
	}
	if executor.calls != 1 {
		t.Fatalf("network-uncertain execution was retried: calls=%d", executor.calls)
	}
}

func (r *agentGuardAuditSystemRepo) GetByKeys(ctx context.Context, keys []string) ([]*repository.SystemSetting, error) {
	return systemSettingsByKeysVia(ctx, r.Get, keys)
}
