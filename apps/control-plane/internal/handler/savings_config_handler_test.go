package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

// mockSavingsConfigRepo implements SavingsConfigRepo for testing.
type mockSavingsConfigRepo struct {
	cfg *repository.CostGovernanceConfig
}

func (m *mockSavingsConfigRepo) Get(_ context.Context, tenantID string) (*repository.CostGovernanceConfig, error) {
	if m.cfg != nil {
		return m.cfg, nil
	}
	return &repository.CostGovernanceConfig{
		TenantID:        tenantID,
		LaborHourlyRate: 250,
		LaborHoursPerOp: 0.5,
	}, nil
}

func (m *mockSavingsConfigRepo) Upsert(_ context.Context, cfg *repository.CostGovernanceConfig) error {
	m.cfg = cfg
	return nil
}

type scSystemRepo struct{}

func (s *scSystemRepo) Get(_ context.Context, _ string) (*repository.SystemSetting, error) {
	return nil, nil
}
func (s *scSystemRepo) GetAll(_ context.Context) ([]*repository.SystemSetting, error) {
	return nil, nil
}
func (s *scSystemRepo) Set(_ context.Context, _, _ string) error         { return nil }
func (s *scSystemRepo) SetMultiple(_ context.Context, _ map[string]string) error { return nil }
func (s *scSystemRepo) CreateAuditOperation(_ context.Context, _ *repository.AuditOperation) error {
	return nil
}
func (s *scSystemRepo) ListAuditOperations(_ context.Context, _, _ int, _ string) ([]*repository.AuditOperation, int, error) {
	return nil, 0, nil
}
func (s *scSystemRepo) GetBool(_ context.Context, _ string) (bool, error) { return false, nil }

func withSCUserCtx(r *http.Request, tenantID string) *http.Request {
	u := &repository.User{ID: "u_sc", TenantID: tenantID, Role: "admin", Status: "active"}
	return r.WithContext(context.WithValue(r.Context(), auth.UserKey, u))
}

func TestGetSavingsConfig_Default(t *testing.T) {
	repo := &mockSavingsConfigRepo{}
	deps := &Dependencies{
		SavingsConfigRepo: repo,
		SystemRepo:        &scSystemRepo{},
	}

	req := httptest.NewRequest(http.MethodGet, "/admin/v1/savings/config", nil)
	req = withSCUserCtx(req, "ten_sc_1")
	rr := httptest.NewRecorder()

	GetSavingsConfig(deps)(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var cfg repository.CostGovernanceConfig
	if err := json.NewDecoder(rr.Body).Decode(&cfg); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if cfg.LaborHourlyRate != 250 {
		t.Errorf("expected default 250, got %f", cfg.LaborHourlyRate)
	}
}

func TestUpdateSavingsConfig(t *testing.T) {
	repo := &mockSavingsConfigRepo{}
	deps := &Dependencies{
		SavingsConfigRepo: repo,
		SystemRepo:        &scSystemRepo{},
	}

	body, _ := json.Marshal(map[string]any{
		"labor_hourly_rate": 300.0,
		"labor_hours_per_op": 0.75,
	})
	req := httptest.NewRequest(http.MethodPut, "/admin/v1/savings/config", bytes.NewReader(body))
	req = withSCUserCtx(req, "ten_sc_1")
	rr := httptest.NewRecorder()

	UpdateSavingsConfig(deps)(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	if repo.cfg == nil {
		t.Fatal("expected upsert to be called")
	}
	if repo.cfg.LaborHourlyRate != 300 {
		t.Errorf("expected 300, got %f", repo.cfg.LaborHourlyRate)
	}
	if repo.cfg.LaborHoursPerOp != 0.75 {
		t.Errorf("expected 0.75, got %f", repo.cfg.LaborHoursPerOp)
	}
}

func (s *scSystemRepo) GetByKeys(ctx context.Context, keys []string) ([]*repository.SystemSetting, error) {
	return systemSettingsByKeysVia(ctx, s.Get, keys)
}
