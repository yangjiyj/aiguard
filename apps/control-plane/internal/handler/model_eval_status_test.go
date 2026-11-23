package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

type fakeEvalStatusRepo struct{ rows []repository.ModelEvalStatusRow }

func (f *fakeEvalStatusRepo) ListModelEvalStatus(ctx context.Context, tenantID string) ([]repository.ModelEvalStatusRow, error) {
	return f.rows, nil
}

func TestListModelsEvalStatusBuildsReportURLAndStatus(t *testing.T) {
	repo := &fakeEvalStatusRepo{rows: []repository.ModelEvalStatusRow{
		{ModelID: "model_a", LSETargetID: "tgt-1", HasHighRisk: true, LatestEvalAt: time.Unix(1700000000, 0)},
		{ModelID: "model_b", LSETargetID: "tgt-2", HasHighRisk: false, LatestEvalAt: time.Unix(1700000000, 0)},
	}}
	sysRepo := &capturingSystemRepo{settings: map[string]string{"lse_base_url": "https://lse.example.com"}}
	deps := &Dependencies{ModelEvalStatusRepo: repo, SystemRepo: sysRepo}

	req := httptest.NewRequest(http.MethodGet, "/admin/v1/models/eval-status", nil)
	ctx := context.WithValue(req.Context(), auth.UserKey, &repository.User{ID: "u1", TenantID: "tenant_default", Role: "platform_admin", Status: "active"})
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()

	ListModelsEvalStatus(deps).ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	var got struct {
		Data []struct {
			ModelID     string `json:"model_id"`
			Status      string `json:"status"`
			ReportURL   string `json:"report_url"`
			HasHighRisk bool   `json:"has_high_risk"`
		} `json:"data"`
	}
	if err := json.NewDecoder(w.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if len(got.Data) != 2 {
		t.Fatalf("want 2 rows got %d", len(got.Data))
	}
	a := got.Data[0]
	if a.ModelID != "model_a" || a.Status != "high_risk" || !a.HasHighRisk {
		t.Errorf("model_a wrong: %+v", a)
	}
	// lse_base_url 只填了 host 未带端口，bakeLSEBase 会自动补 LSE web 对外口 :8090。
	if a.ReportURL != "https://lse.example.com:8090/eval-tasks?modelTargetId=tgt-1" {
		t.Errorf("model_a report_url=%q", a.ReportURL)
	}
	if got.Data[1].Status != "passed" {
		t.Errorf("model_b status=%q want passed", got.Data[1].Status)
	}
	if got.Data[1].ReportURL != "https://lse.example.com:8090/eval-tasks?modelTargetId=tgt-2" {
		t.Errorf("model_b report_url=%q", got.Data[1].ReportURL)
	}
}
