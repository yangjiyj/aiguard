package handler

import (
	"context"
	"net/http/httptest"
	"testing"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

func TestModelQualityCSVFormulaAndUnknownValues(t *testing.T) {
	for _, value := range []string{"=SUM(1,2)", " +formula", "\t@DDE", "-command"} {
		if got := modelQualityCSVText(value); got != "'"+value {
			t.Fatalf("spreadsheet expression accepted: %q", got)
		}
	}
	if modelQualityCSVText("ordinary model") != "ordinary model" || modelQualityCSVNumber(nil) != "" {
		t.Fatal("ordinary text/unknown CSV number changed")
	}
}

func TestModelQualityReportAuthenticationAndInvalidQueryBeforeDatabase(t *testing.T) {
	request := httptest.NewRequest("GET", "/admin/v1/model-operations/sla", nil)
	response := httptest.NewRecorder()
	GetModelOperationsSLA(nil)(response, request)
	if response.Code != 401 {
		t.Fatalf("missing auth = %d", response.Code)
	}
	for _, query := range []string{"?month=2026-13", "?month=2026-10&month=2026-09", "?tenant_id=foreign", "?timezone=bad/location"} {
		request = httptest.NewRequest("GET", "/admin/v1/model-operations/sla"+query, nil)
		request = request.WithContext(context.WithValue(request.Context(), auth.UserKey, &repository.User{ID: "user-a", TenantID: "tenant-a", Role: "tenant_admin"}))
		response = httptest.NewRecorder()
		GetModelOperationsSLA(nil)(response, request)
		if response.Code != 400 {
			t.Fatalf("invalid query reached DB: %s = %d", query, response.Code)
		}
	}
}
