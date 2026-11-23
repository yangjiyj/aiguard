package handler

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"testing"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

type stubAlertCaseStoreStatus struct {
	occurrenceReaderStub
	status repository.AlertCaseStoreStatus
	tenant string
}

func (s *stubAlertCaseStoreStatus) AlertCaseStoreStatus(_ context.Context, tenant string) (repository.AlertCaseStoreStatus, error) {
	s.tenant = tenant
	return s.status, nil
}

// 物化表诊断状态：平台管理员能查到不能用的原因（如触发器定义摘要不一致）和期望、当前摘要；其他角色不行。
func TestAlertCaseStoreStatusIsPlatformAdminOnly(t *testing.T) {
	stub := &stubAlertCaseStoreStatus{status: repository.AlertCaseStoreStatus{Reason: "trigger_definitions_changed", ExpectedTriggerDigest: "a", CurrentTriggerDigest: "b"}}
	deps := &Dependencies{AlertOccurrenceRepo: stub}
	for role, want := range map[string]int{"platform_admin": 200, "tenant_admin": 403, "auditor": 403} {
		r := contentAuditAuthRequest(role)
		r.URL.Path = "/admin/v1/security/alert-occurrences/store-status"
		r.URL.RawQuery = "tenant_id=t1"
		w := httptest.NewRecorder()
		GetAlertCaseStoreStatus(deps).ServeHTTP(w, r)
		if w.Code != want {
			t.Fatalf("%s: status %d, want %d", role, w.Code, want)
		}
		if want != 200 {
			continue
		}
		var got repository.AlertCaseStoreStatus
		if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil || got.Reason != "trigger_definitions_changed" || got.ExpectedTriggerDigest != "a" || stub.tenant != "t1" {
			t.Fatalf("body=%s tenant=%q err=%v", w.Body.String(), stub.tenant, err)
		}
	}
}
