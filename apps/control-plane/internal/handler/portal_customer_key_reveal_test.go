package handler

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRevealPortalCustomerKeyRequiresTenantAndBoundUser(t *testing.T) {
	handler := RevealPortalCustomerKey(nil)

	withoutTenant := httptest.NewRecorder()
	handler(withoutTenant, httptest.NewRequest(http.MethodPost, "/admin/v1/portal-integration/customer-keys/key-1/reveal?user_id=user-1", nil))
	if withoutTenant.Code != http.StatusBadRequest {
		t.Fatalf("without tenant status=%d want=%d", withoutTenant.Code, http.StatusBadRequest)
	}

	withoutUser := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/admin/v1/portal-integration/customer-keys/key-1/reveal", nil)
	req.Header.Set(portalIntegrationTenantHeader, "tenant-1")
	handler(withoutUser, req)
	if withoutUser.Code != http.StatusBadRequest {
		t.Fatalf("without user status=%d want=%d", withoutUser.Code, http.StatusBadRequest)
	}
}
