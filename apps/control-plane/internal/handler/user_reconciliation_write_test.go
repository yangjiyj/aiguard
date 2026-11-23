package handler

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

func TestUserMetadataUpdateReportsConcurrentIdentityPause(t *testing.T) {
	events := []string{}
	store := &lifecycleUserStore{
		events:    &events,
		user:      &repository.User{ID: "user-1", TenantID: "tenant-1", Username: "employee", Role: "chat_user", Status: "active"},
		updateErr: fmt.Errorf("locked actual row: %w", repository.ErrUserReconciliationRequired),
	}
	response := httptest.NewRecorder()
	UpdateUser(&Dependencies{UserStore: store})(response, lifecycleRequest(http.MethodPatch, `{"email":"employee@example.invalid"}`))
	if response.Code != http.StatusConflict || !strings.Contains(response.Body.String(), "identity_reconciliation_required") {
		t.Fatalf("paused metadata status=%d body=%s", response.Code, response.Body.String())
	}
	if store.user.Username != "employee" || store.user.Email != "" || store.user.Status != "active" {
		t.Fatal("failed write changed stored user snapshot")
	}
}
