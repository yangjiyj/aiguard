package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/identitybinding"
)

type setAutomaticRecordingService struct {
	identityBindingServiceStub
	tenantID string
	userID   string
	actorID  string
	calls    int
	err      error
}

func (s *setAutomaticRecordingService) SetAutomatic(
	_ context.Context,
	tenantID, userID, actorID string,
) error {
	s.tenantID = tenantID
	s.userID = userID
	s.actorID = actorID
	s.calls++
	return s.err
}

func TestSetUserDepartmentAutomaticUsesAuthenticatedActor(t *testing.T) {
	service := &setAutomaticRecordingService{}
	request := httptest.NewRequest(
		http.MethodPost,
		"/admin/v1/users/target-user/department/automatic",
		strings.NewReader(`{"actor_id":"forged-actor"}`),
	)
	request = chiCtxWithID(request, "target-user")
	request = withOrgUserCtx(request, "tenant-a", "admin-a")
	response := httptest.NewRecorder()

	SetUserDepartmentAutomatic(&Dependencies{IdentityBindingService: service})(response, request)

	if response.Code != http.StatusNoContent {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	if service.calls != 1 || service.tenantID != "tenant-a" ||
		service.userID != "target-user" || service.actorID != "admin-a" {
		t.Fatalf("SetAutomatic call=%d tenant=%q user=%q actor=%q",
			service.calls, service.tenantID, service.userID, service.actorID)
	}
}

func TestSetUserDepartmentAutomaticRequiresAuthenticatedUser(t *testing.T) {
	service := &setAutomaticRecordingService{}
	request := chiCtxWithID(
		httptest.NewRequest(http.MethodPost, "/admin/v1/users/target-user/department/automatic", nil),
		"target-user",
	)
	response := httptest.NewRecorder()

	SetUserDepartmentAutomatic(&Dependencies{IdentityBindingService: service})(response, request)

	if response.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	if service.calls != 0 {
		t.Fatalf("SetAutomatic calls=%d, want 0", service.calls)
	}
}

func TestSetUserDepartmentAutomaticHidesMissingAndCrossTenantUsers(t *testing.T) {
	var responseBodies []string
	for _, targetUserID := range []string{"missing-user", "cross-tenant-user"} {
		t.Run(targetUserID, func(t *testing.T) {
			service := &setAutomaticRecordingService{err: identitybinding.ErrNotFound}
			request := chiCtxWithID(
				httptest.NewRequest(
					http.MethodPost,
					"/admin/v1/users/"+targetUserID+"/department/automatic",
					nil,
				),
				targetUserID,
			)
			request = withOrgUserCtx(request, "tenant-a", "admin-a")
			response := httptest.NewRecorder()

			SetUserDepartmentAutomatic(&Dependencies{IdentityBindingService: service})(response, request)

			if response.Code != http.StatusNotFound {
				t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
			}
			if service.tenantID != "tenant-a" || service.userID != targetUserID {
				t.Fatalf("tenant=%q user=%q", service.tenantID, service.userID)
			}
			responseBodies = append(responseBodies, response.Body.String())
		})
	}
	if responseBodies[0] != responseBodies[1] {
		t.Fatalf("missing and cross-tenant responses differ: %q != %q", responseBodies[0], responseBodies[1])
	}
}
