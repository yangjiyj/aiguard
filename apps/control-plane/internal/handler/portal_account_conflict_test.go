package handler

import (
	"context"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/identitybinding"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
	"net/http/httptest"
	"strings"
	"testing"
)

type identityFailureService struct {
	IdentityBindingService
	failure error
}

func (s identityFailureService) BindAndResolve(context.Context, identitybinding.ExternalIdentity) (identitybinding.Resolution, error) {
	return identitybinding.Resolution{}, s.failure
}
func TestPortalIdentityConflictHasAdministratorAction(t *testing.T) {
	for _, item := range []struct {
		failure error
		status  int
		code    string
	}{
		{identitybinding.ErrConflict, 409, "identity_conflict"},
		{identitybinding.ErrNotFound, 503, "identity_not_ready"},
	} {
		r := httptest.NewRequest("POST", "/users", strings.NewReader(`{"issuer":"https://idp.test","source_type":"oidc","external_subject":"signed-subject","username":"alice"}`))
		r.Header.Set(portalIntegrationTenantHeader, "tenant_default")
		w := httptest.NewRecorder()
		EnsurePortalUser(&Dependencies{UserRepo: repository.NewUserRepository(nil), IdentityBindingService: identityFailureService{failure: item.failure}})(w, r)
		if w.Code != item.status || decodeConsoleError(t, w).Error.Code != item.code {
			t.Fatalf("identity failure status=%d expected=%d", w.Code, item.status)
		}
	}
}
