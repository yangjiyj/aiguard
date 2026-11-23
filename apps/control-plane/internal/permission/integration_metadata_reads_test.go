package permission

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

func TestIntegrationMetadataReadBoundaries(t *testing.T) {
	for _, path := range []string{"/admin/v1/integration/credential-hits", "/admin/v1/integration/retention-status"} {
		key := "GET " + path
		p := Resolve(httptest.NewRequest("GET", path, nil))
		if p.Resource != "integration_events" || p.Action != "read" || p.ScopeType != "tenant" || p.RequirePlatformAdmin {
			t.Errorf("元数据读取权限未登记：%s %+v", path, p)
		}
		if class, ok := sodRouteTable[key]; !ok || class != SoDSecurityRecordRead {
			t.Errorf("元数据读取未按安全记录登记三员分立：%s", path)
		}
		for _, role := range []string{"security_officer", "auditor"} {
			if DecideSoD(role, SoDClassFor("GET", path), false) != SoDAllow {
				t.Errorf("安全记录职责不一致：%s %s", role, path)
			}
			for _, dryRun := range []bool{false, true} {
				for _, method := range []string{"GET", "POST", "PATCH", "PUT", "DELETE"} {
					r := httptest.NewRequest(method, path+"?tenant_id=foreign", nil)
					r = r.WithContext(context.WithValue(r.Context(), auth.UserKey, &repository.User{Role: "platform_connector", TenantID: "tenant-a"}))
					w := httptest.NewRecorder()
					SoDGuard(nil)(Middleware(nil, nil, dryRun)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))).ServeHTTP(w, r)
					want := 403
					if method == "GET" {
						want = 204
					}
					if w.Code != want {
						t.Errorf("%s %s，演练=%v：%d，期望 %d", method, path, dryRun, w.Code, want)
					}
				}
			}
		}
		for _, suffix := range []string{"/export", "/content", "/key1"} {
			if connectorRouteAllowed(httptest.NewRequest("GET", path+suffix, nil)) {
				t.Errorf("连接器范围意外扩大：%s", path+suffix)
			}
		}
	}
}
