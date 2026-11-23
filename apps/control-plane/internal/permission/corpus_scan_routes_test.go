package permission

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
)

// 训练语料扫描（规格 5.7）：
//   - 新建、上传分片、开始、取消、删除、下载副本：SoDSecurityWrite + security_events:write；
//   - 列表、详情、下载报告：SoDSecurityRecordRead + security_events:read，审计员也能看。
var corpusScanWriteRoutes = []struct{ method, path string }{
	{"POST", "/admin/v1/security/corpus-scans"},
	{"PUT", "/admin/v1/security/corpus-scans/{id}/chunks/{n}"},
	{"POST", "/admin/v1/security/corpus-scans/{id}/start"},
	{"POST", "/admin/v1/security/corpus-scans/{id}/cancel"},
	{"DELETE", "/admin/v1/security/corpus-scans/{id}"},
	{"GET", "/admin/v1/security/corpus-scans/{id}/masked"},
}

var corpusScanReadRoutes = []struct{ method, path string }{
	{"GET", "/admin/v1/security/corpus-scans"},
	{"GET", "/admin/v1/security/corpus-scans/{id}"},
	{"GET", "/admin/v1/security/corpus-scans/{id}/report"},
}

func TestCorpusScanRoutesAreRegisteredWithExpectedClassAndPermission(t *testing.T) {
	for _, c := range corpusScanWriteRoutes {
		key := c.method + " " + c.path
		if got := sodRouteTable[key]; got != SoDSecurityWrite {
			t.Errorf("%s: SoD=%q want security_write", key, got)
		}
		if p, ok := routeTable[key]; !ok || p.Resource != "security_events" || p.Action != "write" || p.ScopeType != "tenant" {
			t.Errorf("%s: RBAC=%+v (registered=%v)", key, p, ok)
		}
	}
	for _, c := range corpusScanReadRoutes {
		key := c.method + " " + c.path
		if got := sodRouteTable[key]; got != SoDSecurityRecordRead {
			t.Errorf("%s: SoD=%q want security_record_read", key, got)
		}
		if p, ok := routeTable[key]; !ok || p.Resource != "security_events" || p.Action != "read" || p.ScopeType != "tenant" {
			t.Errorf("%s: RBAC=%+v (registered=%v)", key, p, ok)
		}
	}
}

func TestCorpusScanRoleDecisions(t *testing.T) {
	for _, c := range corpusScanWriteRoutes {
		class := SoDClassFor(c.method, c.path)
		if DecideSoD("security_officer", class, false) != SoDAllow {
			t.Errorf("security officer denied %s %s", c.method, c.path)
		}
		if DecideSoD("auditor", class, false) != SoDDeny {
			t.Errorf("auditor allowed %s %s", c.method, c.path)
		}
	}
	for _, c := range corpusScanReadRoutes {
		class := SoDClassFor(c.method, c.path)
		if DecideSoD("auditor", class, false) != SoDAllow || DecideSoD("security_officer", class, false) != SoDAllow {
			t.Errorf("officer/auditor denied %s %s", c.method, c.path)
		}
	}
}

// 具体路径（带任务编号）也要解析到登记的权限，不能落到「未登记路径只允许平台管理员」。
func TestCorpusScanConcretePathsResolveToRegisteredPermissions(t *testing.T) {
	cases := []struct{ method, pattern, path, action string }{
		{"POST", "/admin/v1/security/corpus-scans", "/admin/v1/security/corpus-scans", "write"},
		{"GET", "/admin/v1/security/corpus-scans", "/admin/v1/security/corpus-scans", "read"},
		{"GET", "/admin/v1/security/corpus-scans/{id}", "/admin/v1/security/corpus-scans/corpus_6f1c9a52-6a43-4d8b-9a4e-3f0d6c1b2a10", "read"},
		{"PUT", "/admin/v1/security/corpus-scans/{id}/chunks/{n}", "/admin/v1/security/corpus-scans/corpus_6f1c9a52-6a43-4d8b-9a4e-3f0d6c1b2a10/chunks/3", "write"},
		{"POST", "/admin/v1/security/corpus-scans/{id}/start", "/admin/v1/security/corpus-scans/corpus_6f1c9a52-6a43-4d8b-9a4e-3f0d6c1b2a10/start", "write"},
		{"POST", "/admin/v1/security/corpus-scans/{id}/cancel", "/admin/v1/security/corpus-scans/corpus_6f1c9a52-6a43-4d8b-9a4e-3f0d6c1b2a10/cancel", "write"},
		{"DELETE", "/admin/v1/security/corpus-scans/{id}", "/admin/v1/security/corpus-scans/corpus_6f1c9a52-6a43-4d8b-9a4e-3f0d6c1b2a10", "write"},
		{"GET", "/admin/v1/security/corpus-scans/{id}/report", "/admin/v1/security/corpus-scans/corpus_6f1c9a52-6a43-4d8b-9a4e-3f0d6c1b2a10/report", "read"},
		{"GET", "/admin/v1/security/corpus-scans/{id}/masked", "/admin/v1/security/corpus-scans/corpus_6f1c9a52-6a43-4d8b-9a4e-3f0d6c1b2a10/masked", "write"},
	}
	for _, c := range cases {
		// 不经过 chi 路由上下文：只靠路径模板归一化（已知路径段）也必须命中。
		got := Resolve(httptest.NewRequest(c.method, c.path, nil))
		if got.RequirePlatformAdmin || got.Resource != "security_events" || got.Action != c.action {
			t.Errorf("%s %s resolved to %+v", c.method, c.path, got)
		}
		// 经过 chi：按注册的路由模式解析。
		router := chi.NewRouter()
		var viaChi ResolvedPermission
		router.MethodFunc(c.method, c.pattern, func(_ http.ResponseWriter, r *http.Request) { viaChi = Resolve(r) })
		router.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(c.method, c.path, nil))
		if viaChi.RequirePlatformAdmin || viaChi.Resource != "security_events" || viaChi.Action != c.action {
			t.Errorf("chi %s %s resolved to %+v", c.method, c.path, viaChi)
		}
	}
}
