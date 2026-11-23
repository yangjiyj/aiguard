package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
)

type trafficClassStub struct {
	called             bool
	tenant, key, class string
	err                error
}

func (s *trafficClassStub) SetTrafficClass(_ context.Context, tenant, key, class string) error {
	s.called, s.tenant, s.key, s.class = true, tenant, key, class
	return s.err
}

func trafficClassRequest(role, id, body string) *http.Request {
	r := contentAuditAuthRequest(role)
	r.Method = http.MethodPut
	r.URL.Path = "/admin/v1/keys/" + id + "/traffic-class"
	r.Body = http.NoBody
	if body != "" {
		r.Body = httptest.NewRequest(http.MethodPut, "/", strings.NewReader(body)).Body
	}
	rc := chi.NewRouteContext()
	rc.URLParams.Add("id", id)
	return r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rc))
}

// 车道只信这个标记，所以只有控制台管理员能改；其它角色在到达仓储前就被拒绝。
func TestSetKeyTrafficClassRequiresConsoleAdministrator(t *testing.T) {
	for _, role := range []string{"viewer", "auditor", "developer", "chat_user", "dept_manager"} {
		s := &trafficClassStub{}
		w := httptest.NewRecorder()
		SetKeyTrafficClass(s).ServeHTTP(w, trafficClassRequest(role, "key-1", `{"traffic_class":"evaluation"}`))
		if w.Code != http.StatusForbidden || s.called {
			t.Fatalf("role %s: status=%d called=%v", role, w.Code, s.called)
		}
	}
}

func TestSetKeyTrafficClassValidatesValueBeforeWriting(t *testing.T) {
	for _, body := range []string{`{"traffic_class":"bogus"}`, `{"traffic_class":"EVALUATION "}`, `{"traffic_class":null}`, `{}`, `not json`, `{"traffic_class":"evaluation","extra":1}`} {
		s := &trafficClassStub{}
		w := httptest.NewRecorder()
		SetKeyTrafficClass(s).ServeHTTP(w, trafficClassRequest("tenant_admin", "key-1", body))
		if w.Code != http.StatusBadRequest || s.called {
			t.Fatalf("body %q: status=%d called=%v", body, w.Code, s.called)
		}
	}
}

func TestSetKeyTrafficClassWritesWithinCallerTenant(t *testing.T) {
	for class, want := range map[string]string{"evaluation": "evaluation", "coding": "coding", "": ""} {
		s := &trafficClassStub{}
		w := httptest.NewRecorder()
		SetKeyTrafficClass(s).ServeHTTP(w, trafficClassRequest("tenant_admin", "key-9", `{"traffic_class":"`+class+`"}`))
		if w.Code != http.StatusNoContent || !s.called || s.tenant != "tenant-a" || s.key != "key-9" || s.class != want {
			t.Fatalf("class %q: status=%d stub=%+v", class, w.Code, s)
		}
	}
}

func TestSetKeyTrafficClassUnknownKeyIs404(t *testing.T) {
	s := &trafficClassStub{err: errKeyNotFound}
	w := httptest.NewRecorder()
	SetKeyTrafficClass(s).ServeHTTP(w, trafficClassRequest("tenant_admin", "other-tenant-key", `{"traffic_class":"evaluation"}`))
	if w.Code != http.StatusNotFound {
		t.Fatalf("status=%d", w.Code)
	}
}
