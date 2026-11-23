package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"testing"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/modelops"
)

type portalPerfStub struct {
	tenant string
	window int
	models []string
	err    error
}

func (p *portalPerfStub) PortalPerformance(_ context.Context, tenant string, window int, models []string) (modelops.ModelPerformanceReport, error) {
	p.tenant, p.window, p.models = tenant, window, models
	return modelops.ModelPerformanceReport{Data: []modelops.ModelPerformance{{ModelName: "m1"}}, WindowHours: window}, p.err
}

func TestPortalModelPerformanceForwardsTenantWindowAndModels(t *testing.T) {
	stub := &portalPerfStub{}
	r := httptest.NewRequest("GET", "/admin/v1/portal-integration/model-performance?model=m1&model=m2&window_hours=24", nil)
	r.Header.Set(portalIntegrationTenantHeader, "tenant-a")
	w := httptest.NewRecorder()
	GetPortalModelPerformance(stub)(w, r)
	if w.Code != 200 || stub.tenant != "tenant-a" || stub.window != 24 || len(stub.models) != 2 {
		t.Fatalf("code=%d stub=%+v", w.Code, stub)
	}
	var body modelops.ModelPerformanceReport
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil || len(body.Data) != 1 {
		t.Fatalf("响应格式错误: %s", w.Body.String())
	}
	r = httptest.NewRequest("GET", "/admin/v1/portal-integration/model-performance?model=m1", nil)
	r.Header.Set(portalIntegrationTenantHeader, "tenant-a")
	w = httptest.NewRecorder()
	GetPortalModelPerformance(stub)(w, r)
	if w.Code != 200 || stub.window != 168 {
		t.Fatalf("默认窗口应为 168: %d %d", w.Code, stub.window)
	}
}

func TestPortalModelPerformanceRejectsBadInput(t *testing.T) {
	for _, tc := range []struct {
		query, tenant string
		code          int
		err           error
	}{
		{"?model=m1&window_hours=6", "t", 400, nil},
		{"?model=m1&window_hours=x", "t", 400, nil},
		{"?model=m1", "", 400, nil},
		{"?model=m1", "t", 503, errors.New("timeout")},
	} {
		stub := &portalPerfStub{err: tc.err}
		r := httptest.NewRequest("GET", "/admin/v1/portal-integration/model-performance"+tc.query, nil)
		if tc.tenant != "" {
			r.Header.Set(portalIntegrationTenantHeader, tc.tenant)
		}
		w := httptest.NewRecorder()
		GetPortalModelPerformance(stub)(w, r)
		if w.Code != tc.code {
			t.Fatalf("%s → %d，预期 %d", tc.query, w.Code, tc.code)
		}
	}
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/admin/v1/portal-integration/model-performance?model=m1", nil)
	r.Header.Set(portalIntegrationTenantHeader, "t")
	GetPortalModelPerformance(nil)(w, r)
	if w.Code != 503 {
		t.Fatalf("未配置服务应返回 503: %d", w.Code)
	}
}
