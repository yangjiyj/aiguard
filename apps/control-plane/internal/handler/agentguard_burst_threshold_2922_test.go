package handler

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
)

// 复审：保存行为基线时 *_burst_10s 阈值不超过注册表次数上限（1000），超出、负数或非整数返回 400。
func TestAgentGuardPolicy2922BurstThresholdUpperBound(t *testing.T) {
	for _, tc := range []struct {
		behavior string
		want     int
	}{
		{`{"file_read_burst_10s": 1000, "network_egress_burst_10s": 0, "command_execute_burst_10s": 50}`, http.StatusCreated},
		{`{"file_read_burst_10s": 1001}`, http.StatusBadRequest},
		{`{"network_egress_burst_10s": 5000}`, http.StatusBadRequest},
		{`{"command_execute_burst_10s": -1}`, http.StatusBadRequest},
		{`{"command_execute_burst_10s": 2.5}`, http.StatusBadRequest},
		{`{"sensitive_read_egress_window_seconds": 3600}`, http.StatusCreated},
	} {
		repo := newFakeAgentGuardPolicyRepo()
		deps := &Dependencies{AgentGuardPolicyRepo: repo, SystemRepo: &agentGuardAuditSystemRepo{}}
		body := []byte(fmt.Sprintf(`{"name":"租户策略","scope_type":"tenant","enabled":true,"behavior_json":%s}`, tc.behavior))
		rr := httptest.NewRecorder()
		CreateAgentGuardPolicy(deps)(rr, withAgentGuardTenantUser(httptest.NewRequest(http.MethodPost, "/admin/v1/agentguard/policies", bytes.NewReader(body)), "tenant-a"))
		if rr.Code != tc.want {
			t.Fatalf("create %s: status=%d want %d body=%s", tc.behavior, rr.Code, tc.want, rr.Body.String())
		}
		if tc.want != http.StatusCreated {
			if len(repo.policies) != 0 {
				t.Fatalf("a rejected policy must not be stored: %s", tc.behavior)
			}
			continue
		}
		var id string
		for stored := range repo.policies {
			id = stored
		}
		update := []byte(`{"name":"租户策略","scope_type":"tenant","enabled":true,"behavior_json":{"file_read_burst_10s": 1001}}`)
		req := withAgentGuardTenantUser(httptest.NewRequest(http.MethodPut, "/admin/v1/agentguard/policies/"+id, bytes.NewReader(update)), "tenant-a")
		route := chi.NewRouteContext()
		route.URLParams.Add("id", id)
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, route))
		rr = httptest.NewRecorder()
		UpdateAgentGuardPolicy(deps)(rr, req)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("update over the cap: status=%d body=%s", rr.Code, rr.Body.String())
		}
	}
}
