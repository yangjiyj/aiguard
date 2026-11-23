package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

func TestGetRulePackPullStatusRequiresPlatformAdmin(t *testing.T) {
	t.Run("anonymous", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/admin/v1/rules/pull-status", nil)
		rec := httptest.NewRecorder()

		GetRulePackPullStatus(&Dependencies{}).ServeHTTP(rec, req)

		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("无登录用户应返回 401，实际 %d，body=%s", rec.Code, rec.Body.String())
		}
	})

	t.Run("non platform admin", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/admin/v1/rules/pull-status", nil)
		user := &repository.User{ID: "viewer-a", TenantID: "tenant-a", Role: "viewer", Status: "active"}
		req = req.WithContext(context.WithValue(req.Context(), auth.UserKey, user))
		rec := httptest.NewRecorder()

		GetRulePackPullStatus(&Dependencies{}).ServeHTTP(rec, req)

		if rec.Code != http.StatusForbidden {
			t.Fatalf("非 platform_admin 应返回 403，实际 %d，body=%s", rec.Code, rec.Body.String())
		}
	})
}

func TestRulePackNodeIDIsTenantNamespacedWithoutCrossTenantSquatting(t *testing.T) {
	resetRulePackPullLedger(t)
	now := time.Date(2026, 6, 10, 14, 0, 0, 0, time.UTC)
	setRulePackStatusNow(t, now)
	// 恶意/误配租户先到，也只能写入自己的 tenant+node 键，不能占住另一租户。
	if !recordRulePackPullWithTelemetry("shared-node", "tenant-b", "held-b", "served-b", nil, nil, 60, now) {
		t.Fatal("tenant-b registration should succeed in its namespace")
	}
	if !recordRulePackPullWithTelemetry("shared-node", "tenant-a", "held-a", "served-a", nil, nil, 60, now) {
		t.Fatal("tenant-b must not squat tenant-a's same node ID")
	}

	assertTenantStatus := func(t *testing.T, tenantID, wantHeld, forbiddenHeld string, wantCount int) {
		t.Helper()
		rec := httptest.NewRecorder()
		writeRulePackPullStatusResponse(rec, tenantID, "served-"+strings.TrimPrefix(tenantID, "tenant-"), now)
		if rec.Code != http.StatusOK {
			t.Fatalf("租户管理员应返回 200，实际 %d，body=%s", rec.Code, rec.Body.String())
		}
		var body rulePackPullStatusTestBody
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatalf("响应应为 JSON：%v；原文=%s", err, rec.Body.String())
		}
		if body.Count != wantCount || len(body.Nodes) != wantCount {
			t.Fatalf("响应节点数=%d want=%d，实际 %+v", body.Count, wantCount, body)
		}
		if wantCount == 1 && (body.Nodes[0].NodeID != "shared-node" || body.Nodes[0].HeldVersion != wantHeld) {
			t.Fatalf("返回了错误租户的节点状态，实际 %+v", body.Nodes[0])
		}
		raw := rec.Body.String()
		if strings.Contains(raw, forbiddenHeld) {
			t.Fatalf("响应泄露了另一租户的节点版本：%s", raw)
		}
		if strings.Contains(raw, "tenant_id") || strings.Contains(raw, "tenant-a") || strings.Contains(raw, "tenant-b") {
			t.Fatalf("客户响应不得暴露内部租户标识：%s", raw)
		}
	}

	t.Run("tenant a", func(t *testing.T) {
		assertTenantStatus(t, "tenant-a", "held-a", "held-b", 1)
	})
	t.Run("tenant b", func(t *testing.T) {
		assertTenantStatus(t, "tenant-b", "held-b", "held-a", 1)
	})
}

func TestGetRulePackPullStatusReturnsUnavailableWhenAuthoritativeCompileFails(t *testing.T) {
	req := newRulePackAdminRequest(http.MethodGet, "/admin/v1/rules/pull-status", "tenant-unavailable")
	rec := httptest.NewRecorder()

	GetRulePackPullStatus(&Dependencies{}).ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable || !strings.Contains(rec.Body.String(), runtimeCompileUnavailableCode) || strings.Contains(strings.ToLower(rec.Body.String()), "database") {
		t.Fatalf("compile failure must be safe unavailable/503: status=%d body=%s", rec.Code, rec.Body.String())
	}
}
