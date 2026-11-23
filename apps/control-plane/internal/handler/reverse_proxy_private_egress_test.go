package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
	"github.com/go-chi/chi/v5"
)

type reverseProxyAuditRepo struct {
	MockSystemRepo
	op *repository.AuditOperation
}

func (r *reverseProxyAuditRepo) CreateAuditOperation(_ context.Context, op *repository.AuditOperation) error {
	r.op = op
	return nil
}

func privateEgressCreateRequest(cidrs []string) ReverseProxyRouteCreateRequest {
	return ReverseProxyRouteCreateRequest{
		Name:               "Acme",
		PathPrefix:         "/proxy/acme",
		TargetURL:          "https://api.example.cn",
		SecurityEnabled:    true,
		StatsEnabled:       true,
		Status:             "active",
		AllowPrivateEgress: true,
		PrivateEgressCIDRs: cidrs,
	}
}

func TestBuildReverseProxyRouteForCreate_NormalizesPrivateEgressCIDRs(t *testing.T) {
	req := privateEgressCreateRequest([]string{
		" 172.16.20.17/32 ",
		"10.20.30.40/24",
		"172.16.20.17/32",
	})

	entry, err := buildReverseProxyRouteForCreate("tenant_demo", req)
	if err != nil {
		t.Fatalf("build route: %v", err)
	}

	want := []string{"172.16.20.17/32", "10.20.30.0/24"}
	if !reflect.DeepEqual(entry.PrivateEgressCIDRs, want) {
		t.Fatalf("private egress CIDRs mismatch: got %v want %v", entry.PrivateEgressCIDRs, want)
	}
	if !entry.AllowPrivateEgress {
		t.Fatal("expected private egress to be enabled")
	}
}

func TestBuildReverseProxyRouteForCreate_RejectsEnabledWithoutCIDRs(t *testing.T) {
	_, err := buildReverseProxyRouteForCreate("tenant_demo", privateEgressCreateRequest(nil))
	if err == nil || !strings.Contains(err.Error(), "private_egress_cidrs") {
		t.Fatalf("expected private_egress_cidrs validation error, got %v", err)
	}
}

func TestBuildReverseProxyRouteForCreate_RejectsInvalidCIDR(t *testing.T) {
	_, err := buildReverseProxyRouteForCreate("tenant_demo", privateEgressCreateRequest([]string{"172.16.20.17", "bad-cidr"}))
	if err == nil || !strings.Contains(err.Error(), "private_egress_cidrs") {
		t.Fatalf("expected strict CIDR validation error, got %v", err)
	}
}

func TestBuildReverseProxyRouteForUpdate_RejectsClearingEnabledCIDRs(t *testing.T) {
	existing := &repository.ReverseProxyRoute{
		ID:                 "rpr_001",
		TenantID:           "tenant_demo",
		Name:               "Acme",
		PathPrefix:         "/proxy/acme",
		TargetURL:          "https://api.example.cn",
		SecurityEnabled:    true,
		StatsEnabled:       true,
		Status:             "active",
		AllowPrivateEgress: true,
		PrivateEgressCIDRs: []string{"172.16.20.17/32"},
	}
	empty := []string{}

	_, err := buildReverseProxyRouteForUpdate(existing, ReverseProxyRouteUpdateRequest{
		PrivateEgressCIDRs: &empty,
	})
	if err == nil || !strings.Contains(err.Error(), "private_egress_cidrs") {
		t.Fatalf("expected clearing CIDRs to fail while enabled, got %v", err)
	}
}

func TestCreateReverseProxyRoute_ReturnsAndAuditsPrivateEgressAuthorization(t *testing.T) {
	repo := newMockReverseProxyRouteRepo()
	audit := &reverseProxyAuditRepo{}
	deps := &Dependencies{ReverseProxyRouteRepo: repo, SystemRepo: audit}
	body := `{
		"name":"Acme",
		"path_prefix":"/proxy/acme",
		"target_url":"https://api.example.cn",
		"security_enabled":true,
		"stats_enabled":true,
		"status":"active",
		"allow_private_egress":true,
		"private_egress_cidrs":["172.16.20.17/32"]
	}`
	req := reverseProxyTestRequest(http.MethodPost, "/admin/v1/reverse-proxy/routes", body, &repository.User{
		ID: "user_admin", TenantID: "tenant_demo", Role: "platform_admin",
	})
	w := httptest.NewRecorder()

	CreateReverseProxyRoute(deps).ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d body=%s", w.Code, w.Body.String())
	}
	var got ReverseProxyRouteInfo
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !got.AllowPrivateEgress || !reflect.DeepEqual(got.PrivateEgressCIDRs, []string{"172.16.20.17/32"}) {
		t.Fatalf("authorization fields missing from response: %+v", got)
	}
	if audit.op == nil {
		t.Fatal("expected operation audit")
	}
	if audit.op.ActionDetail["allow_private_egress"] != true {
		t.Fatalf("audit missing allow_private_egress: %+v", audit.op.ActionDetail)
	}
	if !reflect.DeepEqual(audit.op.ActionDetail["private_egress_cidrs"], []string{"172.16.20.17/32"}) {
		t.Fatalf("audit missing private_egress_cidrs: %+v", audit.op.ActionDetail)
	}
}

func TestUpdateReverseProxyRoute_ReturnsAndAuditsPrivateEgressAuthorization(t *testing.T) {
	repo := newMockReverseProxyRouteRepo()
	repo.entries["rpr_001"] = &repository.ReverseProxyRoute{
		ID: "rpr_001", TenantID: "tenant_demo", Name: "Acme",
		PathPrefix: "/proxy/acme", TargetURL: "https://api.example.cn",
		Status: "active", SecurityEnabled: true, StatsEnabled: true,
		PrivateEgressCIDRs: []string{},
	}
	audit := &reverseProxyAuditRepo{}
	deps := &Dependencies{ReverseProxyRouteRepo: repo, SystemRepo: audit}
	body := `{
		"allow_private_egress":true,
		"private_egress_cidrs":["172.16.20.17/32"]
	}`
	req := reverseProxyTestRequest(http.MethodPut, "/admin/v1/reverse-proxy/routes/rpr_001", body, &repository.User{
		ID: "user_admin", TenantID: "tenant_demo", Role: "platform_admin",
	})
	w := httptest.NewRecorder()
	router := chi.NewRouter()
	router.Put("/admin/v1/reverse-proxy/routes/{id}", UpdateReverseProxyRoute(deps))

	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", w.Code, w.Body.String())
	}
	var got ReverseProxyRouteInfo
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !got.AllowPrivateEgress || !reflect.DeepEqual(got.PrivateEgressCIDRs, []string{"172.16.20.17/32"}) {
		t.Fatalf("authorization fields missing from response: %+v", got)
	}
	if audit.op == nil || audit.op.ActionType != "update_reverse_proxy_route" {
		t.Fatalf("expected update operation audit, got %+v", audit.op)
	}
	if audit.op.ActionDetail["previous_allow_private_egress"] != false ||
		audit.op.ActionDetail["allow_private_egress"] != true {
		t.Fatalf("audit missing authorization transition: %+v", audit.op.ActionDetail)
	}
	if !reflect.DeepEqual(audit.op.ActionDetail["private_egress_cidrs"], []string{"172.16.20.17/32"}) {
		t.Fatalf("audit missing private_egress_cidrs: %+v", audit.op.ActionDetail)
	}
}

func TestUpdateReverseProxyRoute_RejectsPrivateEgressAuthorizationFromNonPlatformAdmin(t *testing.T) {
	repo := newMockReverseProxyRouteRepo()
	repo.entries["rpr_001"] = &repository.ReverseProxyRoute{
		ID: "rpr_001", TenantID: "tenant_demo", Name: "Acme",
		PathPrefix: "/proxy/acme", TargetURL: "https://api.example.cn",
		Status: "active", PrivateEgressCIDRs: []string{},
	}
	audit := &reverseProxyAuditRepo{}
	deps := &Dependencies{ReverseProxyRouteRepo: repo, SystemRepo: audit}
	body := `{
		"allow_private_egress":true,
		"private_egress_cidrs":["172.16.20.17/32"]
	}`
	req := reverseProxyTestRequest(http.MethodPut, "/admin/v1/reverse-proxy/routes/rpr_001", body, &repository.User{
		ID: "user_developer", TenantID: "tenant_demo", Role: "developer",
	})
	w := httptest.NewRecorder()
	router := chi.NewRouter()
	router.Put("/admin/v1/reverse-proxy/routes/{id}", UpdateReverseProxyRoute(deps))

	router.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d body=%s", w.Code, w.Body.String())
	}
	if repo.entries["rpr_001"].AllowPrivateEgress || len(repo.entries["rpr_001"].PrivateEgressCIDRs) != 0 {
		t.Fatalf("non-admin changed authorization: %+v", repo.entries["rpr_001"])
	}
	if audit.op != nil {
		t.Fatalf("rejected update must not create operation audit: %+v", audit.op)
	}
}

func TestListReverseProxyRoutes_IncludesPrivateEgressFields(t *testing.T) {
	repo := newMockReverseProxyRouteRepo()
	repo.entries["rpr_001"] = &repository.ReverseProxyRoute{
		ID: "rpr_001", TenantID: "tenant_demo", Name: "Acme",
		PathPrefix: "/proxy/acme", TargetURL: "https://api.example.cn",
		Status: "active", AllowPrivateEgress: true,
		PrivateEgressCIDRs: []string{"172.16.20.17/32"},
	}
	deps := &Dependencies{ReverseProxyRouteRepo: repo}
	req := reverseProxyTestRequest(http.MethodGet, "/admin/v1/reverse-proxy/routes", "", &repository.User{
		ID: "user_admin", TenantID: "tenant_demo", Role: "platform_admin",
	})
	w := httptest.NewRecorder()

	ListReverseProxyRoutes(deps).ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", w.Code, w.Body.String())
	}
	var got struct {
		Data []ReverseProxyRouteInfo `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(got.Data) != 1 || !got.Data[0].AllowPrivateEgress ||
		!reflect.DeepEqual(got.Data[0].PrivateEgressCIDRs, []string{"172.16.20.17/32"}) {
		t.Fatalf("list response missing authorization fields: %+v", got.Data)
	}
}
