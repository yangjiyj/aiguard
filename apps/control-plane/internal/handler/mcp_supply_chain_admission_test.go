package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

type fakeMCPSupplyChainRepo struct {
	tenant, id, status, hash, routeHash, reason, actor, assetType string
	err                                                           error
}

func (f *fakeMCPSupplyChainRepo) ApplySupplyChainSync(context.Context, repository.MCPSupplyChainSyncInput) (*repository.MCPSupplyChainSyncResult, error) {
	return nil, nil
}
func (f *fakeMCPSupplyChainRepo) ResolveMCPSupplyChain(context.Context, string, string, string) (repository.MCPSupplyChainResolution, error) {
	return repository.MCPSupplyChainResolution{}, nil
}
func (f *fakeMCPSupplyChainRepo) set(tenant, id, status, hash, reason, actor, assetType string) (*repository.MCPAdmissionMutation, error) {
	f.tenant, f.id, f.status, f.hash, f.reason, f.actor, f.assetType = tenant, id, status, hash, reason, actor, assetType
	if f.err != nil {
		return nil, f.err
	}
	return &repository.MCPAdmissionMutation{AssetType: assetType, ID: id, Status: status, Hash: hash, Revision: 7}, nil
}
func (f *fakeMCPSupplyChainRepo) SetMCPServerAdmission(_ context.Context, tenant, id, status, hash, routeHash, reason, actor string) (*repository.MCPAdmissionMutation, error) {
	f.routeHash = routeHash
	mutation, err := f.set(tenant, id, status, hash, reason, actor, "server")
	return mutation, err
}
func (f *fakeMCPSupplyChainRepo) SetMCPToolAdmission(_ context.Context, tenant, id, status, hash, reason, actor string) (*repository.MCPAdmissionMutation, error) {
	return f.set(tenant, id, status, hash, reason, actor, "tool")
}

func TestSetMCPAdmissionUsesSessionTenantAndExactSnapshot(t *testing.T) {
	hash := strings.Repeat("a", 64)
	repo := &fakeMCPSupplyChainRepo{}
	deps := &Dependencies{MCPSupplyChainRepo: repo}
	request := skillUserRequest(http.MethodPost, "/admin/v1/mcp-tools/tool-a/admission", "tenant-a", "tenant_admin",
		[]byte(`{"status":"approved","expected_hash":"`+hash+`","reason":"reviewed"}`))
	request = skillRouteParam(request, "id", "tool-a")
	recorder := httptest.NewRecorder()
	SetMCPToolAdmission(deps).ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if repo.tenant != "tenant-a" || repo.id != "tool-a" || repo.hash != hash ||
		repo.status != "approved" || repo.actor != "admin-a" || repo.assetType != "tool" {
		t.Fatalf("wrong scoped mutation: %+v", repo)
	}
}

func TestSetMCPServerAdmissionBindsManifestAndRoute(t *testing.T) {
	manifestHash, routeHash := strings.Repeat("e", 64), strings.Repeat("f", 64)
	repo := &fakeMCPSupplyChainRepo{}
	request := skillUserRequest(http.MethodPost, "/admin/v1/mcp-servers/server-a/admission", "tenant-a", "tenant_admin",
		[]byte(`{"status":"approved","expected_hash":"`+manifestHash+`","expected_route_hash":"`+routeHash+`"}`))
	request = skillRouteParam(request, "id", "server-a")
	recorder := httptest.NewRecorder()
	SetMCPServerAdmission(&Dependencies{MCPSupplyChainRepo: repo}).ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if repo.hash != manifestHash || repo.routeHash != routeHash || repo.tenant != "tenant-a" {
		t.Fatalf("server approval not bound to exact route: %+v", repo)
	}
}

func TestSetMCPAdmissionRejectsStaleSnapshotAndNonAdmin(t *testing.T) {

	hash := strings.Repeat("b", 64)
	routeHash := strings.Repeat("d", 64)
	repo := &fakeMCPSupplyChainRepo{err: repository.ErrMCPAdmissionSnapshotConflict}
	deps := &Dependencies{MCPSupplyChainRepo: repo}
	request := skillUserRequest(http.MethodPost, "/admin/v1/mcp-servers/server-a/admission", "tenant-a", "tenant_admin",
		[]byte(`{"status":"quarantined","expected_hash":"`+hash+`","expected_route_hash":"`+routeHash+`","reason":"manual"}`))
	request = skillRouteParam(request, "id", "server-a")
	recorder := httptest.NewRecorder()
	SetMCPServerAdmission(deps).ServeHTTP(recorder, request)
	if recorder.Code != http.StatusConflict {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}

	denied := skillUserRequest(http.MethodPost, "/admin/v1/mcp-servers/server-a/admission", "tenant-a", "developer",
		[]byte(`{"status":"revoked","expected_hash":"`+hash+`"}`))
	denied = skillRouteParam(denied, "id", "server-a")
	deniedRecorder := httptest.NewRecorder()
	SetMCPServerAdmission(deps).ServeHTTP(deniedRecorder, denied)
	if deniedRecorder.Code != http.StatusForbidden {
		t.Fatalf("developer status=%d", deniedRecorder.Code)
	}
}

func TestSetMCPAdmissionStrictRequestContract(t *testing.T) {
	hash := strings.Repeat("c", 64)
	for name, body := range map[string]string{
		"unknown field": `{"status":"approved","expected_hash":"` + hash + `","tenant_id":"other"}`,
		"bad hash":      `{"status":"approved","expected_hash":"short"}`,
		"trailing":      `{"status":"approved","expected_hash":"` + hash + `"}` + `{"x":1}`,
	} {
		t.Run(name, func(t *testing.T) {
			request := skillUserRequest(http.MethodPost, "/admin/v1/mcp-tools/tool-a/admission", "tenant-a", "tenant_admin", []byte(body))
			request = skillRouteParam(request, "id", "tool-a")
			recorder := httptest.NewRecorder()
			SetMCPToolAdmission(&Dependencies{MCPSupplyChainRepo: &fakeMCPSupplyChainRepo{}}).ServeHTTP(recorder, request)
			if recorder.Code != http.StatusBadRequest {
				t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
			}
		})
	}
}

var _ MCPSupplyChainRepo = (*fakeMCPSupplyChainRepo)(nil)
