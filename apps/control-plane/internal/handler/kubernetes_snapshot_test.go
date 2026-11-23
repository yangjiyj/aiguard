package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

type fakeKubernetesSnapshotRepo struct {
	beginCalls int
}

func (f *fakeKubernetesSnapshotRepo) CreateCluster(context.Context, string, string, repository.KubernetesClusterCreate) (*repository.KubernetesClusterRegistration, error) {
	return nil, nil
}
func (f *fakeKubernetesSnapshotRepo) RegisterNamespace(context.Context, string, string, string, repository.KubernetesNamespaceRegister) (*repository.KubernetesNamespaceRegistrationSummary, error) {
	return nil, nil
}
func (f *fakeKubernetesSnapshotRepo) ListClusters(context.Context, string) ([]repository.KubernetesClusterRegistration, error) {
	return nil, nil
}
func (f *fakeKubernetesSnapshotRepo) RevokeNamespace(context.Context, string, string, string) (bool, error) {
	return false, nil
}
func (f *fakeKubernetesSnapshotRepo) GetCoverage(context.Context, string, string) (*repository.KubernetesClusterCoverage, error) {
	return nil, nil
}
func (f *fakeKubernetesSnapshotRepo) BeginSnapshotRun(context.Context, *repository.AgentEndpointContext, repository.KubernetesSnapshotRunRequest) (*repository.KubernetesSnapshotRun, error) {
	f.beginCalls++
	return nil, nil
}
func (f *fakeKubernetesSnapshotRepo) IngestSnapshot(context.Context, *repository.AgentEndpointContext, repository.KubernetesObservationReport) (*repository.KubernetesSnapshotIngestResult, error) {
	return nil, nil
}

func TestKubernetesSnapshotBeginRequiresDedicatedRegisteredProduct(t *testing.T) {
	repo := &fakeKubernetesSnapshotRepo{}
	api := NewAgentKubernetesSnapshotAPI(repo)
	request := httptest.NewRequest(http.MethodPost, "/snapshot-runs", strings.NewReader(`{"request_id":"6ba7b810-9dad-11d1-80b4-00c04fd430c8"}`))
	request = request.WithContext(contextWithEndpoint(request.Context(), &repository.AgentEndpointContext{
		TenantID: "tenant-a", EndpointID: "endpoint-a", AgentProduct: "claude-code",
	}))
	response := httptest.NewRecorder()
	api.BeginSnapshotRun(response, request)
	if response.Code != http.StatusForbidden || repo.beginCalls != 0 {
		t.Fatalf("generic endpoint was accepted: status=%d calls=%d body=%s", response.Code, repo.beginCalls, response.Body.String())
	}
}

func TestKubernetesSnapshotBeginRejectsCallerScopeFields(t *testing.T) {
	repo := &fakeKubernetesSnapshotRepo{}
	api := NewAgentKubernetesSnapshotAPI(repo)
	request := httptest.NewRequest(http.MethodPost, "/snapshot-runs",
		strings.NewReader(`{"request_id":"6ba7b810-9dad-11d1-80b4-00c04fd430c8","tenant_id":"tenant-b","namespace_uid":"attacker-uid"}`))
	request = request.WithContext(contextWithEndpoint(request.Context(), &repository.AgentEndpointContext{
		TenantID: "tenant-a", EndpointID: "endpoint-a", AgentProduct: repository.KubernetesCollectorProduct,
	}))
	response := httptest.NewRecorder()
	api.BeginSnapshotRun(response, request)
	if response.Code != http.StatusBadRequest || repo.beginCalls != 0 {
		t.Fatalf("caller scope fields were accepted: status=%d calls=%d body=%s", response.Code, repo.beginCalls, response.Body.String())
	}
}
