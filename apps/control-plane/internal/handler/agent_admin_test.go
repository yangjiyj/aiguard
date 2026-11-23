package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

type agentAdminFakeRepo struct {
	AgentAdminRepo
	endpointTenant   string
	endpoint         *repository.AgentAdminEndpoint
	detailTenant     string
	detail           *repository.AgentSessionDetail
	created          *repository.AgentEnrollmentTokenCreated
	listed           *repository.AgentEnrollmentTokenPage
	enrollmentFilter repository.AgentEnrollmentTokenFilter
	endpointPage     *repository.AgentEndpointPage
	endpointListCall int
	events           *repository.AgentEventPage
	assets           *repository.AgentAssetPage
	rotatedToken     string
	rotateFound      bool
}

func (f *agentAdminFakeRepo) GetEndpoint(_ context.Context, tenant, _ string) (*repository.AgentAdminEndpoint, error) {
	f.endpointTenant = tenant
	return f.endpoint, nil
}

func (f *agentAdminFakeRepo) GetSessionDetail(_ context.Context, tenant, _ string) (*repository.AgentSessionDetail, error) {
	f.detailTenant = tenant
	return f.detail, nil
}

func (f *agentAdminFakeRepo) CreateEnrollmentToken(_ context.Context, _ string, _ repository.AgentEnrollmentTokenCreate) (*repository.AgentEnrollmentTokenCreated, error) {
	return f.created, nil
}

func (f *agentAdminFakeRepo) ListEnrollmentTokens(_ context.Context, _ string, filter repository.AgentEnrollmentTokenFilter) (*repository.AgentEnrollmentTokenPage, error) {
	f.enrollmentFilter = filter
	return f.listed, nil
}

func (f *agentAdminFakeRepo) ListEndpoints(_ context.Context, _ string, _ repository.AgentEndpointFilter) (*repository.AgentEndpointPage, error) {
	f.endpointListCall++
	return f.endpointPage, nil
}

func (f *agentAdminFakeRepo) ListEvents(_ context.Context, _ string, _ repository.AgentEventFilter) (*repository.AgentEventPage, error) {
	return f.events, nil
}

func (f *agentAdminFakeRepo) ListAssets(_ context.Context, _ string, _ repository.AgentAssetFilter) (*repository.AgentAssetPage, error) {
	return f.assets, nil
}

func (f *agentAdminFakeRepo) RotateEndpointToken(_ context.Context, _, _ string) (string, bool, error) {
	return f.rotatedToken, f.rotateFound, nil
}

func agentAdminRequest(method, path, role string, body []byte) *http.Request {
	req := httptest.NewRequest(method, path, bytes.NewReader(body))
	user := &repository.User{ID: "user-a", TenantID: "tenant-a", Role: role, Status: "active"}
	if role == "emergency_tenant_admin" {
		user.Role = "tenant_admin"
		user.DepartmentAssignmentMode = "emergency"
	}
	ctx := context.WithValue(req.Context(), auth.UserKey, user)
	ctx = context.WithValue(ctx, auth.SessionKey, &repository.Session{UserID: user.ID, TenantID: user.TenantID})
	return req.WithContext(ctx)
}

func TestAgentAdminEndpointBOLAReturns404(t *testing.T) {
	repo := &agentAdminFakeRepo{}
	api := NewAgentAdminAPI(repo, &Dependencies{})
	router := chi.NewRouter()
	router.Get("/admin/v1/agent/endpoints/{id}", api.GetEndpoint)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, agentAdminRequest(http.MethodGet, "/admin/v1/agent/endpoints/other-tenant-id", "tenant_admin", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	if repo.endpointTenant != "tenant-a" {
		t.Fatalf("repository tenant=%q want tenant-a", repo.endpointTenant)
	}
}

func TestAgentSessionDetailDowngradesContentWithoutFullEvidencePermission(t *testing.T) {
	repo := &agentAdminFakeRepo{detail: &repository.AgentSessionDetail{
		Overview:     repository.AgentAdminSession{ID: "row-1", SessionID: "session-1"},
		Turns:        []repository.AgentTurn{{PromptHash: "prompt-hash", PromptPreview: "secret prompt", AssistantPreview: "secret answer"}},
		Events:       []repository.AgentAdminEvent{{Payload: json.RawMessage(`{"content":{"hash":"sha256:abc","length":12,"text":"secret"},"other":"ok"}`)}},
		ToolCallLogs: []repository.AgentToolCall{{ArgsSummary: json.RawMessage(`{"command":"cat ~/.ssh/id_rsa","command_hash":"sha256:def","command_length":17,"safe":"value"}`)}},
	}}
	api := NewAgentAdminAPI(repo, &Dependencies{})
	router := chi.NewRouter()
	router.Get("/admin/v1/agent/sessions/{id}", api.GetSession)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, agentAdminRequest(http.MethodGet, "/admin/v1/agent/sessions/session-1", "emergency_tenant_admin", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	for _, forbidden := range []string{"secret prompt", "secret answer", "cat ~/.ssh/id_rsa", `"text":"secret"`} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("response leaked %q: %s", forbidden, body)
		}
	}
	for _, retained := range []string{"prompt-hash", "sha256:abc", `"length":12`, "sha256:def", `"command_length":17`} {
		if !strings.Contains(body, retained) {
			t.Fatalf("response lost %q: %s", retained, body)
		}
	}
}

func TestEnrollmentTokenPlaintextOnlyInCreateResponse(t *testing.T) {
	repo := &agentAdminFakeRepo{
		created: &repository.AgentEnrollmentTokenCreated{AgentEnrollmentToken: repository.AgentEnrollmentToken{ID: "aet-1", Name: "bootstrap", TokenPrefix: "prefix12"}, Token: "one-time-secret"},
		listed:  &repository.AgentEnrollmentTokenPage{Items: []repository.AgentEnrollmentToken{{ID: "aet-1", Name: "bootstrap", TokenPrefix: "prefix12"}}},
	}
	api := NewAgentAdminAPI(repo, &Dependencies{})
	create := httptest.NewRecorder()
	api.CreateEnrollmentToken(create, agentAdminRequest(http.MethodPost, "/admin/v1/agent/enrollment-tokens", "tenant_admin", []byte(`{"name":"bootstrap"}`)))
	if create.Code != http.StatusCreated || !strings.Contains(create.Body.String(), "one-time-secret") {
		t.Fatalf("create status=%d body=%s", create.Code, create.Body.String())
	}
	assertAgentAdminNoStore(t, create)
	list := httptest.NewRecorder()
	api.ListEnrollmentTokens(list, agentAdminRequest(http.MethodGet, "/admin/v1/agent/enrollment-tokens", "tenant_admin", nil))
	if list.Code != http.StatusOK || strings.Contains(list.Body.String(), "one-time-secret") || strings.Contains(list.Body.String(), "token_hash") {
		t.Fatalf("list leaked token material: status=%d body=%s", list.Code, list.Body.String())
	}
}

func assertAgentAdminNoStore(t *testing.T, rec *httptest.ResponseRecorder) {
	t.Helper()
	if got := rec.Header().Get("Cache-Control"); got != "no-store,max-age=0" {
		t.Fatalf("Cache-Control=%q", got)
	}
	if got := rec.Header().Get("Pragma"); got != "no-cache" {
		t.Fatalf("Pragma=%q", got)
	}
}

func TestAgentAdminAuditDetailKeysExcludeTokenAndHash(t *testing.T) {
	body, err := os.ReadFile("agent_admin.go")
	if err != nil {
		t.Fatal(err)
	}
	source := string(body)
	for _, forbidden := range []string{`map[string]interface{}{"enrollment_token_id"`, `map[string]interface{}{"token"`, `map[string]interface{}{"token_hash"`, `map[string]interface{}{"hash"`} {
		if strings.Contains(source, forbidden) {
			t.Errorf("agent audit detail contains sensitive key %q", forbidden)
		}
	}
}

func TestRotateEndpointTokenResponseDisablesCaching(t *testing.T) {
	repo := &agentAdminFakeRepo{rotatedToken: "rotated-secret", rotateFound: true}
	api := NewAgentAdminAPI(repo, &Dependencies{})
	router := chi.NewRouter()
	router.Post("/admin/v1/agent/endpoints/{id}/rotate-token", api.RotateEndpointToken)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, agentAdminRequest(http.MethodPost, "/admin/v1/agent/endpoints/endpoint-1/rotate-token", "tenant_admin", nil))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "rotated-secret") {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	assertAgentAdminNoStore(t, rec)
}

func TestAgentAdminRejectsInvalidPagination(t *testing.T) {
	for _, query := range []string{"page=0", "page=-1", "page=abc", "page_size=0", "page_size=201", "page_size=abc"} {
		t.Run(query, func(t *testing.T) {
			repo := &agentAdminFakeRepo{endpointPage: &repository.AgentEndpointPage{}}
			api := NewAgentAdminAPI(repo, &Dependencies{})
			rec := httptest.NewRecorder()
			api.ListEndpoints(rec, agentAdminRequest(http.MethodGet, "/admin/v1/agent/endpoints?"+query, "tenant_admin", nil))
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
			}
			if repo.endpointListCall != 0 {
				t.Fatal("repository called for invalid pagination")
			}
		})
	}
}

func TestEnrollmentTokenListFiltersEnabled(t *testing.T) {
	repo := &agentAdminFakeRepo{listed: &repository.AgentEnrollmentTokenPage{}}
	api := NewAgentAdminAPI(repo, &Dependencies{})
	rec := httptest.NewRecorder()
	api.ListEnrollmentTokens(rec, agentAdminRequest(http.MethodGet, "/admin/v1/agent/enrollment-tokens?enabled=false", "tenant_admin", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	if repo.enrollmentFilter.Enabled == nil || *repo.enrollmentFilter.Enabled {
		t.Fatalf("enabled filter=%v", repo.enrollmentFilter.Enabled)
	}
}

func TestAgentEventListDowngradesContentWithoutFullEvidencePermission(t *testing.T) {
	repo := &agentAdminFakeRepo{events: &repository.AgentEventPage{Items: []repository.AgentAdminEvent{{
		Payload:        json.RawMessage(`{"Content":{"hash":"sha256:abc","length":12,"text":"secret"},"nested":{"Authorization":"Bearer secret","safe":"ok"}}`),
		LocalDecision:  json.RawMessage(`{"result":"secret result","result_hash":"sha256:def","score":7}`),
		ServerDecision: json.RawMessage(`not-json-secret`),
	}}}}
	api := NewAgentAdminAPI(repo, &Dependencies{})
	rec := httptest.NewRecorder()
	api.ListEvents(rec, agentAdminRequest(http.MethodGet, "/admin/v1/agent/events", "emergency_tenant_admin", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	for _, forbidden := range []string{"secret", "Bearer", "not-json"} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("response leaked %q: %s", forbidden, body)
		}
	}
	for _, retained := range []string{"sha256:abc", `"length":12`, "sha256:def", `"score":7`, `"safe":"ok"`, `"server_decision":{}`} {
		if !strings.Contains(body, retained) {
			t.Fatalf("response lost %q: %s", retained, body)
		}
	}
}

func TestAgentAssetListDowngradesEvidenceWithoutFullEvidencePermission(t *testing.T) {
	repo := &agentAdminFakeRepo{assets: &repository.AgentAssetPage{Items: []repository.AgentEndpointAsset{{
		Hash:     "asset-hash",
		Evidence: json.RawMessage(`{"raw_evidence":"secret raw","evidence":{"hash":"sha256:evidence","length":9,"text":"secret"},"source_type":"scan"}`),
	}, {
		Hash:     "invalid-hash",
		Evidence: json.RawMessage(`invalid-secret-json`),
	}}}}
	api := NewAgentAdminAPI(repo, &Dependencies{})
	rec := httptest.NewRecorder()
	api.ListAssets(rec, agentAdminRequest(http.MethodGet, "/admin/v1/agent/assets", "emergency_tenant_admin", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	for _, forbidden := range []string{"secret raw", `"text":"secret"`, "invalid-secret-json"} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("response leaked %q: %s", forbidden, body)
		}
	}
	for _, retained := range []string{"asset-hash", "sha256:evidence", `"length":9`, `"source_type":"scan"`, "invalid-hash"} {
		if !strings.Contains(body, retained) {
			t.Fatalf("response lost %q: %s", retained, body)
		}
	}
}
