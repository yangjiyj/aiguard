package handler

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/types"
	"github.com/yangjiyj/aiguard/packages/shared-go/retentionstore"
)

type fixedAccessContentRepo struct {
	item *repository.AccessContentLog
}

func (r fixedAccessContentRepo) GetAccessContentLog(context.Context, string, string) (*repository.AccessContentLog, error) {
	return r.item, nil
}

func (r fixedAccessContentRepo) GetAccessContentLogs(context.Context, string, []string) ([]repository.AccessContentLog, error) {
	return nil, nil
}

func (r fixedAccessContentRepo) ResolveUploadedFileBytes(context.Context, string, []string) (map[string]repository.ResolvedUploadedFile, error) {
	return map[string]repository.ResolvedUploadedFile{}, nil
}

type fixedRetainedArtifactRepo struct {
	artifact *repository.RetainedArtifact
}

type multipleRetainedArtifactRepo struct {
	artifacts []repository.RetainedArtifact
}

func (r multipleRetainedArtifactRepo) ListRetainedArtifacts(_ context.Context, tenantID, requestID string) ([]repository.RetainedArtifact, error) {
	out := []repository.RetainedArtifact{}
	for _, artifact := range r.artifacts {
		if artifact.TenantID == tenantID && artifact.RequestID == requestID {
			out = append(out, artifact)
		}
	}
	return out, nil
}

func (r multipleRetainedArtifactRepo) ListRetainedArtifactsByRequests(_ context.Context, tenantID string, requestIDs []string) ([]repository.RetainedArtifact, error) {
	wanted := make(map[string]bool, len(requestIDs))
	for _, requestID := range requestIDs {
		wanted[requestID] = true
	}
	out := []repository.RetainedArtifact{}
	for _, artifact := range r.artifacts {
		if artifact.TenantID == tenantID && wanted[artifact.RequestID] {
			out = append(out, artifact)
		}
	}
	return out, nil
}

func (r multipleRetainedArtifactRepo) GetRetainedArtifact(_ context.Context, tenantID, requestID, artifactID string) (*repository.RetainedArtifact, error) {
	for _, artifact := range r.artifacts {
		if artifact.TenantID == tenantID && artifact.RequestID == requestID && artifact.ID == artifactID {
			item := artifact
			return &item, nil
		}
	}
	return nil, nil
}

func (r fixedRetainedArtifactRepo) ListRetainedArtifacts(_ context.Context, tenantID, requestID string) ([]repository.RetainedArtifact, error) {
	if r.artifact == nil || r.artifact.TenantID != tenantID || r.artifact.RequestID != requestID {
		return []repository.RetainedArtifact{}, nil
	}
	return []repository.RetainedArtifact{*r.artifact}, nil
}

func (r fixedRetainedArtifactRepo) GetRetainedArtifact(_ context.Context, tenantID, requestID, artifactID string) (*repository.RetainedArtifact, error) {
	if r.artifact == nil || r.artifact.TenantID != tenantID || r.artifact.RequestID != requestID || r.artifact.ID != artifactID {
		return nil, nil
	}
	return r.artifact, nil
}

type fixedArtifactStore struct {
	tenantID string
	key      string
	body     []byte
	mime     string
}

func (s fixedArtifactStore) PutObject(context.Context, retentionstore.PutObjectInput) (retentionstore.ObjectMetadata, error) {
	return retentionstore.ObjectMetadata{}, nil
}

func (s fixedArtifactStore) GetObject(_ context.Context, tenantID, key string) (retentionstore.Object, error) {
	if tenantID != s.tenantID || key != s.key {
		return retentionstore.Object{}, retentionstore.ErrObjectNotFound
	}
	return retentionstore.Object{
		Metadata: retentionstore.ObjectMetadata{Key: key, TenantID: tenantID, ContentType: s.mime, SHA256: "deadbeef"},
		Body:     io.NopCloser(strings.NewReader(string(s.body))),
	}, nil
}

func (s fixedArtifactStore) DeleteObject(context.Context, string, string) error  { return nil }
func (s fixedArtifactStore) ReapExpired(context.Context, time.Time) (int, error) { return 0, nil }

func accessRetentionRequest(t *testing.T, method, path, tenant string) *http.Request {
	t.Helper()
	req := httptest.NewRequest(method, path, nil)
	return req.WithContext(context.WithValue(req.Context(), auth.UserKey, &repository.User{ID: "u", TenantID: tenant, Role: "platform_admin"}))
}

func TestGetAccessRetentionContentReturnsTypedSafeArtifacts(t *testing.T) {
	artifact := &repository.RetainedArtifact{
		ID: "art_1", TenantID: "tenant_a", RequestID: "req_1", Direction: "input", Kind: "file",
		DisplayName: "report.pdf", MediaType: "application/pdf", ByteSize: 12, SHA256: "abc123", Status: "retained",
		OriginalObjectKey: "must-not-leak", PreviewObjectKey: "must-not-leak-preview",
	}
	deps := &Dependencies{
		AccessContentRepo: fixedAccessContentRepo{item: &repository.AccessContentLog{
			RequestID: "req_1", RequestContent: "<system-reminder>hidden system</system-reminder><user_query>real prompt</user_query>",
			ResponseContent: "final answer", FileMetadataJSON: []byte(`[{"object_key":"must-not-leak","download_url":"https://secret.example/x","reference_id":"file-secret"}]`),
		}},
		RetainedArtifactRepo: fixedRetainedArtifactRepo{artifact: artifact},
	}
	router := chi.NewRouter()
	router.Get("/admin/v1/audit/access-retention/{request_id}/content", GetAccessRetentionContent(deps))
	w := httptest.NewRecorder()
	router.ServeHTTP(w, accessRetentionRequest(t, http.MethodGet, "/admin/v1/audit/access-retention/req_1/content", "tenant_a"))
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	var body struct {
		UserInput      string `json:"user_input"`
		ModelOutput    string `json:"model_output"`
		EvidenceStatus string `json:"evidence_status"`
		Artifacts      []struct {
			ID     string `json:"id"`
			Status string `json:"retention_status"`
		} `json:"artifacts"`
	}
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body.UserInput != "real prompt" || body.ModelOutput != "final answer" || body.EvidenceStatus != "complete" {
		t.Fatalf("unsafe typed response: %#v", body)
	}
	if len(body.Artifacts) != 1 || body.Artifacts[0].ID != "art_1" || body.Artifacts[0].Status != "retained" {
		t.Fatalf("artifacts=%#v", body.Artifacts)
	}
	if strings.Contains(w.Body.String(), "hidden system") || strings.Contains(w.Body.String(), "must-not-leak") ||
		strings.Contains(w.Body.String(), "secret.example") || strings.Contains(w.Body.String(), "file-secret") {
		t.Fatalf("customer response leaked unsafe retention data: %s", w.Body.String())
	}
}

func TestAccessRetentionArtifactsForRequestsKeepsOwningRequest(t *testing.T) {
	deps := &Dependencies{RetainedArtifactRepo: multipleRetainedArtifactRepo{artifacts: []repository.RetainedArtifact{
		{ID: "art_input", TenantID: "tenant_a", RequestID: "req_1", Direction: "input", Kind: "file", DisplayName: "brief.docx", Status: "retained", OriginalObjectKey: "input-key"},
		{ID: "art_output", TenantID: "tenant_a", RequestID: "req_2", Direction: "output", Kind: "file", DisplayName: "result.pptx", Status: "retained", OriginalObjectKey: "output-key"},
	}}}

	got, err := accessRetentionArtifactsForRequests(deps, context.Background(), "tenant_a", []string{"req_1", "req_2"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].RequestID != "req_1" || got[1].RequestID != "req_2" {
		t.Fatalf("artifacts did not retain owning request ids: %#v", got)
	}
}

func TestAccessRetentionArtifactsForRequestsCollapsesRepeatedArtifactReferences(t *testing.T) {
	deps := &Dependencies{RetainedArtifactRepo: multipleRetainedArtifactRepo{artifacts: []repository.RetainedArtifact{
		{ID: "art_shared", TenantID: "tenant_a", RequestID: "req_1", Direction: "input", Kind: "image", DisplayName: "architecture.png", SHA256: "same-image", Status: "retained"},
		{ID: "art_output", TenantID: "tenant_a", RequestID: "req_1", Direction: "output", Kind: "image", DisplayName: "architecture.png", SHA256: "same-image", Status: "retained"},
		{ID: "art_shared", TenantID: "tenant_a", RequestID: "req_2", Direction: "input", Kind: "image", DisplayName: "architecture.png", SHA256: "same-image", Status: "retained"},
	}}}

	got, err := accessRetentionArtifactsForRequests(deps, context.Background(), "tenant_a", []string{"req_1", "req_2"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("artifacts=%#v", got)
	}
	if got[0].Direction != "input" || got[0].RequestID != "req_1" || got[0].ReferenceCount != 2 {
		t.Fatalf("input artifact=%#v", got[0])
	}
	if got[1].Direction != "output" || got[1].ReferenceCount != 1 {
		t.Fatalf("output artifact=%#v", got[1])
	}
}

func TestAccessRetentionArtifactCollapseUsesReferenceTimeNotRequestID(t *testing.T) {
	early := time.Date(2026, 9, 3, 8, 0, 0, 0, time.UTC)
	late := early.Add(time.Minute)
	deps := &Dependencies{RetainedArtifactRepo: multipleRetainedArtifactRepo{artifacts: []repository.RetainedArtifact{
		{
			ID: "art-shared", TenantID: "tenant_a", EnvironmentScope: "customer", LinkEnvironmentScope: "customer",
			RequestID: "aaa-random-late", Direction: "input", Kind: "image", SHA256: "same-image",
			Status: "retained", RequestCreatedAt: late, LinkCreatedAt: late,
		},
		{
			ID: "art-shared", TenantID: "tenant_a", EnvironmentScope: "customer", LinkEnvironmentScope: "customer",
			RequestID: "zzz-random-early", Direction: "input", Kind: "image", SHA256: "same-image",
			Status: "retained", RequestCreatedAt: early, LinkCreatedAt: early,
		},
	}}}

	got, err := accessRetentionArtifactsForRequests(
		deps,
		context.Background(),
		"tenant_a",
		[]string{"aaa-random-late", "zzz-random-early"},
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].RequestID != "zzz-random-early" || got[0].ReferenceCount != 2 {
		t.Fatalf("collapsed artifact must keep earliest real reference: %#v", got)
	}
}

func TestAccessRetentionArtifactCollapseDoesNotMergeScopes(t *testing.T) {
	when := time.Date(2026, 9, 3, 8, 0, 0, 0, time.UTC)
	items := []types.AccessRetentionArtifactInfo{
		{
			ID: "art-customer", RequestID: "req-customer", Direction: "input", SHA256: "same-image",
			EnvironmentScope: "customer", LinkEnvironmentScope: "customer", RequestCreatedAt: when, LinkCreatedAt: when,
		},
		{
			ID: "art-home", RequestID: "req-home", Direction: "input", SHA256: "same-image",
			EnvironmentScope: "home", LinkEnvironmentScope: "home", RequestCreatedAt: when, LinkCreatedAt: when,
		},
	}
	got := collapseAccessRetentionArtifactReferences(items)
	if len(got) != 2 {
		t.Fatalf("same SHA in different scopes must remain isolated: %#v", got)
	}
}

func TestGetAccessRetentionArtifactScopesLinkAndForcesDownload(t *testing.T) {
	artifact := &repository.RetainedArtifact{
		ID: "art_1", TenantID: "tenant_a", RequestID: "req_1", Direction: "output", Kind: "file",
		DisplayName: "unsafe.html", MediaType: "text/html", ByteSize: 12, SHA256: "deadbeef", Status: "retained",
		OriginalObjectKey: "original-key",
	}
	deps := &Dependencies{
		RetainedArtifactRepo: fixedRetainedArtifactRepo{artifact: artifact},
		RetentionStore:       fixedArtifactStore{tenantID: "tenant_a", key: "original-key", body: []byte("<html>x</html>"), mime: "text/html"},
	}
	router := chi.NewRouter()
	router.Get("/admin/v1/audit/access-retention/{request_id}/artifacts/{artifact_id}/original", GetAccessRetentionArtifact(false, deps))
	router.Get("/admin/v1/audit/access-retention/{request_id}/blob", GetAccessRetentionBlob(deps))
	for _, tc := range []struct {
		name   string
		path   string
		tenant string
		want   int
	}{
		{name: "matched", path: "/admin/v1/audit/access-retention/req_1/artifacts/art_1/original", tenant: "tenant_a", want: http.StatusOK},
		{name: "wrong tenant", path: "/admin/v1/audit/access-retention/req_1/artifacts/art_1/original", tenant: "tenant_b", want: http.StatusNotFound},
		{name: "wrong request", path: "/admin/v1/audit/access-retention/req_2/artifacts/art_1/original", tenant: "tenant_a", want: http.StatusNotFound},
		{name: "legacy artifact id", path: "/admin/v1/audit/access-retention/req_1/blob?artifact_id=art_1", tenant: "tenant_a", want: http.StatusOK},
		{name: "object key rejected", path: "/admin/v1/audit/access-retention/req_1/blob?key=original-key", tenant: "tenant_a", want: http.StatusNotFound},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			router.ServeHTTP(w, accessRetentionRequest(t, http.MethodGet, tc.path, tc.tenant))
			if w.Code != tc.want {
				t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
			}
			if tc.want == http.StatusOK {
				if !strings.Contains(w.Header().Get("Content-Disposition"), "attachment") || w.Header().Get("X-Content-Type-Options") != "nosniff" {
					t.Fatalf("unsafe download headers: %#v", w.Header())
				}
			}
		})
	}
}

func TestGetAccessRetentionArtifactUsesAuthorizedRasterOriginalAsPreviewFallback(t *testing.T) {
	artifact := &repository.RetainedArtifact{
		ID: "art_image", TenantID: "tenant_a", RequestID: "req_chat", Direction: "input", Kind: "image",
		DisplayName: "screen.png", MediaType: "image/png", ByteSize: 12, SHA256: "deadbeef", Status: "retained",
		OriginalObjectKey: "original-image-key",
	}
	deps := &Dependencies{
		RetainedArtifactRepo: fixedRetainedArtifactRepo{artifact: artifact},
		RetentionStore: fixedArtifactStore{
			tenantID: "tenant_a", key: "original-image-key", body: []byte("png bytes"), mime: "image/png",
		},
	}
	router := chi.NewRouter()
	router.Get("/admin/v1/audit/access-retention/{request_id}/artifacts/{artifact_id}/preview", GetAccessRetentionArtifact(true, deps))
	w := httptest.NewRecorder()
	router.ServeHTTP(w, accessRetentionRequest(t, http.MethodGet, "/admin/v1/audit/access-retention/req_chat/artifacts/art_image/preview", "tenant_a"))
	if w.Code != http.StatusOK || !strings.Contains(w.Header().Get("Content-Disposition"), "inline") {
		t.Fatalf("status=%d headers=%#v body=%s", w.Code, w.Header(), w.Body.String())
	}
}
