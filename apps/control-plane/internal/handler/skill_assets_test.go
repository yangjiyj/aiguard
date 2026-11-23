package handler

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/skillscan"
	"github.com/go-chi/chi/v5"
)

type fakeSkillAssetsRepo struct {
	assets                                                             []*repository.SkillAsset
	upsert                                                             repository.SkillVersionUpsert
	listTenant                                                         string
	admissionTenant, admissionVersion, admissionStatus, admissionActor string
	admissionIP                                                        string
	resolveTenant, resolveName, resolveVersion, resolveHash            string
	resolution                                                         repository.SkillAdmissionResolution
	invocation                                                         repository.SkillInvocationUpsert
	resultTenant, resultSession, resultToolCall, resultStatus          string
	resultFindings                                                     []byte
	upsertErr                                                          error
	admissionErr                                                       error
	invocationErr                                                      error
	assetFilter                                                        repository.SkillAssetFilter
	invocationFilter                                                   repository.SkillInvocationFilter
	review                                                             repository.SkillAdmissionReview
}

func (f *fakeSkillAssetsRepo) UpsertVersion(_ context.Context, in repository.SkillVersionUpsert) (*repository.SkillAssetVersion, error) {
	f.upsert = in
	if f.upsertErr != nil {
		return nil, f.upsertErr
	}
	return &repository.SkillAssetVersion{
		ID: "version-1", AssetID: "asset-1", TenantID: in.TenantID,
		DeclaredVersion: in.DeclaredVersion, BundleHash: in.BundleHash, TreeHash: in.TreeHash,
		RiskLevel: in.RiskLevel, Decision: in.Decision, ScanStatus: in.ScanStatus,
		ScanErrorCode: in.ScanErrorCode, AdmissionStatus: in.AdmissionStatus,
		ManifestJSON: in.ManifestJSON, FindingsJSON: in.FindingsJSON, SignatureStatus: in.SignatureStatus,
	}, nil
}
func (f *fakeSkillAssetsRepo) ListAssets(_ context.Context, tenant string, _, _ int) ([]*repository.SkillAsset, error) {
	f.listTenant = tenant
	return f.assets, nil
}
func (f *fakeSkillAssetsRepo) ListAssetsPage(_ context.Context, tenant string, filter repository.SkillAssetFilter) (repository.SkillAssetPage, error) {
	f.listTenant = tenant
	f.assetFilter = filter
	return repository.SkillAssetPage{Items: f.assets, Total: int64(len(f.assets)), Limit: filter.Limit, Offset: filter.Offset, InventoryScope: "gateway_observed_and_uploaded_scan"}, nil
}
func (f *fakeSkillAssetsRepo) ListVersions(_ context.Context, tenant, asset string) ([]*repository.SkillAssetVersion, error) {
	f.listTenant = tenant + "/" + asset
	return []*repository.SkillAssetVersion{}, nil
}
func (f *fakeSkillAssetsRepo) SetVersionAdmission(_ context.Context, tenant, version, status, actor, ip string) error {
	f.admissionTenant, f.admissionVersion, f.admissionStatus, f.admissionActor = tenant, version, status, actor
	f.admissionIP = ip
	return f.admissionErr
}
func (f *fakeSkillAssetsRepo) SetVersionAdmissionReviewed(ctx context.Context, tenant, version string, review repository.SkillAdmissionReview, actor, ip string) error {
	f.review = review
	return f.SetVersionAdmission(ctx, tenant, version, review.Status, actor, ip)
}
func (f *fakeSkillAssetsRepo) GetVersionAdmissionSnapshot(_ context.Context, _, _ string) (repository.SkillVersionAdmissionSnapshot, error) {
	return repository.SkillVersionAdmissionSnapshot{AssetID: "asset-1", CanonicalName: "demo-skill", DeclaredVersion: "v1", AdmissionStatus: "unverified"}, nil
}
func (f *fakeSkillAssetsRepo) ResolveAdmission(_ context.Context, tenant, name, version, hash string) (repository.SkillAdmissionResolution, error) {
	f.resolveTenant, f.resolveName, f.resolveVersion, f.resolveHash = tenant, name, version, hash
	return f.resolution, nil
}
func (f *fakeSkillAssetsRepo) RecordInvocation(_ context.Context, in repository.SkillInvocationUpsert) (*repository.SkillInvocation, error) {
	f.invocation = in
	if f.invocationErr != nil {
		return nil, f.invocationErr
	}
	return &repository.SkillInvocation{ID: "invocation-1", TenantID: in.TenantID}, nil
}
func (f *fakeSkillAssetsRepo) MarkInvocationResult(_ context.Context, tenant, session, toolCall, status string, findings []byte) error {
	f.resultTenant, f.resultSession, f.resultToolCall, f.resultStatus = tenant, session, toolCall, status
	f.resultFindings = append([]byte(nil), findings...)
	return nil
}
func (f *fakeSkillAssetsRepo) ListInvocations(_ context.Context, tenant string, _, _ int) ([]*repository.SkillInvocation, error) {
	f.listTenant = tenant
	return []*repository.SkillInvocation{}, nil
}
func (f *fakeSkillAssetsRepo) ListInvocationsPage(_ context.Context, tenant string, filter repository.SkillInvocationFilter) (repository.SkillInvocationPage, error) {
	f.listTenant = tenant
	f.invocationFilter = filter
	return repository.SkillInvocationPage{Items: []*repository.SkillInvocation{}, Limit: filter.Limit, Offset: filter.Offset, ObservationScope: "gateway_observed"}, nil
}

type fakeSkillScanner struct {
	report skillscan.Report
	err    error
	got    []byte
	calls  int
}

func (f *fakeSkillScanner) Scan(archive []byte) (skillscan.Report, error) {
	f.got = append([]byte(nil), archive...)
	f.calls++
	return f.report, f.err
}

func skillUserRequest(method, target, tenant, role string, body []byte) *http.Request {
	req := httptest.NewRequest(method, target, bytes.NewReader(body))
	user := &repository.User{ID: "admin-a", TenantID: tenant, Role: role, Status: "active"}
	return req.WithContext(context.WithValue(req.Context(), auth.UserKey, user))
}
func skillRouteParam(req *http.Request, key, value string) *http.Request {
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add(key, value)
	return req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
}
func internalSkillRequest(method, target, tenant, body string) *http.Request {
	req := httptest.NewRequest(method, target, strings.NewReader(body))
	if tenant != "" {
		req.Header.Set(SkillTenantHeader, tenant)
	}
	return req
}

func makeScanMultipart(t *testing.T, fields map[string]string, archive []byte) ([]byte, string) {
	t.Helper()
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	for key, value := range fields {
		if err := writer.WriteField(key, value); err != nil {
			t.Fatal(err)
		}
	}
	part, err := writer.CreateFormFile("archive", "skill.zip")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := part.Write(archive); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return body.Bytes(), writer.FormDataContentType()
}
func makeSafeSkillZip(t *testing.T) []byte {
	t.Helper()
	var body bytes.Buffer
	writer := zip.NewWriter(&body)
	part, err := writer.Create("SKILL.md")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = part.Write([]byte("# Safe\nReads metadata."))
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return body.Bytes()
}

func TestSkillPublicListUsesSessionTenantAndHonestScope(t *testing.T) {
	repo := &fakeSkillAssetsRepo{assets: []*repository.SkillAsset{{ID: "asset-1", TenantID: "tenant-a"}}}
	deps := &Dependencies{SkillAssetsRepo: repo}
	rec := httptest.NewRecorder()
	ListSkillAssets(deps).ServeHTTP(rec, skillUserRequest(http.MethodGet, "/admin/v1/skills/assets", "tenant-a", "tenant_admin", nil))
	if rec.Code != http.StatusOK || repo.listTenant != "tenant-a" {
		t.Fatalf("status=%d tenant=%q body=%s", rec.Code, repo.listTenant, rec.Body.String())
	}
	var out map[string]any
	_ = json.NewDecoder(rec.Body).Decode(&out)
	if out["inventory_scope"] != "gateway_observed_and_uploaded_scan" || out["endpoint_inventory"] != false {
		t.Fatalf("dishonest scope: %#v", out)
	}

	denied := httptest.NewRecorder()
	ListSkillAssets(deps).ServeHTTP(denied, skillUserRequest(http.MethodGet, "/admin/v1/skills/assets", "tenant-a", "developer", nil))
	if denied.Code != http.StatusForbidden {
		t.Fatalf("developer status=%d", denied.Code)
	}
}

func TestScanSkillArchivePersistsObjectManifestAndViolation(t *testing.T) {
	hashA, hashB := strings.Repeat("a", 64), strings.Repeat("b", 64)
	repo := &fakeSkillAssetsRepo{}
	scanner := &fakeSkillScanner{report: skillscan.Report{
		BundleHash: hashA, TreeHash: hashB, RiskLevel: skillscan.RiskLow, Decision: skillscan.DecisionAllow,
		Manifest: []skillscan.ManifestEntry{{Path: "SKILL.md", Size: 10, SHA256: hashA}},
	}}
	deps := &Dependencies{SkillAssetsRepo: repo, SkillArchiveScanner: scanner}
	body, contentType := makeScanMultipart(t, map[string]string{
		"canonical_name": " PDF-Tools ", "declared_version": "1.0.0",
		"source_uri": "https://example.invalid/pdf",
	}, makeSafeSkillZip(t))
	req := skillUserRequest(http.MethodPost, "/admin/v1/skills/scan", "tenant-a", "tenant_admin", body)
	req.Header.Set("Content-Type", contentType)
	rec := httptest.NewRecorder()
	ScanSkillArchive(deps).ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	if repo.upsert.TenantID != "tenant-a" || repo.upsert.CanonicalName != "pdf-tools" || repo.upsert.SourceType != "uploaded" {
		t.Fatalf("wrong identity: %+v", repo.upsert)
	}
	var manifest map[string]any
	if err := json.Unmarshal(repo.upsert.ManifestJSON, &manifest); err != nil || manifest["surface"] != "uploaded_scan" {
		t.Fatalf("manifest=%s err=%v", repo.upsert.ManifestJSON, err)
	}

	repo = &fakeSkillAssetsRepo{}
	deps.SkillAssetsRepo = repo
	deps.SkillArchiveScanner = &fakeSkillScanner{report: skillscan.Report{
		BundleHash: hashA, TreeHash: hashB, RiskLevel: skillscan.RiskCritical, Decision: skillscan.DecisionBlock,
		Findings: []skillscan.Finding{{Type: "archive_violation", Severity: skillscan.RiskCritical}},
	}, err: &skillscan.ScanError{Code: "path_escape"}}
	body, contentType = makeScanMultipart(t, map[string]string{"canonical_name": "danger", "declared_version": "1"}, []byte{})
	req = skillUserRequest(http.MethodPost, "/admin/v1/skills/scan", "tenant-a", "platform_admin", body)
	req.Header.Set("Content-Type", contentType)
	rec = httptest.NewRecorder()
	ScanSkillArchive(deps).ServeHTTP(rec, req)
	if rec.Code != http.StatusUnprocessableEntity || repo.upsert.ScanStatus != "failed" ||
		repo.upsert.ScanErrorCode != "path_escape" || repo.upsert.AdmissionStatus != "quarantined" {
		t.Fatalf("status=%d input=%+v body=%s", rec.Code, repo.upsert, rec.Body.String())
	}
}

func TestScanSkillArchiveRejectsBodyTenantAndSourceCredentials(t *testing.T) {
	for _, fields := range []map[string]string{
		{"canonical_name": "pdf", "tenant_id": "tenant-b"},
		{"canonical_name": "pdf", "source_uri": "https://user:secret@example.invalid/repo"},
		{"canonical_name": "pdf", "source_uri": "http://example.invalid/repo"},
		{"canonical_name": "pdf", "source_uri": "file:///tmp/repo"},
		{"canonical_name": "pdf", "source_uri": "https://example.invalid/repo?token=secret"},
		{"canonical_name": "pdf", "signature_status": "verified", "signer_identity": "self-asserted"},
	} {
		repo := &fakeSkillAssetsRepo{}
		deps := &Dependencies{SkillAssetsRepo: repo, SkillArchiveScanner: &fakeSkillScanner{}}
		body, contentType := makeScanMultipart(t, fields, makeSafeSkillZip(t))
		req := skillUserRequest(http.MethodPost, "/admin/v1/skills/scan", "tenant-a", "tenant_admin", body)
		req.Header.Set("Content-Type", contentType)
		rec := httptest.NewRecorder()
		ScanSkillArchive(deps).ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest || repo.upsert.TenantID != "" {
			t.Fatalf("fields=%v status=%d persisted=%+v", fields, rec.Code, repo.upsert)
		}
	}
}

func TestSetSkillAdmissionPassesTenantActorAndAuditContextAtomically(t *testing.T) {
	repo := &fakeSkillAssetsRepo{}
	deps := &Dependencies{SkillAssetsRepo: repo}
	body, _ := json.Marshal(repository.SkillAdmissionReview{Status: "revoked", Reason: "Retiring this reviewed bundle", ExpectedStatus: "unverified", ExpectedBundleHash: strings.Repeat("a", 64)})
	req := skillUserRequest(http.MethodPost, "/admin/v1/skills/versions/version-a/admission", "tenant-a", "tenant_admin", body)
	req.RemoteAddr = "192.0.2.10:1234"
	req = skillRouteParam(req, "id", "version-a")
	rec := httptest.NewRecorder()
	SetSkillVersionAdmission(deps).ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || repo.admissionTenant != "tenant-a" || repo.admissionActor != "admin-a" || repo.admissionStatus != "revoked" {
		t.Fatalf("status=%d repo=%+v body=%s", rec.Code, repo, rec.Body.String())
	}
	if repo.admissionIP != "192.0.2.10:1234" {
		t.Fatalf("audit context was not included in atomic repository call: %+v", repo)
	}
}

func TestInternalDefinitionAndAdmissionUseHeaderTenantAndExactHash(t *testing.T) {
	hash := strings.Repeat("c", 64)
	repo := &fakeSkillAssetsRepo{resolution: repository.SkillAdmissionResolution{
		AssetID: "asset-1", VersionID: "version-1", Status: "approved", Decision: "allow", RiskLevel: "low",
	}}
	deps := &Dependencies{SkillAssetsRepo: repo}
	body := "{\"tenant_id\":\"tenant-evil\",\"canonical_name\":\" PDF-Tools \",\"declared_version\":\"1.0.0\",\"definition_hash\":\"" + hash + "\",\"source_uri\":\"https://example.invalid/source\"}"
	rec := httptest.NewRecorder()
	ObserveSkillDefinition(deps).ServeHTTP(rec, internalSkillRequest(http.MethodPost, "/admin/v1/internal/security/skills/definitions", "tenant-a", body))
	if rec.Code != http.StatusCreated || repo.upsert.TenantID != "tenant-a" || repo.upsert.SourceType != "observed" ||
		repo.upsert.BundleHash != hash || repo.upsert.TreeHash != hash {
		t.Fatalf("status=%d input=%+v body=%s", rec.Code, repo.upsert, rec.Body.String())
	}
	if repo.upsert.ScanStatus != "pending" || repo.upsert.AdmissionStatus != "unverified" {
		t.Fatalf("observed definition was falsely marked scanned or admitted: %+v", repo.upsert)
	}
	var manifest map[string]any
	_ = json.Unmarshal(repo.upsert.ManifestJSON, &manifest)
	if manifest["surface"] != "gateway_observed" {
		t.Fatalf("manifest=%#v", manifest)
	}

	target := "/admin/v1/internal/security/skills/admission?canonical_name=PDF-Tools&version=1.0.0&bundle_hash=" + hash
	rec = httptest.NewRecorder()
	ResolveSkillAdmission(deps).ServeHTTP(rec, internalSkillRequest(http.MethodGet, target, "tenant-a", ""))
	if rec.Code != http.StatusOK || repo.resolveTenant != "tenant-a" || repo.resolveName != "pdf-tools" ||
		repo.resolveVersion != "1.0.0" || repo.resolveHash != hash {
		t.Fatalf("status=%d lookup=%q/%q/%q/%q body=%s", rec.Code, repo.resolveTenant, repo.resolveName, repo.resolveVersion, repo.resolveHash, rec.Body.String())
	}
	missing := httptest.NewRecorder()
	ResolveSkillAdmission(deps).ServeHTTP(missing, internalSkillRequest(http.MethodGet, target, "", ""))
	if missing.Code != http.StatusBadRequest {
		t.Fatalf("missing tenant status=%d", missing.Code)
	}
}

func TestInternalInvocationAcceptsNoRawParametersAndResultLinksBySession(t *testing.T) {
	digest := strings.Repeat("d", 64)
	repo := &fakeSkillAssetsRepo{}
	deps := &Dependencies{SkillAssetsRepo: repo}
	body := "{\"tenant_id\":\"tenant-evil\",\"request_id\":\"request-1\",\"session_id\":\"session-1\",\"tool_call_id\":\"call-1\",\"canonical_name\":\"PDF-Tools\",\"status\":\"proposed\",\"raw_decision\":\"confirm\",\"effective_decision\":\"confirm\",\"parameters_digest\":\"" + digest + "\",\"redacted_preview\":{\"target\":\"document.pdf\",\"api_key\":\"sk-raw-secret\",\"arbitrary\":\"customer-secret\"},\"attribution_mode\":\"explicit\",\"attribution_confidence\":1}"
	rec := httptest.NewRecorder()
	RecordSkillInvocation(deps).ServeHTTP(rec, internalSkillRequest(http.MethodPost, "/admin/v1/internal/security/skills/invocations", "tenant-a", body))
	if rec.Code != http.StatusCreated || repo.invocation.TenantID != "tenant-a" || repo.invocation.ParametersDigest != digest {
		t.Fatalf("status=%d input=%+v body=%s", rec.Code, repo.invocation, rec.Body.String())
	}
	var preview map[string]any
	if err := json.Unmarshal(repo.invocation.RedactedPreviewJSON, &preview); err != nil ||
		preview["api_key"] != "[redacted]" || preview["arbitrary"] != "[redacted]" {
		t.Fatalf("preview secret was not redacted: %s err=%v", repo.invocation.RedactedPreviewJSON, err)
	}

	bad := httptest.NewRecorder()
	unsafe := "{\"request_id\":\"r\",\"session_id\":\"s\",\"tool_call_id\":\"c\",\"canonical_name\":\"pdf\",\"status\":\"proposed\",\"raw_decision\":\"confirm\",\"effective_decision\":\"confirm\",\"parameters\":{\"secret\":\"raw\"}}"
	RecordSkillInvocation(deps).ServeHTTP(bad, internalSkillRequest(http.MethodPost, "/", "tenant-a", unsafe))
	if bad.Code != http.StatusBadRequest {
		t.Fatalf("raw parameters accepted: %d %s", bad.Code, bad.Body.String())
	}

	result := "{\"tenant_id\":\"tenant-evil\",\"request_id\":\"different\",\"session_id\":\"session-1\",\"tool_call_id\":\"call-1\",\"result_status\":\"completed\",\"findings\":[{\"type\":\"pii\",\"severity\":\"high\",\"code\":\"pii-1\"}]}"
	rec = httptest.NewRecorder()
	LinkSkillResult(deps).ServeHTTP(rec, internalSkillRequest(http.MethodPost, "/", "tenant-a", result))
	if rec.Code != http.StatusOK || repo.resultTenant != "tenant-a" || repo.resultSession != "session-1" || repo.resultToolCall != "call-1" {
		t.Fatalf("status=%d link=%q/%q/%q body=%s", rec.Code, repo.resultTenant, repo.resultSession, repo.resultToolCall, rec.Body.String())
	}
	for _, unsafeResult := range []string{
		"{\"session_id\":\"\",\"tool_call_id\":\"call-1\",\"result_status\":\"completed\",\"findings\":[]}",
		"{\"session_id\":\"session-1\",\"tool_call_id\":\"call-1\",\"result_status\":\"completed\",\"result\":{\"secret\":\"raw\"},\"findings\":[]}",
	} {
		bad = httptest.NewRecorder()
		LinkSkillResult(deps).ServeHTTP(bad, internalSkillRequest(http.MethodPost, "/", "tenant-a", unsafeResult))
		if bad.Code != http.StatusBadRequest {
			t.Fatalf("unsafe result accepted: %d %s", bad.Code, bad.Body.String())
		}
	}
}

func TestInternalInvocationReturnsConflictForReusedToolCallIdentity(t *testing.T) {
	repo := &fakeSkillAssetsRepo{invocationErr: repository.ErrSkillInvocationConflict}
	deps := &Dependencies{SkillAssetsRepo: repo}
	body := "{\"request_id\":\"request-1\",\"session_id\":\"session-1\",\"tool_call_id\":\"call-1\",\"canonical_name\":\"other-skill\",\"status\":\"proposed\",\"raw_decision\":\"confirm\",\"effective_decision\":\"confirm\",\"parameters_digest\":\"" + strings.Repeat("d", 64) + "\"}"
	rec := httptest.NewRecorder()
	RecordSkillInvocation(deps).ServeHTTP(rec, internalSkillRequest(http.MethodPost, "/", "tenant-a", body))
	if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "invocation_conflict") {
		t.Fatalf("conflicting tool call was not rejected: status=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestInternalSkillJSONDepthAndRepositoryErrorsAreBounded(t *testing.T) {
	repo := &fakeSkillAssetsRepo{upsertErr: errors.New("boom")}
	deps := &Dependencies{SkillAssetsRepo: repo}
	deep := strings.Repeat("{\"x\":", 12) + "0" + strings.Repeat("}", 12)
	rec := httptest.NewRecorder()
	RecordSkillInvocation(deps).ServeHTTP(rec, internalSkillRequest(http.MethodPost, "/", "tenant-a", deep))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("deep status=%d", rec.Code)
	}

	rec = httptest.NewRecorder()
	body := "{\"canonical_name\":\"pdf\",\"declared_version\":\"1.0.0\",\"definition_hash\":\"" + strings.Repeat("a", 64) + "\"}"
	ObserveSkillDefinition(deps).ServeHTTP(rec, internalSkillRequest(http.MethodPost, "/", "tenant-a", body))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("repo error status=%d", rec.Code)
	}
}

var _ SkillAssetsRepo = (*fakeSkillAssetsRepo)(nil)
var _ SkillArchiveScanner = (*fakeSkillScanner)(nil)
