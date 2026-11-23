package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/skillscan"
)

func TestSkillGovernanceVersionRequiredBeforeScan(t *testing.T) {
	for _, version := range []string{"", "   "} {
		repo := &fakeSkillAssetsRepo{}
		scanner := &fakeSkillScanner{}
		body, kind := makeScanMultipart(t, map[string]string{"canonical_name": "demo", "declared_version": version}, makeSafeSkillZip(t))
		req := skillUserRequest(http.MethodPost, "/admin/v1/skills/scan", "tenant-a", "tenant_admin", body)
		req.Header.Set("Content-Type", kind)
		rec := httptest.NewRecorder()
		ScanSkillArchive(&Dependencies{SkillAssetsRepo: repo, SkillArchiveScanner: scanner}).ServeHTTP(rec, req)
		if rec.Code != 400 || scanner.calls != 0 || repo.upsert.TenantID != "" {
			t.Fatalf("empty version reached scanner/persistence: %d", rec.Code)
		}
	}
}
func TestSkillGovernanceDeclarationConflictAndSaved422Evidence(t *testing.T) {
	hash := strings.Repeat("a", 64)
	repo := &fakeSkillAssetsRepo{upsertErr: repository.ErrSkillVersionDeclarationConflict}
	scanner := &fakeSkillScanner{report: skillscan.Report{BundleHash: hash, TreeHash: hash, RiskLevel: skillscan.RiskLow, Decision: skillscan.DecisionAllow}}
	call := func() *httptest.ResponseRecorder {
		body, kind := makeScanMultipart(t, map[string]string{"canonical_name": "demo", "declared_version": "1"}, makeSafeSkillZip(t))
		req := skillUserRequest(http.MethodPost, "/admin/v1/skills/scan", "tenant-a", "tenant_admin", body)
		req.Header.Set("Content-Type", kind)
		rec := httptest.NewRecorder()
		ScanSkillArchive(&Dependencies{SkillAssetsRepo: repo, SkillArchiveScanner: scanner}).ServeHTTP(rec, req)
		return rec
	}
	if rec := call(); rec.Code != 409 || !strings.Contains(rec.Body.String(), "declaration_conflict") {
		t.Fatalf("silent declaration conflict: %d %s", rec.Code, rec.Body.String())
	}
	repo.upsertErr = nil
	scanner.err = &skillscan.ScanError{Code: "path_escape"}
	scanner.report.Decision = skillscan.DecisionBlock
	scanner.report.RiskLevel = skillscan.RiskCritical
	scanner.report.Findings = []skillscan.Finding{{Type: "archive_violation", Severity: skillscan.RiskCritical, File: "../escape"}}
	rec := call()
	var out struct {
		Version repository.SkillAssetVersion `json:"version"`
	}
	err := json.Unmarshal(rec.Body.Bytes(), &out)
	if err != nil || rec.Code != 422 || out.Version.ID == "" || out.Version.AdmissionStatus != "quarantined" || out.Version.ScanStatus != "failed" || out.Version.ScanErrorCode != "path_escape" || len(out.Version.FindingsJSON) == 0 {
		t.Fatalf("422 lost persisted evidence: status=%d body=%s", rec.Code, rec.Body.String())
	}
}
func TestSkillGovernanceReviewRequiresReasonAndExactCAS(t *testing.T) {
	valid := repository.SkillAdmissionReview{Status: "approved", Reason: "Reviewed the exact bundle", ExpectedStatus: "unverified", ExpectedBundleHash: strings.Repeat("a", 64)}
	for _, change := range []func(*repository.SkillAdmissionReview){func(r *repository.SkillAdmissionReview) { r.Reason = "" }, func(r *repository.SkillAdmissionReview) { r.ExpectedStatus = "" }, func(r *repository.SkillAdmissionReview) { r.ExpectedBundleHash = "" }, func(r *repository.SkillAdmissionReview) { r.Reason = strings.Repeat("x", 501) }, func(r *repository.SkillAdmissionReview) { r.Reason = "line\ncontrol" }} {
		r := valid
		change(&r)
		body, _ := json.Marshal(r)
		repo := &fakeSkillAssetsRepo{}
		req := skillRouteParam(skillUserRequest(http.MethodPost, "/admin/v1/skills/versions/v/admission", "tenant-a", "tenant_admin", body), "id", "v")
		rec := httptest.NewRecorder()
		SetSkillVersionAdmission(&Dependencies{SkillAssetsRepo: repo}).ServeHTTP(rec, req)
		if rec.Code != 400 || repo.admissionActor != "" {
			t.Fatalf("unreviewed change accepted %+v status=%d", r, rec.Code)
		}
	}
	body, _ := json.Marshal(valid)
	repo := &fakeSkillAssetsRepo{admissionErr: repository.ErrSkillAdmissionConflict}
	req := skillRouteParam(skillUserRequest(http.MethodPost, "/admin/v1/skills/versions/v/admission", "tenant-a", "tenant_admin", body), "id", "v")
	rec := httptest.NewRecorder()
	SetSkillVersionAdmission(&Dependencies{SkillAssetsRepo: repo}).ServeHTTP(rec, req)
	if rec.Code != 409 || repo.review.ExpectedBundleHash != valid.ExpectedBundleHash || repo.review.Reason != valid.Reason {
		t.Fatalf("review/CAS contract lost: %d %+v", rec.Code, repo.review)
	}
}
func TestSkillGovernanceFiltersAreTenantBoundAndInvalidQueriesRejected(t *testing.T) {
	repo := &fakeSkillAssetsRepo{}
	deps := &Dependencies{SkillAssetsRepo: repo}
	rec := httptest.NewRecorder()
	ListSkillAssets(deps).ServeHTTP(rec, skillUserRequest(http.MethodGet, "/skills/assets?limit=10&offset=30&source_type=uploaded&admission_status=unverified&query=pdf", "tenant-a", "tenant_admin", nil))
	if rec.Code != 200 || repo.listTenant != "tenant-a" || repo.assetFilter.Limit != 10 || repo.assetFilter.Offset != 30 || repo.assetFilter.SourceType != "uploaded" || repo.assetFilter.Query != "pdf" {
		t.Fatalf("filter not passed to tenant database: %d %+v", rec.Code, repo.assetFilter)
	}
	rec = httptest.NewRecorder()
	ListSkillInvocations(deps).ServeHTTP(rec, skillUserRequest(http.MethodGet, "/skills/invocations?asset_id=asset&version_id=version&canonical_name=PDF&effective_decision=block&status=blocked", "tenant-a", "tenant_admin", nil))
	if rec.Code != 200 || repo.invocationFilter.VersionID != "version" || repo.invocationFilter.CanonicalName != "pdf" || repo.invocationFilter.EffectiveDecision != "block" {
		t.Fatalf("invocation filter lost: %d %+v", rec.Code, repo.invocationFilter)
	}
	for _, query := range []string{"tenant_id=tenant-b", "limit=0", "limit=201", "offset=-1", "limit=1&limit=2", "source_type=endpoint", "admission_status=unsafe"} {
		rec = httptest.NewRecorder()
		ListSkillAssets(deps).ServeHTTP(rec, skillUserRequest(http.MethodGet, "/skills/assets?"+query, "tenant-a", "tenant_admin", nil))
		if rec.Code != 400 {
			t.Fatalf("query %q accepted: %d", query, rec.Code)
		}
	}
}
