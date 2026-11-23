package handler

// Low-2：证据原文的读取出口（view=raw、/content、/blob、/artifacts/.../original|preview、/image-proxy、GetSessionContent 与其导出）
// 之前只有一道角色闸门，读取行为完全不留痕。三员分立下「安全员看原文必须可追溯」。
//
// 要求：每个出口都写 audit_operations：读取人、角色、租户、证据 ID、出口类型；绝不记内容；
// 只在读取成功（2xx）时记（被拒绝的访问由角色闸门/权限审计另行记录）；审计写入失败不影响读取返回（读取不能因审计库抖动被拒）。

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

type evidenceCase struct {
	name, method, pattern, path, kind, evidenceID string
}

var evidenceReadCases = []evidenceCase{
	{"typed content", "GET", "/admin/v1/audit/access-retention/{request_id}/content", "/admin/v1/audit/access-retention/req_1/content", "content", "req_1"},
	{"raw view", "GET", "/admin/v1/audit/access-retention/{request_id}/content", "/admin/v1/audit/access-retention/req_1/content?view=raw", "content_raw", "req_1"},
	{"typed content POST", "POST", "/admin/v1/audit/access-retention/{request_id}/content", "/admin/v1/audit/access-retention/req_1/content", "content", "req_1"},
	{"blob", "GET", "/admin/v1/audit/access-retention/{request_id}/blob", "/admin/v1/audit/access-retention/req_1/blob", "blob", "req_1"},
	{"image proxy", "GET", "/admin/v1/audit/access-retention/{request_id}/image-proxy", "/admin/v1/audit/access-retention/req_1/image-proxy", "image_proxy", "req_1"},
	{"artifact preview", "GET", "/admin/v1/audit/access-retention/{request_id}/artifacts/{artifact_id}/preview", "/admin/v1/audit/access-retention/req_1/artifacts/art_1/preview", "artifact_preview", "req_1/art_1"},
	{"artifact original", "GET", "/admin/v1/audit/access-retention/{request_id}/artifacts/{artifact_id}/original", "/admin/v1/audit/access-retention/req_1/artifacts/art_1/original", "artifact_original", "req_1/art_1"},
	{"session content", "GET", "/admin/v1/audit/content/{session_id}", "/admin/v1/audit/content/sess_1", "session_content", "sess_1"},
	{"session export", "GET", "/admin/v1/audit/content/{session_id}/export", "/admin/v1/audit/content/sess_1/export", "session_export", "sess_1"},
}

func evidenceUserCtx(req *http.Request, role string) *http.Request {
	u := &repository.User{ID: "reader-1", TenantID: "tenant_a", Role: role, Status: "active"}
	s := &repository.Session{ID: "s1", UserID: u.ID, TenantID: u.TenantID}
	ctx := context.WithValue(req.Context(), auth.UserKey, u)
	ctx = context.WithValue(ctx, auth.SessionKey, s)
	return req.WithContext(ctx)
}

func serveWithEvidenceAudit(t *testing.T, c evidenceCase, role string, status int, repo *capturingSystemRepo) *httptest.ResponseRecorder {
	t.Helper()
	deps := &Dependencies{SystemRepo: repo}
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(status)
		_, _ = w.Write([]byte("CONFIDENTIAL-EVIDENCE-BODY"))
	})
	router := chi.NewRouter()
	router.With(RequireFullTenantContentEvidence, AuditEvidenceRead(deps, c.kind)).MethodFunc(c.method, c.pattern, inner)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, evidenceUserCtx(httptest.NewRequest(c.method, c.path, nil), role))
	return rec
}

func TestEveryEvidenceReadExitWritesAnAuditRecordWithoutTheContent(t *testing.T) {
	for _, c := range evidenceReadCases {
		for _, role := range []string{"security_officer", "auditor", "platform_admin"} {
			t.Run(c.name+"/"+role, func(t *testing.T) {
				repo := &capturingSystemRepo{}
				rec := serveWithEvidenceAudit(t, c, role, http.StatusOK, repo)
				if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "CONFIDENTIAL-EVIDENCE-BODY") {
					t.Fatalf("读取本身应不受审计影响：%d %s", rec.Code, rec.Body.String())
				}
				if len(repo.auditOps) != 1 {
					t.Fatalf("应恰好写一条读取审计，实际 %d", len(repo.auditOps))
				}
				op := repo.auditOps[0]
				if op.ActionType != "evidence.read" || op.TargetType != "evidence" || op.TargetID != c.evidenceID || op.UserID != "reader-1" {
					t.Fatalf("审计字段不对：%+v", op)
				}
				d := op.ActionDetail
				if d["kind"] != c.kind || d["role"] != role || d["tenant_id"] != "tenant_a" || d["evidence_id"] != c.evidenceID {
					t.Fatalf("审计详情应含 读取人角色/租户/证据ID/出口类型：%v", d)
				}
				if strings.Contains(jsonOf(d), "CONFIDENTIAL-EVIDENCE-BODY") {
					t.Fatalf("审计不得含证据内容：%v", d)
				}
			})
		}
	}
}

// 被拒绝（角色闸门 404）或失败（非 2xx）的访问不记「读取」，否则审计里会出现并没发生的读取。
func TestEvidenceReadAuditIsNotWrittenWhenNothingWasRead(t *testing.T) {
	c := evidenceReadCases[0]
	repo := &capturingSystemRepo{}
	rec := serveWithEvidenceAudit(t, c, "dept_manager", http.StatusOK, repo)
	if rec.Code != http.StatusNotFound || len(repo.auditOps) != 0 {
		t.Fatalf("无权限角色被拒时不应记读取：%d ops=%d", rec.Code, len(repo.auditOps))
	}
	for _, status := range []int{http.StatusNotFound, http.StatusInternalServerError, http.StatusBadRequest} {
		repo = &capturingSystemRepo{}
		serveWithEvidenceAudit(t, c, "security_officer", status, repo)
		if len(repo.auditOps) != 0 {
			t.Fatalf("状态 %d 没有读到内容，不应记读取审计：%d", status, len(repo.auditOps))
		}
	}
}

// 审计库抖动不能让合法读取失败（读取已经发生，且证据查阅是取证场景）。
type failingAuditRepo struct{ capturingSystemRepo }

func (r *failingAuditRepo) CreateAuditOperation(context.Context, *repository.AuditOperation) error {
	return context.DeadlineExceeded
}

func TestEvidenceReadSucceedsEvenIfTheAuditWriteFails(t *testing.T) {
	deps := &Dependencies{SystemRepo: &failingAuditRepo{}}
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("ok-body")) })
	rec := httptest.NewRecorder()
	AuditEvidenceRead(deps, "blob")(inner).ServeHTTP(rec, evidenceUserCtx(httptest.NewRequest("GET", "/admin/v1/audit/access-retention/req_1/blob", nil), "security_officer"))
	if rec.Code != http.StatusOK || rec.Body.String() != "ok-body" {
		t.Fatalf("审计写入失败不应影响读取：%d %s", rec.Code, rec.Body.String())
	}
}

// 流式/大文件响应：包装 ResponseWriter 后仍要支持 Flush，否则图片/附件流式下载会被破坏。
func TestEvidenceReadAuditKeepsStreamingFlushAndDownloadHeaders(t *testing.T) {
	deps := &Dependencies{SystemRepo: &capturingSystemRepo{}}
	flushed := false
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Disposition", "attachment; filename=x.bin")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		_, _ = w.Write([]byte("chunk"))
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
			flushed = true
		}
	})
	rec := httptest.NewRecorder()
	AuditEvidenceRead(deps, "artifact_original")(inner).ServeHTTP(rec, evidenceUserCtx(httptest.NewRequest("GET", "/x/req_1/artifacts/a/original", nil), "auditor"))
	if !flushed {
		t.Fatal("包装后的 ResponseWriter 必须仍实现 http.Flusher")
	}
	if rec.Header().Get("Content-Disposition") == "" || rec.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("下载安全头被吞：%v", rec.Header())
	}
}
