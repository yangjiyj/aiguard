package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

// 追加项：上传扫描判为阻断的 Skill 版本允许“强制批准”（设计第 5 节）：批准请求带非空
// override_reason（≤512 字）时放行，不带仍 409；原因随审查提交给仓库。
func TestSkillForceApprove2922OverrideReasonContract(t *testing.T) {
	valid := map[string]any{"status": "approved", "reason": "Reviewed the exact bundle", "expected_status": "unverified",
		"expected_bundle_hash": strings.Repeat("a", 64), "override_reason": "业务必须使用，已人工复核脚本"}
	post := func(body map[string]any, repo *fakeSkillAssetsRepo) *httptest.ResponseRecorder {
		raw, _ := json.Marshal(body)
		req := skillRouteParam(skillUserRequest(http.MethodPost, "/admin/v1/skills/versions/v/admission", "tenant-a", "tenant_admin", raw), "id", "v")
		rec := httptest.NewRecorder()
		SetSkillVersionAdmission(&Dependencies{SkillAssetsRepo: repo}).ServeHTTP(rec, req)
		return rec
	}
	repo := &fakeSkillAssetsRepo{}
	if rec := post(valid, repo); rec.Code != http.StatusOK || repo.review.OverrideReason != "业务必须使用，已人工复核脚本" {
		t.Fatalf("override reason must reach the repository: status=%d body=%s review=%+v", rec.Code, rec.Body.String(), repo.review)
	}
	for name, change := range map[string]func(map[string]any){
		"too long":          func(b map[string]any) { b["override_reason"] = strings.Repeat("长", 513) },
		"control character": func(b map[string]any) { b["override_reason"] = "line\nbreak" },
		"not an approval":   func(b map[string]any) { b["status"] = "quarantined" },
	} {
		body := map[string]any{}
		for k, v := range valid {
			body[k] = v
		}
		change(body)
		repo := &fakeSkillAssetsRepo{}
		if rec := post(body, repo); rec.Code != http.StatusBadRequest || repo.admissionActor != "" {
			t.Fatalf("%s: status=%d body=%s", name, rec.Code, rec.Body.String())
		}
	}
	blocked := &fakeSkillAssetsRepo{admissionErr: repository.ErrSkillVersionNotApprovable}
	withoutOverride := map[string]any{}
	for k, v := range valid {
		if k != "override_reason" {
			withoutOverride[k] = v
		}
	}
	if rec := post(withoutOverride, blocked); rec.Code != http.StatusConflict {
		t.Fatalf("a blocked scan without an override reason stays 409: %d %s", rec.Code, rec.Body.String())
	}
}
