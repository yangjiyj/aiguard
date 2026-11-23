package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

// 复审次要项：管理端文本（审查原因、强制批准原因等）拒绝 unicode.Cf（双向覆盖、零宽字符），
// 避免审计里显示的内容与实际不一致。
func TestSkillText2922RejectsFormatCharacters(t *testing.T) {
	for _, value := range []string{"业务需要\u202e已复核", "a\u200bb", "\ufeffreason", "x\u2066y"} {
		if validateSkillText("reason", value, 512, true) == nil {
			t.Errorf("%q carries a format character and must be rejected", value)
		}
	}
	if err := validateSkillText("reason", "业务必须使用，已人工复核脚本", 512, true); err != nil {
		t.Fatalf("plain text is accepted: %v", err)
	}
	// 网关上报的观测数据（Skill 名称、版本、发布者等）照旧只拒控制字符：名字里藏零宽字符的 Skill
	// 也要登记进清单，不能因为校验被丢掉。
	if err := validateObservedSkillText("display_name", "pdf\u200b", 255, false); err != nil {
		t.Fatalf("observed data with a format character is still recorded: %v", err)
	}
	if validateObservedSkillText("display_name", "pdf\n", 255, false) == nil {
		t.Fatal("observed data still rejects control characters")
	}

	valid := map[string]any{"status": "approved", "reason": "Reviewed the exact bundle", "expected_status": "unverified",
		"expected_bundle_hash": strings.Repeat("a", 64), "override_reason": "业务必须使用"}
	for field, value := range map[string]string{"override_reason": "业务必须使用\u202e", "reason": "Reviewed\u200b"} {
		body := map[string]any{}
		for k, v := range valid {
			body[k] = v
		}
		body[field] = value
		raw, _ := json.Marshal(body)
		repo := &fakeSkillAssetsRepo{}
		rec := httptest.NewRecorder()
		SetSkillVersionAdmission(&Dependencies{SkillAssetsRepo: repo}).ServeHTTP(rec,
			skillRouteParam(skillUserRequest(http.MethodPost, "/admin/v1/skills/versions/v/admission", "tenant-a", "tenant_admin", raw), "id", "v"))
		if rec.Code != http.StatusBadRequest || repo.admissionActor != "" {
			t.Fatalf("%s with a format character: status=%d body=%s", field, rec.Code, rec.Body.String())
		}
	}
}

// 复审次要项：扫描结论不是阻断的版本带 override_reason 时直接 400，不把它当普通批准、原样回显。
func TestSkillForceApprove2922OverrideOnNonBlockedScanIs400(t *testing.T) {
	body, _ := json.Marshal(map[string]any{"status": "approved", "reason": "Reviewed the exact bundle", "expected_status": "unverified",
		"expected_bundle_hash": strings.Repeat("a", 64), "override_reason": "业务必须使用"})
	repo := &fakeSkillAssetsRepo{admissionErr: repository.ErrSkillOverrideNotApplicable}
	rec := httptest.NewRecorder()
	SetSkillVersionAdmission(&Dependencies{SkillAssetsRepo: repo}).ServeHTTP(rec,
		skillRouteParam(skillUserRequest(http.MethodPost, "/admin/v1/skills/versions/v/admission", "tenant-a", "tenant_admin", body), "id", "v"))
	if rec.Code != http.StatusBadRequest || strings.Contains(rec.Body.String(), `"override_reason":"业务必须使用"`) {
		t.Fatalf("an override reason on a non-blocked scan is a bad request: status=%d body=%s", rec.Code, rec.Body.String())
	}
}
