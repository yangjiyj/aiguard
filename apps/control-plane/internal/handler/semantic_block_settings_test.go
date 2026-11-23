package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

// 语义拦截阈值 semantic_block_min_confidence：控制台语义设置项，范围 0.5–1.0，默认 0.85。

func TestSemanticBlockMinConfidenceValidationRange(t *testing.T) {
	for _, good := range []string{"0.5", "0.85", "0.9", "1", "1.0"} {
		if err := validateSemanticSettingValues(context.Background(), map[string]string{semanticBlockMinConfidenceKey: good}); err != nil {
			t.Fatalf("%s 应合法：%v", good, err)
		}
	}
	for _, bad := range []string{"0.49", "1.01", "0", "-1", "abc", "NaN", ""} {
		if err := validateSemanticSettingValues(context.Background(), map[string]string{semanticBlockMinConfidenceKey: bad}); err == nil {
			t.Fatalf("%q 应被拒绝", bad)
		}
	}
}

func TestSemanticBlockMinConfidenceIsWritableAndVersionGuarded(t *testing.T) {
	if !semanticSettingsWritableKeys[semanticBlockMinConfidenceKey] {
		t.Fatal("阈值必须能通过 PUT /security/semantic/settings 保存")
	}
	guarded := false
	for _, key := range semanticVersionGuardKeys() {
		guarded = guarded || key == semanticBlockMinConfidenceKey
	}
	if !guarded {
		t.Fatal("阈值必须参与 expected_version 并发控制")
	}

	repo := newVersionedRepo(map[string]string{"judge_backend": "bundled"})
	v0 := currentVersion(t, repo)
	ok := putSemantic(t, repo, nil, "security_officer", semanticConfigTenant, map[string]any{
		semanticBlockMinConfidenceKey: "0.9", "expected_version": v0,
	})
	if ok.Code != http.StatusOK || repo.settings[semanticBlockMinConfidenceKey] != "0.9" {
		t.Fatalf("安全员保存阈值应成功：%d %s settings=%v", ok.Code, ok.Body.String(), repo.settings)
	}
	stale := putSemantic(t, repo, nil, "security_officer", semanticConfigTenant, map[string]any{
		semanticBlockMinConfidenceKey: "0.7", "expected_version": v0,
	})
	if stale.Code != http.StatusConflict || repo.settings[semanticBlockMinConfidenceKey] != "0.9" {
		t.Fatalf("旧版本保存必须 409 且不覆盖：%d %s settings=%v", stale.Code, stale.Body.String(), repo.settings)
	}
	invalid := putSemantic(t, repo, nil, "security_officer", semanticConfigTenant, map[string]any{
		semanticBlockMinConfidenceKey: "0.3", "expected_version": currentVersion(t, repo),
	})
	if invalid.Code != http.StatusBadRequest || repo.settings[semanticBlockMinConfidenceKey] != "0.9" {
		t.Fatalf("越界阈值必须 400 且不落库：%d %s settings=%v", invalid.Code, invalid.Body.String(), repo.settings)
	}
}

func TestSemanticEngineProjectionCarriesBlockMinConfidence(t *testing.T) {
	cases := map[string]string{"": "0.85", "0.9": "0.9", "0.3": "0.85", "garbage": "0.85", "1": "1"}
	for stored, want := range cases {
		settings := map[string]string{}
		if stored != "" {
			settings[semanticBlockMinConfidenceKey] = stored
		}
		projection, err := buildSemanticEngineProjection(context.Background(), semanticTestDeps(settings))
		if err != nil {
			t.Fatalf("projection: %v", err)
		}
		if projection[semanticBlockMinConfidenceKey] != want {
			t.Fatalf("stored=%q projection=%v want %q", stored, projection[semanticBlockMinConfidenceKey], want)
		}
	}
}

func TestSecurityPolicyHandlersPassSemanticAction(t *testing.T) {
	store := &fakeSecurityPolicyStore{}
	h := newSecurityPoliciesHandler(&Dependencies{}, store, &fakeRegexValidator{valid: true})

	rec := httptest.NewRecorder()
	h.create(rec, policyHandlerRequest(http.MethodPost, "/admin/v1/security/policies",
		`{"name":"语义越狱拦截","scene":"prompt_injection","severity":"high","action":"audit","enabled":true,"capability_categories":["semantic_jailbreak"],"semantic_action":"block"}`,
		"platform_admin"))
	if rec.Code != http.StatusCreated || store.created.SemanticAction != "block" {
		t.Fatalf("create status=%d body=%s input=%+v", rec.Code, rec.Body.String(), store.created)
	}

	rec = httptest.NewRecorder()
	h.update(rec, withPolicyID(policyHandlerRequest(http.MethodPatch, "/admin/v1/security/policies/policy-1",
		`{"semantic_action":"observe"}`, "platform_admin"), "policy-1"))
	if rec.Code != http.StatusOK || store.updated.SemanticAction == nil || *store.updated.SemanticAction != "observe" {
		t.Fatalf("update status=%d body=%s update=%+v", rec.Code, rec.Body.String(), store.updated)
	}

	response := policyResponse(repository.SecurityPolicy{ID: "p", SemanticAction: ""}, false)
	if response.SemanticAction != "audit" {
		t.Fatalf("未配置时对外必须明确为 audit：%q", response.SemanticAction)
	}
}

// 控制台以 JSON 数值提交阈值（InputNumber），落库须是可被引擎解析的规范字符串。
func TestSemanticBlockMinConfidenceAcceptsNumericJSON(t *testing.T) {
	repo := newVersionedRepo(map[string]string{"judge_backend": "bundled"})
	rec := putSemantic(t, repo, nil, "security_officer", semanticConfigTenant, map[string]any{
		semanticBlockMinConfidenceKey: 0.95, "expected_version": currentVersion(t, repo),
	})
	if rec.Code != http.StatusOK || repo.settings[semanticBlockMinConfidenceKey] != "0.95" {
		t.Fatalf("numeric threshold: %d %s settings=%v", rec.Code, rec.Body.String(), repo.settings)
	}
	projection, err := buildSemanticEngineProjection(context.Background(), semanticTestDeps(map[string]string{
		semanticBlockMinConfidenceKey: repo.settings[semanticBlockMinConfidenceKey],
	}))
	if err != nil || projection[semanticBlockMinConfidenceKey] != "0.95" {
		t.Fatalf("projection=%v err=%v", projection[semanticBlockMinConfidenceKey], err)
	}
}
