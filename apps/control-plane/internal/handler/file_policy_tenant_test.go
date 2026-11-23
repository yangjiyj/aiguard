package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/rules"
	"github.com/yangjiyj/aiguard/packages/shared-go/filereference"
)

func TestContentFilePolicySettingKeyIsTenantScopedAndLegacyCompatible(t *testing.T) {
	if got := contentFilePolicySettingKeyForTenant("tenant_default"); got != contentFilePolicySettingKey {
		t.Fatalf("default tenant key=%q want legacy %q", got, contentFilePolicySettingKey)
	}
	a := contentFilePolicySettingKeyForTenant("tenant-a")
	b := contentFilePolicySettingKeyForTenant("tenant-b")
	if a == b || a == contentFilePolicySettingKey || b == contentFilePolicySettingKey || strings.Contains(a, "tenant-a") {
		t.Fatalf("tenant policy keys are not stable isolated hashes: a=%q b=%q", a, b)
	}
}

func TestDecodeAndNormalizeFilePolicyIsStrictAndBounded(t *testing.T) {
	valid, err := decodeAndNormalizeFilePolicy([]byte(`{"allowed_types":[" pdf ","png"],"max_file_mb":0,"max_zip_ratio":0,"max_attachments":0}`))
	if err != nil {
		t.Fatalf("normalize valid policy: %v", err)
	}
	defaults := defaultContentFilePolicy()
	if valid.MaxFileMB != defaults.MaxFileMB || valid.MaxZipRatio != defaults.MaxZipRatio || valid.MaxAttachments != defaults.MaxAttachments || len(valid.AllowedTypes) != 2 || valid.AllowedTypes[0] != "pdf" {
		t.Fatalf("policy was not normalized: %+v", valid)
	}

	tooMany := make([]string, maxFilePolicyItems+1)
	for i := range tooMany {
		tooMany[i] = "pdf"
	}
	tooManyJSON, _ := json.Marshal(map[string]any{"allowed_types": tooMany})
	for _, raw := range [][]byte{
		[]byte(`null`),
		[]byte(`{"max_file_mb":101}`),
		[]byte(`{"max_zip_ratio":1001}`),
		[]byte(`{"max_attachments":101}`),
		[]byte(`{"allowed_types":["   "]}`),
		[]byte(`{"allowed_types":["` + strings.Repeat("x", maxFilePolicyItemLength+1) + `"]}`),
		[]byte(`{"unknown":true}`),
		[]byte(`{} trailing`),
		tooManyJSON,
	} {
		if _, err := decodeAndNormalizeFilePolicy(raw); err == nil {
			t.Fatalf("invalid policy accepted: %s", raw)
		}
	}
}

func TestUpdateContentFilePolicyIsTenantScopedAndRejectsInvalidPayload(t *testing.T) {
	repo := &contentConfigSystemRepo{}
	deps := &Dependencies{SystemRepo: repo}
	update := func(tenantID, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPut, "/admin/v1/content-security/file-policy", bytes.NewBufferString(body))
		req = req.WithContext(context.WithValue(req.Context(), auth.UserKey, &repository.User{ID: "owner-" + tenantID, TenantID: tenantID, Role: "tenant_owner", Status: "active"}))
		rec := httptest.NewRecorder()
		UpdateContentFilePolicy(deps).ServeHTTP(rec, req)
		return rec
	}

	if rec := update("tenant-a", `{"allowed_types":["pdf"],"max_file_mb":10}`); rec.Code != http.StatusOK {
		t.Fatalf("tenant A update status=%d body=%s", rec.Code, rec.Body.String())
	}
	if rec := update("tenant-b", `{"allowed_types":["png"],"max_file_mb":20}`); rec.Code != http.StatusOK {
		t.Fatalf("tenant B update status=%d body=%s", rec.Code, rec.Body.String())
	}
	keyA := contentFilePolicySettingKeyForTenant("tenant-a")
	keyB := contentFilePolicySettingKeyForTenant("tenant-b")
	if keyA == keyB || !strings.Contains(repo.settings[keyA], `"pdf"`) || !strings.Contains(repo.settings[keyB], `"png"`) {
		t.Fatalf("tenant policies overwrote one another: settings=%v", repo.settings)
	}
	for _, invalid := range []string{`null`, `{"unknown":1}`, `{"max_file_mb":101}`, `{} trailing`} {
		if rec := update("tenant-a", invalid); rec.Code != http.StatusUnprocessableEntity {
			t.Fatalf("invalid update %s status=%d want422 body=%s", invalid, rec.Code, rec.Body.String())
		}
	}
}

func TestApplyRulePackFilePolicyReadsOnlyCurrentTenantKey(t *testing.T) {
	repo := &contentConfigSystemRepo{settings: map[string]string{
		contentFilePolicySettingKeyForTenant("tenant-a"): `{"allowed_types":["pdf"],"max_file_mb":10}`,
		contentFilePolicySettingKeyForTenant("tenant-b"): `{"allowed_types":["png"],"max_file_mb":20}`,
	}}
	packA := rules.Compile("tenant-a", nil, nil)
	packB := rules.Compile("tenant-b", nil, nil)
	if err := applyRulePackFilePolicy(context.Background(), repo, "tenant-a", &packA); err != nil {
		t.Fatalf("apply A: %v", err)
	}
	if err := applyRulePackFilePolicy(context.Background(), repo, "tenant-b", &packB); err != nil {
		t.Fatalf("apply B: %v", err)
	}
	if packA.FilePolicy == nil || packB.FilePolicy == nil || packA.FilePolicy.MaxFileMB != 10 || packB.FilePolicy.MaxFileMB != 20 || packA.FilePolicy.AllowedTypes[0] == packB.FilePolicy.AllowedTypes[0] {
		t.Fatalf("tenant compile policy isolation failed: A=%+v B=%+v", packA.FilePolicy, packB.FilePolicy)
	}
}

func TestContentDlpEnabledRoundTripsAndDefaultsOff(t *testing.T) {
	// 显式开启可解码
	on, err := decodeAndNormalizeFilePolicy([]byte(`{"allowed_types":["pdf"],"max_file_mb":20,"content_dlp_enabled":true}`))
	if err != nil {
		t.Fatalf("decode content_dlp_enabled=true: %v", err)
	}
	if !on.ContentDlpEnabled {
		t.Fatalf("content_dlp_enabled=true not preserved: %+v", on)
	}
	// 缺省为关
	off, err := decodeAndNormalizeFilePolicy([]byte(`{"allowed_types":["pdf"],"max_file_mb":20}`))
	if err != nil {
		t.Fatalf("decode without content_dlp_enabled: %v", err)
	}
	if off.ContentDlpEnabled {
		t.Fatalf("content_dlp_enabled must default to false")
	}
	// 非法类型拒绝（DisallowUnknownFields + json 反序列化 bool 校验）
	if _, err := decodeAndNormalizeFilePolicy([]byte(`{"allowed_types":["pdf"],"max_file_mb":20,"content_dlp_enabled":"yes"}`)); err == nil {
		t.Fatalf("non-boolean content_dlp_enabled must be rejected")
	}
}

// 2.9.22 任务 4.1：文件风险类别与文件引用的处置可配，压缩包限制可调。
func TestFilePolicyRiskActionsDefaultToAlertAllowAndValidate(t *testing.T) {
	// 客户现场存量 JSON：缺新字段时按缺省（告警放行）解释，不报错。
	site := `{"allowed_types":["pdf","png","jpeg","webp","rar","7z","gzip","bz2","xz","archive","zip"],"max_file_mb":100,"max_zip_ratio":100,"max_attachments":10}`
	legacy, err := decodeAndNormalizeFilePolicy([]byte(site))
	if err != nil {
		t.Fatalf("site legacy policy rejected: %v", err)
	}
	actions := func(p rules.FilePolicy) map[string]string {
		return map[string]string{
			"executable_action":                    p.ExecutableAction,
			"disguised_executable_action":          p.DisguisedExecutableAction,
			"script_action":                        p.ScriptAction,
			"unknown_action":                       p.UnknownAction,
			"zip_bomb_action":                      p.ZipBombAction,
			"unverified_file_reference_action":     p.UnverifiedFileReferenceAction,
			"file_reference_lookup_failure_action": p.FileReferenceLookupFailureAction,
		}
	}
	for field, value := range actions(legacy) {
		if value != "alert_allow" {
			t.Fatalf("%s 缺省应为 alert_allow，实际 %q", field, value)
		}
	}
	if legacy.MaxZipEntries != 0 || legacy.MaxZipUncompressedMB != 0 || legacy.MaxZipNested != 0 {
		t.Fatalf("压缩包限制未配置时应留 0（引擎取环境缺省）：%+v", legacy)
	}
	if legacy.MaxFileMB != 100 || legacy.MaxZipRatio != 100 || legacy.MaxAttachments != 10 || len(legacy.AllowedTypes) != 11 {
		t.Fatalf("存量字段被改动：%+v", legacy)
	}

	for field := range actions(legacy) {
		for _, value := range []string{"allow", "alert_allow", "block"} {
			got, err := decodeAndNormalizeFilePolicy([]byte(`{"` + field + `":"` + value + `"}`))
			if err != nil || actions(got)[field] != value {
				t.Fatalf("%s=%s 未保留：%+v %v", field, value, got, err)
			}
		}
		for _, bad := range []string{`"deny"`, `"BLOCK"`, `true`, `1`} {
			if _, err := decodeAndNormalizeFilePolicy([]byte(`{"` + field + `":` + bad + `}`)); err == nil {
				t.Fatalf("%s 接受了非法值 %s", field, bad)
			}
		}
	}

	limits, err := decodeAndNormalizeFilePolicy([]byte(`{"max_zip_entries":5000,"max_zip_uncompressed_mb":2048,"max_zip_nested":10}`))
	if err != nil || limits.MaxZipEntries != 5000 || limits.MaxZipUncompressedMB != 2048 || limits.MaxZipNested != 10 {
		t.Fatalf("压缩包限制未保留：%+v %v", limits, err)
	}
	for _, bad := range []string{
		`{"max_zip_entries":-1}`, `{"max_zip_entries":100001}`,
		`{"max_zip_uncompressed_mb":-1}`, `{"max_zip_uncompressed_mb":10241}`,
		`{"max_zip_nested":-1}`, `{"max_zip_nested":101}`,
	} {
		if _, err := decodeAndNormalizeFilePolicy([]byte(bad)); err == nil {
			t.Fatalf("越界压缩包限制被接受：%s", bad)
		}
	}
}

func TestGetContentFilePolicyShowsDefaultRiskActions(t *testing.T) {
	deps := &Dependencies{SystemRepo: &contentConfigSystemRepo{}}
	req := withContentConfigUser(httptest.NewRequest(http.MethodGet, "/admin/v1/content-security/file-policy", nil), "security_officer", "tenant_default")
	rec := httptest.NewRecorder()
	GetContentFilePolicy(deps).ServeHTTP(rec, req)
	var got map[string]any
	if rec.Code != http.StatusOK || json.NewDecoder(rec.Body).Decode(&got) != nil {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	for _, field := range []string{"executable_action", "disguised_executable_action", "script_action", "unknown_action", "zip_bomb_action", "unverified_file_reference_action", "file_reference_lookup_failure_action"} {
		if got[field] != "alert_allow" {
			t.Fatalf("未保存策略时 %s 应显示 alert_allow，实际 %v", field, got[field])
		}
	}
}

// 网关和独立代理按 filereference.SettingKey 读租户文件策略，必须与控制面写入的键一致。
func TestFileReferenceSettingKeyMatchesControlPlane(t *testing.T) {
	for _, tenant := range []string{"", "tenant_default", "tenant-a", "租户B"} {
		if got, want := filereference.SettingKey(tenant), contentFilePolicySettingKeyForTenant(tenant); got != want {
			t.Fatalf("tenant %q: 共享键 %s，控制面键 %s", tenant, got, want)
		}
	}
}

// 审查第 2 项：未保存策略时 GET 显示的默认值要和引擎实际一致。引擎在没有保存策略时
// 不按类型阻断（可执行等走 executable_action，缺省告警放行），默认值不再列 pe、elf、
// macho、script 为阻断；首次把这份默认值原样保存后，也不会多出类型阻断。
func TestDefaultFilePolicyHasNoBuiltinBlockedTypes(t *testing.T) {
	repo := &contentConfigSystemRepo{}
	deps := &Dependencies{SystemRepo: repo}
	get := httptest.NewRecorder()
	GetContentFilePolicy(deps).ServeHTTP(get, withContentConfigUser(httptest.NewRequest(http.MethodGet, "/admin/v1/content-security/file-policy", nil), "security_officer", "tenant_default"))
	var shown rules.FilePolicy
	if get.Code != http.StatusOK || json.Unmarshal(get.Body.Bytes(), &shown) != nil {
		t.Fatalf("status=%d body=%s", get.Code, get.Body.String())
	}
	for _, blocked := range shown.BlockedTypes {
		switch blocked {
		case "pe", "elf", "macho", "script", "executable":
			t.Fatalf("未保存时默认值不应把 %s 列为阻断：%+v", blocked, shown.BlockedTypes)
		}
	}
	if shown.ExecutableAction != "alert_allow" || shown.ScriptAction != "alert_allow" {
		t.Fatalf("可执行与脚本走处置字段，缺省告警放行：%+v", shown)
	}

	put := httptest.NewRecorder()
	UpdateContentFilePolicy(deps).ServeHTTP(put, withContentConfigUser(httptest.NewRequest(http.MethodPut, "/admin/v1/content-security/file-policy", bytes.NewReader(get.Body.Bytes())), "security_officer", "tenant_default"))
	if put.Code != http.StatusOK {
		t.Fatalf("保存默认值失败：status=%d body=%s", put.Code, put.Body.String())
	}
	saved, err := decodeAndNormalizeFilePolicy([]byte(repo.settings[contentFilePolicySettingKey]))
	if err != nil || len(saved.BlockedTypes) != 0 || saved.ExecutableAction != "alert_allow" {
		t.Fatalf("首次保存默认值后不应出现类型阻断：%+v %v", saved, err)
	}
}

// 已保存的策略里管理员显式写的 blocked_types 原样保留，不做迁移。
func TestSavedBlockedTypesArePreserved(t *testing.T) {
	saved, err := decodeAndNormalizeFilePolicy([]byte(`{"blocked_types":["pe","elf","macho","script"],"max_file_mb":20}`))
	if err != nil || len(saved.BlockedTypes) != 4 || saved.BlockedTypes[0] != "pe" {
		t.Fatalf("显式配置的阻断类型必须原样保留：%+v %v", saved, err)
	}
}

// 默认值里 blocked_types 为空时，响应里也要明确写出空数组：控制台在字段缺失时会回落到
// 它自己的默认阻断名单（含 executable、script），原样保存就又把它们拦了。
func TestFilePolicyResponsesAlwaysCarryTypeLists(t *testing.T) {
	repo := &contentConfigSystemRepo{}
	deps := &Dependencies{SystemRepo: repo}
	get := httptest.NewRecorder()
	GetContentFilePolicy(deps).ServeHTTP(get, withContentConfigUser(httptest.NewRequest(http.MethodGet, "/admin/v1/content-security/file-policy", nil), "security_officer", "tenant_default"))
	put := httptest.NewRecorder()
	UpdateContentFilePolicy(deps).ServeHTTP(put, withContentConfigUser(httptest.NewRequest(http.MethodPut, "/admin/v1/content-security/file-policy", strings.NewReader(`{"max_file_mb":20}`)), "security_officer", "tenant_default"))
	for name, rec := range map[string]*httptest.ResponseRecorder{"GET": get, "PUT": put} {
		var raw map[string]json.RawMessage
		if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &raw) != nil {
			t.Fatalf("%s status=%d body=%s", name, rec.Code, rec.Body.String())
		}
		for _, key := range []string{"allowed_types", "blocked_types", "review_types"} {
			if _, ok := raw[key]; !ok {
				t.Fatalf("%s 响应缺 %s，控制台会回落到自己的默认名单：%s", name, key, rec.Body.String())
			}
		}
		if string(raw["blocked_types"]) != "[]" {
			t.Fatalf("%s blocked_types 应为空数组：%s", name, raw["blocked_types"])
		}
	}
}
