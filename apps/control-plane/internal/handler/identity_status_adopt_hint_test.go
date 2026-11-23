package handler

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/identityruntime"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

func TestDiffObservedSettings(t *testing.T) {
	active := &repository.IdentitySource{SignatureMode: "jwks", UsernameClaim: "preferred_username"}
	cases := []struct {
		name     string
		observed identityruntime.ObservedSettings
		active   *repository.IdentitySource
		want     []string
	}{
		{"签名方式不同", identityruntime.ObservedSettings{Exists: true, SignatureMode: "none", UsernameClaim: "preferred_username"}, active, []string{"signature_mode"}},
		{"用户名不同", identityruntime.ObservedSettings{Exists: true, SignatureMode: "jwks", UsernameClaim: "email"}, active, []string{"username_claim"}},
		{"观测用户名为空不算差异", identityruntime.ObservedSettings{Exists: true, SignatureMode: "jwks", UsernameClaim: ""}, active, nil},
		{"库内空签名方式按 jwks 归一", identityruntime.ObservedSettings{Exists: true, SignatureMode: "jwks", UsernameClaim: "preferred_username"}, &repository.IdentitySource{UsernameClaim: "preferred_username"}, nil},
		{"跳过资料页不同", identityruntime.ObservedSettings{Exists: true, SignatureMode: "jwks", SkipProfileReview: true}, active, []string{"skip_profile_review"}},
		{"三项都不同", identityruntime.ObservedSettings{Exists: true, SignatureMode: "none", UsernameClaim: "email", SkipProfileReview: true}, active, []string{"signature_mode", "username_claim", "skip_profile_review"}},
		{"运行态不存在", identityruntime.ObservedSettings{Exists: false, SignatureMode: "none"}, active, nil},
	}
	for _, c := range cases {
		if got := diffObservedSettings(c.observed, c.active); !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: got %v want %v", c.name, got, c.want)
		}
	}
}

func TestObserveAdoptableDriftHandlesErrorAndMissingObserver(t *testing.T) {
	active := &repository.IdentitySource{SignatureMode: "jwks", UsernameClaim: "preferred_username"}
	rt := &fakeIdentityRuntime{observeErr: errors.New("boom"), observed: identityruntime.ObservedSettings{Exists: true, SignatureMode: "none"}}
	if got := observeAdoptableDrift(httptest.NewRequest(http.MethodGet, "/", nil).Context(), &Dependencies{IdentityRuntime: rt}, "enterprise", active); got != nil || rt.observeCalls != 1 {
		t.Fatalf("Observe 出错应静默降级: %v calls=%d", got, rt.observeCalls)
	}
	if got := observeAdoptableDrift(httptest.NewRequest(http.MethodGet, "/", nil).Context(), &Dependencies{IdentityRuntime: noObserveRuntime{}}, "enterprise", active); got != nil {
		t.Fatalf("未实现 observer 应跳过: %v", got)
	}
}

func TestObserveFailureCode(t *testing.T) {
	cases := []struct {
		err  error
		want string
	}{
		{identityruntime.ErrRuntimeUnavailable, "runtime_unavailable"},
		{fmt.Errorf("wrap: %w", identityruntime.ErrRuntimeUnauthorized), "unauthorized"},
		{context.DeadlineExceeded, "timeout"},
		{identityruntime.ErrRuntimeNotFound, "not_found"},
		{identityruntime.ErrRuntimeRejected, "rejected"},
		{identityruntime.ErrRuntimeResponseTooLarge, "response_too_large"},
		{errors.New("secret=abc http://x?token=1"), "other"},
	}
	for _, c := range cases {
		if got := observeFailureCode(c.err); got != c.want {
			t.Errorf("%v: got %s want %s", c.err, got, c.want)
		}
	}
}

type noObserveRuntime struct{ IdentityRuntime }

func statusReq(t *testing.T, deps *Dependencies, tenantID, userID string) string {
	t.Helper()
	req := withOrgUserCtx(httptest.NewRequest(http.MethodGet, "/admin/v1/identity/status", nil), tenantID, userID)
	rr := httptest.NewRecorder()
	GetIdentityStatus(deps)(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("code=%d %s", rr.Code, rr.Body.String())
	}
	return rr.Body.String()
}

func TestStatusDriftRecommendsAdoptWhenSignatureModeDiffers(t *testing.T) {
	pool, tenantID, userID := setupOrgHandlerPool(t)
	rt := &fakeIdentityRuntime{
		status:   identityruntime.RuntimeStatus{Exists: true, Enabled: true, Drifted: true, Digest: "sha256:x"},
		observed: identityruntime.ObservedSettings{Exists: true, SignatureMode: "none", UsernameClaim: "preferred_username"},
	}
	deps := buildRuntimeIdentityDeps(t, pool, rt)
	seedActiveIdentitySource(t, deps, tenantID, userID)
	body := statusReq(t, deps, tenantID, userID)
	if !strings.Contains(body, `"drift_fields":["signature_mode"]`) || !strings.Contains(body, `"adopt_recommended":true`) ||
		!strings.Contains(body, "如这些差异是现场有意调整，请先「采纳现场运行态」，再「按当前配置修复」") {
		t.Fatalf("unexpected: %s", body)
	}
}

func TestStatusDriftUsernameDiffers(t *testing.T) {
	pool, tenantID, userID := setupOrgHandlerPool(t)
	rt := &fakeIdentityRuntime{
		status:   identityruntime.RuntimeStatus{Exists: true, Enabled: true, Drifted: true, Digest: "sha256:x"},
		observed: identityruntime.ObservedSettings{Exists: true, SignatureMode: "jwks", UsernameClaim: "email"},
	}
	deps := buildRuntimeIdentityDeps(t, pool, rt)
	seedActiveIdentitySource(t, deps, tenantID, userID)
	if body := statusReq(t, deps, tenantID, userID); !strings.Contains(body, `"drift_fields":["username_claim"]`) {
		t.Fatalf("unexpected: %s", body)
	}
}

func TestStatusDriftEmptyObservedUsernameKeepsOriginalMessage(t *testing.T) {
	pool, tenantID, userID := setupOrgHandlerPool(t)
	rt := &fakeIdentityRuntime{
		status:   identityruntime.RuntimeStatus{Exists: true, Enabled: true, Drifted: true, Digest: "sha256:x"},
		observed: identityruntime.ObservedSettings{Exists: true, SignatureMode: "jwks", UsernameClaim: ""},
	}
	deps := buildRuntimeIdentityDeps(t, pool, rt)
	seedActiveIdentitySource(t, deps, tenantID, userID)
	body := statusReq(t, deps, tenantID, userID)
	if strings.Contains(body, "drift_fields") || strings.Contains(body, "adopt_recommended") ||
		!strings.Contains(body, "运行配置与当前设置不一致，可按当前配置修复") {
		t.Fatalf("unexpected: %s", body)
	}
}

func TestStatusDriftObserveErrorKeepsOriginalBehavior(t *testing.T) {
	pool, tenantID, userID := setupOrgHandlerPool(t)
	rt := &fakeIdentityRuntime{
		status:     identityruntime.RuntimeStatus{Exists: true, Enabled: true, Drifted: true, Digest: "sha256:x"},
		observeErr: errors.New("boom"),
	}
	deps := buildRuntimeIdentityDeps(t, pool, rt)
	seedActiveIdentitySource(t, deps, tenantID, userID)
	body := statusReq(t, deps, tenantID, userID)
	if strings.Contains(body, "drift_fields") || strings.Contains(body, "adopt_recommended") ||
		!strings.Contains(body, "运行配置与当前设置不一致，可按当前配置修复") {
		t.Fatalf("unexpected: %s", body)
	}
}

func TestStatusNotDriftedDoesNotObserve(t *testing.T) {
	pool, tenantID, userID := setupOrgHandlerPool(t)
	rt := &fakeIdentityRuntime{status: identityruntime.RuntimeStatus{Exists: true, Enabled: true, Drifted: false, Digest: "sha256:x"}}
	deps := buildRuntimeIdentityDeps(t, pool, rt)
	seedActiveIdentitySource(t, deps, tenantID, userID)
	statusReq(t, deps, tenantID, userID)
	if rt.observeCalls != 0 {
		t.Fatalf("未漂移不应 Observe: %d", rt.observeCalls)
	}
}
