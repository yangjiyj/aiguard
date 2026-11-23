package handler

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/bootstrap"
	entlicense "github.com/yangjiyj/aiguard/apps/control-plane/internal/license"
)

func TestLicenseGuardBlocksUnlicensedFeatureRoute(t *testing.T) {
	token, publicKeys := signedV2HandlerLicense(t, func(payload *entlicense.PayloadV2) {
		payload.Features = []string{"web_ai"}
	})
	t.Setenv("JJD_LICENSE_ENFORCE", "true")
	t.Setenv("JJD_LICENSE_PUBLIC_KEYS", publicKeys)
	deps := &Dependencies{SystemRepo: &licenseSystemRepo{settings: map[string]string{LicenseSettingKey: token}}}
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("next should not be called for unlicensed feature")
	})
	req := httptest.NewRequest(http.MethodGet, "/admin/v1/agentguard/policies", nil)
	w := httptest.NewRecorder()

	LicenseGuard(deps)(next).ServeHTTP(w, req)

	if w.Code != http.StatusPaymentRequired {
		t.Fatalf("status = %d, want %d; body=%s", w.Code, http.StatusPaymentRequired, w.Body.String())
	}
}

func TestAgentAdminRequiresAgentSecurityForEveryMethod(t *testing.T) {
	for _, method := range []string{http.MethodGet, http.MethodPost} {
		t.Run(method, func(t *testing.T) {
			token, publicKeys := signedV2HandlerLicense(t, func(payload *entlicense.PayloadV2) {
				payload.Features = []string{"web_ai"}
			})
			t.Setenv("JJD_LICENSE_ENFORCE", "true")
			t.Setenv("JJD_LICENSE_PUBLIC_KEYS", publicKeys)
			deps := &Dependencies{SystemRepo: &licenseSystemRepo{settings: map[string]string{LicenseSettingKey: token}}}
			called := false
			request := httptest.NewRequest(method, "/admin/v1/agent/endpoints", nil)
			w := httptest.NewRecorder()
			LicenseGuard(deps)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true })).ServeHTTP(w, request)
			if called || w.Code != http.StatusPaymentRequired {
				t.Fatalf("unlicensed method %s status=%d called=%v", method, w.Code, called)
			}
		})
	}
}

func TestAgentAdminDeniedWithoutLicenseAndAcceptedWithFeature(t *testing.T) {
	t.Setenv("JJD_LICENSE_ENFORCE", "true")
	deps := &Dependencies{SystemRepo: &licenseSystemRepo{settings: map[string]string{}}}
	request := httptest.NewRequest(http.MethodGet, "/admin/v1/agent/overview", nil)
	called := false
	guard := LicenseGuard(deps)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true }))
	w := httptest.NewRecorder()
	guard.ServeHTTP(w, request)
	if called || w.Code != http.StatusPaymentRequired {
		t.Fatalf("no license status=%d called=%v", w.Code, called)
	}
	token, publicKeys := signedV2HandlerLicense(t, func(payload *entlicense.PayloadV2) {
		payload.Features = append(payload.Features, "agent_security")
	})
	t.Setenv("JJD_LICENSE_PUBLIC_KEYS", publicKeys)
	deps.SystemRepo = &licenseSystemRepo{settings: map[string]string{LicenseSettingKey: token}}
	w = httptest.NewRecorder()
	guard.ServeHTTP(w, request)
	if !called || w.Code != http.StatusOK {
		t.Fatalf("licensed status=%d called=%v", w.Code, called)
	}
}

func TestNativeTrialFeatureGuard(t *testing.T) {
	t.Setenv("JJD_LICENSE_ENFORCE", "true")
	t.Setenv("JJD_LICENSE_PUBLIC_KEY", "")
	t.Setenv("JJD_LICENSE_PUBLIC_KEYS", "")
	deps := &Dependencies{SystemRepo: &licenseSystemRepo{settings: map[string]string{
		bootstrap.LicenseInstallAnchorKey: time.Now().UTC().AddDate(0, 0, -10).Format(time.RFC3339),
	}}}
	for _, path := range []string{
		"/admin/v1/projects", "/admin/v1/providers", "/admin/v1/models", "/admin/v1/keys",
		"/admin/v1/agentguard/policies", "/admin/v1/audit/access-retention",
		"/admin/v1/reverse-proxy", "/admin/v1/detectors",
	} {
		for _, method := range []string{http.MethodGet, http.MethodPost} {
			t.Run(method+path, func(t *testing.T) {
				called := false
				w := httptest.NewRecorder()
				request := httptest.NewRequest(method, path, nil)
				LicenseGuard(deps)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					called = true
					w.WriteHeader(http.StatusNoContent)
				})).ServeHTTP(w, request)
				if !called || w.Code != http.StatusNoContent {
					t.Fatalf("native trial status=%d called=%v body=%s", w.Code, called, w.Body.String())
				}
			})
		}
	}
	for _, method := range []string{http.MethodGet, http.MethodPost} {
		t.Run(method+"/admin/v1/agent/endpoints", func(t *testing.T) {
			called := false
			w := httptest.NewRecorder()
			LicenseGuard(deps)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
				called = true
			})).ServeHTTP(w, httptest.NewRequest(method, "/admin/v1/agent/endpoints", nil))
			if called || w.Code != http.StatusPaymentRequired || !strings.Contains(w.Body.String(), "license_feature_required") {
				t.Fatalf("native trial agent route status=%d called=%v body=%s", w.Code, called, w.Body.String())
			}
		})
	}
	status := licenseStatusFromStored(httptest.NewRequest(http.MethodGet, "/admin/v1/system/license", nil), deps, "", "", time.Now().UTC())
	for _, feature := range []string{"agent_security", "unknown_future_feature", "*"} {
		if licenseHasFeature(status, feature) {
			t.Fatalf("native trial unexpectedly grants %q", feature)
		}
	}
}

func TestNativeTrialInactiveGuardKeepsReadOnlyDegradation(t *testing.T) {
	t.Setenv("JJD_LICENSE_ENFORCE", "true")
	for _, tc := range []struct {
		name   string
		anchor string
	}{
		{name: "missing"},
		{name: "expired", anchor: time.Now().UTC().AddDate(0, 0, -91).Format(time.RFC3339)},
	} {
		for _, method := range []string{http.MethodGet, http.MethodPost} {
			t.Run(tc.name+method, func(t *testing.T) {
				deps := &Dependencies{SystemRepo: &licenseSystemRepo{settings: map[string]string{bootstrap.LicenseInstallAnchorKey: tc.anchor}}}
				called := false
				w := httptest.NewRecorder()
				LicenseGuard(deps)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					called = true
					w.WriteHeader(http.StatusNoContent)
				})).ServeHTTP(w, httptest.NewRequest(method, "/admin/v1/projects", nil))
				if method == http.MethodGet {
					if !called || w.Code != http.StatusNoContent {
						t.Fatalf("inactive trial read status=%d called=%v", w.Code, called)
					}
				} else if called || w.Code != http.StatusPaymentRequired || !strings.Contains(w.Body.String(), "license_required") {
					t.Fatalf("inactive trial write status=%d called=%v body=%s", w.Code, called, w.Body.String())
				}
			})
		}
	}
}

func TestNativeTrialAnchorDoesNotExpandSignedFeatures(t *testing.T) {
	token, publicKeys := signedV2HandlerLicense(t, func(payload *entlicense.PayloadV2) {
		payload.Features = []string{"web_ai"}
	})
	t.Setenv("JJD_LICENSE_ENFORCE", "true")
	t.Setenv("JJD_LICENSE_PUBLIC_KEYS", publicKeys)
	deps := &Dependencies{SystemRepo: &licenseSystemRepo{settings: map[string]string{
		LicenseSettingKey:                 token,
		bootstrap.LicenseInstallAnchorKey: time.Now().UTC().AddDate(0, 0, -10).Format(time.RFC3339),
	}}}
	for _, tc := range []struct {
		path    string
		allowed bool
	}{
		{path: "/admin/v1/projects", allowed: true},
		{path: "/admin/v1/detectors"},
	} {
		t.Run(tc.path, func(t *testing.T) {
			called := false
			w := httptest.NewRecorder()
			LicenseGuard(deps)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				called = true
				w.WriteHeader(http.StatusNoContent)
			})).ServeHTTP(w, httptest.NewRequest(http.MethodPost, tc.path, nil))
			if tc.allowed {
				if !called || w.Code != http.StatusNoContent {
					t.Fatalf("signed feature rejected: status=%d called=%v body=%s", w.Code, called, w.Body.String())
				}
			} else if called || w.Code != http.StatusPaymentRequired || !strings.Contains(w.Body.String(), "license_feature_required") {
				t.Fatalf("trial anchor expanded signed features: status=%d called=%v body=%s", w.Code, called, w.Body.String())
			}
		})
	}
}
