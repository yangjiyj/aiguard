package handler

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	entlicense "github.com/yangjiyj/aiguard/apps/control-plane/internal/license"
)

func TestLicenseGuardAllowsLicenseRoutesWhenMissing(t *testing.T) {
	t.Setenv("JJD_LICENSE_ENFORCE", "true")
	repo := &licenseSystemRepo{}
	deps := &Dependencies{SystemRepo: repo}
	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusNoContent)
	})
	req := httptest.NewRequest(http.MethodGet, "/admin/v1/system/license", nil)
	w := httptest.NewRecorder()

	LicenseGuard(deps)(next).ServeHTTP(w, req)

	if !nextCalled || w.Code != http.StatusNoContent {
		t.Fatalf("license status route should pass through: called=%v status=%d", nextCalled, w.Code)
	}
}

func TestLicenseGuardAllowsProductRouteWhenMissing(t *testing.T) {
	t.Setenv("JJD_LICENSE_ENFORCE", "true")
	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusNoContent)
	})
	req := httptest.NewRequest(http.MethodGet, "/admin/v1/system/product", nil)
	w := httptest.NewRecorder()
	LicenseGuard(&Dependencies{})(next).ServeHTTP(w, req)
	if !nextCalled || w.Code != http.StatusNoContent {
		t.Fatalf("product route must bypass missing license: called=%v status=%d body=%s", nextCalled, w.Code, w.Body.String())
	}
}

func TestLicenseGuardBlocksRevokedV2License(t *testing.T) {
	token, publicKeys := signedV2HandlerLicense(t, nil)
	list := signedV2HandlerRevocationList(t, func(payload *entlicense.RevocationPayload) {
		payload.RevokedLicenses = []entlicense.RevokedLicense{{LicenseID: "lic_v2_handler_unit"}}
	})
	data, err := json.Marshal(list)
	if err != nil {
		t.Fatalf("marshal revocation list: %v", err)
	}
	revocationPath := t.TempDir() + "/revocations.json"
	if err := os.WriteFile(revocationPath, data, 0o600); err != nil {
		t.Fatalf("write revocation list: %v", err)
	}
	t.Setenv("JJD_LICENSE_ENFORCE", "true")
	t.Setenv("JJD_LICENSE_PUBLIC_KEYS", publicKeys)
	t.Setenv("JJD_LICENSE_REVOCATION_FILE", revocationPath)
	repo := &licenseSystemRepo{settings: map[string]string{LicenseSettingKey: token}}
	deps := &Dependencies{SystemRepo: repo}
	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusNoContent)
	})
	req := httptest.NewRequest(http.MethodGet, "/admin/v1/users", nil)
	w := httptest.NewRecorder()

	LicenseGuard(deps)(next).ServeHTTP(w, req)

	if !nextCalled || w.Code != http.StatusNoContent {
		t.Fatalf("revoked license read route should pass through: called=%v status=%d body=%s", nextCalled, w.Code, w.Body.String())
	}
}

func TestLicenseGuardAllowsProtectedAdminReadRouteWhenMissing(t *testing.T) {
	t.Setenv("JJD_LICENSE_ENFORCE", "true")
	repo := &licenseSystemRepo{}
	deps := &Dependencies{SystemRepo: repo}
	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusNoContent)
	})
	req := httptest.NewRequest(http.MethodGet, "/admin/v1/users", nil)
	w := httptest.NewRecorder()

	LicenseGuard(deps)(next).ServeHTTP(w, req)

	if !nextCalled || w.Code != http.StatusNoContent {
		t.Fatalf("missing license read route should pass through: called=%v status=%d body=%s", nextCalled, w.Code, w.Body.String())
	}
}

func TestLicenseGuardEnforcesByDefault(t *testing.T) {
	repo := &licenseSystemRepo{}
	deps := &Dependencies{SystemRepo: repo}
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("next should not be called")
	})
	req := httptest.NewRequest(http.MethodPost, "/admin/v1/users", nil)
	w := httptest.NewRecorder()

	LicenseGuard(deps)(next).ServeHTTP(w, req)

	if w.Code != http.StatusPaymentRequired {
		t.Fatalf("status = %d, want %d; body=%s", w.Code, http.StatusPaymentRequired, w.Body.String())
	}
}

func TestLicenseGuardDegradesInvalidLicenseToReadOnly(t *testing.T) {
	t.Setenv("JJD_LICENSE_ENFORCE", "true")
	repo := &licenseSystemRepo{}
	deps := &Dependencies{SystemRepo: repo}

	for _, method := range []string{http.MethodGet, http.MethodHead} {
		t.Run(method+" allowed", func(t *testing.T) {
			nextCalled := false
			next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				nextCalled = true
				w.WriteHeader(http.StatusNoContent)
			})
			req := httptest.NewRequest(method, "/admin/v1/tenants", nil)
			w := httptest.NewRecorder()

			LicenseGuard(deps)(next).ServeHTTP(w, req)

			if !nextCalled || w.Code == http.StatusPaymentRequired {
				t.Fatalf("read route should pass through: called=%v status=%d body=%s", nextCalled, w.Code, w.Body.String())
			}
		})
	}

	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete} {
		t.Run(method+" blocked", func(t *testing.T) {
			next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				t.Fatalf("next should not be called")
			})
			req := httptest.NewRequest(method, "/admin/v1/tenants", nil)
			w := httptest.NewRecorder()

			LicenseGuard(deps)(next).ServeHTTP(w, req)

			if w.Code != http.StatusPaymentRequired {
				t.Fatalf("status = %d, want %d; body=%s", w.Code, http.StatusPaymentRequired, w.Body.String())
			}
			if !strings.Contains(w.Body.String(), "license 已到期，续期后方可修改配置") {
				t.Fatalf("body should include renewal prompt, got %s", w.Body.String())
			}
		})
	}
}

func TestLicenseGuardBypassRoutesStillPassThroughWhenMissing(t *testing.T) {
	t.Setenv("JJD_LICENSE_ENFORCE", "true")
	repo := &licenseSystemRepo{}
	deps := &Dependencies{SystemRepo: repo}

	for _, tc := range []struct {
		method string
		path   string
	}{
		{method: http.MethodPost, path: "/admin/v1/system/license/import"},
		{method: http.MethodGet, path: "/admin/v1/system/version"},
		{method: http.MethodGet, path: "/admin/v1/me"},
		{method: http.MethodPost, path: "/admin/v1/logout"},
	} {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			nextCalled := false
			next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				nextCalled = true
				w.WriteHeader(http.StatusNoContent)
			})
			req := httptest.NewRequest(tc.method, tc.path, nil)
			w := httptest.NewRecorder()

			LicenseGuard(deps)(next).ServeHTTP(w, req)

			if !nextCalled || w.Code != http.StatusNoContent {
				t.Fatalf("bypass route should pass through: called=%v status=%d body=%s", nextCalled, w.Code, w.Body.String())
			}
		})
	}
}

func TestLicenseGuardAllowsProtectedAdminRouteWithValidLicense(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	now := time.Now().UTC()
	file, err := entlicense.Sign(entlicense.Payload{
		LicenseID:   "lic_guard_unit",
		Customer:    "customer-a",
		LicenseType: "trial",
		Edition:     "enterprise",
		IssuedAt:    now,
		NotBefore:   now.Add(-time.Minute),
		ExpiresAt:   now.Add(90 * 24 * time.Hour),
		MaxUsers:    25,
		Features:    []string{"web_ai"},
	}, priv)
	if err != nil {
		t.Fatalf("sign license: %v", err)
	}
	raw, err := json.Marshal(file)
	if err != nil {
		t.Fatalf("marshal license: %v", err)
	}
	t.Setenv("JJD_LICENSE_ENFORCE", "true")
	t.Setenv("JJD_LICENSE_PUBLIC_KEY", base64.StdEncoding.EncodeToString(pub))
	repo := &licenseSystemRepo{settings: map[string]string{LicenseSettingKey: string(raw)}}
	deps := &Dependencies{SystemRepo: repo}

	for _, method := range []string{http.MethodGet, http.MethodPost} {
		t.Run(method, func(t *testing.T) {
			nextCalled := false
			next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				nextCalled = true
				w.WriteHeader(http.StatusNoContent)
			})
			req := httptest.NewRequest(method, "/admin/v1/users", nil)
			w := httptest.NewRecorder()

			LicenseGuard(deps)(next).ServeHTTP(w, req)

			if !nextCalled || w.Code != http.StatusNoContent {
				t.Fatalf("valid license should pass through: called=%v status=%d body=%s", nextCalled, w.Code, w.Body.String())
			}
		})
	}
}
