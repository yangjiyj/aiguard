package handler

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	entlicense "github.com/yangjiyj/aiguard/apps/control-plane/internal/license"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

type licenseSystemRepo struct {
	settings map[string]string
	audits   []*repository.AuditOperation
}

func (r *licenseSystemRepo) Get(_ context.Context, key string) (*repository.SystemSetting, error) {
	if r.settings == nil {
		return nil, nil
	}
	value, ok := r.settings[key]
	if !ok {
		return nil, nil
	}
	return &repository.SystemSetting{Key: key, Value: value, UpdatedAt: time.Now()}, nil
}

func (r *licenseSystemRepo) GetAll(context.Context) ([]*repository.SystemSetting, error) {
	out := make([]*repository.SystemSetting, 0, len(r.settings))
	for key, value := range r.settings {
		out = append(out, &repository.SystemSetting{Key: key, Value: value, UpdatedAt: time.Now()})
	}
	return out, nil
}

func (r *licenseSystemRepo) Set(_ context.Context, key, value string) error {
	if r.settings == nil {
		r.settings = map[string]string{}
	}
	r.settings[key] = value
	return nil
}

func (r *licenseSystemRepo) SetMultiple(ctx context.Context, settings map[string]string) error {
	for key, value := range settings {
		if err := r.Set(ctx, key, value); err != nil {
			return err
		}
	}
	return nil
}

func (r *licenseSystemRepo) CreateAuditOperation(_ context.Context, op *repository.AuditOperation) error {
	r.audits = append(r.audits, op)
	return nil
}

func (r *licenseSystemRepo) ListAuditOperations(context.Context, int, int, string) ([]*repository.AuditOperation, int, error) {
	return nil, 0, nil
}

func (r *licenseSystemRepo) GetBool(_ context.Context, key string) (bool, error) {
	return r.settings[key] == "true", nil
}

func signedTestLicense(t *testing.T, expiresAt time.Time) (token string, publicKey string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	file, err := entlicense.Sign(entlicense.Payload{
		LicenseID:   "lic_test_trial",
		Customer:    "customer-a",
		LicenseType: "trial",
		Edition:     "enterprise",
		IssuedAt:    time.Now().UTC().Add(-time.Hour),
		NotBefore:   time.Now().UTC().Add(-time.Minute),
		ExpiresAt:   expiresAt.UTC(),
		MaxUsers:    25,
		Features:    []string{"web_ai", "agent_audit", "ide_proxy", "content_retention"},
	}, priv)
	if err != nil {
		t.Fatalf("sign license: %v", err)
	}
	data, err := json.Marshal(file)
	if err != nil {
		t.Fatalf("marshal license: %v", err)
	}
	return string(data), base64.StdEncoding.EncodeToString(pub)
}

func signedV2HandlerLicense(t *testing.T, mutate func(*entlicense.PayloadV2)) (token string, publicKeys string) {
	t.Helper()
	seed, err := base64.RawURLEncoding.DecodeString("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8")
	if err != nil {
		t.Fatalf("decode seed: %v", err)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	payload := entlicense.PayloadV2{
		SchemaVersion: entlicense.SchemaVersionV2,
		LicenseID:     "lic_v2_handler_unit",
		Customer: entlicense.CustomerV2{
			ID:          "cust_handler",
			DisplayName: "Handler Customer",
		},
		Subject: entlicense.SubjectV2{
			DisplayName: "Handler License",
			Products:    []string{entlicense.ProductJJDGuardEnterprise},
		},
		Edition:   "enterprise",
		IssuedAt:  "2026-06-21T00:00:00Z",
		NotBefore: "2026-06-21T00:00:00Z",
		ExpiresAt: "2027-12-31T23:59:59Z",
		MaxUsers:  25,
		Features:  []string{"web_ai", "agent_audit", "ide_proxy", "content_retention", "sensitive_data_guard"},
		DeploymentBinding: entlicense.DeploymentBinding{
			Mode: "none",
		},
		GracePolicy: entlicense.GracePolicy{
			ExpiryGraceDays:            7,
			ClockRollbackGraceHours:    24,
			OfflineRevocationStaleDays: 30,
		},
		RevocationInfo: entlicense.RevocationInfo{Mode: "none"},
		Issuer:         "huoxianbao-license-authority-prod",
	}
	if mutate != nil {
		mutate(&payload)
	}
	file, err := entlicense.SignV2(payload, "hxb-prod-lic-2026-01", priv)
	if err != nil {
		t.Fatalf("sign v2 license: %v", err)
	}
	raw, err := entlicense.MarshalFileV2(*file)
	if err != nil {
		t.Fatalf("marshal v2 license: %v", err)
	}
	return raw, "hxb-prod-lic-2026-01=A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg" // pragma: allowlist secret
}

func signedV2HandlerRevocationList(t *testing.T, mutate func(*entlicense.RevocationPayload)) *entlicense.RevocationList {
	t.Helper()
	seed, err := base64.RawURLEncoding.DecodeString("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8")
	if err != nil {
		t.Fatalf("decode seed: %v", err)
	}
	payload := entlicense.RevocationPayload{
		SchemaVersion: "license-revocation-list.v1",
		ListID:        "rl_handler",
		Issuer:        "huoxianbao-license-authority-prod",
		IssuedAt:      "2026-06-21T00:00:00Z",
		ValidUntil:    "2026-06-30T00:00:00Z",
	}
	if mutate != nil {
		mutate(&payload)
	}
	list, err := entlicense.SignRevocationList(payload, "hxb-prod-lic-2026-01", ed25519.NewKeyFromSeed(seed))
	if err != nil {
		t.Fatalf("sign revocation list: %v", err)
	}
	return list
}

func licenseAdminRequest(method, target string, body any) *http.Request {
	var reader *bytes.Reader
	if body == nil {
		reader = bytes.NewReader(nil)
	} else {
		data, _ := json.Marshal(body)
		reader = bytes.NewReader(data)
	}
	req := httptest.NewRequest(method, target, reader)
	ctx := context.WithValue(req.Context(), auth.UserKey, &repository.User{
		ID:       "user_admin",
		TenantID: "tenant_default",
		Role:     "platform_admin",
		Status:   "active",
	})
	return req.WithContext(ctx)
}

func TestGetLicenseStatusReportsMissingLicense(t *testing.T) {
	repo := &licenseSystemRepo{}
	deps := &Dependencies{SystemRepo: repo}
	req := licenseAdminRequest(http.MethodGet, "/admin/v1/system/license", nil)
	w := httptest.NewRecorder()

	GetLicenseStatus(deps).ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%s", w.Code, http.StatusOK, w.Body.String())
	}
	var got entlicense.Status
	if err := json.NewDecoder(w.Body).Decode(&got); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if got.Status != entlicense.StatusMissing || got.Valid {
		t.Fatalf("license status = %+v, want missing invalid", got)
	}
}

func TestImportLicenseRejectsTamperedSignature(t *testing.T) {
	token, publicKey := signedTestLicense(t, time.Now().UTC().Add(90*24*time.Hour))
	t.Setenv("JJD_LICENSE_PUBLIC_KEY", publicKey)
	tampered := strings.Replace(token, "customer-a", "customer-b", 1)
	repo := &licenseSystemRepo{}
	deps := &Dependencies{SystemRepo: repo}
	req := licenseAdminRequest(http.MethodPost, "/admin/v1/system/license/import", map[string]string{"license": tampered})
	w := httptest.NewRecorder()

	ImportLicense(deps).ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d; body=%s", w.Code, http.StatusBadRequest, w.Body.String())
	}
	if repo.settings[LicenseSettingKey] != "" {
		t.Fatalf("tampered license should not be persisted")
	}
}

func TestImportLicenseStoresSignedTrialLicense(t *testing.T) {
	token, publicKey := signedTestLicense(t, time.Now().UTC().Add(90*24*time.Hour))
	t.Setenv("JJD_LICENSE_PUBLIC_KEY", publicKey)
	repo := &licenseSystemRepo{}
	deps := &Dependencies{SystemRepo: repo}
	req := licenseAdminRequest(http.MethodPost, "/admin/v1/system/license/import", map[string]string{"license": token})
	w := httptest.NewRecorder()

	ImportLicense(deps).ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%s", w.Code, http.StatusOK, w.Body.String())
	}
	if repo.settings[LicenseSettingKey] != token {
		t.Fatalf("persisted license mismatch")
	}
	if repo.settings[LicenseImportedAtSettingKey] == "" {
		t.Fatalf("import timestamp was not persisted")
	}
	var got entlicense.Status
	if err := json.NewDecoder(w.Body).Decode(&got); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if got.Status != entlicense.StatusActive || !got.Valid || got.Payload == nil || got.Payload.LicenseType != "trial" {
		t.Fatalf("license status = %+v, want active trial", got)
	}
}

func TestImportLicenseStoresV2LicenseAndTimeState(t *testing.T) {
	token, publicKeys := signedV2HandlerLicense(t, nil)
	t.Setenv("JJD_LICENSE_PUBLIC_KEYS", publicKeys)
	repo := &licenseSystemRepo{}
	deps := &Dependencies{SystemRepo: repo}
	req := licenseAdminRequest(http.MethodPost, "/admin/v1/system/license/import", map[string]string{"license": token})
	w := httptest.NewRecorder()

	ImportLicense(deps).ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%s", w.Code, http.StatusOK, w.Body.String())
	}
	if repo.settings[LicenseSettingKey] != token {
		t.Fatalf("persisted v2 license mismatch")
	}
	if repo.settings[LicenseTimeStateSettingKey] == "" {
		t.Fatalf("time state was not persisted")
	}
	var got entlicense.Status
	if err := json.NewDecoder(w.Body).Decode(&got); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if got.Version != entlicense.SchemaVersionV2 || got.KeyID != "hxb-prod-lic-2026-01" || !got.Valid {
		t.Fatalf("status = %+v, want valid v2", got)
	}
}

func TestImportLicenseAcceptsDeploymentBoundV2License(t *testing.T) {
	deploymentID := "dep_unit_test"
	fp := deploymentFingerprint(deploymentID)
	token, publicKeys := signedV2HandlerLicense(t, func(payload *entlicense.PayloadV2) {
		payload.DeploymentBinding = entlicense.DeploymentBinding{
			Mode:      "required",
			BindingID: deploymentID,
			Fingerprints: []entlicense.Fingerprint{{
				Scope:     "deployment",
				Algorithm: "sha256",
				Value:     fp,
			}},
		}
	})
	t.Setenv("JJD_LICENSE_PUBLIC_KEYS", publicKeys)
	repo := &licenseSystemRepo{settings: map[string]string{LicenseDeploymentIDKey: deploymentID}}
	deps := &Dependencies{SystemRepo: repo}
	req := licenseAdminRequest(http.MethodPost, "/admin/v1/system/license/import", map[string]string{"license": token})
	w := httptest.NewRecorder()

	ImportLicense(deps).ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%s", w.Code, http.StatusOK, w.Body.String())
	}
	var got entlicense.Status
	if err := json.NewDecoder(w.Body).Decode(&got); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if got.Binding == nil || !got.Binding.Matched {
		t.Fatalf("binding = %+v, want matched", got.Binding)
	}
}

func TestGetLicenseStatusReportsClockRollback(t *testing.T) {
	token, publicKeys := signedV2HandlerLicense(t, nil)
	t.Setenv("JJD_LICENSE_PUBLIC_KEYS", publicKeys)
	repo := &licenseSystemRepo{settings: map[string]string{
		LicenseSettingKey:          token,
		LicenseTimeStateSettingKey: `{"schemaVersion":"license-time-state.v1","licenseId":"lic_v2_handler_unit","lastSeenWallTime":"2026-06-22T00:00:00Z","maxSeenWallTime":"2999-01-01T00:00:00Z","firstSeenAt":"2026-06-22T00:00:00Z"}`,
	}}
	deps := &Dependencies{SystemRepo: repo}
	req := licenseAdminRequest(http.MethodGet, "/admin/v1/system/license", nil)
	w := httptest.NewRecorder()

	GetLicenseStatus(deps).ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%s", w.Code, http.StatusOK, w.Body.String())
	}
	var got entlicense.Status
	if err := json.NewDecoder(w.Body).Decode(&got); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if got.Status != entlicense.StatusClockRollback || got.Valid || got.Clock == nil || !got.Clock.RollbackDetected {
		t.Fatalf("status = %+v, want clock rollback", got)
	}
}

func TestLicenseStatusPersistsRuntimeTimeHighWaterAndDetectsRollback(t *testing.T) {
	token, publicKeys := signedV2HandlerLicense(t, nil)
	t.Setenv("JJD_LICENSE_PUBLIC_KEYS", publicKeys)
	repo := &licenseSystemRepo{settings: map[string]string{
		LicenseSettingKey:          token,
		LicenseTimeStateSettingKey: `{"schemaVersion":"license-time-state.v1","licenseId":"lic_v2_handler_unit","lastSeenWallTime":"2026-06-22T00:00:00Z","maxSeenWallTime":"2026-06-22T00:00:00Z","firstSeenAt":"2026-06-22T00:00:00Z"}`,
	}}
	deps := &Dependencies{SystemRepo: repo}
	req := licenseAdminRequest(http.MethodGet, "/admin/v1/system/license", nil)

	first := licenseStatusFromStored(req, deps, token, "", time.Date(2026, 6, 25, 12, 0, 0, 0, time.UTC))
	if !first.Valid {
		t.Fatalf("first status = %+v, want valid", first)
	}
	var updated entlicense.TimeState
	if err := json.Unmarshal([]byte(repo.settings[LicenseTimeStateSettingKey]), &updated); err != nil {
		t.Fatalf("decode updated time state: %v", err)
	}
	if updated.LastSeenWallTime != "2026-06-25T12:00:00Z" || updated.MaxSeenWallTime != "2026-06-25T12:00:00Z" {
		t.Fatalf("updated time state = %+v, want high water advanced", updated)
	}

	second := licenseStatusFromStored(req, deps, token, "", time.Date(2026, 6, 24, 12, 0, 0, 0, time.UTC))
	if second.Status != entlicense.StatusClockRollback || second.Valid || second.Clock == nil || !second.Clock.RollbackDetected {
		t.Fatalf("second status = %+v, want clock rollback", second)
	}
	var rollback entlicense.TimeState
	if err := json.Unmarshal([]byte(repo.settings[LicenseTimeStateSettingKey]), &rollback); err != nil {
		t.Fatalf("decode rollback time state: %v", err)
	}
	if rollback.ClockRollbackDetectedAt != "2026-06-24T12:00:00Z" {
		t.Fatalf("rollback detected at = %q, want 2026-06-24T12:00:00Z", rollback.ClockRollbackDetectedAt)
	}
	if rollback.MaxSeenWallTime != "2026-06-25T12:00:00Z" {
		t.Fatalf("max seen = %q, want unchanged high water", rollback.MaxSeenWallTime)
	}
}

func TestLoadLicenseRevocationListRequiresValidSignature(t *testing.T) {
	list := signedV2HandlerRevocationList(t, func(payload *entlicense.RevocationPayload) {
		payload.RevokedLicenses = []entlicense.RevokedLicense{{LicenseID: "lic_v2_handler_unit"}}
	})
	data, err := json.Marshal(list)
	if err != nil {
		t.Fatalf("marshal revocation list: %v", err)
	}
	path := t.TempDir() + "/revocations.json"
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write revocation list: %v", err)
	}
	t.Setenv("JJD_LICENSE_PUBLIC_KEYS", "hxb-prod-lic-2026-01=A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg") // pragma: allowlist secret
	t.Setenv("JJD_LICENSE_REVOCATION_FILE", path)

	got, err := loadLicenseRevocationList(time.Date(2026, 6, 22, 0, 0, 0, 0, time.UTC), parseLicensePublicKeys(os.Getenv("JJD_LICENSE_PUBLIC_KEYS")))
	if err != nil {
		t.Fatalf("load revocation list: %v", err)
	}
	if got == nil || len(got.Payload.RevokedLicenses) != 1 {
		t.Fatalf("revocation list = %+v, want verified list", got)
	}

	list.Payload.RevokedLicenses = append(list.Payload.RevokedLicenses, entlicense.RevokedLicense{LicenseID: "lic_extra"})
	tampered, err := json.Marshal(list)
	if err != nil {
		t.Fatalf("marshal tampered list: %v", err)
	}
	if err := os.WriteFile(path, tampered, 0o600); err != nil {
		t.Fatalf("write tampered list: %v", err)
	}
	if got, err := loadLicenseRevocationList(time.Date(2026, 6, 22, 0, 0, 0, 0, time.UTC), parseLicensePublicKeys(os.Getenv("JJD_LICENSE_PUBLIC_KEYS"))); got != nil || err == nil {
		t.Fatalf("tampered revocation list = %+v, want nil", got)
	}
}

func TestImportLicenseMarksV1Legacy(t *testing.T) {
	token, publicKey := signedTestLicense(t, time.Now().UTC().Add(90*24*time.Hour))
	t.Setenv("JJD_LICENSE_PUBLIC_KEY", publicKey)
	repo := &licenseSystemRepo{}
	deps := &Dependencies{SystemRepo: repo}
	req := licenseAdminRequest(http.MethodPost, "/admin/v1/system/license/import", map[string]string{"license": token})
	w := httptest.NewRecorder()

	ImportLicense(deps).ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%s", w.Code, http.StatusOK, w.Body.String())
	}
	var got entlicense.Status
	if err := json.NewDecoder(w.Body).Decode(&got); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if got.Version != entlicense.SchemaVersionV1 {
		t.Fatalf("version = %q, want v1 legacy", got.Version)
	}
}

func TestLicenseStatusFromStored_TrialWhenMissing(t *testing.T) {
	repo := &licenseSystemRepo{}
	deps := &Dependencies{SystemRepo: repo}
	ctx := context.Background()
	// 预置安装锚点为 10 天前
	_ = deps.SystemRepo.Set(ctx, "enterprise_license_install_anchor",
		time.Now().UTC().AddDate(0, 0, -10).Format(time.RFC3339))
	r := httptest.NewRequest("GET", "/admin/v1/system/license", nil)
	st := licenseStatusFromStored(r, deps, "", "", time.Now().UTC())
	if !st.Valid || st.Status != entlicense.StatusTrial {
		t.Fatalf("缺 license 且试用期内应为有效试用, got %s valid=%v", st.Status, st.Valid)
	}
}

func TestLicenseVerificationOptionsUsesExplicitProductAllowlist(t *testing.T) {
	opts := licenseVerificationOptions(nil, nil, time.Date(2026, 7, 18, 12, 0, 0, 0, time.UTC))
	if opts.Product != "" {
		t.Fatalf("legacy Product must be empty in production options, got %q", opts.Product)
	}
	if len(opts.AcceptedProducts) != 2 ||
		opts.AcceptedProducts[0] != entlicense.ProductJJDGuardEnterprise ||
		opts.AcceptedProducts[1] != entlicense.ProductLegacyEnterprise {
		t.Fatalf("AcceptedProducts = %v, want JJDGuard plus exact legacy product", opts.AcceptedProducts)
	}
}

func TestGetLicenseHostInfo(t *testing.T) {
	deps := &Dependencies{SystemRepo: &licenseSystemRepo{}}
	r := httptest.NewRequest("GET", "/admin/v1/system/license/host-info", nil)
	w := httptest.NewRecorder()
	GetLicenseHostInfo(deps)(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("状态码应 200, got %d", w.Code)
	}
	var body map[string]any
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body["product"] != "jjdguard-enterprise" {
		t.Fatalf("product 应为 jjdguard-enterprise, got %v", body["product"])
	}
	if body["deploymentId"] == nil || body["deploymentId"] == "" {
		t.Fatalf("deploymentId 不应为空")
	}
	if body["fingerprint"] == nil || body["fingerprint"] == "" {
		t.Fatalf("fingerprint 不应为空")
	}
}

func (r *licenseSystemRepo) GetByKeys(ctx context.Context, keys []string) ([]*repository.SystemSetting, error) {
	return systemSettingsByKeysVia(ctx, r.Get, keys)
}
