package license

import (
	"crypto/ed25519"
	"encoding/base64"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestSignVerifyTrialLicense(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	now := time.Now().UTC()
	file, err := Sign(Payload{
		LicenseID:   "lic_trial_unit",
		Customer:    "customer-a",
		LicenseType: "trial",
		Edition:     "enterprise",
		IssuedAt:    now,
		NotBefore:   now.Add(-time.Minute),
		ExpiresAt:   now.Add(90 * 24 * time.Hour),
		MaxUsers:    25,
		Features:    []string{"ide_proxy", "web_ai", "web_ai"},
	}, priv)
	if err != nil {
		t.Fatalf("sign license: %v", err)
	}

	raw, err := marshalFile(file)
	if err != nil {
		t.Fatalf("marshal license: %v", err)
	}
	_, status, err := Verify(raw, encodePublicKey(pub), now)
	if err != nil {
		t.Fatalf("verify license: %v", err)
	}
	if !status.Valid || status.Status != StatusActive || status.Payload.LicenseType != "trial" {
		t.Fatalf("status = %+v, want active trial", status)
	}
	if len(status.Payload.Features) != 2 || status.Payload.Features[0] != "ide_proxy" || status.Payload.Features[1] != "web_ai" {
		t.Fatalf("features not normalized: %+v", status.Payload.Features)
	}
}

func TestVerifyExpiredLicense(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	now := time.Now().UTC()
	file, err := Sign(Payload{
		LicenseID:   "lic_expired_unit",
		Customer:    "customer-a",
		LicenseType: "trial",
		Edition:     "enterprise",
		IssuedAt:    now.Add(-100 * 24 * time.Hour),
		NotBefore:   now.Add(-100 * 24 * time.Hour),
		ExpiresAt:   now.Add(-time.Hour),
		MaxUsers:    25,
		Features:    []string{"web_ai"},
	}, priv)
	if err != nil {
		t.Fatalf("sign license: %v", err)
	}
	raw, err := marshalFile(file)
	if err != nil {
		t.Fatalf("marshal license: %v", err)
	}

	_, status, err := Verify(raw, encodePublicKey(pub), now)
	if err != ErrExpired {
		t.Fatalf("err = %v, want ErrExpired", err)
	}
	if status == nil || status.Valid || status.Status != StatusExpired {
		t.Fatalf("status = %+v, want expired invalid", status)
	}
}

func TestV2CanonicalMatchesUnifiedVector(t *testing.T) {
	payload := unifiedV2VectorPayload()
	canonical, err := CanonicalPayloadV2(payload)
	if err != nil {
		t.Fatalf("canonical payload: %v", err)
	}
	want := `{"customer":{"displayName":"Example Government Customer","id":"cust_example_gov"},"deploymentBinding":{"bindingId":"dep_x7f9","fingerprints":[{"algorithm":"sha256","scope":"machine","value":"1c4f2b0a9f2c8a1e3d5b6c7d8e9f00112233445566778899aabbccddeeff0011"}],"mode":"required"},"edition":"enterprise","expiresAt":"2027-12-31T23:59:59Z","features":["agent_audit","content_retention","ide_proxy","sensitive_data_guard","web_ai"],"gracePolicy":{"clockRollbackGraceHours":24,"expiryGraceDays":7,"offlineRevocationStaleDays":30},"issuedAt":"2026-06-21T00:00:00Z","issuer":"huoxianbao-license-authority-prod","licenseId":"lic_v2_test_vector_001","maxUsers":500,"notBefore":"2026-06-21T00:00:00Z","revocationInfo":{"listId":"rl_prod_cn_001","mode":"offline-file","url":"offline-package://revocations/newapi-lse.json"},"schemaVersion":"license.v2","subject":{"displayName":"政企安全网关联合授权","products":["llm-safety-eval-platform","newapi-enterprise"]}}` // pragma: allowlist secret
	if string(canonical) != want {
		t.Fatalf("canonical mismatch\n got: %s\nwant: %s", canonical, want)
	}
}

func TestVerifyV2UnifiedVector(t *testing.T) {
	file := FileV2{
		SchemaVersion:      SchemaVersionV2,
		Payload:            unifiedV2VectorPayload(),
		SignatureAlgorithm: SignatureAlgorithmV2,
		KeyID:              "hxb-prod-lic-2026-01",
		Signature:          "9Fptnm0N2rvUfNRzutMR7xbediQqFyljtpYhaf-yWOQDlm6n7KOWaNypGZIXmXvNOAgMkHcjJswwrgsuplfkBA", // pragma: allowlist secret
	}
	raw, err := MarshalFileV2(file)
	if err != nil {
		t.Fatalf("marshal v2 file: %v", err)
	}

	_, status, err := VerifyAny(raw, VerificationOptions{
		PublicKeysV2:     map[string]string{"hxb-prod-lic-2026-01": "A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg"},
		AcceptedProducts: []string{ProductJJDGuardEnterprise, ProductLegacyEnterprise},
		TrustedIssuers: map[string]struct{}{
			"huoxianbao-license-authority-prod": {},
		},
		DeploymentFingerprints: []Fingerprint{{
			Scope:     "machine",
			Algorithm: "sha256",
			Value:     "1c4f2b0a9f2c8a1e3d5b6c7d8e9f00112233445566778899aabbccddeeff0011", // pragma: allowlist secret
		}},
		Now: time.Date(2026, 6, 22, 0, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatalf("verify v2 vector: %v", err)
	}
	if status == nil || !status.Valid || status.Version != SchemaVersionV2 || status.KeyID != "hxb-prod-lic-2026-01" {
		t.Fatalf("status = %+v, want valid v2", status)
	}
}

func TestVerifyV2RejectsTamperedPayload(t *testing.T) {
	file := FileV2{
		SchemaVersion:      SchemaVersionV2,
		Payload:            unifiedV2VectorPayload(),
		SignatureAlgorithm: SignatureAlgorithmV2,
		KeyID:              "hxb-prod-lic-2026-01",
		Signature:          "9Fptnm0N2rvUfNRzutMR7xbediQqFyljtpYhaf-yWOQDlm6n7KOWaNypGZIXmXvNOAgMkHcjJswwrgsuplfkBA", // pragma: allowlist secret
	}
	raw, err := MarshalFileV2(file)
	if err != nil {
		t.Fatalf("marshal v2 file: %v", err)
	}
	tampered := strings.Replace(raw, `"maxUsers":500`, `"maxUsers":501`, 1)

	_, _, err = VerifyAny(tampered, VerificationOptions{
		PublicKeysV2:     map[string]string{"hxb-prod-lic-2026-01": "A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg"},
		AcceptedProducts: []string{ProductJJDGuardEnterprise, ProductLegacyEnterprise},
		TrustedIssuers: map[string]struct{}{
			"huoxianbao-license-authority-prod": {},
		},
		DeploymentFingerprints: []Fingerprint{{
			Scope:     "machine",
			Algorithm: "sha256",
			Value:     "1c4f2b0a9f2c8a1e3d5b6c7d8e9f00112233445566778899aabbccddeeff0011", // pragma: allowlist secret
		}},
		Now: time.Date(2026, 6, 22, 0, 0, 0, 0, time.UTC),
	})
	if err != ErrInvalidSignature {
		t.Fatalf("err = %v, want ErrInvalidSignature", err)
	}
}

func TestVerifyV2RejectsWrongProduct(t *testing.T) {
	raw := signedV2TestLicense(t, func(payload *PayloadV2) {
		payload.DeploymentBinding.Mode = "none"
		payload.DeploymentBinding.BindingID = ""
		payload.DeploymentBinding.Fingerprints = nil
	})

	_, status, err := VerifyAny(raw, baseV2VerificationOptions(time.Date(2026, 6, 22, 0, 0, 0, 0, time.UTC), func(opts *VerificationOptions) {
		opts.AcceptedProducts = []string{"unknown-product"}
		opts.Product = ProductLegacyEnterprise
		opts.DeploymentFingerprints = nil
	}))

	if err != ErrProductMismatch {
		t.Fatalf("err = %v, want ErrProductMismatch", err)
	}
	if status == nil || status.Valid || status.Status != StatusInvalid || status.Reason != ErrProductMismatch.Error() {
		t.Fatalf("status = %+v, want product mismatch invalid", status)
	}
}

func TestVerifyV2AcceptedProductsSemantics(t *testing.T) {
	now := time.Date(2026, 6, 22, 0, 0, 0, 0, time.UTC)
	raw := signedV2TestLicense(t, func(payload *PayloadV2) {
		payload.Subject.Products = []string{"jjdguard-enterprise"}
		payload.DeploymentBinding = DeploymentBinding{Mode: "none"}
	})
	tests := []struct {
		name string
		opts VerificationOptions
		want error
	}{
		{
			name: "accepted products takes exclusive precedence",
			opts: baseV2VerificationOptions(now, func(opts *VerificationOptions) {
				opts.AcceptedProducts = []string{"jjdguard-enterprise"}
				opts.Product = "newapi-enterprise"
				opts.DeploymentFingerprints = nil
			}),
		},
		{
			name: "legacy product field is a singleton fallback",
			opts: baseV2VerificationOptions(now, func(opts *VerificationOptions) {
				opts.AcceptedProducts = nil
				opts.Product = "jjdguard-enterprise"
				opts.DeploymentFingerprints = nil
			}),
		},
		{
			name: "empty product policy skips product check",
			opts: baseV2VerificationOptions(now, func(opts *VerificationOptions) {
				opts.AcceptedProducts = nil
				opts.Product = ""
				opts.DeploymentFingerprints = nil
			}),
		},
		{
			name: "third product is rejected even when legacy field matches",
			opts: baseV2VerificationOptions(now, func(opts *VerificationOptions) {
				opts.AcceptedProducts = []string{"third-product"}
				opts.Product = "jjdguard-enterprise"
				opts.DeploymentFingerprints = nil
			}),
			want: ErrProductMismatch,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := VerifyAny(raw, tt.opts)
			if err != tt.want {
				t.Fatalf("err = %v, want %v", err, tt.want)
			}
		})
	}
}

func TestVerifyV2ChecksProductOnlyAfterSignature(t *testing.T) {
	raw := signedV2TestLicense(t, func(payload *PayloadV2) {
		payload.Subject.Products = []string{"jjdguard-enterprise"}
		payload.DeploymentBinding = DeploymentBinding{Mode: "none"}
	})
	tampered := strings.Replace(raw, "jjdguard-enterprise", "third-product", 1)
	opts := baseV2VerificationOptions(time.Date(2026, 6, 22, 0, 0, 0, 0, time.UTC), func(opts *VerificationOptions) {
		opts.AcceptedProducts = []string{"jjdguard-enterprise", "newapi-enterprise"}
		opts.Product = ""
		opts.DeploymentFingerprints = nil
	})
	_, _, err := VerifyAny(tampered, opts)
	if err != ErrInvalidSignature {
		t.Fatalf("err = %v, want ErrInvalidSignature before product policy", err)
	}
}

func TestVerifyV2RejectsDeploymentMismatch(t *testing.T) {
	raw := signedV2TestLicense(t, nil)

	_, status, err := VerifyAny(raw, baseV2VerificationOptions(time.Date(2026, 6, 22, 0, 0, 0, 0, time.UTC), func(opts *VerificationOptions) {
		opts.DeploymentFingerprints = []Fingerprint{{
			Scope:     "machine",
			Algorithm: "sha256",
			Value:     "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
		}}
	}))

	if err != ErrDeploymentBindingMismatch {
		t.Fatalf("err = %v, want ErrDeploymentBindingMismatch", err)
	}
	if status == nil || status.Valid || status.Reason != ErrDeploymentBindingMismatch.Error() {
		t.Fatalf("status = %+v, want deployment mismatch invalid", status)
	}
}

func TestVerifyV2DetectsClockRollback(t *testing.T) {
	raw := signedV2TestLicense(t, nil)

	_, status, err := VerifyAny(raw, baseV2VerificationOptions(time.Date(2026, 6, 22, 0, 0, 0, 0, time.UTC), func(opts *VerificationOptions) {
		opts.TimeState = &TimeState{
			SchemaVersion:    TimeStateSchemaVersion,
			LicenseID:        "lic_v2_test_vector_001",
			LastSeenWallTime: "2026-06-22T00:00:00Z",
			MaxSeenWallTime:  "2026-06-24T02:00:00Z",
			FirstSeenAt:      "2026-06-22T00:00:00Z",
		}
	}))

	if err != ErrClockRollback {
		t.Fatalf("err = %v, want ErrClockRollback", err)
	}
	if status == nil || status.Valid || status.Clock == nil || !status.Clock.RollbackDetected {
		t.Fatalf("status = %+v, want clock rollback status", status)
	}
}

func TestVerifyV2RejectsRevokedLicense(t *testing.T) {
	raw := signedV2TestLicense(t, nil)
	list := signedRevocationList(t, func(payload *RevocationPayload) {
		payload.RevokedLicenses = []RevokedLicense{{LicenseID: "lic_v2_test_vector_001"}}
	})

	_, status, err := VerifyAny(raw, baseV2VerificationOptions(time.Date(2026, 6, 22, 0, 0, 0, 0, time.UTC), func(opts *VerificationOptions) {
		opts.RevocationList = list
	}))

	if err != ErrLicenseRevoked {
		t.Fatalf("err = %v, want ErrLicenseRevoked", err)
	}
	if status == nil || status.Valid || status.Revocation == nil || !status.Revocation.Revoked {
		t.Fatalf("status = %+v, want revoked status", status)
	}
}

func TestVerifyV2IgnoresUnsignedRevocationList(t *testing.T) {
	raw := signedV2TestLicense(t, nil)

	_, status, err := VerifyAny(raw, baseV2VerificationOptions(time.Date(2026, 6, 22, 0, 0, 0, 0, time.UTC), func(opts *VerificationOptions) {
		opts.RevocationList = &RevocationList{
			Payload: RevocationPayload{
				SchemaVersion:   "license-revocation-list.v1",
				ListID:          "rl_test",
				Issuer:          "huoxianbao-license-authority-prod",
				IssuedAt:        "2026-06-21T00:00:00Z",
				ValidUntil:      "2026-06-30T00:00:00Z",
				RevokedLicenses: []RevokedLicense{{LicenseID: "lic_v2_test_vector_001"}},
			},
		}
	}))

	if err != nil {
		t.Fatalf("verify with unsigned revocation list: %v", err)
	}
	if status == nil || !status.Valid || status.Revocation == nil || !status.Revocation.Checked || status.Revocation.Revoked {
		t.Fatalf("status = %+v, want unsigned revocation list ignored", status)
	}
}

func TestVerifyRevocationListRejectsTamperedPayload(t *testing.T) {
	list := signedRevocationList(t, func(payload *RevocationPayload) {
		payload.RevokedLicenses = []RevokedLicense{{LicenseID: "lic_other"}}
	})
	list.Payload.RevokedLicenses = []RevokedLicense{{LicenseID: "lic_v2_test_vector_001"}}

	err := VerifyRevocationList(*list, map[string]string{"hxb-prod-lic-2026-01": "A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg"}, map[string]struct{}{
		"huoxianbao-license-authority-prod": {},
	}, time.Date(2026, 6, 22, 0, 0, 0, 0, time.UTC))

	if err != ErrInvalidSignature {
		t.Fatalf("err = %v, want ErrInvalidSignature", err)
	}
}

func TestVerifyV2AllowsExpiryGrace(t *testing.T) {
	raw := signedV2TestLicense(t, func(payload *PayloadV2) {
		payload.ExpiresAt = "2026-06-21T00:00:00Z"
		payload.GracePolicy.ExpiryGraceDays = 7
	})

	_, status, err := VerifyAny(raw, baseV2VerificationOptions(time.Date(2026, 6, 22, 0, 0, 0, 0, time.UTC), nil))

	if err != nil {
		t.Fatalf("verify in expiry grace: %v", err)
	}
	if status == nil || !status.Valid || status.Status != StatusGrace || status.Grace == nil || status.Grace.Reason != "expired" {
		t.Fatalf("status = %+v, want valid expiry grace", status)
	}
}

func TestVerifyStillAcceptsV1License(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	now := time.Now().UTC()
	file, err := Sign(Payload{
		LicenseID:   "lic_v1_compat",
		Customer:    "customer-a",
		LicenseType: "trial",
		Edition:     "enterprise",
		IssuedAt:    now.Add(-time.Hour),
		NotBefore:   now.Add(-time.Minute),
		ExpiresAt:   now.Add(time.Hour),
		MaxUsers:    25,
		Features:    []string{"web_ai"},
	}, priv)
	if err != nil {
		t.Fatalf("sign v1 license: %v", err)
	}
	raw, err := marshalFile(file)
	if err != nil {
		t.Fatalf("marshal v1 license: %v", err)
	}

	_, status, err := VerifyAny(raw, VerificationOptions{
		PublicKeyV1: encodePublicKey(pub),
		Now:         now,
	})
	if err != nil {
		t.Fatalf("verify v1 through VerifyAny: %v", err)
	}
	if status == nil || !status.Valid || status.Version != "license.v1" || status.Payload == nil || status.Payload.LicenseID != "lic_v1_compat" {
		t.Fatalf("status = %+v, want valid v1 compat", status)
	}
}

func unifiedV2VectorPayload() PayloadV2 {
	return PayloadV2{
		SchemaVersion: SchemaVersionV2,
		LicenseID:     "lic_v2_test_vector_001",
		Customer: CustomerV2{
			ID:          "cust_example_gov",
			DisplayName: "Example Government Customer",
		},
		Subject: SubjectV2{
			DisplayName: "政企安全网关联合授权",
			Products:    []string{"llm-safety-eval-platform", "newapi-enterprise"},
		},
		Edition:   "enterprise",
		IssuedAt:  "2026-06-21T00:00:00Z",
		NotBefore: "2026-06-21T00:00:00Z",
		ExpiresAt: "2027-12-31T23:59:59Z",
		MaxUsers:  500,
		Features:  []string{"agent_audit", "content_retention", "ide_proxy", "sensitive_data_guard", "web_ai"},
		DeploymentBinding: DeploymentBinding{
			Mode:      "required",
			BindingID: "dep_x7f9",
			Fingerprints: []Fingerprint{{
				Scope:     "machine",
				Algorithm: "sha256",
				Value:     "1c4f2b0a9f2c8a1e3d5b6c7d8e9f00112233445566778899aabbccddeeff0011", // pragma: allowlist secret
			}},
		},
		GracePolicy: GracePolicy{
			ExpiryGraceDays:            7,
			ClockRollbackGraceHours:    24,
			OfflineRevocationStaleDays: 30,
		},
		RevocationInfo: RevocationInfo{
			Mode:   "offline-file",
			ListID: "rl_prod_cn_001",
			URL:    "offline-package://revocations/newapi-lse.json",
		},
		Issuer: "huoxianbao-license-authority-prod",
	}
}

func signedV2TestLicense(t *testing.T, mutate func(*PayloadV2)) string {
	t.Helper()
	payload := unifiedV2VectorPayload()
	if mutate != nil {
		mutate(&payload)
	}
	file, err := SignV2(payload, "hxb-prod-lic-2026-01", testV2PrivateKey(t))
	if err != nil {
		t.Fatalf("sign v2 license: %v", err)
	}
	raw, err := MarshalFileV2(*file)
	if err != nil {
		t.Fatalf("marshal v2 license: %v", err)
	}
	return raw
}

func signedRevocationList(t *testing.T, mutate func(*RevocationPayload)) *RevocationList {
	t.Helper()
	payload := RevocationPayload{
		SchemaVersion: "license-revocation-list.v1",
		ListID:        "rl_test",
		Issuer:        "huoxianbao-license-authority-prod",
		IssuedAt:      "2026-06-21T00:00:00Z",
		ValidUntil:    "2026-06-30T00:00:00Z",
	}
	if mutate != nil {
		mutate(&payload)
	}
	list, err := SignRevocationList(payload, "hxb-prod-lic-2026-01", testV2PrivateKey(t))
	if err != nil {
		t.Fatalf("sign revocation list: %v", err)
	}
	return list
}

func baseV2VerificationOptions(now time.Time, mutate func(*VerificationOptions)) VerificationOptions {
	opts := VerificationOptions{
		PublicKeysV2:     map[string]string{"hxb-prod-lic-2026-01": "A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg"},
		AcceptedProducts: []string{ProductJJDGuardEnterprise, ProductLegacyEnterprise},
		Product:          "",
		TrustedIssuers: map[string]struct{}{
			"huoxianbao-license-authority-prod": {},
		},
		DeploymentFingerprints: []Fingerprint{{
			Scope:     "machine",
			Algorithm: "sha256",
			Value:     "1c4f2b0a9f2c8a1e3d5b6c7d8e9f00112233445566778899aabbccddeeff0011", // pragma: allowlist secret
		}},
		Now: now,
	}
	if mutate != nil {
		mutate(&opts)
	}
	return opts
}

func testV2PrivateKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	// 固定 seed 只用于仓库测试向量，禁止用于任何正式许可证签发。
	seed, err := base64.RawURLEncoding.DecodeString("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8")
	if err != nil {
		t.Fatalf("decode test seed: %v", err)
	}
	return ed25519.NewKeyFromSeed(seed)
}

func TestTrialStatusFromAnchor(t *testing.T) {
	anchor := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	// 窗口内 → 试用有效
	s := TrialStatusFromAnchor(anchor, true, anchor.AddDate(0, 0, 10))
	if !s.Valid || s.Status != StatusTrial {
		t.Fatalf("窗口内应为有效试用, got status=%s valid=%v", s.Status, s.Valid)
	}
	if s.DaysLeft != 80 {
		t.Fatalf("应剩 80 天, got %d", s.DaysLeft)
	}
	// 窗口外 → 过期
	s2 := TrialStatusFromAnchor(anchor, true, anchor.AddDate(0, 0, 95))
	if s2.Valid || s2.Status != StatusExpired {
		t.Fatalf("窗口外应过期, got status=%s valid=%v", s2.Status, s2.Valid)
	}
	// 无锚点 → 回退 missing
	s3 := TrialStatusFromAnchor(time.Time{}, true, anchor)
	if s3.Status != StatusMissing {
		t.Fatalf("无锚点应为 missing, got %s", s3.Status)
	}
}

func TestNativeTrialFeatureCatalog(t *testing.T) {
	anchor := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	want := []string{"agent_audit", "content_retention", "ide_proxy", "sensitive_data_guard", "web_ai"}
	for _, publicKeySet := range []bool{false, true} {
		for _, now := range []time.Time{anchor.AddDate(0, 0, 10), anchor.AddDate(0, 0, TrialWindowDays)} {
			status := TrialStatusFromAnchor(anchor, publicKeySet, now)
			if !status.Valid || status.Status != StatusTrial || status.PublicKeySet != publicKeySet {
				t.Fatalf("native trial status = %+v", status)
			}
			if !slices.Equal(status.Features, want) {
				t.Fatalf("native trial features = %v, want %v", status.Features, want)
			}
		}
	}
	for _, tc := range []struct {
		name   string
		anchor time.Time
		now    time.Time
		state  string
	}{
		{name: "missing", now: anchor, state: StatusMissing},
		{name: "expired", anchor: anchor, now: anchor.AddDate(0, 0, TrialWindowDays).Add(time.Nanosecond), state: StatusExpired},
	} {
		t.Run(tc.name, func(t *testing.T) {
			status := TrialStatusFromAnchor(tc.anchor, false, tc.now)
			if status.Valid || status.Status != tc.state || len(status.Features) != 0 {
				t.Fatalf("inactive trial status = %+v", status)
			}
		})
	}
}

func TestNativeTrialFeatureSlicesAreIndependent(t *testing.T) {
	anchor := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	first := TrialStatusFromAnchor(anchor, false, anchor)
	second := TrialStatusFromAnchor(anchor, false, anchor)
	if len(first.Features) == 0 || len(second.Features) == 0 {
		t.Fatal("active native trial must project its feature catalog")
	}
	want := slices.Clone(second.Features)
	first.Features[0] = "caller-mutated-feature"
	third := TrialStatusFromAnchor(anchor, false, anchor)
	if !slices.Equal(second.Features, want) || !slices.Equal(third.Features, want) {
		t.Fatalf("native trial calls share mutable features: second=%v third=%v", second.Features, third.Features)
	}
}
