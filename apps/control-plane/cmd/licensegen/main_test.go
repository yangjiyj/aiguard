package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	entlicense "github.com/yangjiyj/aiguard/apps/control-plane/internal/license"
)

func TestLoadSigningKeyRequiresPrivateKeyInProduction(t *testing.T) {
	var stdout, stderr bytes.Buffer
	err := run([]string{"--out", filepath.Join(t.TempDir(), "license.json")}, map[string]string{}, &stdout, &stderr)

	if err == nil {
		t.Fatalf("run without production private key should fail")
	}
	if !strings.Contains(err.Error(), "private key is required") {
		t.Fatalf("err = %v, want private key required", err)
	}
}

func TestLicensegenDevModeCanGenerateDevKey(t *testing.T) {
	out := filepath.Join(t.TempDir(), "license.json")
	var stdout, stderr bytes.Buffer

	err := run([]string{
		"--mode", "dev",
		"--generate-dev-key",
		"--key-id", "dev-key",
		"--customer-id", "cust_dev",
		"--out", out,
	}, map[string]string{}, &stdout, &stderr)

	if err != nil {
		t.Fatalf("run dev licensegen: %v stderr=%s", err, stderr.String())
	}
	if !strings.Contains(stdout.String(), "key_id=dev-key") {
		t.Fatalf("stdout = %q, want key_id summary", stdout.String())
	}
	var file entlicense.FileV2
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read license: %v", err)
	}
	if err := json.Unmarshal(data, &file); err != nil {
		t.Fatalf("decode license: %v", err)
	}
	if file.SchemaVersion != entlicense.SchemaVersionV2 || file.KeyID != "dev-key" {
		t.Fatalf("file = %+v, want v2 dev license", file)
	}
	if len(file.Payload.Subject.Products) != 1 || file.Payload.Subject.Products[0] != "jjdguard-enterprise" {
		t.Fatalf("products = %v, want JJDGuard-only default", file.Payload.Subject.Products)
	}
	if file.Payload.Subject.DisplayName != "JJDGuard Enterprise License" {
		t.Fatalf("display name = %q, want JJDGuard Enterprise License", file.Payload.Subject.DisplayName)
	}
}

func TestLicensegenSignsV2Envelope(t *testing.T) {
	seed := bytes.Repeat([]byte{7}, ed25519.SeedSize)
	privateKey := ed25519.NewKeyFromSeed(seed)
	publicKey := privateKey.Public().(ed25519.PublicKey)
	out := filepath.Join(t.TempDir(), "license.json")
	var stdout, stderr bytes.Buffer

	err := run([]string{
		"--key-id", "prod-key-1",
		"--customer", "政企客户",
		"--customer-id", "cust_prod",
		"--deployment-mode", "required",
		"--deployment-id", "dep_prod",
		"--deployment-fingerprint", "deployment:sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"--out", out,
	}, map[string]string{
		"JJD_LICENSE_SIGNING_PRIVATE_KEY": base64.StdEncoding.EncodeToString(privateKey),
	}, &stdout, &stderr)

	if err != nil {
		t.Fatalf("run prod licensegen: %v stderr=%s", err, stderr.String())
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read license: %v", err)
	}
	var file entlicense.FileV2
	if err := json.Unmarshal(data, &file); err != nil {
		t.Fatalf("decode license: %v", err)
	}
	_, status, err := entlicense.VerifyAny(string(data), entlicense.VerificationOptions{
		PublicKeysV2:     map[string]string{"prod-key-1": base64.RawURLEncoding.EncodeToString(publicKey)},
		AcceptedProducts: []string{entlicense.ProductJJDGuardEnterprise},
		TrustedIssuers: map[string]struct{}{
			"huoxianbao-license-authority-prod": {},
		},
		DeploymentFingerprints: []entlicense.Fingerprint{{
			Scope:     "deployment",
			Algorithm: "sha256",
			Value:     "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		}},
	})
	if err != nil {
		t.Fatalf("verify generated license: %v", err)
	}
	if status == nil || !status.Valid || status.Version != entlicense.SchemaVersionV2 {
		t.Fatalf("status = %+v, want valid v2", status)
	}
	if file.Payload.Customer.ID != "cust_prod" || len(file.Payload.Subject.Products) != 1 || file.Payload.Subject.Products[0] != "jjdguard-enterprise" {
		t.Fatalf("payload = %+v, want customer id and JJDGuard-only product", file.Payload)
	}
}
