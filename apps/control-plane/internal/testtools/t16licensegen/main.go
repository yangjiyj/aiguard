//go:build t16e2e

// Command t16licensegen is a throwaway Ed25519 signer used only by the
// isolated T16 real-E2E fixture (deploy/tests/t16_real_e2e/run.sh). It signs
// a v2 license payload entirely in-process for a single ephemeral Compose
// project and prints the license, its public key, and the public key's
// SHA-256 digest; the private key never touches disk and is never printed.
//
// Issuer is intentionally left at the product's fixed protocol value
// ("huoxianbao-license-authority-prod"): Issuer is a declared field of the
// license payload itself, not a trust anchor. Trust comes only from
// VerificationOptions.PublicKeysV2 (see internal/license.validatePayloadV2
// and VerifyAny), which control-plane populates from JJD_LICENSE_PUBLIC_KEYS.
// The isolated E2E stack injects only this run's one-off generated public
// key under this run's KeyID, so no production deployment can ever verify a
// license signed by this tool: nothing here impersonates the production
// signer's key material, and this artifact is never treated as a production
// deliverable. KeyID carries an explicit, unambiguous test marker
// ("t16-e2e-test-signer-<timestamp>", no "prod"/"authority" substrings) so
// the fixture is self-evidently a test artifact even though Issuer reads
// like production. This mirrors the frozen T03 precedent recorded at
// pskc:/home/dev/agent-platform-orchestration/run-20260924-115441/results/T03-dev/revocation-list-resume-event133/runtime-adoption-plan-event136/adoption-plan-event136.md
// ("Its issuer claim is huoxianbao-license-authority-prod, but the artifact
// is signed by an independent test key. This is test-stack-only and conveys
// no production issuer authority or production trust.").
//
// It is excluded from the production build via the t16e2e build tag, so
// `go build ./...` / `go list ./...` in apps/control-plane never produce or
// list it.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"time"

	entlicense "github.com/yangjiyj/aiguard/apps/control-plane/internal/license"
)

func main() {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		fail(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	keyID := "t16-e2e-test-signer-" + now.Format("20060102T150405")
	payload := entlicense.PayloadV2{
		SchemaVersion:     entlicense.SchemaVersionV2,
		LicenseID:         "lic_t16-e2e-" + now.Format("20060102T150405"),
		Customer:          entlicense.CustomerV2{ID: "cust_t16-e2e-" + now.Format("20060102T150405"), DisplayName: "Isolated T16 E2E Fixture"},
		Subject:           entlicense.SubjectV2{DisplayName: "Isolated T16 E2E Fixture", Products: []string{entlicense.ProductJJDGuardEnterprise}},
		Edition:           "enterprise",
		IssuedAt:          now.Format(time.RFC3339),
		NotBefore:         now.Add(-time.Minute).Format(time.RFC3339),
		ExpiresAt:         now.Add(24 * time.Hour).Format(time.RFC3339),
		MaxUsers:          25,
		Features:          []string{"web_ai", "agent_audit", "agent_security", "ide_proxy", "content_retention", "sensitive_data_guard"},
		DeploymentBinding: entlicense.DeploymentBinding{Mode: "none"},
		GracePolicy:       entlicense.GracePolicy{ExpiryGraceDays: 1, ClockRollbackGraceHours: 1, OfflineRevocationStaleDays: 1},
		RevocationInfo:    entlicense.RevocationInfo{Mode: "none"},
		Issuer:            "huoxianbao-license-authority-prod",
	}
	file, err := entlicense.SignV2(payload, keyID, priv)
	if err != nil {
		fail(err)
	}
	raw, err := entlicense.MarshalFileV2(*file)
	if err != nil {
		fail(err)
	}
	pubKeySHA256 := sha256.Sum256(pub)
	err = json.NewEncoder(os.Stdout).Encode(map[string]string{
		"license":           raw,
		"public_keys":       keyID + "=" + base64.RawURLEncoding.EncodeToString(pub),
		"key_id":            keyID,
		"issuer_claim":      payload.Issuer,
		"public_key_sha256": hex.EncodeToString(pubKeySHA256[:]),
	})
	if err != nil {
		fail(err)
	}
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
