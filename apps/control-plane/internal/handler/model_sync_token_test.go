package handler

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

const modelSyncTokenTestSecret = "model-sync-test-secret-that-must-not-leak"

func TestModelSyncTokenRoundTripIsOpaqueAndRandomized(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	claim := validModelSyncTokenClaim(now)
	claim.TenantID = "tenant-a-sensitive-marker-0123456789"
	claim.ProviderID = "provider-a-sensitive-marker-0123456789"
	claim.CredentialID = "credential-a-sensitive-marker-0123456789"
	claim.CatalogID = "catalog-gpt-5-5-sensitive-marker-0123456789"
	claim.DeploymentName = "deployment-prod-gpt-55-sensitive-marker-0123456789"
	claim.EndpointType = "endpoint-chat-sensitive-marker-0123456789"
	claim.VerificationBatchID = "batch-sensitive-marker-0123456789"

	token1, err := sealModelSyncClaim(modelSyncTokenTestSecret, claim)
	if err != nil {
		t.Fatalf("sealModelSyncClaim() error = %v", err)
	}
	token2, err := sealModelSyncClaim(modelSyncTokenTestSecret, claim)
	if err != nil {
		t.Fatalf("second sealModelSyncClaim() error = %v", err)
	}
	if !strings.HasPrefix(token1, "msv2.") {
		t.Fatalf("token prefix = %q, want msv2.", token1)
	}
	if len(token1) >= modelSyncTokenMaxLength {
		t.Fatalf("normal token length = %d, want below %d", len(token1), modelSyncTokenMaxLength)
	}
	if token1 == token2 {
		t.Fatal("sealing the same claim twice returned the same token; nonce must be random")
	}
	for _, sensitive := range []string{
		claim.TenantID,
		claim.ProviderID,
		claim.CredentialID,
		claim.CatalogID,
		claim.DeploymentName,
		claim.EndpointType,
		claim.VerificationBatchID,
	} {
		for _, fragment := range []string{
			sensitive,
			base64.StdEncoding.EncodeToString([]byte(sensitive)),
			base64.RawStdEncoding.EncodeToString([]byte(sensitive)),
			base64.RawURLEncoding.EncodeToString([]byte(sensitive)),
		} {
			if strings.Contains(token1, fragment) {
				t.Fatalf("token exposes sensitive claim material %q", fragment)
			}
		}
	}
	decodedPayload, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(token1, "msv2."))
	if err != nil {
		t.Fatalf("decode sealed payload: %v", err)
	}
	claimJSON, err := json.Marshal(claim)
	if err != nil {
		t.Fatalf("json.Marshal(): %v", err)
	}
	if strings.Contains(string(decodedPayload), string(claimJSON)) {
		t.Fatal("sealed payload contains the complete plaintext JSON claim")
	}

	got, err := openModelSyncClaim(modelSyncTokenTestSecret, token1, now)
	if err != nil {
		t.Fatalf("openModelSyncClaim() error = %v", err)
	}
	if !reflect.DeepEqual(got, claim) {
		t.Fatalf("opened claim = %#v, want %#v", got, claim)
	}
}

func TestModelSyncTokenRejectsOversizedTokens(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	oversized := "msv2." + strings.Repeat("A", modelSyncTokenMaxLength)
	got, err := openModelSyncClaim(modelSyncTokenTestSecret, oversized, now)
	requireInvalidModelSyncToken(t, got, err)

	// A token at the length gate is allowed to reach authentication checks but is still invalid.
	exactlyAtLimit := "msv2." + strings.Repeat("A", modelSyncTokenMaxLength-len("msv2."))
	if len(exactlyAtLimit) != modelSyncTokenMaxLength {
		t.Fatalf("boundary token length = %d, want %d", len(exactlyAtLimit), modelSyncTokenMaxLength)
	}
	got, err = openModelSyncClaim(modelSyncTokenTestSecret, exactlyAtLimit, now)
	requireInvalidModelSyncToken(t, got, err)
}

func TestModelSyncTokenSealRejectsOversizedClaim(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	claim := validModelSyncTokenClaim(now)
	claim.DeploymentName = strings.Repeat("d", modelSyncTokenMaxLength)

	token, err := sealModelSyncClaim(modelSyncTokenTestSecret, claim)
	if token != "" {
		t.Fatalf("oversized claim returned token of length %d", len(token))
	}
	requireModelSyncTokenSentinel(t, err)
}

func TestModelSyncTokenRoundTripsMaximumBusinessBinding(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	claim := validModelSyncTokenClaim(now)
	claim.DeploymentName = strings.Repeat("d", 255)

	token, err := sealModelSyncClaim(modelSyncTokenTestSecret, claim)
	if err != nil {
		t.Fatalf("seal 255-character deployment name: %v", err)
	}
	if len(token) >= modelSyncTokenMaxLength {
		t.Fatalf("normal business token length = %d, want below %d", len(token), modelSyncTokenMaxLength)
	}
	got, err := openModelSyncClaim(modelSyncTokenTestSecret, token, now)
	if err != nil {
		t.Fatalf("open 255-character deployment name: %v", err)
	}
	if !reflect.DeepEqual(got, claim) {
		t.Fatalf("opened claim = %#v, want %#v", got, claim)
	}
}

func TestModelSyncTokenOpenFailsClosed(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	claim := validModelSyncTokenClaim(now)
	validToken, err := sealModelSyncClaim(modelSyncTokenTestSecret, claim)
	if err != nil {
		t.Fatalf("seal valid claim: %v", err)
	}

	randomPayload := make([]byte, 64)
	if _, err := rand.Read(randomPayload); err != nil {
		t.Fatalf("rand.Read(): %v", err)
	}
	tampered := []byte(validToken)
	tamperAt := len("msv2.") + 4
	if tampered[tamperAt] == 'A' {
		tampered[tamperAt] = 'B'
	} else {
		tampered[tamperAt] = 'A'
	}

	invalidJSONToken := sealRawModelSyncTokenPayload(t, modelSyncTokenTestSecret, []byte("{"))
	unsupportedVersion := claim
	unsupportedVersion.Version = 1
	unsupportedPayload, err := json.Marshal(unsupportedVersion)
	if err != nil {
		t.Fatal(err)
	}
	versionToken := sealRawModelSyncTokenPayload(t, modelSyncTokenTestSecret, unsupportedPayload)
	nonPositiveExpiry := claim
	nonPositiveExpiry.ExpiresAt = 0
	nonPositivePayload, err := json.Marshal(nonPositiveExpiry)
	if err != nil {
		t.Fatal(err)
	}
	nonPositiveExpiryToken := sealRawModelSyncTokenPayload(t, modelSyncTokenTestSecret, nonPositivePayload)
	validPayload, err := json.Marshal(claim)
	if err != nil {
		t.Fatal(err)
	}
	unknownPayload := append([]byte(nil), validPayload[:len(validPayload)-1]...)
	unknownPayload = append(unknownPayload, []byte(`,"unexpected":true}`)...)
	unknownFieldToken := sealRawModelSyncTokenPayload(t, modelSyncTokenTestSecret, unknownPayload)
	legacyV1Token := sealLegacyV1ModelSyncTokenPayload(t, modelSyncTokenTestSecret, []byte(`{"v":1}`))
	expiryClaim := claim
	expiryClaim.ExpiresAt = now.Unix()
	expiryToken, err := sealModelSyncClaim(modelSyncTokenTestSecret, expiryClaim)
	if err != nil {
		t.Fatalf("seal expiring claim: %v", err)
	}

	tests := []struct {
		name   string
		secret string
		token  string
		now    time.Time
	}{
		{name: "tampered", secret: modelSyncTokenTestSecret, token: string(tampered), now: now},
		{name: "wrong secret", secret: "wrong-secret", token: validToken, now: now},
		{name: "empty secret", secret: "", token: validToken, now: now},
		{name: "whitespace secret", secret: "    ", token: validToken, now: now},
		{name: "empty token", secret: modelSyncTokenTestSecret, token: "", now: now},
		{name: "wrong prefix", secret: modelSyncTokenTestSecret, token: "other." + strings.TrimPrefix(validToken, "msv2."), now: now},
		{name: "invalid base64", secret: modelSyncTokenTestSecret, token: "msv2.%%%", now: now},
		{name: "short payload", secret: modelSyncTokenTestSecret, token: "msv2." + base64.RawURLEncoding.EncodeToString([]byte("short")), now: now},
		{name: "random valid base64", secret: modelSyncTokenTestSecret, token: "msv2." + base64.RawURLEncoding.EncodeToString(randomPayload), now: now},
		{name: "damaged json", secret: modelSyncTokenTestSecret, token: invalidJSONToken, now: now},
		{name: "unsupported version", secret: modelSyncTokenTestSecret, token: versionToken, now: now},
		{name: "legacy v1 envelope", secret: modelSyncTokenTestSecret, token: legacyV1Token, now: now},
		{name: "non-positive expiry", secret: modelSyncTokenTestSecret, token: nonPositiveExpiryToken, now: now},
		{name: "unexpected json field", secret: modelSyncTokenTestSecret, token: unknownFieldToken, now: now},
		{name: "equal to expiry", secret: modelSyncTokenTestSecret, token: expiryToken, now: now},
		{name: "after expiry", secret: modelSyncTokenTestSecret, token: expiryToken, now: now.Add(time.Second)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := openModelSyncClaim(tt.secret, tt.token, tt.now)
			requireInvalidModelSyncToken(t, got, err)
		})
	}
}

func TestModelSyncTokenRejectsInvalidSealAndBindingClaims(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	valid := validModelSyncTokenClaim(now)
	invalidSealTests := []struct {
		name   string
		secret string
		mutate func(*modelSyncClaim)
	}{
		{name: "empty secret", secret: ""},
		{name: "whitespace secret", secret: "    "},
		{name: "unsupported version", secret: modelSyncTokenTestSecret, mutate: func(c *modelSyncClaim) { c.Version = 3 }},
		{name: "zero expiry", secret: modelSyncTokenTestSecret, mutate: func(c *modelSyncClaim) { c.ExpiresAt = 0 }},
		{name: "negative expiry", secret: modelSyncTokenTestSecret, mutate: func(c *modelSyncClaim) { c.ExpiresAt = -1 }},
		{name: "empty tenant", secret: modelSyncTokenTestSecret, mutate: func(c *modelSyncClaim) { c.TenantID = "" }},
		{name: "empty provider", secret: modelSyncTokenTestSecret, mutate: func(c *modelSyncClaim) { c.ProviderID = "" }},
		{name: "empty credential", secret: modelSyncTokenTestSecret, mutate: func(c *modelSyncClaim) { c.CredentialID = "" }},
		{name: "empty provider config digest", secret: modelSyncTokenTestSecret, mutate: func(c *modelSyncClaim) { c.ProviderConfigDigest = "" }},
		{name: "uppercase provider config digest", secret: modelSyncTokenTestSecret, mutate: func(c *modelSyncClaim) { c.ProviderConfigDigest = strings.Repeat("A", 64) }},
		{name: "empty active set digest", secret: modelSyncTokenTestSecret, mutate: func(c *modelSyncClaim) { c.ActiveSetDigest = "" }},
		{name: "empty verification batch", secret: modelSyncTokenTestSecret, mutate: func(c *modelSyncClaim) { c.VerificationBatchID = "" }},
		{name: "empty catalog", secret: modelSyncTokenTestSecret, mutate: func(c *modelSyncClaim) { c.CatalogID = "" }},
		{name: "empty deployment", secret: modelSyncTokenTestSecret, mutate: func(c *modelSyncClaim) { c.DeploymentName = "" }},
		{name: "empty endpoint type", secret: modelSyncTokenTestSecret, mutate: func(c *modelSyncClaim) { c.EndpointType = "" }},
	}
	for _, tt := range invalidSealTests {
		t.Run("seal/"+tt.name, func(t *testing.T) {
			claim := valid
			if tt.mutate != nil {
				tt.mutate(&claim)
			}
			token, err := sealModelSyncClaim(tt.secret, claim)
			if token != "" {
				t.Fatalf("invalid seal returned token %q", token)
			}
			requireModelSyncTokenSentinel(t, err)
			if strings.Contains(err.Error(), modelSyncTokenTestSecret) {
				t.Fatalf("seal error leaked secret: %q", err.Error())
			}
		})
	}

	invalidOpenTests := []struct {
		name   string
		mutate func(*modelSyncClaim)
	}{
		{name: "empty tenant", mutate: func(c *modelSyncClaim) { c.TenantID = "" }},
		{name: "blank provider", mutate: func(c *modelSyncClaim) { c.ProviderID = "    " }},
		{name: "empty credential", mutate: func(c *modelSyncClaim) { c.CredentialID = "" }},
		{name: "empty provider config digest", mutate: func(c *modelSyncClaim) { c.ProviderConfigDigest = "" }},
		{name: "empty active set digest", mutate: func(c *modelSyncClaim) { c.ActiveSetDigest = "" }},
		{name: "blank verification batch", mutate: func(c *modelSyncClaim) { c.VerificationBatchID = "   " }},
		{name: "empty catalog", mutate: func(c *modelSyncClaim) { c.CatalogID = "" }},
		{name: "empty deployment", mutate: func(c *modelSyncClaim) { c.DeploymentName = "" }},
		{name: "empty endpoint type", mutate: func(c *modelSyncClaim) { c.EndpointType = "" }},
	}
	for _, tt := range invalidOpenTests {
		t.Run("open/"+tt.name, func(t *testing.T) {
			claim := valid
			tt.mutate(&claim)
			plaintext, err := json.Marshal(claim)
			if err != nil {
				t.Fatalf("json.Marshal(): %v", err)
			}
			token := sealRawModelSyncTokenPayload(t, modelSyncTokenTestSecret, plaintext)
			got, err := openModelSyncClaim(modelSyncTokenTestSecret, token, now)
			requireInvalidModelSyncToken(t, got, err)
		})
	}
}

func validModelSyncTokenClaim(now time.Time) modelSyncClaim {
	return modelSyncClaim{
		Version:              2,
		TenantID:             "tenant-a",
		ProviderID:           "provider-a",
		CredentialID:         "cred-a",
		ProviderConfigDigest: strings.Repeat("a", 64),
		ActiveSetDigest:      strings.Repeat("b", 64),
		VerificationBatchID:  "batch-a",
		CatalogID:            "gpt-5.5",
		DeploymentName:       "prod-gpt-55",
		EndpointType:         "chat",
		ExpiresAt:            now.Add(10 * time.Minute).Unix(),
	}
}

func requireModelSyncTokenSentinel(t *testing.T, err error) {
	t.Helper()
	if !errors.Is(err, errInvalidVerificationToken) {
		t.Fatalf("error = %v, want %v", err, errInvalidVerificationToken)
	}
	if err.Error() != errInvalidVerificationToken.Error() {
		t.Fatalf("error leaked internal detail: %q", err.Error())
	}
}

func requireInvalidModelSyncToken(t *testing.T, got modelSyncClaim, err error) {
	t.Helper()
	if !reflect.DeepEqual(got, modelSyncClaim{}) {
		t.Fatalf("invalid token returned non-zero claim: %#v", got)
	}
	requireModelSyncTokenSentinel(t, err)
}

func sealRawModelSyncTokenPayload(t *testing.T, secret string, plaintext []byte) string {
	t.Helper()
	key := sha256.Sum256([]byte("jjdguard:model-sync-proof:v2" + string([]byte{0}) + secret))
	block, err := aes.NewCipher(key[:])
	if err != nil {
		t.Fatalf("aes.NewCipher(): %v", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("cipher.NewGCM(): %v", err)
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		t.Fatalf("rand.Read(): %v", err)
	}
	ciphertext := aead.Seal(nil, nonce, plaintext, []byte("msv2."))
	payload := append(nonce, ciphertext...)
	return "msv2." + base64.RawURLEncoding.EncodeToString(payload)
}

func sealLegacyV1ModelSyncTokenPayload(t *testing.T, secret string, plaintext []byte) string {
	t.Helper()
	key := sha256.Sum256([]byte("jjdguard:model-sync-proof:v1" + string([]byte{0}) + secret))
	block, err := aes.NewCipher(key[:])
	if err != nil {
		t.Fatalf("aes.NewCipher(): %v", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("cipher.NewGCM(): %v", err)
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		t.Fatalf("rand.Read(): %v", err)
	}
	ciphertext := aead.Seal(nil, nonce, plaintext, []byte("msv1."))
	payload := append(nonce, ciphertext...)
	return "msv1." + base64.RawURLEncoding.EncodeToString(payload)
}
