package handler

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"time"
)

const (
	modelSyncTokenPrefix    = "msv2."
	modelSyncTokenKeyDomain = "jjdguard:model-sync-proof:v2"
	modelSyncTokenMaxLength = 4096
)

var errInvalidVerificationToken = errors.New("invalid_verification_token")

type modelSyncClaim struct {
	Version              int      `json:"v"`
	TenantID             string   `json:"tenant_id"`
	ProviderID           string   `json:"provider_id"`
	CredentialID         string   `json:"credential_id"`
	ProviderConfigDigest string   `json:"provider_config_digest"`
	ActiveSetDigest      string   `json:"active_set_digest"`
	VerificationBatchID  string   `json:"verification_batch_id"`
	CatalogID            string   `json:"catalog_id"`
	DeploymentName       string   `json:"deployment_name"`
	EndpointType         string   `json:"endpoint_type"`
	Protocols            []string `json:"protocols,omitempty"`
	ExpiresAt            int64    `json:"expires_at"`
}

func sealModelSyncClaim(secret string, claim modelSyncClaim) (string, error) {
	if strings.TrimSpace(secret) == "" || !validModelSyncClaim(claim) {
		return "", errInvalidVerificationToken
	}

	plaintext, err := json.Marshal(claim)
	if err != nil {
		return "", errInvalidVerificationToken
	}
	aead, err := newModelSyncTokenAEAD(secret)
	if err != nil {
		return "", errInvalidVerificationToken
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", errInvalidVerificationToken
	}
	ciphertext := aead.Seal(nil, nonce, plaintext, []byte(modelSyncTokenPrefix))
	payload := make([]byte, 0, len(nonce)+len(ciphertext))
	payload = append(payload, nonce...)
	payload = append(payload, ciphertext...)
	token := modelSyncTokenPrefix + base64.RawURLEncoding.EncodeToString(payload)
	if len(token) > modelSyncTokenMaxLength {
		return "", errInvalidVerificationToken
	}
	return token, nil
}

func openModelSyncClaim(secret, token string, now time.Time) (modelSyncClaim, error) {
	if strings.TrimSpace(secret) == "" || !strings.HasPrefix(token, modelSyncTokenPrefix) {
		return modelSyncClaim{}, errInvalidVerificationToken
	}
	if len(token) > modelSyncTokenMaxLength {
		return modelSyncClaim{}, errInvalidVerificationToken
	}

	encoded := strings.TrimPrefix(token, modelSyncTokenPrefix)
	if encoded == "" || strings.ContainsAny(encoded, " \t\r\n") {
		return modelSyncClaim{}, errInvalidVerificationToken
	}
	payload, err := base64.RawURLEncoding.Strict().DecodeString(encoded)
	if err != nil {
		return modelSyncClaim{}, errInvalidVerificationToken
	}
	aead, err := newModelSyncTokenAEAD(secret)
	if err != nil || len(payload) < aead.NonceSize()+aead.Overhead() {
		return modelSyncClaim{}, errInvalidVerificationToken
	}

	nonce := payload[:aead.NonceSize()]
	ciphertext := payload[aead.NonceSize():]
	plaintext, err := aead.Open(nil, nonce, ciphertext, []byte(modelSyncTokenPrefix))
	if err != nil {
		return modelSyncClaim{}, errInvalidVerificationToken
	}

	var claim modelSyncClaim
	decoder := json.NewDecoder(bytes.NewReader(plaintext))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&claim); err != nil {
		return modelSyncClaim{}, errInvalidVerificationToken
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return modelSyncClaim{}, errInvalidVerificationToken
	}
	if !validModelSyncClaim(claim) || claim.ExpiresAt <= now.Unix() {
		return modelSyncClaim{}, errInvalidVerificationToken
	}
	return claim, nil
}

func newModelSyncTokenAEAD(secret string) (cipher.AEAD, error) {
	key := sha256.Sum256([]byte(modelSyncTokenKeyDomain + string([]byte{0}) + secret))
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func validModelSyncClaim(claim modelSyncClaim) bool {
	if claim.Version != 2 || claim.ExpiresAt <= 0 || !validModelSyncDigest(claim.ProviderConfigDigest) || !validModelSyncDigest(claim.ActiveSetDigest) {
		return false
	}
	for _, binding := range []string{
		claim.TenantID,
		claim.ProviderID,
		claim.CredentialID,
		claim.VerificationBatchID,
		claim.CatalogID,
		claim.DeploymentName,
		claim.EndpointType,
	} {
		if strings.TrimSpace(binding) == "" {
			return false
		}
	}
	if _, err := verifiedModelProtocols(claim.Protocols); err != nil {
		return false
	}
	return true
}

func validModelSyncDigest(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && hex.EncodeToString(decoded) == value
}
