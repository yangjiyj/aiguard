package secrets

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strings"
)

const (
	providerSecretPrefix = "enc:v1:"
	caPrivateKeyPrefix   = "enc:ca:v1:"
	caPrivateKeyDomain   = "jjdguard:proxy-ca-private-key:v1"
	mcpResultPrefix      = "enc:v2:"
	mcpResultKeyDomain   = "jjdguard:mcp-confirmation:result-key:v2"
	providerSecretEnv    = "JJD_PROVIDER_SECRET_KEY"
	masterSecretEnv      = "JJD_MASTER_KEY" // #nosec G101 -- environment variable name, not a credential value.
	internalAPISecretEnv = "JJD_INTERNAL_API_SECRET"
)

var ErrSecretKeyNotConfigured = errors.New("provider secret encryption key not configured")

var ErrCAPrivateKeyNotConfigured = errors.New("CA private key encryption secret not configured")

func EncryptProviderSecret(plaintext string) (string, string, error) {
	if plaintext == "" {
		return "", "", nil
	}

	key, err := loadSecretKey()
	if err != nil {
		return "", "", err
	}
	mode, err := ConfiguredCipher()
	if err != nil {
		return "", "", err
	}
	if mode == CipherSM4GCM {
		out, _, err := sm4Seal(familyProvider, providerSecretPrefix, []byte(plaintext), nil)
		if err != nil {
			return "", "", err
		}
		return out, encryptionKeyRef(), nil
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", "", fmt.Errorf("create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", "", fmt.Errorf("create gcm: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", "", fmt.Errorf("generate nonce: %w", err)
	}

	encrypted := gcm.Seal(nil, nonce, []byte(plaintext), nil)
	payload := append(nonce, encrypted...)
	return providerSecretPrefix + base64.RawStdEncoding.EncodeToString(payload), encryptionKeyRef(), nil
}

func DecryptProviderSecret(ciphertext string) (string, error) {
	if ciphertext == "" {
		return "", nil
	}

	if !strings.HasPrefix(ciphertext, providerSecretPrefix) {
		return ciphertext, nil
	}
	if env, isSM4, err := parseSM4Envelope(ciphertext, providerSecretPrefix); err != nil {
		return "", err
	} else if isSM4 {
		plaintext, err := sm4Open(familyProvider, env, nil)
		if err != nil {
			return "", err
		}
		return string(plaintext), nil
	}

	key, err := loadSecretKey()
	if err != nil {
		return "", err
	}

	encoded := strings.TrimPrefix(ciphertext, providerSecretPrefix)
	payload, err := base64.RawStdEncoding.DecodeString(encoded)
	if err != nil {
		return "", fmt.Errorf("decode ciphertext: %w", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("create gcm: %w", err)
	}

	if len(payload) < gcm.NonceSize() {
		return "", errors.New("ciphertext too short")
	}

	nonce := payload[:gcm.NonceSize()]
	encrypted := payload[gcm.NonceSize():]
	plaintext, err := gcm.Open(nil, nonce, encrypted, nil)
	if err != nil {
		return "", fmt.Errorf("decrypt ciphertext: %w", err)
	}

	return string(plaintext), nil
}

// EncryptCAPrivateKey encrypts a proxy CA private key with a domain-separated
// key derived from the internal service secret shared by control-plane and proxy-server.
func EncryptCAPrivateKey(plaintext string) (string, error) {
	if plaintext == "" {
		return "", nil
	}
	key, err := caPrivateKeyEncryptionKey()
	if err != nil {
		return "", err
	}
	mode, err := ConfiguredCipher()
	if err != nil {
		return "", err
	}
	if mode == CipherSM4GCM {
		out, _, err := sm4Seal(familyCA, caPrivateKeyPrefix, []byte(plaintext), []byte(caPrivateKeyDomain))
		return out, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("create CA private key cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("create CA private key GCM: %w", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("generate CA private key nonce: %w", err)
	}
	encrypted := gcm.Seal(nil, nonce, []byte(plaintext), []byte(caPrivateKeyDomain))
	return caPrivateKeyPrefix + base64.RawStdEncoding.EncodeToString(append(nonce, encrypted...)), nil
}

// DecryptCAPrivateKey accepts legacy plaintext PEM records so existing
// installations can rotate forward without a disruptive one-shot migration.
func DecryptCAPrivateKey(ciphertext string) (string, error) {
	if ciphertext == "" || !strings.HasPrefix(ciphertext, caPrivateKeyPrefix) {
		return ciphertext, nil
	}
	if env, isSM4, err := parseSM4Envelope(ciphertext, caPrivateKeyPrefix); err != nil {
		return "", err
	} else if isSM4 {
		plaintext, err := sm4Open(familyCA, env, []byte(caPrivateKeyDomain))
		if err != nil {
			return "", err
		}
		return string(plaintext), nil
	}
	key, err := caPrivateKeyEncryptionKey()
	if err != nil {
		return "", err
	}
	payload, err := base64.RawStdEncoding.DecodeString(strings.TrimPrefix(ciphertext, caPrivateKeyPrefix))
	if err != nil {
		return "", fmt.Errorf("decode CA private key ciphertext: %w", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("create CA private key cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("create CA private key GCM: %w", err)
	}
	if len(payload) < gcm.NonceSize() {
		return "", errors.New("CA private key ciphertext too short")
	}
	plaintext, err := gcm.Open(nil, payload[:gcm.NonceSize()], payload[gcm.NonceSize():], []byte(caPrivateKeyDomain))
	if err != nil {
		return "", fmt.Errorf("decrypt CA private key ciphertext: %w", err)
	}
	return string(plaintext), nil
}

func caPrivateKeyEncryptionKey() ([]byte, error) {
	rawKey := strings.TrimSpace(os.Getenv(internalAPISecretEnv))
	if rawKey == "" {
		return nil, ErrCAPrivateKeyNotConfigured
	}
	mac := hmac.New(sha256.New, []byte(rawKey))
	_, _ = mac.Write([]byte(caPrivateKeyDomain))
	return mac.Sum(nil), nil
}

func loadSecretKey() ([]byte, error) {
	rawKey := strings.TrimSpace(os.Getenv(providerSecretEnv))
	if rawKey == "" {
		rawKey = strings.TrimSpace(os.Getenv(masterSecretEnv))
	}
	if rawKey == "" {
		return nil, ErrSecretKeyNotConfigured
	}

	sum := sha256.Sum256([]byte(rawKey))
	return sum[:], nil
}

func encryptionKeyRef() string {
	if strings.TrimSpace(os.Getenv(providerSecretEnv)) != "" {
		return "env:" + providerSecretEnv
	}
	if strings.TrimSpace(os.Getenv(masterSecretEnv)) != "" {
		return "env:" + masterSecretEnv
	}
	return ""
}

func mcpResultKey() ([]byte, error) {
	base, err := loadSecretKey()
	if err != nil {
		return nil, err
	}
	mac := hmac.New(sha256.New, base)
	_, _ = mac.Write([]byte(mcpResultKeyDomain))
	return mac.Sum(nil), nil
}

// EncryptMCPResult uses a domain-separated AES-GCM key and mandatory AAD.
// It is intentionally separate from provider-secret encryption so replay
// results cannot be decrypted under the legacy no-AAD API.
func EncryptMCPResult(plaintext, aad []byte) (string, error) {
	if len(plaintext) == 0 || len(aad) == 0 {
		return "", errors.New("MCP result plaintext and AAD are required")
	}
	key, err := mcpResultKey()
	if err != nil {
		return "", err
	}
	mode, err := ConfiguredCipher()
	if err != nil {
		return "", err
	}
	if mode == CipherSM4GCM {
		out, _, err := sm4Seal(familyMCPResult, mcpResultPrefix, plaintext, aad)
		return out, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("create MCP result cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("create MCP result GCM: %w", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("generate MCP result nonce: %w", err)
	}
	encrypted := gcm.Seal(nil, nonce, plaintext, aad)
	return mcpResultPrefix + base64.RawStdEncoding.EncodeToString(append(nonce, encrypted...)), nil
}

// DecryptMCPResult rejects legacy/plaintext values and requires byte-identical
// AAD, preserving tenant/principal/invocation/request/result binding.
func DecryptMCPResult(ciphertext string, aad []byte) ([]byte, error) {
	if !strings.HasPrefix(ciphertext, mcpResultPrefix) || len(aad) == 0 {
		return nil, errors.New("invalid MCP result ciphertext or AAD")
	}
	if env, isSM4, err := parseSM4Envelope(ciphertext, mcpResultPrefix); err != nil {
		return nil, err
	} else if isSM4 {
		return sm4Open(familyMCPResult, env, aad)
	}
	key, err := mcpResultKey()
	if err != nil {
		return nil, err
	}
	payload, err := base64.RawStdEncoding.DecodeString(strings.TrimPrefix(ciphertext, mcpResultPrefix))
	if err != nil {
		return nil, fmt.Errorf("decode MCP result ciphertext: %w", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create MCP result cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create MCP result GCM: %w", err)
	}
	if len(payload) < gcm.NonceSize() {
		return nil, errors.New("MCP result ciphertext too short")
	}
	plaintext, err := gcm.Open(nil, payload[:gcm.NonceSize()], payload[gcm.NonceSize():], aad)
	if err != nil {
		return nil, fmt.Errorf("decrypt MCP result ciphertext: %w", err)
	}
	return plaintext, nil
}
