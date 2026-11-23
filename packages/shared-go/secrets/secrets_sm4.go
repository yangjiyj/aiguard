package secrets

// SM4-GCM envelope (W10, GB/T 32907 SM4 + GB/T 32905 SM3 key derivation).
//
// Wire format keeps each family's existing outer prefix so every caller and
// SQL CHECK that tests "enc:v1:" / "enc:v2:" / "enc:ca:v1:" keeps working:
//
//	<prefix>sm4:<key-id>:<base64raw(nonce12 || ciphertext || tag16)>
//
// Legacy AES-GCM payloads are raw base64 and can never contain ':' so the
// "sm4:" marker is unambiguous. Decryption always accepts both formats;
// JJD_SECRETS_CIPHER only selects the algorithm used for new writes.

import (
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/emmansun/gmsm/sm3"
	"github.com/emmansun/gmsm/sm4"
)

const (
	// CipherEnv selects the algorithm for NEW ciphertext. Empty = aes-gcm.
	CipherEnv = "JJD_SECRETS_CIPHER"
	// SM4KeyringEnv lists SM4 root secrets as "id=secret,id2=secret2".
	// Optional: when empty the built-in key id "root" derives SM4 keys from
	// the family's existing secret (JJD_PROVIDER_SECRET_KEY / JJD_INTERNAL_API_SECRET).
	SM4KeyringEnv = "JJD_SM4_KEYRING"
	// SM4ActiveKeyEnv picks the key id used for new SM4 writes.
	// Default: first keyring entry, or "root" when the keyring is empty.
	SM4ActiveKeyEnv = "JJD_SM4_ACTIVE_KEY_ID"

	CipherAESGCM = "aes-gcm"
	CipherSM4GCM = "sm4-gcm"

	sm4Marker          = "sm4:"
	sm4RootKeyID       = "root"
	sm4KeyDomainPrefix = "jjdguard:secrets:sm4-gcm:v1:"
	sm4MinSecretLen    = 16
)

type secretFamily string

const (
	familyProvider  secretFamily = "provider-secret"
	familyCA        secretFamily = "ca-private-key"
	familyMCPResult secretFamily = "mcp-result"
)

var (
	ErrUnsupportedCipher  = errors.New("unsupported " + CipherEnv + " value")
	ErrInvalidSM4Keyring  = errors.New("invalid " + SM4KeyringEnv)
	ErrSM4KeyNotFound     = errors.New("SM4 key id is not configured")
	ErrMalformedSM4Header = errors.New("malformed SM4 ciphertext header")
	sm4KeyIDPattern       = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`)
)

// ConfiguredCipher returns the algorithm used for new ciphertext.
// Unknown values fail closed (encryption returns an error) instead of
// silently falling back to AES.
func ConfiguredCipher() (string, error) {
	v := strings.ToLower(strings.TrimSpace(os.Getenv(CipherEnv)))
	switch v {
	case "", CipherAESGCM:
		return CipherAESGCM, nil
	case CipherSM4GCM:
		return CipherSM4GCM, nil
	}
	return "", fmt.Errorf("%w: %q", ErrUnsupportedCipher, v)
}

func sm4Keyring() (map[string][]byte, []string, error) {
	raw := strings.TrimSpace(os.Getenv(SM4KeyringEnv))
	ring := map[string][]byte{}
	var order []string
	if raw == "" {
		return ring, order, nil
	}
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		id, secret, ok := strings.Cut(part, "=")
		id = strings.TrimSpace(id)
		secret = strings.TrimSpace(secret)
		switch {
		case !ok || !sm4KeyIDPattern.MatchString(id):
			return nil, nil, fmt.Errorf("%w: bad key id %q", ErrInvalidSM4Keyring, id)
		case id == sm4RootKeyID:
			return nil, nil, fmt.Errorf("%w: key id %q is reserved", ErrInvalidSM4Keyring, id)
		case len(secret) < sm4MinSecretLen:
			return nil, nil, fmt.Errorf("%w: secret for %q shorter than %d bytes", ErrInvalidSM4Keyring, id, sm4MinSecretLen)
		}
		if _, dup := ring[id]; dup {
			return nil, nil, fmt.Errorf("%w: duplicate key id %q", ErrInvalidSM4Keyring, id)
		}
		ring[id] = []byte(secret)
		order = append(order, id)
	}
	return ring, order, nil
}

// ActiveSM4KeyID returns the key id used for new SM4 writes.
func ActiveSM4KeyID() (string, error) {
	ring, order, err := sm4Keyring()
	if err != nil {
		return "", err
	}
	if id := strings.TrimSpace(os.Getenv(SM4ActiveKeyEnv)); id != "" {
		if id != sm4RootKeyID {
			if _, ok := ring[id]; !ok {
				return "", fmt.Errorf("%w: active key %q", ErrSM4KeyNotFound, id)
			}
		}
		return id, nil
	}
	if len(order) > 0 {
		return order[0], nil
	}
	return sm4RootKeyID, nil
}

func familyRootSecret(fam secretFamily) ([]byte, error) {
	if fam == familyCA {
		return caPrivateKeyEncryptionKey()
	}
	return loadSecretKey()
}

// sm4Key derives a 128-bit SM4 key: HMAC-SM3(secret, domain || family)[:16].
func sm4Key(fam secretFamily, keyID string) ([]byte, error) {
	var secret []byte
	if keyID == sm4RootKeyID {
		root, err := familyRootSecret(fam)
		if err != nil {
			return nil, err
		}
		secret = root
	} else {
		ring, _, err := sm4Keyring()
		if err != nil {
			return nil, err
		}
		s, ok := ring[keyID]
		if !ok {
			return nil, fmt.Errorf("%w: %q", ErrSM4KeyNotFound, keyID)
		}
		secret = s
	}
	mac := hmac.New(sm3.New, secret)
	_, _ = mac.Write([]byte(sm4KeyDomainPrefix + string(fam)))
	return mac.Sum(nil)[:sm4.BlockSize], nil
}

func newSM4GCM(key []byte) (cipher.AEAD, error) {
	block, err := sm4.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create SM4 cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create SM4 GCM: %w", err)
	}
	return aead, nil
}

// The header (prefix + marker + key id) is bound into the AAD so a value
// cannot be moved between families or relabelled with another key id.
func sm4AAD(header string, extra []byte) []byte {
	aad := make([]byte, 0, len(header)+1+len(extra))
	aad = append(aad, header...)
	aad = append(aad, 0)
	return append(aad, extra...)
}

func sm4Seal(fam secretFamily, prefix string, plaintext, extraAAD []byte) (string, string, error) {
	keyID, err := ActiveSM4KeyID()
	if err != nil {
		return "", "", err
	}
	key, err := sm4Key(fam, keyID)
	if err != nil {
		return "", "", err
	}
	aead, err := newSM4GCM(key)
	if err != nil {
		return "", "", err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", "", fmt.Errorf("generate SM4 nonce: %w", err)
	}
	header := prefix + sm4Marker + keyID + ":"
	sealed := aead.Seal(nil, nonce, plaintext, sm4AAD(header, extraAAD))
	return header + base64.RawStdEncoding.EncodeToString(append(nonce, sealed...)), keyID, nil
}

type sm4Envelope struct {
	keyID   string
	header  string
	payload string
}

// parseSM4Envelope reports whether ciphertext (already known to start with
// prefix) is an SM4 envelope. A value carrying the marker but a broken
// header is reported as SM4 with an error; it is never retried as AES.
func parseSM4Envelope(ciphertext, prefix string) (sm4Envelope, bool, error) {
	rest := strings.TrimPrefix(ciphertext, prefix)
	if !strings.HasPrefix(rest, sm4Marker) {
		return sm4Envelope{}, false, nil
	}
	rest = rest[len(sm4Marker):]
	keyID, payload, ok := strings.Cut(rest, ":")
	if !ok || (keyID != sm4RootKeyID && !sm4KeyIDPattern.MatchString(keyID)) {
		return sm4Envelope{}, true, ErrMalformedSM4Header
	}
	return sm4Envelope{keyID: keyID, header: prefix + sm4Marker + keyID + ":", payload: payload}, true, nil
}

func sm4Open(fam secretFamily, env sm4Envelope, extraAAD []byte) ([]byte, error) {
	key, err := sm4Key(fam, env.keyID)
	if err != nil {
		return nil, err
	}
	payload, err := base64.RawStdEncoding.DecodeString(env.payload)
	if err != nil {
		return nil, fmt.Errorf("decode SM4 ciphertext: %w", err)
	}
	aead, err := newSM4GCM(key)
	if err != nil {
		return nil, err
	}
	if len(payload) < aead.NonceSize()+aead.Overhead() {
		return nil, errors.New("SM4 ciphertext too short")
	}
	n := aead.NonceSize()
	plaintext, err := aead.Open(nil, payload[:n], payload[n:], sm4AAD(env.header, extraAAD))
	if err != nil {
		return nil, fmt.Errorf("decrypt SM4 ciphertext: %w", err)
	}
	return plaintext, nil
}

// isTargetFormat reports whether ciphertext already matches the configured
// write format (algorithm and, for SM4, the active key id).
func isTargetFormat(ciphertext, prefix string) (bool, error) {
	mode, err := ConfiguredCipher()
	if err != nil {
		return false, err
	}
	env, isSM4, err := parseSM4Envelope(ciphertext, prefix)
	if err != nil {
		return false, err
	}
	if mode == CipherAESGCM {
		return !isSM4, nil
	}
	if !isSM4 {
		return false, nil
	}
	active, err := ActiveSM4KeyID()
	if err != nil {
		return false, err
	}
	return env.keyID == active, nil
}

// RewrapProviderSecret re-encrypts an enc:v1: value into the configured
// write format (used for SM4 migration, key rotation and rollback to AES).
// Empty and legacy plaintext values are returned unchanged.
func RewrapProviderSecret(ciphertext string) (string, bool, error) {
	if ciphertext == "" || !strings.HasPrefix(ciphertext, providerSecretPrefix) {
		return ciphertext, false, nil
	}
	if ok, err := isTargetFormat(ciphertext, providerSecretPrefix); err != nil || ok {
		return ciphertext, false, err
	}
	plaintext, err := DecryptProviderSecret(ciphertext)
	if err != nil {
		return ciphertext, false, err
	}
	out, _, err := EncryptProviderSecret(plaintext)
	if err != nil {
		return ciphertext, false, err
	}
	return out, true, nil
}

// RewrapCAPrivateKey is RewrapProviderSecret for enc:ca:v1: values.
func RewrapCAPrivateKey(ciphertext string) (string, bool, error) {
	if ciphertext == "" || !strings.HasPrefix(ciphertext, caPrivateKeyPrefix) {
		return ciphertext, false, nil
	}
	if ok, err := isTargetFormat(ciphertext, caPrivateKeyPrefix); err != nil || ok {
		return ciphertext, false, err
	}
	plaintext, err := DecryptCAPrivateKey(ciphertext)
	if err != nil {
		return ciphertext, false, err
	}
	out, err := EncryptCAPrivateKey(plaintext)
	if err != nil {
		return ciphertext, false, err
	}
	return out, true, nil
}

// DescribeCiphertext classifies a stored value without decrypting it:
// "empty", "plaintext", "aes-gcm", "sm4-gcm:<key-id>" or "malformed".
func DescribeCiphertext(value string) string {
	if value == "" {
		return "empty"
	}
	// caPrivateKeyPrefix must be checked before the shorter "enc:" forms.
	for _, prefix := range []string{caPrivateKeyPrefix, providerSecretPrefix, mcpResultPrefix, rawEvidencePrefix} {
		if !strings.HasPrefix(value, prefix) {
			continue
		}
		env, isSM4, err := parseSM4Envelope(value, prefix)
		switch {
		case err != nil:
			return "malformed"
		case isSM4:
			return CipherSM4GCM + ":" + env.keyID
		default:
			return CipherAESGCM
		}
	}
	return "plaintext"
}
