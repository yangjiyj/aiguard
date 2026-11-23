package audit_chain

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
)

// Sign returns an HMAC-SHA256 hex signature of chainHash using key.
func Sign(chainHash string, key []byte) string {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(chainHash))
	return hex.EncodeToString(h.Sum(nil))
}

// Verify returns true when signature matches Sign(chainHash, key).
func Verify(chainHash, signature string, key []byte) bool {
	expected := Sign(chainHash, key)
	return hmac.Equal([]byte(expected), []byte(signature))
}
