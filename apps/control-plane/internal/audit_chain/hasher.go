package audit_chain

import (
	"crypto/sha256"
	"encoding/hex"
	"strconv"
)

func canonicalJSON(v any) []byte {
	payload, err := CanonicalPayload(v)
	if err != nil {
		return nil
	}
	return payload
}

// PayloadHash returns a SHA-256 hex digest of the canonical JSON of payload.
func PayloadHash(payload any) string {
	canonical := canonicalJSON(payload)
	if canonical == nil {
		return ""
	}
	sum := sha256.Sum256(canonical)
	return hex.EncodeToString(sum[:])
}

// ChainHash combines prevHash, payloadHash, and seq into a single SHA-256 digest.
func ChainHash(prevHash, payloadHash string, seq int64) string {
	data := prevHash + payloadHash + strconv.FormatInt(seq, 10)
	sum := sha256.Sum256([]byte(data))
	return hex.EncodeToString(sum[:])
}
