package modelrouter

import (
	"crypto/sha256"
	"encoding/binary"
)

// CanaryHit returns true if the given key falls within the canary bucket for the given ratio (0-100).
// The assignment is deterministic: the same key always produces the same result.
func CanaryHit(key string, ratio int) bool {
	if ratio <= 0 {
		return false
	}
	if ratio >= 100 {
		return true
	}
	sum := sha256.Sum256([]byte(key))
	bucket := binary.BigEndian.Uint32(sum[:4]) % 100
	return int(bucket) < ratio
}
