package repository

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// ScopedAlertGroupKey confines legacy fingerprint signatures to their known
// project and detection stage. Its version prefix permits read-only compatibility
// with historical false-positive decisions without widening their scope.
func ScopedAlertGroupKey(key, projectID, stage string) string {
	if strings.HasPrefix(key, "v2:") {
		return key
	}
	sum := sha256.Sum256([]byte("v2|" + projectID + "|" + stage + "|" + key))
	return "v2:" + hex.EncodeToString(sum[:])[:16]
}
