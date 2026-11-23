package audit_chain

// SM3 variant of the audit chain primitives (W10). New file only: the
// existing SHA-256/HMAC-SHA256 functions in hasher.go/signer.go are
// untouched and remain the default. SM3 digests are 32 bytes, so the hex
// forms fit the existing CHAR(64) payload_hash/chain_hash columns.
//
// Rows written with SM3 must be verified with SM3; the algorithm is
// recorded per segment by the caller (see migration 940).

import (
	"crypto/hmac"
	"encoding/hex"
	"strconv"

	"github.com/emmansun/gmsm/sm3"
)

const (
	AlgSHA256 = "sha256-hmac"
	AlgSM3    = "sm3-hmac"
)

// Algorithm bundles the three chain operations so repositories can pick
// SHA-256 or SM3 per segment without branching at every call site.
type Algorithm struct {
	Name        string
	PayloadHash func(payload any) string
	ChainHash   func(prevHash, payloadHash string, seq int64) string
	Sign        func(chainHash string, key []byte) string
	Verify      func(chainHash, signature string, key []byte) bool
}

// AlgorithmByName returns the named algorithm; ok=false for unknown names
// so callers fail closed instead of silently verifying with SHA-256.
func AlgorithmByName(name string) (Algorithm, bool) {
	switch name {
	case "", AlgSHA256:
		return Algorithm{Name: AlgSHA256, PayloadHash: PayloadHash, ChainHash: ChainHash, Sign: Sign, Verify: Verify}, true
	case AlgSM3:
		return Algorithm{Name: AlgSM3, PayloadHash: PayloadHashSM3, ChainHash: ChainHashSM3, Sign: SignSM3, Verify: VerifySM3}, true
	}
	return Algorithm{}, false
}

// PayloadHashSM3 returns the SM3 hex digest of the canonical JSON of payload.
func PayloadHashSM3(payload any) string {
	canonical := canonicalJSON(payload)
	if canonical == nil {
		return ""
	}
	sum := sm3.Sum(canonical)
	return hex.EncodeToString(sum[:])
}

// ChainHashSM3 uses the same input layout as ChainHash.
func ChainHashSM3(prevHash, payloadHash string, seq int64) string {
	sum := sm3.Sum([]byte(prevHash + payloadHash + strconv.FormatInt(seq, 10)))
	return hex.EncodeToString(sum[:])
}

// SignSM3 returns an HMAC-SM3 hex signature of chainHash.
func SignSM3(chainHash string, key []byte) string {
	h := hmac.New(sm3.New, key)
	h.Write([]byte(chainHash))
	return hex.EncodeToString(h.Sum(nil))
}

// VerifySM3 checks an HMAC-SM3 signature in constant time.
func VerifySM3(chainHash, signature string, key []byte) bool {
	return hmac.Equal([]byte(SignSM3(chainHash, key)), []byte(signature))
}

// VerifyRow is the pure (DB-free) integrity check for one row under alg.
// It returns "" when the row is intact, otherwise the same detail strings
// the repository Verify uses.
func VerifyRow(alg Algorithm, key []byte, prevChainHash string, checkLink bool, prevHash string, payload any, payloadHash, chainHash, signature string, seq int64) string {
	return VerifyRecordedRow(alg, key, prevChainHash, checkLink, prevHash, "", payload, payloadHash, chainHash, signature, seq)
}

// VerifyRecordedRow includes the event type needed for bounded historical
// encoding compatibility, followed by the unchanged chain and signature checks.
func VerifyRecordedRow(alg Algorithm, key []byte, prevChainHash string, checkLink bool, prevHash, eventType string, payload any, payloadHash, chainHash, signature string, seq int64) string {
	if checkLink && prevHash != prevChainHash {
		return "prev_hash mismatch"
	}
	if !RecordedPayloadMatches(alg, eventType, payload, payloadHash) {
		return "payload_hash mismatch"
	}
	if alg.ChainHash(prevHash, payloadHash, seq) != chainHash {
		return "chain_hash mismatch"
	}
	if !alg.Verify(chainHash, signature, key) {
		return "signature invalid"
	}
	return ""
}
