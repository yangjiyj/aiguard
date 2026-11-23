package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	lseCorrelationSignatureHeader = "X-LSE-Correlation-Signature"
	defaultLSECorrelationMaxSkew  = 5 * time.Minute
)

type lseCorrelationHMACConfig struct {
	mode    string
	keys    map[string][]byte
	maxSkew time.Duration
}

// loadLSECorrelationHMACConfig reads the keyring for every request so a key can
// be rotated by updating the process environment and restarting one replica at
// a time. The value is a comma-separated list of kid=secret pairs. Secrets are
// intentionally opaque strings; deployments should source them from a secret
// manager rather than commit them to compose files.
func loadLSECorrelationHMACConfig() lseCorrelationHMACConfig {
	keys := make(map[string][]byte)
	for _, entry := range strings.Split(os.Getenv("LSE_CORRELATION_HMAC_KEYS"), ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		parts := strings.SplitN(entry, "=", 2)
		if len(parts) != 2 {
			parts = strings.SplitN(entry, ":", 2)
		}
		if len(parts) != 2 {
			continue
		}
		kid := strings.TrimSpace(parts[0])
		secret := strings.TrimSpace(parts[1])
		if kid == "" || secret == "" || !validLSECorrelationToken(kid, 64) {
			continue
		}
		keys[kid] = []byte(secret)
	}

	mode := strings.ToLower(strings.TrimSpace(os.Getenv("LSE_CORRELATION_HMAC_MODE")))
	if mode == "" {
		mode = "off"
	}
	if mode != "off" && mode != "optional" && mode != "required" {
		// A typo must not silently downgrade a configured deployment to legacy
		// unsigned evidence handling.
		mode = "required"
	}
	maxSkew := defaultLSECorrelationMaxSkew
	if raw := strings.TrimSpace(os.Getenv("LSE_CORRELATION_HMAC_MAX_SKEW_SECONDS")); raw != "" {
		if seconds, err := strconv.Atoi(raw); err == nil && seconds >= 1 && seconds <= 3600 {
			maxSkew = time.Duration(seconds) * time.Second
		}
	}
	return lseCorrelationHMACConfig{mode: mode, keys: keys, maxSkew: maxSkew}
}

// extractVerifiedLSECorrelation keeps legacy headers only in explicit off
// mode. In optional/required mode, unsigned or invalid headers are discarded,
// so a caller cannot manufacture trusted evidence by simply setting X-LSE-*.
func extractVerifiedLSECorrelation(r *http.Request) (LSECorrelation, bool) {
	corr := extractLSECorrelationHeaders(r.Header)
	cfg := loadLSECorrelationHMACConfig()
	if cfg.mode == "off" {
		return corr, false
	}
	if len(cfg.keys) == 0 || strings.TrimSpace(r.Header.Get(lseCorrelationSignatureHeader)) == "" {
		return LSECorrelation{}, false
	}
	if !verifyLSECorrelationSignature(r, corr, cfg) {
		return LSECorrelation{}, false
	}
	return corr, true
}

func canonicalLSECorrelation(_ *http.Request, corr LSECorrelation, timestamp int64, nonce string) string {
	return strings.Join([]string{
		"v1",
		corr.EvalRunID,
		corr.TaskID,
		corr.SampleID,
		corr.TargetID,
		corr.TraceID,
		strconv.FormatInt(timestamp, 10),
		nonce,
	}, "\n")
}

func verifyLSECorrelationSignature(r *http.Request, corr LSECorrelation, cfg lseCorrelationHMACConfig) bool {
	parts := strings.Split(strings.TrimSpace(r.Header.Get(lseCorrelationSignatureHeader)), ".")
	if len(parts) != 5 || parts[0] != "v1" {
		return false
	}
	kid := parts[1]
	if !validLSECorrelationToken(kid, 64) {
		return false
	}
	timestamp, err := strconv.ParseInt(parts[2], 10, 64)
	if err != nil {
		return false
	}
	nonce := parts[3]
	if !validLSECorrelationToken(nonce, 64) {
		return false
	}
	if delta := time.Now().Unix() - timestamp; delta > int64(cfg.maxSkew/time.Second) || delta < -int64(cfg.maxSkew/time.Second) {
		return false
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[4])
	if err != nil || len(signature) != sha256.Size {
		return false
	}
	secret, ok := cfg.keys[kid]
	if !ok {
		return false
	}
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write([]byte(canonicalLSECorrelation(r, corr, timestamp, nonce)))
	return hmac.Equal(signature, mac.Sum(nil))
}

func validLSECorrelationToken(value string, maxLen int) bool {
	if value == "" || len(value) > maxLen {
		return false
	}
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= 'A' && r <= 'Z':
		case r >= '0' && r <= '9':
		case r == '_' || r == '-':
		default:
			return false
		}
	}
	return true
}
