package audit_chain

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"sort"
	"strconv"
	"time"

	"github.com/emmansun/gmsm/sm3"
)

// These private types freeze the exact pre-canonical catalog audit shape and
// field order. Do not replace them with the live repository result type.
type legacyCatalogFailure struct {
	ModelID         string `json:"model_id"`
	UpstreamModelID string `json:"upstream_model_id"`
	Reason          string `json:"reason"`
}
type legacyCatalogResult struct {
	Created              int64                  `json:"created"`
	Updated              int64                  `json:"updated"`
	Deactivated          int64                  `json:"deactivated"`
	Reappeared           int64                  `json:"reappeared"`
	Skipped              int64                  `json:"skipped"`
	Verified             int64                  `json:"verified"`
	VerificationFailed   int64                  `json:"verification_failed"`
	TotalSeen            int64                  `json:"total_seen"`
	Pending              int64                  `json:"pending"`
	SelectedMatched      int64                  `json:"selected_matched"`
	NotFoundModelIDs     []string               `json:"not_found_model_ids,omitempty"`
	VerificationFailures []legacyCatalogFailure `json:"verification_failures"`
	RemovedIDs           []string               `json:"removed_model_ids"`
	SyncedAt             time.Time              `json:"synced_at"`
}

var errLegacyPayload = errors.New("payload does not match a supported legacy encoding")

// 冻结旧文件策略的字段顺序、类型及省略规则，不能改用随业务演进的 rules.FilePolicy。
type legacyFilePolicy struct {
	AllowedTypes      []string `json:"allowed_types,omitempty"`
	BlockedTypes      []string `json:"blocked_types,omitempty"`
	ReviewTypes       []string `json:"review_types,omitempty"`
	MaxFileMB         int      `json:"max_file_mb,omitempty"`
	MaxZipRatio       int      `json:"max_zip_ratio,omitempty"`
	MaxAttachments    int      `json:"max_attachments,omitempty"`
	ContentDlpEnabled bool     `json:"content_dlp_enabled,omitempty"`
}

// legacyJSON deliberately preserves v1 encoding; the new canonicalizer must
// not be used to generate historical candidate hashes.
func legacyJSON(v any) ([]byte, error) {
	switch m := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(m))
		for k := range m {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		buf := []byte("{")
		for i, k := range keys {
			if i > 0 {
				buf = append(buf, ',')
			}
			key, err := json.Marshal(k)
			if err != nil {
				return nil, err
			}
			buf = append(buf, key...)
			buf = append(buf, ':')
			value, err := legacyJSON(m[k])
			if err != nil {
				return nil, err
			}
			buf = append(buf, value...)
		}
		return append(buf, '}'), nil
	case []any:
		buf := []byte("[")
		for i, x := range m {
			if i > 0 {
				buf = append(buf, ',')
			}
			value, err := legacyJSON(x)
			if err != nil {
				return nil, err
			}
			buf = append(buf, value...)
		}
		return append(buf, ']'), nil
	default:
		return json.Marshal(v)
	}
}
func legacyDigest(algName string, payload any) (string, error) {
	b, err := legacyJSON(payload)
	if err != nil {
		return "", err
	}
	switch algName {
	case "", AlgSHA256:
		sum := sha256.Sum256(b)
		return hex.EncodeToString(sum[:]), nil
	case AlgSM3:
		sum := sm3.Sum(b)
		return hex.EncodeToString(sum[:]), nil
	}
	return "", errors.New("unknown audit chain algorithm")
}
func sameJSON(a, b any) bool {
	ca, ea := CanonicalPayload(a)
	cb, eb := CanonicalPayload(b)
	return ea == nil && eb == nil && bytes.Equal(ca, cb)
}

// LegacyCatalogPayloadHash is restricted to the known catalog detail schema,
// including a full lossless JSON equivalence check. Unknown/missing fields,
// null-vs-empty arrays and values lost by typed decoding cannot be ignored.
func LegacyCatalogPayloadHash(payload any, algName string) (string, error) {
	canonical, err := CanonicalPayload(payload)
	if err != nil {
		return "", err
	}
	m, err := DecodePayload(canonical)
	if err != nil {
		return "", err
	}
	if len(m) != 2 {
		return "", errLegacyPayload
	}
	provider, ok := m["provider_id"].(string)
	if !ok || provider == "" {
		return "", errLegacyPayload
	}
	result, ok := m["result"].(map[string]any)
	if !ok {
		return "", errLegacyPayload
	}
	raw, err := json.Marshal(result)
	if err != nil {
		return "", err
	}
	var frozen legacyCatalogResult
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&frozen); err != nil {
		return "", errLegacyPayload
	}
	for _, value := range []int64{frozen.Created, frozen.Updated, frozen.Deactivated, frozen.Reappeared, frozen.Skipped, frozen.Verified, frozen.VerificationFailed, frozen.TotalSeen, frozen.Pending, frozen.SelectedMatched} {
		if value < 0 {
			return "", errLegacyPayload
		}
	}
	if frozen.VerificationFailures == nil || frozen.RemovedIDs == nil || frozen.SyncedAt.IsZero() {
		return "", errLegacyPayload
	}
	candidate := map[string]any{"provider_id": provider, "result": frozen}
	if !sameJSON(candidate, m) {
		return "", errLegacyPayload
	}
	return legacyDigest(algName, candidate)
}

// LegacyFilePolicyPayloadHash 仅重建外层只有 policy 的旧文件策略编码。
// 严格解码并校验语义无损，避免未知字段、零值省略或类型转换掩盖内容变化。
func LegacyFilePolicyPayloadHash(payload any, algName string) (string, error) {
	canonical, err := CanonicalPayload(payload)
	if err != nil {
		return "", err
	}
	m, err := DecodePayload(canonical)
	if err != nil {
		return "", err
	}
	if len(m) != 1 {
		return "", errLegacyPayload
	}
	policy, ok := m["policy"].(map[string]any)
	if !ok {
		return "", errLegacyPayload
	}
	raw, err := json.Marshal(policy)
	if err != nil {
		return "", err
	}
	var frozen legacyFilePolicy
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&frozen); err != nil {
		return "", errLegacyPayload
	}
	if frozen.MaxFileMB < 0 || frozen.MaxZipRatio < 0 || frozen.MaxAttachments < 0 {
		return "", errLegacyPayload
	}
	candidate := map[string]any{"policy": frozen}
	if !sameJSON(candidate, m) {
		return "", errLegacyPayload
	}
	return legacyDigest(algName, candidate)
}

func legacyFloatValue(v any) (any, error) {
	switch m := v.(type) {
	case json.Number:
		value, err := strconv.ParseFloat(string(m), 64)
		if err != nil || math.IsNaN(value) || math.IsInf(value, 0) || !sameJSON(value, m) {
			return nil, errLegacyPayload
		}
		return value, nil
	case map[string]any:
		if m == nil {
			return nil, nil
		}
		result := make(map[string]any, len(m))
		for k, x := range m {
			value, err := legacyFloatValue(x)
			if err != nil {
				return nil, err
			}
			result[k] = value
		}
		return result, nil
	case []any:
		if m == nil {
			return nil, nil
		}
		result := make([]any, len(m))
		for i, x := range m {
			value, err := legacyFloatValue(x)
			if err != nil {
				return nil, err
			}
			result[i] = value
		}
		return result, nil
	default:
		return v, nil
	}
}

// LegacyFloatPayloadHash permits historical scientific notation only if the
// float re-serialization preserves every JSON numeric value exactly. A nearby
// large integer/decimal cannot use a rounded candidate to bypass content checks.
func LegacyFloatPayloadHash(payload any, algName string) (string, error) {
	canonical, err := CanonicalPayload(payload)
	if err != nil {
		return "", err
	}
	decoded, err := DecodePayload(canonical)
	if err != nil {
		return "", err
	}
	candidate, err := legacyFloatValue(decoded)
	if err != nil || !sameJSON(candidate, decoded) {
		return "", errLegacyPayload
	}
	return legacyDigest(algName, candidate)
}

// RecordedPayloadMatches verifies content under the current encoding, or a
// narrowly checked historical encoding. Chain linkage and HMAC remain mandatory
// checks performed by the caller after this content check succeeds.
func RecordedPayloadMatches(alg Algorithm, eventType string, payload any, recorded string) bool {
	if len(recorded) != 64 {
		return false
	}
	if current := alg.PayloadHash(payload); current != "" && current == recorded {
		return true
	}
	if eventType == "audit_op" {
		if legacy, err := LegacyCatalogPayloadHash(payload, alg.Name); err == nil && legacy != "" && legacy == recorded {
			return true
		}
		if legacy, err := LegacyFilePolicyPayloadHash(payload, alg.Name); err == nil && legacy != "" && legacy == recorded {
			return true
		}
	}
	legacy, err := LegacyFloatPayloadHash(payload, alg.Name)
	return err == nil && legacy != "" && legacy == recorded
}
