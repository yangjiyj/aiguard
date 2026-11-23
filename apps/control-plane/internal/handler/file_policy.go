package handler

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/rules"
)

// defaultFileRiskAction 是文件风险类别与文件引用的缺省处置（2.9.22 设计 D2：告警放行）。
const defaultFileRiskAction = "alert_allow"

const (
	maxFilePolicyItems      = 100
	maxFilePolicyItemLength = 64
	maxFilePolicyBytes      = 64 << 10
)

func contentFilePolicySettingKeyForTenant(tenantID string) string {
	if tenantID == "" || tenantID == "tenant_default" {
		return contentFilePolicySettingKey
	}
	sum := sha256.Sum256([]byte(tenantID))
	return contentFilePolicySettingKey + ":" + hex.EncodeToString(sum[:])
}

func decodeAndNormalizeFilePolicy(raw []byte) (rules.FilePolicy, error) {
	if len(raw) == 0 || len(raw) > maxFilePolicyBytes {
		return rules.FilePolicy{}, errors.New("file policy payload size is invalid")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var policy *rules.FilePolicy
	if err := decoder.Decode(&policy); err != nil {
		return rules.FilePolicy{}, fmt.Errorf("decode file policy: %w", err)
	}
	if policy == nil {
		return rules.FilePolicy{}, errors.New("file policy must be an object")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return rules.FilePolicy{}, errors.New("file policy contains trailing JSON")
		}
		return rules.FilePolicy{}, fmt.Errorf("decode trailing file policy data: %w", err)
	}
	return normalizeContentFilePolicy(*policy)
}

func normalizeContentFilePolicy(policy rules.FilePolicy) (rules.FilePolicy, error) {
	var err error
	if policy.AllowedTypes, err = normalizeFilePolicyItems("allowed_types", policy.AllowedTypes); err != nil {
		return rules.FilePolicy{}, err
	}
	if policy.BlockedTypes, err = normalizeFilePolicyItems("blocked_types", policy.BlockedTypes); err != nil {
		return rules.FilePolicy{}, err
	}
	if policy.ReviewTypes, err = normalizeFilePolicyItems("review_types", policy.ReviewTypes); err != nil {
		return rules.FilePolicy{}, err
	}
	defaults := defaultContentFilePolicy()
	if policy.MaxFileMB == 0 {
		policy.MaxFileMB = defaults.MaxFileMB
	}
	if policy.MaxZipRatio == 0 {
		policy.MaxZipRatio = defaults.MaxZipRatio
	}
	if policy.MaxAttachments == 0 {
		policy.MaxAttachments = defaults.MaxAttachments
	}
	if policy.MaxFileMB < 1 || policy.MaxFileMB > 100 {
		return rules.FilePolicy{}, errors.New("max_file_mb must be between 1 and 100")
	}
	if policy.MaxZipRatio < 1 || policy.MaxZipRatio > 1000 {
		return rules.FilePolicy{}, errors.New("max_zip_ratio must be between 1 and 1000")
	}
	if policy.MaxAttachments < 1 || policy.MaxAttachments > 100 {
		return rules.FilePolicy{}, errors.New("max_attachments must be between 1 and 100")
	}
	for _, field := range []struct {
		name  string
		value *string
	}{
		{"executable_action", &policy.ExecutableAction},
		{"disguised_executable_action", &policy.DisguisedExecutableAction},
		{"script_action", &policy.ScriptAction},
		{"unknown_action", &policy.UnknownAction},
		{"zip_bomb_action", &policy.ZipBombAction},
		{"unverified_file_reference_action", &policy.UnverifiedFileReferenceAction},
		{"file_reference_lookup_failure_action", &policy.FileReferenceLookupFailureAction},
	} {
		switch *field.value {
		case "":
			// 旧策略 JSON 没有这些字段：按缺省告警放行解释（2.9.22 升级不变严）。
			*field.value = defaultFileRiskAction
		case "allow", "alert_allow", "block":
		default:
			return rules.FilePolicy{}, fmt.Errorf("%s must be allow, alert_allow or block", field.name)
		}
	}
	// 压缩包限制：0 = 未配置（引擎取部署环境变量缺省），配置了就必须在范围内。
	for _, limit := range []struct {
		name     string
		value    int
		min, max int
	}{
		{"max_zip_entries", policy.MaxZipEntries, 1, 100000},
		{"max_zip_uncompressed_mb", policy.MaxZipUncompressedMB, 1, 10240},
		{"max_zip_nested", policy.MaxZipNested, 1, 100},
	} {
		if limit.value != 0 && (limit.value < limit.min || limit.value > limit.max) {
			return rules.FilePolicy{}, fmt.Errorf("%s must be between %d and %d", limit.name, limit.min, limit.max)
		}
	}
	return policy, nil
}

func normalizeFilePolicyItems(field string, values []string) ([]string, error) {
	if len(values) > maxFilePolicyItems {
		return nil, fmt.Errorf("%s contains too many items", field)
	}
	normalized := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			return nil, fmt.Errorf("%s contains a blank item", field)
		}
		if len([]rune(value)) > maxFilePolicyItemLength {
			return nil, fmt.Errorf("%s item is too long", field)
		}
		normalized = append(normalized, value)
	}
	return normalized, nil
}
