package license

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"
)

// 授权在 system_settings 中的存储键。handler 与 diagnostics 共用，避免两处各写一份。
const (
	SettingKeyLicense      = "enterprise_license"
	SettingKeyImportedAt   = "enterprise_license_imported_at"
	SettingKeyTimeState    = "enterprise_license_time_state"
	SettingKeyDeploymentID = "enterprise_license_deployment_id"
	// SettingKeyInstallAnchor 记录平台首次启动时间，用于零签名试用窗口判定。
	SettingKeyInstallAnchor = "enterprise_license_install_anchor"
)

const defaultTrustedIssuer = "huoxianbao-license-authority-prod"

// ParsePublicKeys 解析 JJD_LICENSE_PUBLIC_KEYS（keyID=publicKey,keyID=publicKey）。
func ParsePublicKeys(raw string) map[string]string {
	out := map[string]string{}
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		keyID, publicKey, ok := strings.Cut(part, "=")
		if !ok {
			continue
		}
		keyID = strings.TrimSpace(keyID)
		publicKey = strings.TrimSpace(publicKey)
		if keyID != "" && publicKey != "" {
			out[keyID] = publicKey
		}
	}
	return out
}

// PublicKeySetFromEnv 报告部署是否配置了任何授权公钥。
func PublicKeySetFromEnv() bool {
	return strings.TrimSpace(os.Getenv("JJD_LICENSE_PUBLIC_KEY")) != "" ||
		len(ParsePublicKeys(os.Getenv("JJD_LICENSE_PUBLIC_KEYS"))) > 0
}

// DeploymentFingerprint 由部署 ID 派生授权绑定指纹。
func DeploymentFingerprint(deploymentID string) string {
	sum := sha256.Sum256([]byte("license.v2.deployment|" + deploymentID))
	return hex.EncodeToString(sum[:])
}

// LoadRevocationList 读取并校验吊销列表文件。已配置吊销列表时任何失败都 fail-closed
// （evaluateV2 据 RevocationListError 判无效）。错误文本不带文件路径，避免经状态接口泄露部署细节。
func LoadRevocationList(now time.Time, publicKeys map[string]string, trustedIssuerSet ...map[string]struct{}) (*RevocationList, error) {
	trustedIssuers := map[string]struct{}{defaultTrustedIssuer: {}}
	if len(trustedIssuerSet) > 0 && trustedIssuerSet[0] != nil {
		trustedIssuers = trustedIssuerSet[0]
	}
	path := strings.TrimSpace(os.Getenv("JJD_LICENSE_REVOCATION_FILE"))
	if path == "" {
		return nil, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("%w: read failed", ErrRevocationListUnavailable)
	}
	var list RevocationList
	if err := json.Unmarshal(data, &list); err != nil {
		return nil, fmt.Errorf("%w: parse failed", ErrRevocationListUnavailable)
	}
	if err := VerifyRevocationList(list, publicKeys, trustedIssuers, now); err != nil {
		return nil, fmt.Errorf("%w: verification failed: %v", ErrRevocationListUnavailable, err)
	}
	return &list, nil
}

// BaseVerificationOptions 返回只依赖环境变量的校验选项（公钥、可信签发方、吊销列表）。
// 部署指纹与时间状态来自数据库，由调用方补充。
func BaseVerificationOptions(now time.Time) VerificationOptions {
	publicKeysV2 := ParsePublicKeys(os.Getenv("JJD_LICENSE_PUBLIC_KEYS"))
	trustedIssuers := map[string]struct{}{defaultTrustedIssuer: {}}
	revocationList, revocationErr := LoadRevocationList(now, publicKeysV2, trustedIssuers)
	opts := VerificationOptions{
		PublicKeyV1:      os.Getenv("JJD_LICENSE_PUBLIC_KEY"),
		PublicKeysV2:     publicKeysV2,
		AcceptedProducts: []string{ProductJJDGuardEnterprise, ProductLegacyEnterprise},
		TrustedIssuers:   trustedIssuers,
		Now:              now,
		RevocationList:   revocationList,
	}
	if revocationErr != nil {
		opts.RevocationListError = revocationErr.Error()
	}
	return opts
}

// ParseTimeState 解析已存的时间状态；空串或损坏返回 nil。
func ParseTimeState(raw string) *TimeState {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	var state TimeState
	if json.Unmarshal([]byte(raw), &state) != nil {
		return nil
	}
	return &state
}

// EvaluateStored 判定已存授权的当前状态，不做任何写入。
// raw 为空时按安装锚点 anchorRaw 判定零签名试用；否则按 opts 校验。
func EvaluateStored(raw, importedAt, anchorRaw string, opts VerificationOptions, now time.Time) Status {
	if strings.TrimSpace(raw) == "" {
		anchor, _ := time.Parse(time.RFC3339, strings.TrimSpace(anchorRaw))
		st := TrialStatusFromAnchor(anchor, PublicKeySetFromEnv(), now)
		st.ImportedAt = importedAt
		return st
	}
	_, status, err := VerifyAny(raw, opts)
	if status == nil {
		status = &Status{
			Status:       StatusInvalid,
			Valid:        false,
			Reason:       "invalid license",
			TrialDays:    TrialWindowDays,
			PublicKeySet: PublicKeySetFromEnv(),
		}
		if err != nil {
			status.Reason = err.Error()
		}
	}
	status.ImportedAt = importedAt
	return *status
}
