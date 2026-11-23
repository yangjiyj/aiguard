package handler

import (
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/bootstrap"
	entlicense "github.com/yangjiyj/aiguard/apps/control-plane/internal/license"
	"github.com/yangjiyj/aiguard/packages/shared-go/buildinfo"
)

const (
	LicenseSettingKey           = entlicense.SettingKeyLicense
	LicenseImportedAtSettingKey = entlicense.SettingKeyImportedAt
	LicenseTimeStateSettingKey  = entlicense.SettingKeyTimeState
	LicenseDeploymentIDKey      = entlicense.SettingKeyDeploymentID
)

type importLicenseRequest struct {
	License string `json:"license"`
}

func GetLicenseStatus(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		stored, err := getLicenseSetting(r, deps, LicenseSettingKey)
		if err != nil {
			writeError(w, "internal_error", "failed to load license")
			return
		}
		importedAt, err := getLicenseSetting(r, deps, LicenseImportedAtSettingKey)
		if err != nil {
			writeError(w, "internal_error", "failed to load license")
			return
		}
		status := licenseStatusFromStored(r, deps, stored, importedAt, time.Now().UTC())
		writeJSON(w, status)
	}
}

func ImportLicense(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !requirePlatformAdmin(w, r) {
			return
		}
		var req importLicenseRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, "invalid_request", "invalid JSON format")
			return
		}
		status, err := importLicense(r, deps, req.License)
		if err != nil {
			writeErrorWithStatus(w, http.StatusBadRequest, "invalid_license", err.Error())
			return
		}
		logAudit(r, deps, "license.import", map[string]interface{}{
			"license_id":   licenseID(status),
			"customer":     licenseCustomer(status),
			"license_type": licenseType(status),
			"expires_at":   licenseExpiresAt(status),
		}, "system", "license")
		writeJSON(w, status)
	}
}

func LicenseGuard(deps *Dependencies) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !licenseEnforcementEnabled() || licenseGuardBypass(r.URL.Path) {
				next.ServeHTTP(w, r)
				return
			}
			stored, err := getLicenseSetting(r, deps, LicenseSettingKey)
			if err != nil {
				writeError(w, "internal_error", "failed to load license")
				return
			}
			status := licenseStatusFromStored(r, deps, stored, "", time.Now().UTC())
			if status.Valid {
				if !enforceLicensedFeature(w, r, status) {
					return
				}
				next.ServeHTTP(w, r)
				return
			}
			if licenseReadOnlyMethod(r.Method) && requiredLicenseFeature(r.URL.Path) != "agent_security" {
				next.ServeHTTP(w, r)
				return
			}
			writeErrorWithStatus(w, http.StatusPaymentRequired, "license_required", "license 已到期，续期后方可修改配置")
		})
	}
}

func importLicense(r *http.Request, deps *Dependencies, raw string) (*entlicense.Status, error) {
	raw = strings.TrimSpace(raw)
	now := time.Now().UTC()
	opts := licenseVerificationOptions(r, deps, now)
	_, status, err := entlicense.VerifyAny(raw, opts)
	if err != nil {
		return status, err
	}
	importedAt := now.Format(time.RFC3339)
	settings := map[string]string{
		LicenseSettingKey:           raw,
		LicenseImportedAtSettingKey: importedAt,
	}
	if status.Version == entlicense.SchemaVersionV2 && status.PayloadV2 != nil {
		state, err := json.Marshal(entlicense.TimeState{
			SchemaVersion:    entlicense.TimeStateSchemaVersion,
			LicenseID:        status.PayloadV2.LicenseID,
			LastSeenWallTime: importedAt,
			MaxSeenWallTime:  importedAt,
			FirstSeenAt:      importedAt,
		})
		if err != nil {
			return nil, err
		}
		settings[LicenseTimeStateSettingKey] = string(state)
	}
	if err := deps.SystemRepo.SetMultiple(r.Context(), settings); err != nil {
		return nil, err
	}
	status.ImportedAt = importedAt
	return status, nil
}

func licenseStatusFromStored(r *http.Request, deps *Dependencies, raw string, importedAt string, now time.Time) entlicense.Status {
	if strings.TrimSpace(raw) == "" {
		anchorRaw, _ := getLicenseSetting(r, deps, bootstrap.LicenseInstallAnchorKey)
		return entlicense.EvaluateStored("", importedAt, anchorRaw, entlicense.VerificationOptions{}, now)
	}
	opts := licenseVerificationOptions(r, deps, now)
	status := entlicense.EvaluateStored(raw, importedAt, "", opts, now)
	persistLicenseTimeState(r, deps, &status, opts.TimeState, now)
	return status
}

func licenseVerificationOptions(r *http.Request, deps *Dependencies, now time.Time) entlicense.VerificationOptions {
	opts := entlicense.BaseVerificationOptions(now)
	if deps != nil && deps.SystemRepo != nil && r != nil {
		if deploymentID := getOrCreateLicenseDeploymentID(r, deps); deploymentID != "" {
			opts.DeploymentFingerprints = append(opts.DeploymentFingerprints, entlicense.Fingerprint{
				Scope:     "deployment",
				Algorithm: "sha256",
				Value:     deploymentFingerprint(deploymentID),
			})
		}
		if rawState, err := getLicenseSetting(r, deps, LicenseTimeStateSettingKey); err == nil {
			opts.TimeState = entlicense.ParseTimeState(rawState)
		}
	}
	return opts
}

func parseLicensePublicKeys(raw string) map[string]string { return entlicense.ParsePublicKeys(raw) }

func loadLicenseRevocationList(now time.Time, publicKeys map[string]string, trustedIssuerSet ...map[string]struct{}) (*entlicense.RevocationList, error) {
	return entlicense.LoadRevocationList(now, publicKeys, trustedIssuerSet...)
}

func persistLicenseTimeState(r *http.Request, deps *Dependencies, status *entlicense.Status, previous *entlicense.TimeState, now time.Time) {
	if r == nil || deps == nil || deps.SystemRepo == nil || status == nil || status.PayloadV2 == nil || status.Version != entlicense.SchemaVersionV2 {
		return
	}
	licenseID := status.PayloadV2.LicenseID
	nowText := now.UTC().Format(time.RFC3339)
	state := entlicense.TimeState{
		SchemaVersion:    entlicense.TimeStateSchemaVersion,
		LicenseID:        licenseID,
		LastSeenWallTime: nowText,
		MaxSeenWallTime:  nowText,
		FirstSeenAt:      nowText,
	}
	if previous != nil {
		state.FirstSeenAt = previous.FirstSeenAt
		if strings.TrimSpace(state.FirstSeenAt) == "" || previous.LicenseID != licenseID {
			state.FirstSeenAt = nowText
		}
		state.MaxSeenWallTime = maxRFC3339(previous.MaxSeenWallTime, nowText)
		if previous.ClockRollbackDetectedAt != "" {
			state.ClockRollbackDetectedAt = previous.ClockRollbackDetectedAt
		}
	}
	if status.Clock != nil && status.Clock.RollbackDetected {
		state.MaxSeenWallTime = maxRFC3339(state.MaxSeenWallTime, status.Clock.MaxSeenWallTime)
		if strings.TrimSpace(state.ClockRollbackDetectedAt) == "" {
			state.ClockRollbackDetectedAt = nowText
		}
	}
	data, err := json.Marshal(state)
	if err != nil {
		return
	}
	_ = deps.SystemRepo.Set(r.Context(), LicenseTimeStateSettingKey, string(data))
}

func maxRFC3339(a, b string) string {
	ta, errA := time.Parse(time.RFC3339, strings.TrimSpace(a))
	tb, errB := time.Parse(time.RFC3339, strings.TrimSpace(b))
	if errA != nil {
		if errB != nil {
			return ""
		}
		return tb.UTC().Format(time.RFC3339)
	}
	if errB != nil {
		return ta.UTC().Format(time.RFC3339)
	}
	if tb.After(ta) {
		return tb.UTC().Format(time.RFC3339)
	}
	return ta.UTC().Format(time.RFC3339)
}

func licensePublicKeySet() bool { return entlicense.PublicKeySetFromEnv() }

func licenseEnforcementEnabled() bool {
	value := strings.ToLower(strings.TrimSpace(os.Getenv("JJD_LICENSE_ENFORCE")))
	return value != "false" && value != "0" && value != "no"
}

func licenseReadOnlyMethod(method string) bool {
	return method == http.MethodGet || method == http.MethodHead
}

func licenseGuardBypass(path string) bool {
	if path == "/admin/v1/system/license" ||
		path == "/admin/v1/system/product" ||
		path == "/admin/v1/system/version" ||
		path == "/admin/v1/system/license/import" ||
		path == "/admin/v1/system/license/trial" {
		return true
	}
	return strings.HasPrefix(path, "/admin/v1/me") ||
		path == "/admin/v1/logout"
}

func getLicenseSetting(r *http.Request, deps *Dependencies, key string) (string, error) {
	setting, err := deps.SystemRepo.Get(r.Context(), key)
	if err != nil || setting == nil {
		return "", err
	}
	return setting.Value, nil
}

func getOrCreateLicenseDeploymentID(r *http.Request, deps *Dependencies) string {
	deploymentID, err := getLicenseSetting(r, deps, LicenseDeploymentIDKey)
	if err != nil {
		return ""
	}
	deploymentID = strings.TrimSpace(deploymentID)
	if deploymentID != "" {
		return deploymentID
	}
	deploymentID = "dep_" + uuid.NewString()
	if err := deps.SystemRepo.Set(r.Context(), LicenseDeploymentIDKey, deploymentID); err != nil {
		return ""
	}
	return deploymentID
}

func deploymentFingerprint(deploymentID string) string {
	return entlicense.DeploymentFingerprint(deploymentID)
}

func requirePlatformAdmin(w http.ResponseWriter, r *http.Request) bool {
	user := auth.GetUser(r.Context())
	if user == nil || user.Role != "platform_admin" {
		writeErrorWithStatus(w, http.StatusForbidden, "forbidden", "insufficient permissions")
		return false
	}
	return true
}

func licenseID(status *entlicense.Status) string {
	if status == nil {
		return ""
	}
	if status.PayloadV2 != nil {
		return status.PayloadV2.LicenseID
	}
	if status.Payload == nil {
		return ""
	}
	return status.Payload.LicenseID
}

func licenseCustomer(status *entlicense.Status) string {
	if status == nil {
		return ""
	}
	if status.PayloadV2 != nil {
		return status.PayloadV2.Customer.DisplayName
	}
	if status.Payload == nil {
		return ""
	}
	return status.Payload.Customer
}

func licenseType(status *entlicense.Status) string {
	if status == nil {
		return ""
	}
	if status.PayloadV2 != nil {
		return status.PayloadV2.Edition
	}
	if status.Payload == nil {
		return ""
	}
	return status.Payload.LicenseType
}

func licenseExpiresAt(status *entlicense.Status) string {
	if status == nil {
		return ""
	}
	if status.PayloadV2 != nil {
		return status.PayloadV2.ExpiresAt
	}
	if status.Payload == nil {
		return ""
	}
	return status.Payload.ExpiresAt.Format(time.RFC3339)
}

// GetLicenseHostInfo 返回本机部署信息，供续费时按 deploymentId 绑定签发使用。
func GetLicenseHostInfo(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		depID := getOrCreateLicenseDeploymentID(r, deps)
		host, _ := os.Hostname()
		writeJSON(w, map[string]any{
			"product":      entlicense.ProductJJDGuardEnterprise,
			"deploymentId": depID,
			"fingerprint":  deploymentFingerprint(depID),
			"hostname":     host,
			"version":      buildinfo.Current().Version,
			"edition":      "enterprise",
			"generatedAt":  time.Now().UTC().Format(time.RFC3339),
		})
	}
}
