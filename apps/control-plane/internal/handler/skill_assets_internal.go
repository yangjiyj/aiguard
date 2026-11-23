package handler

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

const (
	skillInternalDefinitionMaxBytes = int64(32 << 10)
	skillInternalInvocationMaxBytes = int64(48 << 10)
	skillInternalResultMaxBytes     = int64(32 << 10)
	skillInternalJSONMaxDepth       = 8
)

var skillTenantPattern = regexp.MustCompile("^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
var skillResultStatusPattern = regexp.MustCompile("^[a-z][a-z0-9_-]{0,23}$")

func internalSkillTenant(r *http.Request) (string, error) {
	values := r.Header.Values(SkillTenantHeader)
	if len(values) != 1 {
		return "", errors.New("exactly one X-Tenant-ID header is required")
	}
	tenantID := strings.TrimSpace(values[0])
	if strings.Contains(tenantID, ",") || !skillTenantPattern.MatchString(tenantID) {
		return "", errors.New("X-Tenant-ID is invalid")
	}
	return tenantID, nil
}

func decodeStrictSkillJSON(w http.ResponseWriter, r *http.Request, maxBytes int64, out any) error {
	r.Body = http.MaxBytesReader(w, r.Body, maxBytes)
	payload, err := io.ReadAll(r.Body)
	if err != nil {
		return errors.New("request body exceeds limit or is unreadable")
	}
	if len(bytes.TrimSpace(payload)) == 0 {
		return errors.New("JSON body required")
	}
	if err := validateSkillJSONShape(payload, skillInternalJSONMaxDepth); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(out); err != nil {
		return fmt.Errorf("invalid JSON contract: %w", err)
	}
	if err := ensureSkillJSONEOF(decoder); err != nil {
		return err
	}
	return nil
}

func ensureSkillJSONEOF(decoder *json.Decoder) error {
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("JSON body must contain exactly one value")
	}
	return nil
}

func validateSkillJSONShape(payload []byte, maxDepth int) error {
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.UseNumber()
	if err := consumeSkillJSONValue(decoder, 1, maxDepth); err != nil {
		return err
	}
	if decoder.More() {
		return errors.New("JSON body has trailing values")
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return errors.New("JSON body must contain exactly one value")
	}
	return nil
}

func consumeSkillJSONValue(decoder *json.Decoder, depth, maxDepth int) error {
	if depth > maxDepth {
		return errors.New("JSON nesting exceeds limit")
	}
	token, err := decoder.Token()
	if err != nil {
		return errors.New("invalid JSON")
	}
	delim, isDelim := token.(json.Delim)
	if !isDelim {
		return nil
	}
	switch delim {
	case '{':
		keys := map[string]struct{}{}
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return errors.New("invalid JSON object")
			}
			key, ok := keyToken.(string)
			if !ok {
				return errors.New("invalid JSON object key")
			}
			if _, exists := keys[key]; exists {
				return errors.New("duplicate JSON field")
			}
			keys[key] = struct{}{}
			if len(keys) > 128 {
				return errors.New("too many JSON fields")
			}
			if err := consumeSkillJSONValue(decoder, depth+1, maxDepth); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim('}') {
			return errors.New("invalid JSON object")
		}
	case '[':
		count := 0
		for decoder.More() {
			count++
			if count > 256 {
				return errors.New("too many JSON array elements")
			}
			if err := consumeSkillJSONValue(decoder, depth+1, maxDepth); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim(']') {
			return errors.New("invalid JSON array")
		}
	default:
		return errors.New("invalid JSON delimiter")
	}
	return nil
}

type observeSkillDefinitionRequest struct {
	TenantID        string `json:"tenant_id,omitempty"`
	CanonicalName   string `json:"canonical_name"`
	DisplayName     string `json:"display_name,omitempty"`
	DeclaredVersion string `json:"declared_version"`
	DefinitionHash  string `json:"definition_hash"`
	SourceURI       string `json:"source_uri,omitempty"`
	Publisher       string `json:"publisher,omitempty"`
}

func ObserveSkillDefinition(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !skillRepoReady(deps, w) {
			return
		}
		tenantID, err := internalSkillTenant(r)
		if err != nil {
			writeErrorWithStatus(w, http.StatusBadRequest, "invalid_tenant", err.Error())
			return
		}
		var request observeSkillDefinitionRequest
		if err := decodeStrictSkillJSON(w, r, skillInternalDefinitionMaxBytes, &request); err != nil {
			writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", err.Error())
			return
		}
		request.CanonicalName = canonicalSkillAssetName(request.CanonicalName)
		request.DisplayName = strings.TrimSpace(request.DisplayName)
		request.DeclaredVersion = strings.TrimSpace(request.DeclaredVersion)
		request.DefinitionHash = strings.ToLower(strings.TrimSpace(request.DefinitionHash))
		request.Publisher = strings.TrimSpace(request.Publisher)
		for _, check := range []struct {
			name, value string
			max         int
			required    bool
		}{
			{"canonical_name", request.CanonicalName, 255, true},
			{"display_name", request.DisplayName, 255, false},
			{"declared_version", request.DeclaredVersion, 255, true},
			{"publisher", request.Publisher, 255, false},
		} {
			if err := validateObservedSkillText(check.name, check.value, check.max, check.required); err != nil {
				writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", err.Error())
				return
			}
		}
		if !validSkillHash(request.DefinitionHash) {
			writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "definition_hash must be 64 lowercase hex characters")
			return
		}
		request.SourceURI, err = validateSkillSourceURI(request.SourceURI)
		if err != nil {
			writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", err.Error())
			return
		}
		manifest, _ := json.Marshal(map[string]any{
			"surface":         "gateway_observed",
			"definition_hash": request.DefinitionHash,
		})
		version, err := deps.SkillAssetsRepo.UpsertVersion(r.Context(), repository.SkillVersionUpsert{
			TenantID:        tenantID,
			CanonicalName:   request.CanonicalName,
			DisplayName:     request.DisplayName,
			SourceType:      "observed",
			SourceURI:       request.SourceURI,
			Publisher:       request.Publisher,
			DeclaredVersion: request.DeclaredVersion,
			BundleHash:      request.DefinitionHash,
			TreeHash:        request.DefinitionHash,
			SignatureStatus: "unknown",
			ManifestJSON:    manifest,
			FindingsJSON:    []byte("[]"),
			RiskLevel:       "medium",
			Decision:        "confirm",
			ScanStatus:      "pending",
			AdmissionStatus: "unverified",
		})
		if err != nil {
			writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", "failed to persist gateway-observed Skill definition")
			return
		}
		writeSkillJSON(w, http.StatusCreated, map[string]any{
			"asset_id":                       version.AssetID,
			"version_id":                     version.ID,
			"status":                         version.AdmissionStatus,
			"decision":                       version.Decision,
			"risk_level":                     version.RiskLevel,
			"definition_fingerprint":         request.DefinitionHash,
			"observation_surface":            "gateway_observed",
			"endpoint_installation_observed": false,
		})
	}
}

func ResolveSkillAdmission(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !skillRepoReady(deps, w) {
			return
		}
		tenantID, err := internalSkillTenant(r)
		if err != nil {
			writeErrorWithStatus(w, http.StatusBadRequest, "invalid_tenant", err.Error())
			return
		}
		canonicalName := canonicalSkillAssetName(r.URL.Query().Get("canonical_name"))
		version := strings.TrimSpace(r.URL.Query().Get("version"))
		bundleHash := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("bundle_hash")))
		if err := validateObservedSkillText("canonical_name", canonicalName, 255, true); err != nil {
			writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", err.Error())
			return
		}
		if err := validateObservedSkillText("version", version, 255, true); err != nil {
			writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", err.Error())
			return
		}
		if !validSkillHash(bundleHash) {
			writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "bundle_hash must be 64 lowercase hex characters")
			return
		}
		resolution, err := deps.SkillAssetsRepo.ResolveAdmission(r.Context(), tenantID, canonicalName, version, bundleHash)
		if err != nil {
			writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", "failed to resolve Skill admission")
			return
		}
		if resolution.Status == "" {
			resolution.Status = "unverified"
		}
		if resolution.Decision == "" {
			resolution.Decision = "confirm"
		}
		if resolution.RiskLevel == "" {
			resolution.RiskLevel = "high"
		}
		writeSkillJSON(w, http.StatusOK, map[string]any{
			"asset_id":   resolution.AssetID,
			"version_id": resolution.VersionID,
			"status":     resolution.Status,
			"decision":   resolution.Decision,
			"risk_level": resolution.RiskLevel,
		})
	}
}

type recordSkillInvocationRequest struct {
	TenantID              string          `json:"tenant_id,omitempty"`
	AssetID               string          `json:"asset_id,omitempty"`
	VersionID             string          `json:"version_id,omitempty"`
	RequestID             string          `json:"request_id"`
	SessionID             string          `json:"session_id,omitempty"`
	ToolCallID            string          `json:"tool_call_id"`
	CanonicalName         string          `json:"canonical_name"`
	DeclaredVersion       string          `json:"declared_version,omitempty"`
	SourceURI             string          `json:"source_uri,omitempty"`
	Status                string          `json:"status"`
	RawDecision           string          `json:"raw_decision"`
	EffectiveDecision     string          `json:"effective_decision"`
	ParametersDigest      string          `json:"parameters_digest,omitempty"`
	RedactedPreview       json.RawMessage `json:"redacted_preview,omitempty"`
	AttributionMode       string          `json:"attribution_mode,omitempty"`
	AttributionConfidence float64         `json:"attribution_confidence,omitempty"`
	// 请求归属：网关上报 Skill 调用时带上请求上下文里的用户 / 项目 / API key，
	// 用于 skill_invocation_risk 告警归属。旧网关不传时三者为空，行为与之前一致。
	UserID    string `json:"user_id,omitempty"`
	ProjectID string `json:"project_id,omitempty"`
	APIKeyID  string `json:"api_key_id,omitempty"`
}

func RecordSkillInvocation(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !skillRepoReady(deps, w) {
			return
		}
		tenantID, err := internalSkillTenant(r)
		if err != nil {
			writeErrorWithStatus(w, http.StatusBadRequest, "invalid_tenant", err.Error())
			return
		}
		var request recordSkillInvocationRequest
		if err := decodeStrictSkillJSON(w, r, skillInternalInvocationMaxBytes, &request); err != nil {
			writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", err.Error())
			return
		}
		request.CanonicalName = canonicalSkillAssetName(request.CanonicalName)
		request.RequestID = strings.TrimSpace(request.RequestID)
		request.SessionID = strings.TrimSpace(request.SessionID)
		request.ToolCallID = strings.TrimSpace(request.ToolCallID)
		request.AssetID = strings.TrimSpace(request.AssetID)
		request.VersionID = strings.TrimSpace(request.VersionID)
		request.DeclaredVersion = strings.TrimSpace(request.DeclaredVersion)
		for _, check := range []struct {
			name, value string
			max         int
			required    bool
		}{
			{"request_id", request.RequestID, 255, true},
			{"session_id", request.SessionID, 255, false},
			{"tool_call_id", request.ToolCallID, 255, true},
			{"asset_id", request.AssetID, 128, false},
			{"version_id", request.VersionID, 128, false},
			{"canonical_name", request.CanonicalName, 255, true},
			{"declared_version", request.DeclaredVersion, 255, false},
		} {
			if err := validateObservedSkillText(check.name, check.value, check.max, check.required); err != nil {
				writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", err.Error())
				return
			}
		}
		if request.VersionID != "" && request.AssetID == "" {
			writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "version_id requires asset_id")
			return
		}
		request.SourceURI, err = validateSkillSourceURI(request.SourceURI)
		if err != nil {
			writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", err.Error())
			return
		}
		request.Status = strings.ToLower(strings.TrimSpace(request.Status))
		if !oneOfSkill(request.Status, "proposed", "confirmed", "blocked", "forwarded") {
			writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "invalid invocation status")
			return
		}
		request.RawDecision = strings.ToLower(strings.TrimSpace(request.RawDecision))
		request.EffectiveDecision = strings.ToLower(strings.TrimSpace(request.EffectiveDecision))
		if !oneOfSkill(request.RawDecision, "allow", "audit", "confirm", "block") ||
			!oneOfSkill(request.EffectiveDecision, "allow", "audit", "confirm", "block") {
			writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "invalid Skill decision")
			return
		}
		request.ParametersDigest = strings.ToLower(strings.TrimSpace(request.ParametersDigest))
		if request.ParametersDigest != "" && !validSkillHash(request.ParametersDigest) {
			writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "parameters_digest must be 64 lowercase hex characters")
			return
		}
		preview, err := sanitizedSkillPreview(request.RedactedPreview)
		if err != nil {
			writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", err.Error())
			return
		}
		request.AttributionMode = strings.ToLower(strings.TrimSpace(request.AttributionMode))
		if request.SessionID == "" {
			if request.AttributionMode != "" && request.AttributionMode != "none" {
				writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "session-less observation must use attribution_mode=none")
				return
			}
			request.AttributionMode = "none"
			request.AttributionConfidence = 0
		} else {
			if request.AttributionMode == "" {
				request.AttributionMode = "explicit"
			}
			if !oneOfSkill(request.AttributionMode, "explicit", "linked", "none") {
				writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "unsupported attribution mode")
				return
			}
			if request.AttributionConfidence < 0 || request.AttributionConfidence > 1 {
				writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "attribution_confidence must be between 0 and 1")
				return
			}
		}
		invocation, err := deps.SkillAssetsRepo.RecordInvocation(r.Context(), repository.SkillInvocationUpsert{
			TenantID:              tenantID,
			AssetID:               request.AssetID,
			AssetVersionID:        request.VersionID,
			RequestID:             request.RequestID,
			SessionID:             request.SessionID,
			ToolCallID:            request.ToolCallID,
			CanonicalName:         request.CanonicalName,
			DeclaredVersion:       request.DeclaredVersion,
			SourceURI:             request.SourceURI,
			Status:                request.Status,
			RawDecision:           request.RawDecision,
			EffectiveDecision:     request.EffectiveDecision,
			ParametersDigest:      request.ParametersDigest,
			RedactedPreviewJSON:   preview,
			AttributionMode:       request.AttributionMode,
			AttributionConfidence: request.AttributionConfidence,
		})
		if err != nil {
			if errors.Is(err, repository.ErrSkillInvocationConflict) {
				writeErrorWithStatus(w, http.StatusConflict, "invocation_conflict", "tool_call_id was already used with different Skill identity or parameters")
				return
			}
			writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", "failed to record Skill invocation observation")
			return
		}
		writeSkillJSON(w, http.StatusCreated, map[string]any{
			"invocation_id":            invocation.ID,
			"observation_scope":        "gateway_observed",
			"endpoint_execution_proof": false,
		})
		writeSkillInvocationSecurityEvent(r.Context(), deps, tenantID, request)
	}
}

// skillInvocationActionTaken maps the effective Skill decision to the
// security_events.action_taken vocabulary.
func skillInvocationActionTaken(effective string) string {
	switch effective {
	case "confirm":
		return "confirm"
	case "block":
		return "block"
	case "allow":
		return "allow"
	default:
		return "audit"
	}
}

// writeSkillInvocationSecurityEvent raises one skill_invocation_risk security
// event per recorded Skill invocation so the skill risk domain always has an
// alert flow. The proposed record carries no risk level, so every invocation
// is surfaced at low severity — except confirm/block decisions, which are
// always high (spec: prefer low-noise over a silent skill domain). Best-effort:
// a failed event write never fails the invocation observation itself.
func writeSkillInvocationSecurityEvent(ctx context.Context, deps *Dependencies, tenantID string, request recordSkillInvocationRequest) {
	if deps == nil || deps.SecurityEventRepo == nil {
		return
	}
	if err := deps.SecurityEventRepo.Upsert(ctx, buildSkillInvocationSecurityEvent(tenantID, request)); err != nil {
		log.Printf("[skill] write skill_invocation_risk event failed (tenant=%s tool_call=%s): %v", tenantID, request.ToolCallID, err)
	}
}

// buildSkillInvocationSecurityEvent 拼装 skill_invocation_risk 事件（纯函数，便于脱离数据库测试）。
// 项目、用户取请求上报的归属，缺失时才回退默认项目 / 空用户；API key 作为主体键的回退，
// 同时记入 matched_summary 便于溯源。
func buildSkillInvocationSecurityEvent(tenantID string, request recordSkillInvocationRequest) repository.SecurityEventUpsert {
	severity := "low"
	if request.EffectiveDecision == "confirm" || request.EffectiveDecision == "block" {
		severity = "high"
	}
	projectID := strings.TrimSpace(request.ProjectID)
	if projectID == "" {
		projectID = defaultEvalIntegrationProjectID
	}
	userID := strings.TrimSpace(request.UserID)
	apiKeyID := strings.TrimSpace(request.APIKeyID)
	principalKey := userID
	if principalKey == "" {
		principalKey = apiKeyID
	}
	// Deterministic event ID: a gateway retry of the same tool call folds onto
	// the same row (Upsert ON CONFLICT) instead of duplicating the alert.
	digest := sha256.Sum256([]byte("skill_invocation|" + tenantID + "|" + request.ToolCallID))
	summary := map[string]interface{}{
		"skill_name":         request.CanonicalName,
		"skill_version":      request.DeclaredVersion,
		"asset_id":           request.AssetID,
		"raw_decision":       request.RawDecision,
		"effective_decision": request.EffectiveDecision,
		"source":             "gateway",
		"stage":              "tool",
		"summary":            "Skill 调用风险观察",
	}
	if apiKeyID != "" {
		summary["api_key_id"] = apiKeyID
	}
	return repository.SecurityEventUpsert{
		ID:        "evt_" + hex.EncodeToString(digest[:])[:16],
		RequestID: request.RequestID,
		TenantID:  tenantID,
		ProjectID: projectID,
		UserID:    userID,
		EventType: "skill_invocation_risk",
		Severity:  severity,
		// audit→audit / confirm→confirm / block→block / allow→allow
		ActionTaken:    skillInvocationActionTaken(request.EffectiveDecision),
		MatchedSummary: summary,
		PrincipalKey:   principalKey,
	}
}

func sanitizedSkillPreview(raw json.RawMessage) ([]byte, error) {
	if len(bytes.TrimSpace(raw)) == 0 {
		return []byte("{}"), nil
	}
	if len(raw) > 8192 {
		return nil, errors.New("redacted_preview exceeds limit")
	}
	if err := validateSkillJSONShape(raw, 4); err != nil {
		return nil, fmt.Errorf("redacted_preview: %w", err)
	}
	var preview map[string]any
	if err := json.Unmarshal(raw, &preview); err != nil || preview == nil {
		return nil, errors.New("redacted_preview must be a JSON object")
	}
	nodes := 0
	sanitized, err := sanitizeSkillPreviewMap(preview, 0, &nodes)
	if err != nil {
		return nil, err
	}
	return json.Marshal(sanitized)
}

func sanitizeSkillPreviewMap(input map[string]any, depth int, nodes *int) (map[string]any, error) {
	if depth > 3 || len(input) > 32 {
		return nil, errors.New("redacted_preview exceeds structure limits")
	}
	out := make(map[string]any, len(input))
	for key, value := range input {
		*nodes++
		if *nodes > 128 {
			return nil, errors.New("redacted_preview exceeds node limit")
		}
		key = strings.TrimSpace(key)
		if err := validateObservedSkillText("redacted_preview key", key, 64, true); err != nil {
			return nil, err
		}
		sensitive := isSensitiveSkillPreviewKey(key) || !isAllowedSkillPreviewKey(key)
		clean, err := sanitizeSkillPreviewValue(value, depth+1, nodes, sensitive)
		if err != nil {
			return nil, err
		}
		out[key] = clean
	}
	return out, nil
}

func sanitizeSkillPreviewValue(value any, depth int, nodes *int, sensitive bool) (any, error) {
	if sensitive {
		return "[redacted]", nil
	}
	switch typed := value.(type) {
	case nil, bool, float64:
		return typed, nil
	case string:
		if !utf8.ValidString(typed) {
			return nil, errors.New("redacted_preview contains invalid UTF-8")
		}
		typed = strings.TrimSpace(typed)
		if looksSensitiveSkillPreviewValue(typed) {
			return "[redacted]", nil
		}
		runes := []rune(typed)
		if len(runes) > 160 {
			runes = runes[:160]
		}
		return string(runes), nil
	case map[string]any:
		return sanitizeSkillPreviewMap(typed, depth, nodes)
	case []any:
		if depth > 3 || len(typed) > 32 {
			return nil, errors.New("redacted_preview exceeds structure limits")
		}
		out := make([]any, 0, len(typed))
		for _, item := range typed {
			*nodes++
			if *nodes > 128 {
				return nil, errors.New("redacted_preview exceeds node limit")
			}
			clean, err := sanitizeSkillPreviewValue(item, depth+1, nodes, false)
			if err != nil {
				return nil, err
			}
			out = append(out, clean)
		}
		return out, nil
	default:
		return nil, errors.New("redacted_preview contains unsupported value")
	}
}

func isSensitiveSkillPreviewKey(key string) bool {
	key = strings.ToLower(key)
	for _, marker := range []string{"secret", "token", "password", "passwd", "authorization", "api_key", "apikey", "credential", "cookie", "private_key", "content", "body", "prompt"} {
		if strings.Contains(key, marker) {
			return true
		}
	}
	return false
}

func isAllowedSkillPreviewKey(key string) bool {
	switch strings.ToLower(strings.TrimSpace(key)) {
	case "skill", "skill_name", "canonical_name", "name",
		"version", "declared_version", "bundle_hash", "tree_hash",
		"source", "source_uri", "target", "path", "url", "host",
		"method", "operation", "tool", "tool_name", "status":
		return true
	default:
		return false
	}
}

func looksSensitiveSkillPreviewValue(value string) bool {
	lower := strings.ToLower(value)
	if parsed, err := url.Parse(value); err == nil && parsed.User != nil {
		return true
	}
	return strings.Contains(lower, "bearer ") ||
		strings.Contains(lower, "-----begin ") ||
		strings.HasPrefix(lower, "sk-") ||
		strings.Count(value, ".") == 2 && len(value) > 80 ||
		strings.Contains(value, "?")
}

type skillResultFinding struct {
	Type        string `json:"type"`
	Severity    string `json:"severity,omitempty"`
	Code        string `json:"code,omitempty"`
	RuleID      string `json:"rule_id,omitempty"`
	Category    string `json:"category,omitempty"`
	Field       string `json:"field,omitempty"`
	ContentHash string `json:"content_hash,omitempty"`
}

type linkSkillResultRequest struct {
	TenantID     string          `json:"tenant_id,omitempty"`
	RequestID    string          `json:"request_id,omitempty"`
	SessionID    string          `json:"session_id"`
	ToolCallID   string          `json:"tool_call_id"`
	ResultStatus string          `json:"result_status"`
	Findings     json.RawMessage `json:"findings"`
}

func LinkSkillResult(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !skillRepoReady(deps, w) {
			return
		}
		tenantID, err := internalSkillTenant(r)
		if err != nil {
			writeErrorWithStatus(w, http.StatusBadRequest, "invalid_tenant", err.Error())
			return
		}
		var request linkSkillResultRequest
		if err := decodeStrictSkillJSON(w, r, skillInternalResultMaxBytes, &request); err != nil {
			writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", err.Error())
			return
		}
		request.SessionID = strings.TrimSpace(request.SessionID)
		request.ToolCallID = strings.TrimSpace(request.ToolCallID)
		request.ResultStatus = strings.ToLower(strings.TrimSpace(request.ResultStatus))
		if err := validateObservedSkillText("session_id", request.SessionID, 255, true); err != nil {
			writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", err.Error())
			return
		}
		if err := validateObservedSkillText("tool_call_id", request.ToolCallID, 255, true); err != nil {
			writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", err.Error())
			return
		}
		if !skillResultStatusPattern.MatchString(request.ResultStatus) {
			writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "result_status is invalid")
			return
		}
		findings, err := validateSkillResultFindings(request.Findings)
		if err != nil {
			writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", err.Error())
			return
		}
		if err := deps.SkillAssetsRepo.MarkInvocationResult(
			r.Context(), tenantID, request.SessionID, request.ToolCallID, request.ResultStatus, findings,
		); err != nil {
			writeErrorWithStatus(w, http.StatusNotFound, "not_found", "matching Skill invocation observation was not found")
			return
		}
		writeSkillJSON(w, http.StatusOK, map[string]any{
			"status":                   "linked",
			"attribution_mode":         "linked",
			"link_key":                 "tenant_session_tool_call",
			"endpoint_execution_proof": false,
		})
	}
}

func validateSkillResultFindings(raw json.RawMessage) ([]byte, error) {
	if len(bytes.TrimSpace(raw)) == 0 {
		return []byte("[]"), nil
	}
	if len(raw) > 16384 {
		return nil, errors.New("findings exceed limit")
	}
	if err := validateSkillJSONShape(raw, 4); err != nil {
		return nil, fmt.Errorf("findings: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var findings []skillResultFinding
	if err := decoder.Decode(&findings); err != nil {
		return nil, errors.New("findings must contain only sanitized finding fields")
	}
	if len(findings) > 100 {
		return nil, errors.New("too many findings")
	}
	for i := range findings {
		findings[i].Type = strings.TrimSpace(findings[i].Type)
		findings[i].Severity = strings.ToLower(strings.TrimSpace(findings[i].Severity))
		findings[i].Code = strings.TrimSpace(findings[i].Code)
		findings[i].RuleID = strings.TrimSpace(findings[i].RuleID)
		findings[i].Category = strings.TrimSpace(findings[i].Category)
		findings[i].Field = strings.TrimSpace(findings[i].Field)
		findings[i].ContentHash = strings.ToLower(strings.TrimSpace(findings[i].ContentHash))
		for _, check := range []struct {
			name, value string
			max         int
			required    bool
		}{
			{"finding type", findings[i].Type, 64, true},
			{"finding code", findings[i].Code, 64, false},
			{"finding rule_id", findings[i].RuleID, 64, false},
			{"finding category", findings[i].Category, 64, false},
			{"finding field", findings[i].Field, 128, false},
		} {
			if err := validateObservedSkillText(check.name, check.value, check.max, check.required); err != nil {
				return nil, err
			}
		}
		if findings[i].Severity != "" && !oneOfSkill(findings[i].Severity, "low", "medium", "high", "critical") {
			return nil, errors.New("finding severity is invalid")
		}
		if findings[i].ContentHash != "" && !validSkillHash(findings[i].ContentHash) {
			return nil, errors.New("finding content_hash is invalid")
		}
	}
	return json.Marshal(findings)
}

func oneOfSkill(value string, candidates ...string) bool {
	for _, candidate := range candidates {
		if value == candidate {
			return true
		}
	}
	return false
}
