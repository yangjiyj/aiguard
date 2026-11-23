package handler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/roles"
	"io"
	"log"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/skillscan"
	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"
)

const (
	SkillTenantHeader      = "X-Tenant-ID"
	skillArchiveMaxBytes   = int64(20 << 20)
	skillMultipartMaxBytes = int64(21 << 20)
	skillFormFieldMaxBytes = int64(4096)
)

type SkillAssetsRepo interface {
	UpsertVersion(context.Context, repository.SkillVersionUpsert) (*repository.SkillAssetVersion, error)
	ListAssets(context.Context, string, int, int) ([]*repository.SkillAsset, error)
	ListAssetsPage(context.Context, string, repository.SkillAssetFilter) (repository.SkillAssetPage, error)
	ListVersions(context.Context, string, string) ([]*repository.SkillAssetVersion, error)
	GetVersionAdmissionSnapshot(context.Context, string, string) (repository.SkillVersionAdmissionSnapshot, error)
	SetVersionAdmission(context.Context, string, string, string, string, string) error
	SetVersionAdmissionReviewed(context.Context, string, string, repository.SkillAdmissionReview, string, string) error
	ResolveAdmission(context.Context, string, string, string, string) (repository.SkillAdmissionResolution, error)
	RecordInvocation(context.Context, repository.SkillInvocationUpsert) (*repository.SkillInvocation, error)
	MarkInvocationResult(context.Context, string, string, string, string, []byte) error
	ListInvocations(context.Context, string, int, int) ([]*repository.SkillInvocation, error)
	ListInvocationsPage(context.Context, string, repository.SkillInvocationFilter) (repository.SkillInvocationPage, error)
}

type SkillArchiveScanner interface {
	Scan([]byte) (skillscan.Report, error)
}

func skillAdmin(r *http.Request, w http.ResponseWriter) *repository.User {
	user := auth.GetUser(r.Context())
	if user == nil || strings.TrimSpace(user.TenantID) == "" {
		writeUnauthorized(w, "no user")
		return nil
	}
	if !canManageAgentGuard(user.Role) {
		writeErrorWithStatus(w, http.StatusForbidden, "forbidden", "only unit administrators can manage Skill admission")
		return nil
	}
	return user
}

// skillRecordReader 用于只读的 Skill 调用观察：SoD 把 GET skills/invocations 归 security_record_read，审计员可读；
// 准入、扫描等写操作与资产清单仍走 skillAdmin。
func skillRecordReader(r *http.Request, w http.ResponseWriter) *repository.User {
	user := auth.GetUser(r.Context())
	if user == nil || strings.TrimSpace(user.TenantID) == "" {
		writeUnauthorized(w, "no user")
		return nil
	}
	if !canManageAgentGuard(user.Role) && !roles.IsAuditor(user.Role) {
		writeErrorWithStatus(w, http.StatusForbidden, "forbidden", "only unit administrators, security officers or auditors can read Skill invocations")
		return nil
	}
	return user
}

func skillRepoReady(deps *Dependencies, w http.ResponseWriter) bool {
	if deps == nil || deps.SkillAssetsRepo == nil {
		writeErrorWithStatus(w, http.StatusServiceUnavailable, "service_unavailable", "Skill gateway asset service is not configured")
		return false
	}
	return true
}

func skillPagination(r *http.Request) (int, int) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	if limit <= 0 {
		limit = 50
	}
	if limit > 200 {
		limit = 200
	}
	if offset < 0 {
		offset = 0
	}
	return limit, offset
}

func ListSkillAssets(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := skillAdmin(r, w)
		if user == nil || !skillRepoReady(deps, w) {
			return
		}
		filter, err := skillAssetListFilter(r)
		if err != nil {
			writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", err.Error())
			return
		}
		page, err := deps.SkillAssetsRepo.ListAssetsPage(r.Context(), user.TenantID, filter)
		if err != nil {
			writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", "failed to list Skill assets")
			return
		}
		writeSkillJSON(w, http.StatusOK, page)
	}
}

func ListSkillAssetVersions(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := skillAdmin(r, w)
		if user == nil || !skillRepoReady(deps, w) {
			return
		}
		assetID := strings.TrimSpace(chi.URLParam(r, "id"))
		if err := validateSkillText("asset id", assetID, 128, true); err != nil {
			writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", err.Error())
			return
		}
		versions, err := deps.SkillAssetsRepo.ListVersions(r.Context(), user.TenantID, assetID)
		if err != nil {
			writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", "failed to list Skill versions")
			return
		}
		safeVersions := make([]*repository.SkillAssetVersion, len(versions))
		for i := range versions {
			safeVersions[i] = sanitizeSkillVersionEvidence(versions[i])
		}
		writeSkillJSON(w, http.StatusOK, map[string]any{
			"items":                       safeVersions,
			"total":                       len(versions),
			"analysis_surfaces":           []string{"gateway_observed", "uploaded_scan"},
			"endpoint_execution_observed": false,
		})
	}
}

func ListSkillInvocations(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := skillRecordReader(r, w)
		if user == nil || !skillRepoReady(deps, w) {
			return
		}
		filter, err := skillInvocationListFilter(r)
		if err != nil {
			writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", err.Error())
			return
		}
		page, err := deps.SkillAssetsRepo.ListInvocationsPage(r.Context(), user.TenantID, filter)
		if err != nil {
			writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", "failed to list Skill invocation observations")
			return
		}
		writeSkillJSON(w, http.StatusOK, page)
	}
}

type skillScanFields struct {
	CanonicalName   string
	DisplayName     string
	DeclaredVersion string
	SourceURI       string
	Publisher       string
	SourceCommit    string
	SignatureStatus string
	SignerIdentity  string
	Archive         []byte
}

var allowedSkillScanFields = map[string]bool{
	"canonical_name":   true,
	"display_name":     true,
	"declared_version": true,
	"source_uri":       true,
	"publisher":        true,
	"source_commit":    true,
}

func readSkillScanMultipart(w http.ResponseWriter, r *http.Request) (skillScanFields, error) {
	var out skillScanFields
	r.Body = http.MaxBytesReader(w, r.Body, skillMultipartMaxBytes)
	reader, err := r.MultipartReader()
	if err != nil {
		return out, errors.New("multipart/form-data required")
	}
	seen := map[string]bool{}
	parts := 0
	for {
		part, nextErr := reader.NextPart()
		if errors.Is(nextErr, io.EOF) {
			break
		}
		if nextErr != nil {
			return out, errors.New("multipart body exceeds limit or is malformed")
		}
		parts++
		if parts > 16 {
			_ = part.Close()
			return out, errors.New("too many multipart fields")
		}
		name := part.FormName()
		if name == "" || seen[name] {
			_ = part.Close()
			return out, errors.New("duplicate or unnamed multipart field")
		}
		seen[name] = true
		if name == "archive" {
			if part.FileName() == "" {
				_ = part.Close()
				return out, errors.New("archive must be a file")
			}
			payload, readErr := io.ReadAll(io.LimitReader(part, skillArchiveMaxBytes+1))
			_ = part.Close()
			if readErr != nil || int64(len(payload)) > skillArchiveMaxBytes {
				return out, errors.New("Skill zip exceeds 20 MiB")
			}
			out.Archive = payload
			continue
		}
		if !allowedSkillScanFields[name] {
			_ = part.Close()
			return out, errors.New("unsupported multipart field")
		}
		if part.FileName() != "" {
			_ = part.Close()
			return out, errors.New("only archive may be a file")
		}
		value, readErr := io.ReadAll(io.LimitReader(part, skillFormFieldMaxBytes+1))
		_ = part.Close()
		if readErr != nil || int64(len(value)) > skillFormFieldMaxBytes {
			return out, errors.New("multipart field exceeds limit")
		}
		switch name {
		case "canonical_name":
			out.CanonicalName = string(value)
		case "display_name":
			out.DisplayName = string(value)
		case "declared_version":
			out.DeclaredVersion = string(value)
		case "source_uri":
			out.SourceURI = string(value)
		case "publisher":
			out.Publisher = string(value)
		case "source_commit":
			out.SourceCommit = string(value)
		case "signature_status":
			out.SignatureStatus = string(value)
		case "signer_identity":
			out.SignerIdentity = string(value)
		}
	}
	if !seen["archive"] {
		return out, errors.New("archive file required")
	}
	return out, nil
}

func validateSkillScanFields(fields *skillScanFields) error {
	fields.CanonicalName = canonicalSkillAssetName(fields.CanonicalName)
	if fields.CanonicalName == "" {
		return errors.New("canonical_name required")
	}
	checks := []struct {
		name  string
		value *string
		max   int
	}{
		{"canonical_name", &fields.CanonicalName, 255},
		{"display_name", &fields.DisplayName, 255},
		{"declared_version", &fields.DeclaredVersion, 255},
		{"publisher", &fields.Publisher, 255},
		{"source_commit", &fields.SourceCommit, 255},
		{"signer_identity", &fields.SignerIdentity, 512},
	}
	for _, check := range checks {
		*check.value = strings.TrimSpace(*check.value)
		if err := validateSkillText(check.name, *check.value, check.max, check.name == "canonical_name" || check.name == "declared_version"); err != nil {
			return err
		}
	}
	var err error
	fields.SourceURI, err = validateSkillSourceURI(fields.SourceURI)
	if err != nil {
		return err
	}
	fields.SignatureStatus = strings.ToLower(strings.TrimSpace(fields.SignatureStatus))
	switch fields.SignatureStatus {
	case "", "unknown", "unsigned", "verified", "invalid":
	default:
		return errors.New("signature_status is invalid")
	}
	return nil
}

func ScanSkillArchive(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := skillAdmin(r, w)
		if user == nil || !skillRepoReady(deps, w) {
			return
		}
		fields, err := readSkillScanMultipart(w, r)
		if err != nil {
			writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", err.Error())
			return
		}
		if err := validateSkillScanFields(&fields); err != nil {
			writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", err.Error())
			return
		}
		scanner := deps.SkillArchiveScanner
		if scanner == nil {
			scanner = skillscan.NewScanner(skillscan.Limits{})
		}
		report, scanErr := scanner.Scan(fields.Archive)
		if report.Manifest == nil {
			report.Manifest = []skillscan.ManifestEntry{}
		}
		if report.Findings == nil {
			report.Findings = []skillscan.Finding{}
		}
		report.Findings = skillscan.SanitizeFindings(report.Findings)
		manifest, err := json.Marshal(map[string]any{
			"surface": "uploaded_scan",
			"files":   report.Manifest,
		})
		if err != nil {
			writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", "failed to encode scan manifest")
			return
		}
		findings, err := json.Marshal(report.Findings)
		if err != nil {
			writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", "failed to encode scan findings")
			return
		}
		scanStatus, scanErrorCode := "completed", ""
		if scanErr != nil {
			scanStatus = "failed"
			scanErrorCode = "archive_rejected"
			var typed *skillscan.ScanError
			if errors.As(scanErr, &typed) && typed.Code != "" {
				scanErrorCode = typed.Code
			}
		}
		initialAdmissionStatus := "unverified"
		if scanErr != nil || report.Decision == skillscan.DecisionBlock {
			initialAdmissionStatus = "quarantined"
		}
		version, err := deps.SkillAssetsRepo.UpsertVersion(r.Context(), repository.SkillVersionUpsert{
			TenantID:        user.TenantID,
			CanonicalName:   fields.CanonicalName,
			DisplayName:     fields.DisplayName,
			SourceType:      "uploaded",
			SourceURI:       fields.SourceURI,
			Publisher:       fields.Publisher,
			DeclaredVersion: fields.DeclaredVersion,
			SourceCommit:    fields.SourceCommit,
			BundleHash:      report.BundleHash,
			TreeHash:        report.TreeHash,
			SignatureStatus: fields.SignatureStatus,
			SignerIdentity:  fields.SignerIdentity,
			ManifestJSON:    manifest,
			FindingsJSON:    findings,
			RiskLevel:       string(report.RiskLevel),
			Decision:        string(report.Decision),
			ScanStatus:      scanStatus,
			ScanErrorCode:   scanErrorCode,
			AdmissionStatus: initialAdmissionStatus,
		})
		if err != nil {
			if errors.Is(err, repository.ErrSkillVersionDeclarationConflict) {
				writeErrorWithStatus(w, http.StatusConflict, "declaration_conflict", "This bundle is already registered with a different version declaration; existing evidence and approval were preserved")
				return
			}
			writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", "failed to persist Skill scan")
			return
		}
		status := http.StatusCreated
		if scanErr != nil {
			status = http.StatusUnprocessableEntity
		}
		writeSkillJSON(w, status, map[string]any{
			"version":                     sanitizeSkillVersionEvidence(version),
			"analysis_surface":            "uploaded_scan",
			"endpoint_execution_observed": false,
		})
	}
}

func SetSkillVersionAdmission(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := skillAdmin(r, w)
		if user == nil || !skillRepoReady(deps, w) {
			return
		}
		// 强制批准的审计由仓库用事务审计写：请求上下文带上审计链出口与来源地址（requestClientIP）。
		r = withOperationAudit(r, deps)
		versionID := strings.TrimSpace(chi.URLParam(r, "id"))
		if err := validateSkillText("version id", versionID, 128, true); err != nil {
			writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", err.Error())
			return
		}
		var request repository.SkillAdmissionReview
		if err := decodeStrictSkillJSON(w, r, 4096, &request); err != nil {
			writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", err.Error())
			return
		}
		request.Status = strings.ToLower(strings.TrimSpace(request.Status))
		request.ExpectedStatus = strings.ToLower(strings.TrimSpace(request.ExpectedStatus))
		request.ExpectedBundleHash = strings.ToLower(strings.TrimSpace(request.ExpectedBundleHash))
		request.Reason = strings.TrimSpace(request.Reason)
		request.OverrideReason = strings.TrimSpace(request.OverrideReason)
		if request.OverrideReason != "" && (request.Status != "approved" || validateSkillText("override_reason", request.OverrideReason, 512, true) != nil) {
			writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "override_reason is only for approvals and must be at most 512 characters")
			return
		}
		if !validSkillHash(request.ExpectedBundleHash) || !oneOfSkill(request.ExpectedStatus, "unverified", "approved", "quarantined", "revoked") || validateSkillText("reason", request.Reason, 500, true) != nil {
			writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "reason, expected_status and exact expected_bundle_hash are required")
			return
		}
		switch request.Status {
		case "approved", "quarantined", "revoked":
		default:
			writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "status must be approved, quarantined, or revoked")
			return
		}
		// 准入变更告警需要变更前的状态与 skill 身份：先取快照再执行变更。
		// 快照失败不阻断管理动作（告警降级为只有 version_id 可用）。
		snapshot, _ := deps.SkillAssetsRepo.GetVersionAdmissionSnapshot(r.Context(), user.TenantID, versionID)
		if err := deps.SkillAssetsRepo.SetVersionAdmissionReviewed(r.Context(), user.TenantID, versionID, request, user.ID, r.RemoteAddr); err != nil {
			switch {
			case errors.Is(err, pgx.ErrNoRows):
				writeErrorWithStatus(w, http.StatusNotFound, "not_found", "Skill version was not found in this tenant")
			case errors.Is(err, repository.ErrSkillOverrideNotApplicable):
				writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "override_reason is only for approving a version whose scan was blocked or failed")
			case errors.Is(err, repository.ErrSkillVersionNotApprovable):
				writeErrorWithStatus(w, http.StatusConflict, "admission_rejected", "Only scanned uploaded Skill bundles can be approved; observed definitions and invalid signatures are not approvable, and blocked or failed scans need an override_reason")
			case errors.Is(err, repository.ErrSkillAdmissionConflict):
				writeErrorWithStatus(w, http.StatusConflict, "admission_conflict", "Version admission or bundle changed; refresh and review the current evidence")
			default:
				writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", "failed to change Skill admission")
			}
			return
		}
		writeSkillAdmissionChangedAlert(r.Context(), deps, user.TenantID, user.ID, versionID, snapshot, request.Status)
		response := map[string]any{
			"version_id": versionID,
			"status":     request.Status,
			"reason":     request.Reason, "previous_status": request.ExpectedStatus, "bundle_hash": request.ExpectedBundleHash,
		}
		if request.OverrideReason != "" {
			response["override_reason"] = request.OverrideReason
		}
		writeSkillJSON(w, http.StatusOK, response)
	}
}

// skillAdmissionStatusLabels 是准入状态的面向人中文标签。
var skillAdmissionStatusLabels = map[string]string{
	"approved":    "已批准",
	"quarantined": "已隔离",
	"revoked":     "已撤销",
}

// skillAdmissionSeverityLabels 把告警严重度翻成中文（与 alert 包 severityLabelCN 同口径）。
var skillAdmissionSeverityLabels = map[string]string{
	"medium": "中危",
	"high":   "高危",
}

// writeSkillAdmissionChangedAlert 在 Skill 准入状态变更成功后发告警：
// 撤销/隔离=high（需行动），批准=medium（知会）。
//
// security_events.request_id 外键指向 request_logs，管理面变更没有对应代理请求
// （2026-09-27 线上验证，同 mode_watcher 口径），因此直接写告警组与消息中心：
// 告警组带 domain=skill 供风险域视图，消息中心保证运营可见。
func writeSkillAdmissionChangedAlert(ctx context.Context, deps *Dependencies, tenantID, actorID, versionID string, snapshot repository.SkillVersionAdmissionSnapshot, toStatus string) {
	if deps == nil {
		return
	}
	severity := "medium"
	disposition := "informational"
	if toStatus != "approved" {
		severity = "high"
		disposition = "action_required"
	}
	fromLabel := skillAdmissionStatusLabels[snapshot.AdmissionStatus]
	if fromLabel == "" {
		fromLabel = snapshot.AdmissionStatus
		if fromLabel == "" {
			fromLabel = "未记录"
		}
	}
	toLabel := skillAdmissionStatusLabels[toStatus]
	name := strings.TrimSpace(snapshot.CanonicalName)
	if name == "" {
		name = versionID
	}
	now := time.Now().UTC()
	title := fmt.Sprintf("Skill 准入变更【%s】%s · %s → %s", skillAdmissionSeverityLabels[severity], name, fromLabel, toLabel)
	body := map[string]any{
		"event_type":        "skill_admission_changed",
		"severity":          severity,
		"skill_name":        snapshot.CanonicalName,
		"skill_version":     snapshot.DeclaredVersion,
		"asset_id":          snapshot.AssetID,
		"version_id":        versionID,
		"from_status":       snapshot.AdmissionStatus,
		"to_status":         toStatus,
		"actor_id":          actorID,
		"domain":            "skill",
		"created_at":        now.Format(time.RFC3339),
		"notification_kind": "security_event",
	}
	groupKey := "skill_admission_changed|" + versionID + "|" + toStatus

	// 告警组（生产 AlertGroupRepository 支持 UpsertOpen；轻量测试替身没有则跳过）。
	if grouper, ok := deps.AlertGroupRepo.(interface {
		UpsertOpen(context.Context, repository.AlertGroupUpsertInput) (*repository.AlertGroup, bool, error)
	}); ok && grouper != nil {
		_, _, err := grouper.UpsertOpen(ctx, repository.AlertGroupUpsertInput{
			TenantID:          tenantID,
			ProjectID:         defaultEvalIntegrationProjectID,
			GroupKey:          groupKey,
			Severity:          severity,
			AlertType:         "security_event",
			Title:             title,
			OccurredAt:        now,
			BodyJSON:          body,
			EffectiveSeverity: severity,
			DispositionClass:  disposition,
			Domain:            "skill",
		})
		if err != nil {
			log.Printf("[skill] admission-changed alert group upsert failed (tenant=%s version=%s): %v", tenantID, versionID, err)
		}
	}

	// 消息中心（用户可见的收件箱，与 SecEventBridge 的收件箱同一条链路）。
	if deps.AlertService != nil {
		inboxBody := map[string]any{"domain": "skill"}
		for key, value := range body {
			inboxBody[key] = value
		}
		if _, err := deps.AlertService.UpsertByGroup(ctx, tenantID, severity, "security_event", title, inboxBody, "/security/skills", groupKey); err != nil {
			log.Printf("[skill] admission-changed inbox upsert failed (tenant=%s version=%s): %v", tenantID, versionID, err)
		}
	}
}

func canonicalSkillAssetName(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return ""
	}
	out := make([]rune, 0, len(value))
	dash := false
	for _, char := range value {
		switch {
		case unicode.IsLetter(char) || unicode.IsDigit(char):
			out = append(out, char)
			dash = false
		case char == '.' || char == '/' || char == '@' || char == '+':
			out = append(out, char)
			dash = false
		default:
			if len(out) > 0 && !dash {
				out = append(out, '-')
				dash = true
			}
		}
		if len(out) >= 255 {
			break
		}
	}
	return strings.Trim(string(out), "-./+")
}

// validateSkillText 校验管理端提交的文本（审查原因、强制批准原因、上传包里的名称等）：拒绝控制字符，
// 也拒绝格式字符（unicode.Cf：双向覆盖、零宽字符等），审计和页面上显示的与实际一致。
func validateSkillText(name, value string, maxRunes int, required bool) error {
	if err := validateObservedSkillText(name, value, maxRunes, required); err != nil {
		return err
	}
	for _, char := range value {
		if unicode.Is(unicode.Cf, char) {
			return errors.New(name + " contains invisible format characters")
		}
	}
	return nil
}

// validateObservedSkillText 校验网关上报的观测数据（Skill 名称、版本、发布者、请求编号等）：只拒控制
// 字符。名字里藏零宽、双向覆盖字符的 Skill 也要登记进清单，不能因为校验被丢掉。
func validateObservedSkillText(name, value string, maxRunes int, required bool) error {
	if required && value == "" {
		return errors.New(name + " required")
	}
	if !utf8.ValidString(value) || len([]rune(value)) > maxRunes {
		return errors.New(name + " exceeds limit or is invalid UTF-8")
	}
	for _, char := range value {
		if unicode.IsControl(char) {
			return errors.New(name + " contains control characters")
		}
	}
	return nil
}

func validateSkillSourceURI(value string) (string, error) {
	value = strings.TrimSpace(value)
	if err := validateSkillText("source_uri", value, 2048, false); err != nil {
		return "", err
	}
	if value == "" {
		return "", nil
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.Hostname() == "" {
		return "", errors.New("source_uri is invalid")
	}
	if parsed.Scheme != "https" && parsed.Scheme != "git+https" {
		return "", errors.New("source_uri must use https or git+https")
	}
	if parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", errors.New("source_uri must not contain credentials, query, or fragment")
	}
	return parsed.String(), nil
}

var skillHashPattern = regexp.MustCompile("^[0-9a-f]{64}$")

func validSkillHash(value string) bool {
	return skillHashPattern.MatchString(strings.ToLower(strings.TrimSpace(value)))
}

func writeSkillJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

var _ SkillAssetsRepo = (*repository.SkillAssetsRepository)(nil)
var _ SkillArchiveScanner = (*skillscan.Scanner)(nil)
