package handler

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
	"github.com/yangjiyj/aiguard/packages/shared-go/securityexit"
	"github.com/google/uuid"
)

// GetPortalFilePolicy 返回租户的文件上传策略（mirror GetPortalModelPolicy 的鉴权与读取模式）。
// 机器通道（PortalIntegrationAPIMiddleware）已校验 shared-secret；此处只取 tenant + 读 SystemRepo。
// 默认策略来自 defaultContentFilePolicy（与 admin GET /admin/v1/content-security/file-policy 同源）。
func GetPortalFilePolicy(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tenantID, ok := portalTenantID(w, r)
		if !ok {
			return
		}
		policy := defaultContentFilePolicy()
		if deps == nil || deps.SystemRepo == nil {
			writeErrorWithStatus(w, http.StatusServiceUnavailable, "file_policy_unavailable", "file policy is unavailable")
			return
		}
		setting, err := deps.SystemRepo.Get(r.Context(), contentFilePolicySettingKeyForTenant(tenantID))
		if err != nil {
			writeErrorWithStatus(w, http.StatusServiceUnavailable, "file_policy_unavailable", "file policy is unavailable")
			return
		}
		if setting != nil && strings.TrimSpace(setting.Value) != "" {
			policy, err = decodeAndNormalizeFilePolicy([]byte(setting.Value))
			if err != nil {
				writeErrorWithStatus(w, http.StatusServiceUnavailable, "file_policy_invalid", "stored file policy is invalid")
				return
			}
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(filePolicyResponse(policy))
	}
}

// portalUploadIngestRequest 是 POST /admin/v1/portal-integration/upload-ingest 的请求体。
type portalUploadIngestRequest struct {
	UserID        string `json:"user_id"`
	Filename      string `json:"filename"`
	MimeType      string `json:"mime_type"`
	Size          int64  `json:"size"`
	SHA256        string `json:"sha256"`
	BytesBase64   string `json:"bytes_base64"`
	ExtractedText string `json:"extracted_text"`
	Model         string `json:"model,omitempty"`
}

// PortalUploadIngest 接收门户上传的文件字节 + 抽取文本：
//  1. 始终通过临时 scan-object 做真实字节文件类型判定，结束后即焚，不保存原文件
//  2. 文件正文 DLP 开启时追加抽取文本检测；审计模式只留痕不阻断
//  3. PortalUploadEventRepo 写文件级元数据留痕（user_id 归因、命中策略，不含原文）
func PortalUploadIngest(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tenantID, ok := portalTenantID(w, r)
		if !ok {
			return
		}
		if deps == nil {
			writeErrorWithStatus(w, http.StatusServiceUnavailable, "portal_integration_not_configured", "dependencies not configured")
			return
		}

		ctx := r.Context()
		policy := defaultContentFilePolicy()
		// 策略读取失败或存储内容无法解析属于检测未完成：按默认策略继续并记覆盖缺口，
		// 不以 503 中断上传（securityexit.DetectionFailure）。
		policyGap := ""
		if deps.SystemRepo != nil {
			setting, policyErr := deps.SystemRepo.Get(ctx, contentFilePolicySettingKeyForTenant(tenantID))
			if policyErr != nil {
				policyGap = "file_policy_unavailable"
			} else if setting != nil && strings.TrimSpace(setting.Value) != "" {
				decoded, decodeErr := decodeAndNormalizeFilePolicy([]byte(setting.Value))
				if decodeErr != nil {
					policyGap = "file_policy_invalid"
				} else {
					policy = decoded
				}
			}
		}
		maxFileBytes := int64(policy.MaxFileMB) * 1024 * 1024
		// JSON/base64 的理论膨胀约 4/3；额外 1MiB 给元数据。MaxBytesReader
		// 同时覆盖无 Content-Length 的分块请求，避免先把超大 JSON 字符串载入内存。
		maxRequestBytes := (maxFileBytes*4)/3 + 1024*1024
		r.Body = http.MaxBytesReader(w, r.Body, maxRequestBytes)

		var req portalUploadIngestRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			if strings.Contains(err.Error(), "request body too large") {
				writeErrorWithStatus(w, http.StatusRequestEntityTooLarge, "file_too_large", "文件超过当前上传大小限制")
				return
			}
			writeError(w, "invalid_request", "invalid JSON")
			return
		}
		// 必填校验（user_id 强制，防归因缺失）
		if req.UserID == "" {
			writeError(w, "invalid_request", "user_id is required")
			return
		}
		if req.Filename == "" || req.MimeType == "" || req.Size <= 0 || req.SHA256 == "" || req.BytesBase64 == "" {
			writeError(w, "invalid_request", "filename/mime_type/size/sha256/bytes_base64 are required")
			return
		}

		// 服务端按租户策略执行文件上限，不能只相信门户前端。先用声明大小和
		// base64 长度估算做 O(1) 拒绝，避免为明显超限文件分配解码内存。
		estimatedBytes := int64(len(req.BytesBase64)/4) * 3
		if req.Size > maxFileBytes || estimatedBytes > maxFileBytes {
			writeErrorWithStatus(w, http.StatusRequestEntityTooLarge, "file_too_large", "文件超过当前上传大小限制")
			return
		}

		// 1. 解码字节 + 服务端二次校验 sha256（不信客户端）
		rawBytes, err := base64.StdEncoding.DecodeString(req.BytesBase64)
		if err != nil {
			writeError(w, "invalid_request", "bytes_base64 decode failed")
			return
		}
		if int64(len(rawBytes)) > maxFileBytes {
			writeErrorWithStatus(w, http.StatusRequestEntityTooLarge, "file_too_large", "文件超过当前上传大小限制")
			return
		}
		if int64(len(rawBytes)) != req.Size {
			writeError(w, "invalid_request", "size mismatch (client vs server)")
			return
		}
		shaCk := sha256.Sum256(rawBytes)
		shaHex := hex.EncodeToString(shaCk[:])
		if shaHex != req.SHA256 {
			writeError(w, "invalid_request", "sha256 mismatch (client vs server)")
			return
		}

		// 2. 文件类型策略始终在原始字节上判定；正文 DLP 只决定是否追加正文扫描。
		// 原始字节仅用于临时 scan-object，检测后即焚。审计模式只留痕，绝不返回 403。
		findings := []map[string]interface{}{}
		if policyGap != "" {
			gap := securityexit.Decide(securityexit.Protect, "block", securityexit.DetectionFailure)
			findings = append(findings, map[string]interface{}{
				"type": "file", "category": policyGap,
				"severity": "low", "rule_id": strings.ReplaceAll(policyGap, "_", "-"), "action": gap.Action,
				"counts_as_security_finding": false,
				"matched_text_preview":       "file policy could not be loaded; default policy applied and recorded",
			})
		}
		engineAction := "audit"
		blockedByFilePolicy := false
		requestID := "portal-upload-" + uuid.NewString()
		fileDlpOn := fileContentDLPEnabled(r.Context(), deps)
		mode := securityexit.ModeFromAuditOnly(securityAuditOnlyEnabled(r.Context(), deps))
		client := newSecurityEngineClient(
			deps.SecurityEngineURL, deps.SecurityEngineInternalToken)
		var attAction string
		var attFindings []map[string]interface{}
		var attErr error
		if deps.SecurityEngineURL == "" || deps.SecurityEngineInternalToken == "" {
			attErr = fmt.Errorf("file DLP engine is not configured")
		} else {
			var objectID string
			objectID, attErr = client.uploadScanObject(ctx, tenantID, requestID, req.Filename, req.MimeType, rawBytes)
			if attErr == nil {
				defer client.consumeScanObject(ctx, tenantID, objectID)
				attAction, attFindings, attErr = client.scanAttachmentObject(
					ctx, tenantID, requestID, req.Filename, req.MimeType, shaHex, objectID)
			}
		}
		// 上传时检测失败按控制台 upload_inspection_failure_action 处置（2.9.22 审查第 4 项）：
		// 缺省 forward_alert 照原样放行并留痕；选 block 时只在防护模式下拒绝。
		failurePolicy := securityexit.Policy{FailClosedOnDetectionFailure: portalUploadInspectionFailureBlocks(ctx, deps)}
		inspectionFailed := false
		if attErr != nil {
			gap := securityexit.DecideWithPolicy(mode, "block", securityexit.DetectionFailure, failurePolicy)
			inspectionFailed = gap.Enforce
			findings = append(findings, map[string]interface{}{
				"type": "file", "category": "file_type_engine_unavailable",
				"severity": "high", "rule_id": "file-type-engine-unavailable", "action": gap.Action,
				"counts_as_security_finding": false,
				"matched_text_preview":       "文件类型检测引擎不可用，已按当前模式留痕",
			})
		} else {
			findings = append(findings, attFindings...)
			cause, raw := securityexit.RuleHit, attAction
			if portalUploadExplicitTypePolicyBlocks(attFindings) {
				cause, raw = securityexit.ExplicitFileType, "block"
			} else if portalUploadResultBlocks(attAction, attFindings) {
				raw = "block"
			}
			if securityexit.Decide(mode, raw, cause).Enforce {
				engineAction = "block"
				blockedByFilePolicy = true
			} else if attAction != "" {
				engineAction = attAction
			}
		}

		// 3. 正文 DLP 开启时追加既有抽取文本审计；类型策略不受该开关影响。
		if !blockedByFilePolicy && attErr == nil && fileDlpOn {
			scannedAction, scannedFindings, scanErr := client.scanContent(ctx, requestID, req.ExtractedText, req.Filename, "", shaHex)
			if scanErr != nil {
				gap := securityexit.DecideWithPolicy(mode, "block", securityexit.DetectionFailure, failurePolicy)
				inspectionFailed = gap.Enforce
				findings = append(findings, map[string]interface{}{
					"type": "file", "category": "file_content_text_engine_unavailable",
					"severity": "high", "rule_id": "file-content-text-engine-unavailable", "action": gap.Action,
					"counts_as_security_finding": false,
					"matched_text_preview":       "文件抽取文本检测引擎不可用，已按当前模式留痕",
				})
			} else {
				if scannedAction != "" {
					engineAction = scannedAction
				}
				findings = append(findings, scannedFindings...)
				raw := scannedAction
				if portalUploadResultBlocks(scannedAction, scannedFindings) {
					raw = "block"
				}
				if securityexit.Decide(mode, raw, securityexit.RuleHit).Enforce {
					engineAction = "block"
					blockedByFilePolicy = true
				}
			}
		}

		if inspectionFailed && !blockedByFilePolicy {
			// 检测失败按设置拒绝：留一条上传记录，不进上游、不写 retention。
			if deps.PortalUploadEventRepo != nil {
				findingsJSON, _ := json.Marshal(map[string]interface{}{
					"model": req.Model, "findings": findings, "engine_action": "block",
					"severity": severityForFindings(findings),
				})
				_ = deps.PortalUploadEventRepo.Insert(ctx, repository.PortalUploadEvent{
					ID: "pue-" + uuid.NewString(), TenantID: tenantID, UserID: req.UserID,
					Filename: req.Filename, MimeType: req.MimeType, Size: req.Size, SHA256: shaHex,
					Model: req.Model, ActionTaken: "block", FindingsJSON: findingsJSON,
				})
			}
			writeErrorWithStatus(w, http.StatusServiceUnavailable, "upload_inspection_unavailable",
				"文件安全检测暂不可用，已按控制台设置拒绝本次上传")
			return
		}

		finalAction := "audit"
		if blockedByFilePolicy {
			finalAction = "block"
			// 被阻断文件：不写 retention、不进上游，直接 403（设计§13）
			if deps.PortalUploadEventRepo != nil {
				findingsJSON, _ := json.Marshal(map[string]interface{}{
					"model":         req.Model,
					"findings":      findings,
					"engine_action": engineAction,
					"severity":      severityForFindings(findings),
				})
				_ = deps.PortalUploadEventRepo.Insert(ctx, repository.PortalUploadEvent{
					ID:           "pue-" + uuid.NewString(),
					TenantID:     tenantID,
					UserID:       req.UserID,
					Filename:     req.Filename,
					MimeType:     req.MimeType,
					Size:         req.Size,
					SHA256:       shaHex,
					Model:        req.Model,
					ActionTaken:  finalAction,
					FindingsJSON: findingsJSON,
				})
			}
			writeErrorWithStatus(w, http.StatusForbidden, "file_content_blocked",
				"文件包含敏感内容，已被数据外发防护策略阻断")
			return
		}

		// 写文件级元数据留痕到 portal_upload_events，不保存文件原文。
		if deps.PortalUploadEventRepo != nil {
			findingsJSON, _ := json.Marshal(map[string]interface{}{
				"model":         req.Model,
				"findings":      findings,
				"engine_action": engineAction,
				"severity":      severityForFindings(findings),
			})
			insertErr := deps.PortalUploadEventRepo.Insert(ctx, repository.PortalUploadEvent{
				ID:           "pue-" + uuid.NewString(),
				TenantID:     tenantID,
				UserID:       req.UserID,
				Filename:     req.Filename,
				MimeType:     req.MimeType,
				Size:         req.Size,
				SHA256:       shaHex,
				ReferenceKey: "",
				Model:        req.Model,
				ActionTaken:  finalAction,
				FindingsJSON: findingsJSON,
			})
			if insertErr != nil {
				fmt.Printf("portal_upload_ingest: PortalUploadEventRepo.Insert failed: %v\n", insertErr)
			}
		}

		writeJSON(w, map[string]interface{}{
			"reference":    "",
			"text_preview": truncatePreview(req.ExtractedText, 200),
			"action":       finalAction,
			"sha256":       shaHex,
		})
	}
}

// portalUploadActionBlocks 使用全服务统一的阻断集合（block/reply/deny/quarantine）。
// mask 属于改写而非阻断；门户无法改写文件，按留痕放行处理。
func portalUploadActionBlocks(action string) bool {
	return securityexit.Blocks(action)
}

func portalUploadResultBlocks(action string, findings []map[string]interface{}) bool {
	if portalUploadActionBlocks(action) {
		return true
	}
	for _, finding := range findings {
		findingAction, _ := finding["action"].(string)
		if portalUploadActionBlocks(findingAction) {
			return true
		}
	}
	return false
}

// portalUploadExplicitTypePolicyBlocks 报告文件类型“禁止”命中是否仍要拦：只算动作仍是
// block/quarantine、又没被内容例外放开（没有 exception_id）的命中，与网关同口径。
func portalUploadExplicitTypePolicyBlocks(findings []map[string]interface{}) bool {
	for _, finding := range findings {
		category, _ := finding["category"].(string)
		ruleID, _ := finding["rule_id"].(string)
		exceptionID, _ := finding["exception_id"].(string)
		action, _ := finding["action"].(string)
		if !portalUploadFileTypeBlockedFinding(category, ruleID) || strings.TrimSpace(exceptionID) != "" {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(action)) {
		case "block", "quarantine":
			return true
		}
	}
	return false
}

// portalUploadFileTypeBlockedFinding 认文件类型“禁止”命中：类别，或规则编号（2.9.22 起带类型，
// 如 file-policy-blocked-type:exe；旧编号不带）。
func portalUploadFileTypeBlockedFinding(category, ruleID string) bool {
	ruleID = strings.ToLower(strings.TrimSpace(ruleID))
	return category == "file_policy_blocked_type" || ruleID == "file-policy-blocked-type" ||
		strings.HasPrefix(ruleID, "file-policy-blocked-type:")
}

// ListPortalUploadEvents (Phase-3) 门户机器通道读本人上传留痕（user_id 强制过滤）。
func ListPortalUploadEvents(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tenantID, ok := portalTenantID(w, r)
		if !ok {
			return
		}
		userID := strings.TrimSpace(r.URL.Query().Get("user_id"))
		if userID == "" {
			writeError(w, "invalid_request", "user_id is required")
			return
		}
		limit, err := parseEvalIntegrationLimit(r.URL.Query().Get("limit"))
		if err != nil {
			writeErrorWithStatus(w, http.StatusBadRequest, "invalid_limit", err.Error())
			return
		}
		offset, err := parseEvalIntegrationCursor(r.URL.Query().Get("cursor"))
		if err != nil {
			writeErrorWithStatus(w, http.StatusBadRequest, "invalid_cursor", err.Error())
			return
		}
		if deps == nil || deps.PortalUploadEventRepo == nil {
			portalNotConfigured(w, "portal upload event repository")
			return
		}
		events, total, err := deps.PortalUploadEventRepo.ListByUser(r.Context(), tenantID, userID, limit, offset)
		if err != nil {
			writeErrorWithStatus(w, http.StatusInternalServerError, "query_failed", "failed to query upload events")
			return
		}
		data := make([]map[string]interface{}, len(events))
		for i, e := range events {
			data[i] = map[string]interface{}{
				"id":           e.ID,
				"filename":     e.Filename,
				"mime_type":    e.MimeType,
				"size":         e.Size,
				"sha256":       e.SHA256,
				"reference":    e.ReferenceKey,
				"model":        e.Model,
				"action_taken": e.ActionTaken,
				"findings":     e.FindingsJSON,
				"created_at":   e.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
			}
		}
		writeJSON(w, map[string]interface{}{"data": data, "total": total})
	}
}

func severityForFindings(findings []map[string]interface{}) string {
	if len(findings) > 0 {
		return "warning"
	}
	return "info"
}

func truncatePreview(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}

// portalUploadInspectionFailureBlocks 读控制台 upload_inspection_failure_action：只有 block 才拒绝；
// 读取失败或未配置时按缺省 forward_alert（照原样放行并留痕）。
func portalUploadInspectionFailureBlocks(ctx context.Context, deps *Dependencies) bool {
	if deps == nil || deps.SystemRepo == nil {
		return false
	}
	setting, err := deps.SystemRepo.Get(ctx, uploadInspectionFailureActionKey)
	return err == nil && setting != nil && strings.TrimSpace(setting.Value) == "block"
}
