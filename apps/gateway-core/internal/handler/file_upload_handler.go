package handler

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/auth"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/config"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/provider"
	securityclient "github.com/yangjiyj/aiguard/apps/gateway-core/internal/security"
	"github.com/yangjiyj/aiguard/packages/shared-go/securityexit"
)

// FileUploadHandler handles the authenticated, model-free OpenAI-compatible
// files endpoint. File policy decisions remain in SecurityChecker; this
// handler only supplies the authenticated attachment context and enforces the
// final block action before any upstream call.
type FileUploadHandler struct {
	cfg                    *config.Config
	modelResolver          ModelResolver
	securityClient         SecurityChecker
	auditWriter            AuditWriter
	providerAdapterFactory ProviderAdapterFactory
	toolRiskClient         *ToolRiskClient
}

func NewFileUploadHandler(
	cfg *config.Config,
	modelResolver ModelResolver,
	securityClient SecurityChecker,
	auditWriter AuditWriter,
	providerAdapterFactory ProviderAdapterFactory,
	toolRiskClient *ToolRiskClient,
) *FileUploadHandler {
	if providerAdapterFactory == nil {
		providerAdapterFactory = &RealProviderAdapterFactory{}
	}
	return &FileUploadHandler{
		cfg:                    cfg,
		modelResolver:          modelResolver,
		securityClient:         securityClient,
		auditWriter:            auditWriter,
		providerAdapterFactory: providerAdapterFactory,
		toolRiskClient:         toolRiskClient,
	}
}

func (h *FileUploadHandler) securityAuditOnly(ctx context.Context) bool {
	fallback := false
	if h != nil && h.cfg != nil {
		fallback = h.cfg.SecurityAuditOnly
	}
	if h != nil && h.toolRiskClient != nil {
		return h.toolRiskClient.SecurityAuditOnly(ctx, fallback)
	}
	return fallback
}

func (h *FileUploadHandler) Handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		requestID := uuid.New().String()
		startedAt := time.Now()
		ctx := r.Context()
		authInfo := auth.GetAuthInfo(r)
		partial := buildPartialEnvelope(requestID, authInfo, "", "files")

		// The runtime route is normally wrapped by AuthMiddleware. Keep the
		// handler fail-closed as well so direct/internal mounts cannot create an
		// unscoped upload.
		if authInfo == nil || strings.TrimSpace(authInfo.TenantID) == "" {
			h.finalize(ctx, partial, nil, "unauthorized", http.StatusUnauthorized, startedAt, nil)
			writeErrorResponse(w, "unauthorized", "authenticated tenant is required", requestID)
			return
		}

		upload, err := parseFileUpload(w, r, apiRequestBodyLimitBytes(h.cfg))
		if err != nil {
			status, code := fileUploadParseError(err)
			h.finalize(ctx, partial, nil, code, status, startedAt, nil)
			writeErrorResponseWithStatus(w, code, err.Error(), requestID, status)
			return
		}

		resolver, ok := h.modelResolver.(FileUploadRouteResolver)
		if !ok || resolver == nil {
			h.finalize(ctx, partial, nil, "model_route_unavailable", http.StatusServiceUnavailable, startedAt, nil)
			writeErrorResponse(w, "model_route_unavailable", "file upload route is not configured", requestID)
			return
		}
		route, err := resolver.ResolveFileUploadRoute(ctx, authInfo.TenantID)
		if err != nil || route == nil {
			if errors.Is(err, modelrouter.ErrAmbiguousFileUploadRoute) {
				h.finalize(ctx, partial, nil, "invalid_request", http.StatusBadRequest, startedAt, nil)
				writeErrorResponse(w, "invalid_request", "file upload route is ambiguous", requestID)
				return
			}
			h.finalize(ctx, partial, nil, "model_route_unavailable", http.StatusServiceUnavailable, startedAt, nil)
			writeErrorResponse(w, "model_route_unavailable", "no usable file upload route", requestID)
			return
		}
		if !route.SupportsConfiguredEndpoint("files") {
			h.finalize(ctx, partial, nil, "provider_unsupported", http.StatusBadRequest, startedAt, nil)
			writeErrorResponse(w, "provider_unsupported", "configured upstream route does not support files", requestID)
			return
		}

		envelope := fileUploadEnvelope(requestID, authInfo, route)
		h.ensure(ctx, envelope)

		attachment := map[string]interface{}{
			"content_type": upload.ContentType,
			"data_base64":  base64.StdEncoding.EncodeToString(upload.Content),
			"file_name":    upload.FileName,
			"file_size":    len(upload.Content),
			"purpose":      upload.Purpose,
			"source":       "multipart_file_upload",
		}
		securityCtx := withAttachments(ctx, []map[string]interface{}{attachment})
		var (
			action        string
			findings      []SecurityFinding
			bindingTokens []securityclient.FileBindingToken
		)
		if h.securityClient == nil {
			// No detector wired is a detection failure: a coverage gap, not a block.
			err = errors.New("security checker is not configured")
		} else {
			action, findings, bindingTokens, err = h.checkFileUploadSecurity(securityCtx, envelope)
		}
		exitMode := securityexit.ModeFromAuditOnly(h.securityAuditOnly(ctx))
		if clientGoneDuring(ctx, err) {
			// 客户端在文件检测期间断开（Esc / 中断）：不是检测失败，不写 security_check_failed，
			// 也不再把文件转发给上游；按 client_canceled 收尾。
			h.finalize(ctx, envelope, nil, "client_canceled", http.StatusRequestTimeout, startedAt, nil)
			writeErrorResponseWithStatus(w, "request_canceled", "request was canceled", requestID, http.StatusRequestTimeout)
			return
		}
		if err != nil {
			// 上传时检测失败按控制台 upload_inspection_failure_action 处置（2.9.22）：
			// 缺省 forward_alert 照常转发并记一条告警；选 block 时只在防护模式下拦。
			if h.toolRiskClient.UploadInspectionFailureBlocks() && exitMode == securityexit.Protect {
				h.writeSecurityEvent(ctx, envelope, findings, "security_check_failed", "file upload security check failed; rejected by upload_inspection_failure_action=block")
				h.finalize(ctx, envelope, nil, "security_blocked", http.StatusServiceUnavailable, startedAt, nil)
				writeErrorResponse(w, guardrailDetectionUnavailableCode, "file upload security inspection failed; the upload was rejected by the console setting", requestID)
				return
			}
			h.writeSecurityEvent(ctx, envelope, findings, "security_check_failed", "file upload security check failed; forwarded")
		} else if explicitFileTypePolicyBlocks(findings) && securityexit.Decide(exitMode, "block", securityexit.ExplicitFileType).Enforce {
			h.writeSecurityEvent(ctx, envelope, findings, "security_blocked", "file upload blocked by explicit file type policy")
			h.finalize(ctx, envelope, nil, "security_blocked", http.StatusForbidden, startedAt, nil)
			writeErrorResponse(w, "security_blocked", "file upload blocked by explicit file type policy", requestID)
			return
		} else if exitMode == securityexit.Record {
			if hasSecurityFindings(findings) || !isAllowSecurityAction(action) {
				h.writeSecurityEvent(ctx, envelope, findings, "security_audit_only", fmt.Sprintf("file upload matched security action %q", action))
			}
		} else if securityexit.Decide(exitMode, action, securityexit.RuleHit).Enforce {
			h.writeSecurityEvent(ctx, envelope, findings, "security_blocked", "file upload blocked by security policy")
			h.finalize(ctx, envelope, nil, "security_blocked", http.StatusForbidden, startedAt, nil)
			writeErrorResponse(w, "security_blocked", "file upload blocked by security policy", requestID)
			return
		} else if hasSecurityFindings(findings) || !isAllowSecurityAction(action) {
			// Non-blocking actions (mask/redact/audit) are retained for audit;
			// a binary upload cannot be rewritten, so they forward unchanged.
			h.writeSecurityEvent(ctx, envelope, findings, "security_audit", fmt.Sprintf("file upload observed security action %q", action))
		}

		apiKey, err := h.modelResolver.GetProviderCredential(ctx, route.ProviderID)
		if err != nil || strings.TrimSpace(apiKey) == "" {
			h.finalize(ctx, envelope, nil, "provider_not_configured", http.StatusServiceUnavailable, startedAt, nil)
			writeErrorResponse(w, "provider_not_configured", "provider credentials not configured", requestID)
			return
		}
		caller := h.providerAdapterFactory.CreateAdapter(route, apiKey)
		fileCaller, ok := caller.(provider.FileUploadCaller)
		if !ok || fileCaller == nil {
			h.finalize(ctx, envelope, nil, "provider_unsupported", http.StatusBadRequest, startedAt, nil)
			writeErrorResponse(w, "provider_unsupported", "provider adapter does not support files", requestID)
			return
		}

		responseBody, err := fileCaller.UploadFile(ctx, provider.FileUploadRequest{
			FileName:    upload.FileName,
			ContentType: upload.ContentType,
			Purpose:     upload.Purpose,
			Content:     upload.Content,
		})
		if err != nil {
			h.writeProviderError(w, ctx, envelope, err, requestID, startedAt)
			return
		}
		h.bindFileUploadIfVerified(ctx, envelope, responseBody, bindingTokens)
		h.finalize(ctx, envelope, responseBody, "completed", http.StatusOK, startedAt, nil)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(responseBody)
	}
}

func (h *FileUploadHandler) checkFileUploadSecurity(ctx context.Context, envelope *modelrouter.RequestEnvelope) (string, []SecurityFinding, []securityclient.FileBindingToken, error) {
	if detailed, ok := h.securityClient.(detailedInputChecker); ok {
		out, err := detailed.CheckInputDetailed(ctx, envelope, "", 0, "user", "file_attachment")
		if err != nil {
			return "", nil, nil, err
		}
		if out == nil {
			return "", nil, nil, errors.New("security checker returned an empty outcome")
		}
		return out.Action, out.Findings, out.FileBindings, nil
	}
	action, _, findings, err := h.securityClient.CheckInput(ctx, envelope, "", 0, "user", "file_attachment")
	return action, findings, nil, err
}

type fileUploadBindingRegistrar interface {
	BindScannedFile(context.Context, *modelrouter.RequestEnvelope, securityclient.FileBindingToken, string) error
}

func (h *FileUploadHandler) bindFileUploadIfVerified(ctx context.Context, envelope *modelrouter.RequestEnvelope, responseBody []byte, tokens []securityclient.FileBindingToken) {
	if len(tokens) == 0 {
		return
	}
	fileID, ok := verifiedUpstreamFileID(responseBody)
	if !ok {
		// A successful HTTP response is not enough to create a trusted
		// reference; only the provider's object=file contract qualifies.
		h.writeSecurityEvent(ctx, envelope, nil, "file_binding_skipped", "upstream response was not object=file")
		return
	}
	binder, ok := h.securityClient.(fileUploadBindingRegistrar)
	if !ok {
		h.writeSecurityEvent(ctx, envelope, nil, "file_binding_skipped", "security checker cannot consume file binding")
		return
	}
	for _, token := range tokens {
		if err := binder.BindScannedFile(ctx, envelope, token, fileID); err != nil {
			h.writeSecurityEvent(ctx, envelope, nil, "file_binding_failed", "scanned file binding was not persisted")
		}
	}
}

func verifiedUpstreamFileID(responseBody []byte) (string, bool) {
	var response struct {
		ID     string `json:"id"`
		Object string `json:"object"`
	}
	if err := json.Unmarshal(responseBody, &response); err != nil {
		return "", false
	}
	if !strings.EqualFold(strings.TrimSpace(response.Object), "file") || strings.TrimSpace(response.ID) == "" {
		return "", false
	}
	return strings.TrimSpace(response.ID), true
}

type parsedFileUpload struct {
	FileName    string
	ContentType string
	Purpose     string
	Content     []byte
}

func parseFileUpload(w http.ResponseWriter, r *http.Request, bodyLimit int64) (parsedFileUpload, error) {
	r.Body = http.MaxBytesReader(w, r.Body, bodyLimit)
	if err := r.ParseMultipartForm(32 << 20); err != nil {
		return parsedFileUpload{}, fmt.Errorf("invalid multipart upload: %w", err)
	}
	file, header, err := r.FormFile("file")
	if err != nil {
		return parsedFileUpload{}, errors.New("multipart field file is required")
	}
	defer file.Close()
	content, err := io.ReadAll(file)
	if err != nil {
		return parsedFileUpload{}, fmt.Errorf("read uploaded file: %w", err)
	}
	contentType := ""
	if header != nil {
		contentType = normalizedMediaType(header.Header.Get("Content-Type"))
	}
	if contentType == "" {
		contentType = http.DetectContentType(content)
	}
	if contentType == "" {
		contentType = "application/octet-stream"
	}
	fileName := "upload"
	if header != nil && strings.TrimSpace(header.Filename) != "" {
		fileName = header.Filename
	}
	return parsedFileUpload{
		FileName:    fileName,
		ContentType: contentType,
		Purpose:     strings.TrimSpace(r.FormValue("purpose")),
		Content:     content,
	}, nil
}

func fileUploadParseError(err error) (int, string) {
	var maxBytesErr *http.MaxBytesError
	if errors.As(err, &maxBytesErr) {
		return http.StatusRequestEntityTooLarge, "request_too_large"
	}
	return http.StatusBadRequest, "invalid_request"
}

func fileUploadEnvelope(requestID string, info *auth.AuthInfo, route *modelrouter.ModelRecord) *modelrouter.RequestEnvelope {
	model := route.ModelName
	if model == "" {
		model = route.ID
	}
	envelope := buildPartialEnvelope(requestID, info, model, "files")
	envelope.ModelID = route.ID
	envelope.Provider = route.ProviderType
	envelope.ProviderID = route.ProviderID
	envelope.ProtocolCapabilities = route.ProtocolCapabilities
	envelope.UpstreamModelID = route.UpstreamModelID
	envelope.KeyPrefix = info.KeyPrefix
	return envelope
}

func isAllowSecurityAction(action string) bool {
	action = strings.ToLower(strings.TrimSpace(action))
	return action == "" || action == "allow" || action == "audit"
}

func (h *FileUploadHandler) ensure(ctx context.Context, envelope *modelrouter.RequestEnvelope) {
	if h.auditWriter != nil {
		h.auditWriter.EnsureRequestLog(ctx, envelope)
	}
}

func (h *FileUploadHandler) finalize(ctx context.Context, envelope *modelrouter.RequestEnvelope, body []byte, status string, code int, startedAt time.Time, result *AuditResult) {
	if h.auditWriter != nil {
		h.auditWriter.FinalizeRequestLog(ctx, envelope, body, status, code, int(time.Since(startedAt)/time.Millisecond), result)
	}
}

func (h *FileUploadHandler) writeSecurityEvent(ctx context.Context, envelope *modelrouter.RequestEnvelope, findings []SecurityFinding, action, summary string) {
	if h.auditWriter != nil {
		h.auditWriter.WriteSecurityEvent(ctx, envelope, findings, action, summary)
	}
}

func (h *FileUploadHandler) writeProviderError(w http.ResponseWriter, ctx context.Context, envelope *modelrouter.RequestEnvelope, err error, requestID string, startedAt time.Time) {
	if upstreamErr := provider.GetUpstreamHTTPError(err); upstreamErr != nil {
		h.finalize(ctx, envelope, nil, "provider_error", upstreamErr.StatusCode, startedAt, nil)
		writeUpstreamErrorResponse(w, upstreamErr, requestID, "upstream_response")
		return
	}
	h.finalize(ctx, envelope, nil, "provider_unavailable", http.StatusBadGateway, startedAt, nil)
	writeErrorResponse(w, "provider_unavailable", "file upload provider unavailable", requestID)
}
