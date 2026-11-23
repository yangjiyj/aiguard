package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/yangjiyj/aiguard/packages/shared-go/llmcatalog"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/yangjiyj/aiguard/packages/shared-go/securityexit"
)

const inspectionTransportLimit = int64(128 * 1024 * 1024)

func (s *SecurityClient) checkInputDurable(ctx context.Context, tenant, request string, req *http.Request) (string, []map[string]interface{}, *FingerprintScanMeta) {
	if llmcatalog.IsTelemetry(req.Host, req.URL.Path) {
		return "allow", nil, nil
	}
	failure := func(reason string) (string, []map[string]interface{}, *FingerprintScanMeta) {
		if reason == "request_body_limit_exceeded" || reason == "inspection_part_limit" {
			return "audit", nil, &FingerprintScanMeta{SemanticStatus: "incomplete", SemanticReason: reason, ScanMode: "durable_inspection"}
		}
		action, findings, meta := s.inspectionFailure(ctx, securityexit.NewInspectionFailure(reason, nil), reason)
		meta.ScanMode = "durable_inspection"
		return action, findings, meta
	}
	if ctx.Value(inspectionPermitKey{}) == nil {
		wait, cancel := context.WithTimeout(ctx, 45*time.Second)
		release, err := s.inspectionQueue.admit(wait)
		cancel()
		if err != nil {
			// 排队期间客户端断开（父 ctx 取消，wait 返回 Canceled）不是容量不足；45s 等待到期仍是 DeadlineExceeded。
			action, findings, meta := failure("inspection_admission_timeout")
			meta.ClientGone = proxyClientGone(ctx, err)
			return action, findings, meta
		}
		defer release()
	}
	if req.ContentLength > inspectionTransportLimit {
		return failure("request_body_limit_exceeded")
	}
	if req.Body == nil {
		req.Body = http.NoBody
	}
	body, err := io.ReadAll(io.LimitReader(req.Body, inspectionTransportLimit+1))
	if err != nil {
		return failure("inspection_body_read_failed")
	}
	if int64(len(body)) > inspectionTransportLimit {
		return failure("request_body_limit_exceeded")
	}
	_ = req.Body.Close()
	req.Body = io.NopCloser(bytes.NewReader(body))
	decoded, err := decodeInspectionBody(body, req.Header.Get("Content-Encoding"))
	if err != nil {
		return failure("inspection_decode_failed")
	}
	decodeReq := req.Clone(ctx)
	decodeReq.Header = req.Header.Clone()
	decodeReq.Header.Del("Content-Encoding")
	if strings.Contains(strings.ToLower(req.Header.Get("Content-Type")), "json") && !json.Valid(decoded) {
		return failure("inspection_invalid_json")
	}
	decoder, _ := detectLLMDecoders(req.Host, req.URL.Path)
	extracted := extractRequestContentWithDecoder(decodeReq, decoded, decoder)
	if json.Valid(decoded) && len(extracted.Messages) == 0 {
		allAttachments := extractHTTPContent(decoded, "application/json", "request").Attachments
		extracted.Attachments = append(extracted.Attachments, allAttachments...)
	}
	restoreInspectionAttachmentBytes(&extracted, decoded, req.Header.Get("Content-Type"))
	if extracted.NonDialogue {
		return "allow", nil, nil
	}
	extracted = selectExtractedInspection(extracted, s.inspectionPolicy(ctx))
	if extracted.InspectionScopeKnown && len(extracted.Messages) == 0 && len(extracted.Attachments) == 0 {
		return "allow", nil, nil
	}
	provider := detectLLMProvider(req.Host, req.URL.Path)
	text := extracted.Text
	if extracted.SecurityTextKnown {
		text = extracted.SecurityText
	}
	if len(extracted.Messages) == 0 && !extracted.InspectionScopeKnown && (strings.Contains(req.Header.Get("Content-Type"), "json") || strings.HasPrefix(req.Header.Get("Content-Type"), "text/")) {
		text = string(decoded)
	}
	payload := map[string]interface{}{"request_id": request, "content": text, "content_type": extracted.ContentType, "principal": forwardProxyPrincipal(tenant, provider), "context": map[string]interface{}{"tenant_id": tenant, "environment_scope": s.inspectionQueue.environment, "endpoint": req.URL.Path, "endpoint_kind": provider.EndpointKind, "provider": provider.Provider, "product": provider.Product, "access_type": accessTypeForMatch(provider), "method": req.Method, "host": req.Host, "headers": requestHeaders(req), "file_content_dlp_enabled": s.fileDLPEnabled(ctx)}}
	tasks, err := buildInspectionPlan(payload, extracted)
	if err != nil {
		return failure("inspection_part_limit")
	}
	action, findings, meta := s.inspectionQueue.inspect(ctx, tenant, request, req.Host, tasks, s.securityAuditOnly(ctx))
	if meta != nil {
		meta.ScanMode = "durable_inspection"
	}
	return action, findings, meta
}
