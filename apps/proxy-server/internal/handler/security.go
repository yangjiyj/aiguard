package handler

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/yangjiyj/aiguard/packages/shared-go/filereference"
	"github.com/yangjiyj/aiguard/packages/shared-go/headeraudit"
	"github.com/yangjiyj/aiguard/packages/shared-go/inspectionscope"
	"github.com/yangjiyj/aiguard/packages/shared-go/llmcatalog"
	"github.com/yangjiyj/aiguard/packages/shared-go/principal"
	"github.com/yangjiyj/aiguard/packages/shared-go/scanfp"
	"github.com/yangjiyj/aiguard/packages/shared-go/securityexit"
)

const defaultFileDLPRequestLimitBytes = int64(25 * 1024 * 1024)

type replayReadCloser struct {
	io.Reader
	closer io.Closer
}

func (r *replayReadCloser) Close() error {
	return r.closer.Close()
}

func fileDLPRequestLimitBytes() int64 {
	raw := strings.TrimSpace(os.Getenv("SECURITY_FILE_CONTENT_MAX_REQUEST_MB"))
	if raw == "" {
		return defaultFileDLPRequestLimitBytes
	}
	var mb int64
	if _, err := fmt.Sscanf(raw, "%d", &mb); err != nil || mb < 1 {
		return defaultFileDLPRequestLimitBytes
	}
	if mb > 100 {
		mb = 100
	}
	return mb * 1024 * 1024
}

// fileContentDLPEnv 返回文件内容 DLP 环境变量原始值（与 security-engine/gateway 同名 env，默认关）。
// 仅作启动/DB 不可用时的后备；运行态真源是 system_settings.file_content_dlp_enabled 经
// SecurityClient.fileDLPSettings 动态读取（短 TTL 缓存）。
func fileContentDLPEnv() string {
	return os.Getenv("SECURITY_FILE_CONTENT_DLP_ENABLED")
}

// SecurityClient calls the security-engine for input/output checks
type SecurityClient struct {
	inspectionScope   inspectionscope.Reader
	inspectionQueue   *InspectionQueue
	baseURL           string
	internalSecret    string
	client            *http.Client
	fingerprints      *scanfp.Store
	fileDLPSettings   FileDLPSettingReader
	auditOnlySettings FileDLPSettingReader
	// fileReferencePolicy 读租户文件策略里的文件引用处置（2.9.22）；nil 时缺省告警放行。
	fileReferencePolicy FileReferencePolicyReader
	// detectionFailClosed 读控制台“检测服务不可用”开关；nil 时沿用 PROXY_DETECTION_FAIL_MODE。
	detectionFailClosed FileDLPSettingReader
}

func (s *SecurityClient) WithInspectionScope(reader inspectionscope.Reader) *SecurityClient {
	s.inspectionScope = reader
	return s
}
func (s *SecurityClient) inspectionPolicy(ctx context.Context) inspectionscope.Policy {
	if s != nil && s.inspectionScope != nil {
		return s.inspectionScope.InspectionPolicy(ctx)
	}
	return inspectionscope.Default()
}

// FingerprintScanMeta 标注一次 CheckInput 结果的来源（指纹重放时非 nil），
// 由调用方写进 security_events.matched_summary（契约 9）。
type FingerprintScanMeta struct {
	SemanticStatus     string
	SemanticReason     string
	ScanMode           string // "fingerprint_reuse"
	FirstSeenRequestID string
	CapacityRejected   bool
	DetectionRejected  bool
	// ClientGone：这次失败只是因为客户端在检测期间断开（请求 ctx 被取消）。action 仍按原失败口径
	// 给出，不看该标记的调用方行为不变；明文转发据此收尾记 cancelled/408，不写检测失败或拦截事件。
	ClientGone bool
}

func (s *SecurityClient) inspectionFailure(ctx context.Context, err error, fallback string) (string, []map[string]interface{}, *FingerprintScanMeta) {
	action, findings, meta := proxyInspectionFailure(s.securityAuditOnly(ctx), err, fallback, s.detectionPolicy())
	meta.ClientGone = proxyClientGone(ctx, err)
	return action, findings, meta
}

// proxyClientGone 判断检测失败是否只是客户端断开：错误是 context.Canceled 且请求 ctx 已结束。
// 与 gateway-core 的 clientGoneDuring 同语义（proxy-server 是独立模块，不跨模块引用）。
// DeadlineExceeded（检测超时）、引擎不可达、引擎自己 cancel 而请求 ctx 仍然存活都不算。
func proxyClientGone(ctx context.Context, err error) bool {
	return errors.Is(err, context.Canceled) && ctx != nil && ctx.Err() != nil
}

func proxyInspectionFailure(auditOnly bool, err error, fallback string, policy securityexit.Policy) (string, []map[string]interface{}, *FingerprintScanMeta) {
	cause := securityexit.FailureCause(err)
	outcome := securityexit.DecideWithPolicy(securityexit.ModeFromAuditOnly(auditOnly), "block", cause, policy)
	return outcome.Action, nil, &FingerprintScanMeta{
		SemanticStatus: "incomplete", SemanticReason: securityexit.FailureReason(err, fallback),
		CapacityRejected:  cause == securityexit.Capacity && outcome.Enforce,
		DetectionRejected: cause == securityexit.DetectionFailure && outcome.Enforce,
	}
}

func forwardProxyPrincipal(tenantID string, match LLMProviderMatch) *principal.Context {
	ctx, err := principal.Normalize(principal.Context{
		TenantID: tenantID, Protocol: strings.ToLower(strings.TrimSpace(match.Provider)),
		EntryPoint: "forward_proxy", IdentitySource: principal.SourceForwardProxy,
		TrustLevel: principal.TrustUnknown, IdentityVersion: "1",
	})
	if err != nil {
		return nil
	}
	return &ctx
}

// WithFingerprintStore 注入已检指纹缓存（nil=禁用，默认零回归）。
func (s *SecurityClient) WithFingerprintStore(store *scanfp.Store) *SecurityClient {
	s.fingerprints = store
	return s
}

// WithFileDLPSettingReader 注入文件内容 DLP 全局动态开关读取器（system_settings 真源）。
// 未注入时回落到启动环境变量 SECURITY_FILE_CONTENT_DLP_ENABLED，默认关闭。
func (s *SecurityClient) WithFileDLPSettingReader(reader FileDLPSettingReader) *SecurityClient {
	s.fileDLPSettings = reader
	return s
}

// WithSecurityAuditOnlySettingReader 注入审计模式的动态配置读取器。
func (s *SecurityClient) WithSecurityAuditOnlySettingReader(reader FileDLPSettingReader) *SecurityClient {
	s.auditOnlySettings = reader
	return s
}

// fileDLPEnabled 解析本次请求的文件 DLP 开关快照：动态读取器优先，未注入则回落环境变量。
// 单次请求内由 CheckInput 调用一次并复用，避免处理中途刷新造成前后不一致。
func (s *SecurityClient) fileDLPEnabled(ctx context.Context) bool {
	if s != nil && s.fileDLPSettings != nil {
		return s.fileDLPSettings.Enabled(ctx)
	}
	return EnvFileDLPSettingReader{}.Enabled(ctx)
}

// SecurityAuditOnly 导出审计模式判定，供正向代理的受限文件显式拒绝使用。
func (s *SecurityClient) SecurityAuditOnly(ctx context.Context) bool {
	return s.securityAuditOnly(ctx)
}

func (s *SecurityClient) securityAuditOnly(ctx context.Context) bool {
	// The DB reader resolves the administrator's explicit mode and the legacy
	// ceiling in one snapshot. Legacy readers retain the deployment override.
	if s != nil {
		if reader, ok := s.auditOnlySettings.(interface {
			securityExecutionMode(context.Context) bool
		}); ok {
			return reader.securityExecutionMode(ctx)
		}
	}
	if (EnvSecurityAuditOnlySettingReader{}).Enabled(ctx) {
		return true
	}
	if s != nil && s.auditOnlySettings != nil {
		return s.auditOnlySettings.Enabled(ctx)
	}
	return false
}

// NewSecurityClient creates a new security client
func NewSecurityClient(baseURL string) *SecurityClient {
	return NewSecurityClientWithSecret(baseURL, "")
}

func NewSecurityClientWithSecret(baseURL, internalSecret string) *SecurityClient {
	return &SecurityClient{
		baseURL:        baseURL,
		internalSecret: strings.TrimSpace(internalSecret),
		client:         &http.Client{Timeout: 10 * time.Second},
	}
}

// CheckInput checks the request input for security issues.
// requestID 是本次代理请求的 audit RequestID（指纹首见溯源用，落 first_request_id）。
// 第三返回值非 nil 表示结果来自指纹缓存重放（fingerprint_reuse），调用方据此标注事件。
func (s *SecurityClient) CheckInput(ctx context.Context, tenantID, requestID string, req *http.Request) (action string, findings []map[string]interface{}, meta *FingerprintScanMeta) {
	// 告警放行的文件引用命中并入本次检测结果（2.9.22）：放行时至少留 audit。告警放行的未经扫描
	// 引用在这里（拿到引擎结果后）核对内容例外。
	var gate fileIDGateResult
	defer func() {
		referenceAlerts := s.resolveReferenceAlerts(ctx, &gate, findings)
		if len(referenceAlerts) == 0 {
			return
		}
		findings = append(findings, referenceAlerts...)
		if action == "" || action == "allow" {
			action = "audit"
		}
	}()
	if llmcatalog.IsTelemetry(req.Host, req.URL.Path) {
		return "allow", nil, nil
	}
	if s.inspectionQueue != nil {
		return s.checkInputDurable(ctx, tenantID, requestID, req)
	}
	// 正文 DLP 开关仅作为运行态上下文透传；文件类型/大小和 file_id 判决始终执行。
	contentDLPOn := s.fileDLPEnabled(ctx)
	auditOnly := s.securityAuditOnly(ctx)
	limit := fileDLPRequestLimitBytes()
	if req.ContentLength > limit {
		// 检测未完成一律放行并记录（2026-09-23 定案）。
		action := "audit"
		preview := "请求体超过检测容量限制，检测未完成，已放行并记录"
		return action, []map[string]interface{}{{
			"type": "system", "category": "request_body_limit_exceeded",
			"severity": "low", "rule_id": "request-body-limit-exceeded",
			"counts_as_security_finding": false,
			"request_limit_bytes":        limit,
			"action":                     action, "matched_text_preview": preview,
		}}, &FingerprintScanMeta{SemanticStatus: "incomplete", SemanticReason: "request_body_limit_exceeded"}
	}
	// 请求体硬限制独立于 DLP 开关，避免关闭文件扫描后出现无界内存读取。
	reader := io.LimitReader(req.Body, limit+1)
	body, err := io.ReadAll(reader)
	if err != nil {
		log.Printf("Failed to read request body: %v", err)
		return s.inspectionFailure(ctx, err, "security_engine_unavailable")
	}
	if int64(len(body)) > limit {
		// 检测未完成一律放行并记录（2026-09-23 定案）。
		action := "audit"
		preview := "请求体超过检测容量限制，检测未完成，已放行并记录"
		// LimitReader 已消费前缀；放行时需向上游完整转发原始流。
		remaining := req.Body
		req.Body = &replayReadCloser{
			Reader: io.MultiReader(bytes.NewReader(body), remaining),
			closer: remaining,
		}
		return action, []map[string]interface{}{{
			"type": "system", "category": "request_body_limit_exceeded",
			"severity": "low", "rule_id": "request-body-limit-exceeded",
			"counts_as_security_finding": false,
			"request_limit_bytes":        limit,
			"action":                     action, "matched_text_preview": preview,
		}}, &FingerprintScanMeta{SemanticStatus: "incomplete", SemanticReason: "request_body_limit_exceeded"}
	}
	req.Body = io.NopCloser(bytes.NewReader(body))

	// 与留证路径（proxy.go serveOneMITMRequest 的 detectLLMDecoders）同口径：检测抽取也走
	// catalog 声明的解码器。此前只靠 sniff 链，anthropic/openai API 流量永远落回通用平铺，
	// 检测 content 被 system/tools/全量历史 JSON 噪音淹没（投诉④误报源之一）。
	requestDecoder, _ := detectLLMDecoders(req.Host, req.URL.Path)
	extracted := extractRequestContentWithDecoder(req, body, requestDecoder)
	if extracted.NonDialogue {
		return "allow", nil, nil
	}
	extracted = selectExtractedInspection(extracted, s.inspectionPolicy(ctx))
	if extracted.InspectionScopeKnown && len(extracted.Messages) == 0 && len(extracted.Attachments) == 0 {
		return "allow", nil, nil
	}
	provider := detectLLMProvider(req.Host, req.URL.Path)
	scanText := extracted.Text
	if extracted.SecurityTextKnown {
		scanText = extracted.SecurityText
	}
	if len(extracted.Messages) > 0 {
		var parts []string
		for _, message := range extracted.Messages {
			parts = append(parts, message.Source+"\n"+message.Content)
		}
		scanText = strings.Join(parts, "\n")
	}
	// 只带文件 id 的附件按租户文件策略处置（2.9.22，与网关同口径）：检测结论为阻断照拦，
	// 没有检测记录、检测未完成、查询失败按两项处置（缺省告警放行）。
	gate = s.fileIDVerdictGate(ctx, tenantID, provider.Provider, extracted.Attachments)
	if gate.blocked {
		blockAction := securityexit.Clamp(securityexit.ModeFromAuditOnly(auditOnly), "block")
		var gateMeta *FingerprintScanMeta
		if gate.clientGone {
			// 判决查询期间客户端断开：判决照旧，只打断开标记。
			gateMeta = &FingerprintScanMeta{ClientGone: true}
		}
		blocked := gate.findings[0]
		blocked["action"] = blockAction
		return blockAction, []map[string]interface{}{blocked}, gateMeta
	}

	// P1-B 指纹缓存（模块 2a）：正代路径以整包平铺文本为缓存单元（重试/Agent 心跳类
	// 完全重复请求受益；逐消息增量收益随 1a 消息形态在后续落地）。
	sha := ""
	// Text fingerprints do not identify attachment bytes or mutable file objects.
	if s.fingerprints != nil && scanText != "" && len(extracted.Messages) <= 1 && len(extracted.Attachments) == 0 {
		cacheContext, _ := json.Marshal([]any{extracted.Messages, extracted.JudgmentContext, extracted.UserTask})
		sha = scanfp.SHA256Hex(extracted.InspectionPolicyFingerprint + "|" + scanText + "|" + string(cacheContext))
		if entry, hit := s.fingerprints.Lookup(ctx, tenantID, sha); hit {
			if !entry.HasFindings() {
				// 契约 9：首见无 findings 的重复内容静默跳过（现状无 findings 也不写事件）
				return "allow", nil, nil
			}
			action, findings, aerr := s.applyContext(ctx, tenantID, entry.RawFindings, provider)
			if aerr == nil && action != "mask" {
				action = forwardProxyEffectiveAction(clampFileDLPActionForAudit(action, auditOnly))
				return action, findings, &FingerprintScanMeta{
					ScanMode:           "fingerprint_reuse",
					FirstSeenRequestID: entry.FirstRequestID,
				}
			}
			// 重放失败或判 mask（无法产出脱敏内容）→ 契约 9 回退全量送检
		}
	}

	checkURL := fmt.Sprintf("%s/check-input/", strings.TrimRight(s.baseURL, "/"))
	// 文件内容 DLP：大附件走 object_id 临时区（不跨服务传大 base64），检测后即焚。
	attContext, uploadedObjects, materializationFailed := s.materializeObjectsWithSnapshot(ctx, tenantID, requestID, provider.Provider, extracted.Attachments, true)
	if materializationFailed {
		if len(uploadedObjects) > 0 {
			s.consumeObjects(ctx, tenantID, uploadedObjects)
		}
		// 附件字节没能送检：按控制台 upload_inspection_failure_action 处置（2.9.22）。
		return s.attachmentUploadFailure(ctx)
	}
	payload := map[string]interface{}{
		"request_id":   requestID,
		"content":      scanText,
		"content_type": extracted.ContentType,
		"principal":    forwardProxyPrincipal(tenantID, provider),
		"context": map[string]interface{}{
			"tenant_id":                tenantID,
			"endpoint":                 req.URL.Path,
			"endpoint_kind":            provider.EndpointKind,
			"provider":                 provider.Provider,
			"product":                  provider.Product,
			"access_type":              accessTypeForMatch(provider),
			"method":                   req.Method,
			"host":                     req.Host,
			"headers":                  requestHeaders(req),
			"attachments":              attContext,
			"file_content_dlp_enabled": contentDLPOn,
		},
	}

	resp, err := s.checkInputSources(ctx, checkURL, payload, extracted)
	// 无论检测成功/失败/阻断，已上传的临时对象都立即清理（即焚，设计§4/§15）
	if len(uploadedObjects) > 0 {
		s.consumeObjects(ctx, tenantID, uploadedObjects)
	}
	if err != nil {
		log.Printf("Security check failed: %v", err)
		action, _, meta := s.inspectionFailure(ctx, err, "security_engine_unavailable")
		if len(extracted.Attachments) > 0 {
			// Attachment failures use the same policy while retaining gap evidence.
			return action, []map[string]interface{}{{
				"type": "engine_runtime", "category": "file_content_engine_unavailable",
				"counts_as_security_finding": false,
				"severity":                   "low", "rule_id": "file-content-engine-unavailable",
				"action": action, "matched_text_preview": "文件检测服务不可用，尚未形成风险结论",
			}}, meta
		}
		return action, nil, meta
	}

	action, findings = s.parseResponse(resp)
	action = forwardProxyEffectiveAction(clampFileDLPActionForAudit(action, auditOnly))
	if s.fingerprints != nil && sha != "" {
		s.storeFingerprint(ctx, tenantID, requestID, sha, resp)
	}
	return action, findings, responseSemanticMeta(resp)
}

// fileDLPActionBlocksExternalSend reports an action an administrator
// configured to stop the send. A configured mask the proxy cannot apply to the
// original body is not a block: it is forwarded and alerted.
func fileDLPActionBlocksExternalSend(action string) bool {
	return securityexit.Blocks(action)
}

// exitMode resolves the execution mode used at every interrupting exit, with
// the same resolution the inline checks used before (a handler without a
// security client has no mode reader; the deployment lock still applies).
func (h *ProxyHandler) exitMode() securityexit.Mode {
	if h == nil || h.securityClient == nil {
		return securityexit.ModeFromAuditOnly((EnvSecurityAuditOnlySettingReader{}).Enabled(context.Background()))
	}
	return securityexit.ModeFromAuditOnly(h.securityClient.SecurityAuditOnly(context.Background()))
}

// forwardProxyEffectiveAction reports what the forward proxy actually does.
// It never rewrites a request body, so a configured mask means the original is
// forwarded; it is recorded as an alert rather than claimed as masked.
func forwardProxyEffectiveAction(action string) string {
	switch strings.ToLower(strings.TrimSpace(action)) {
	case "mask", "redact":
		return "audit"
	default:
		return action
	}
}

// strongerProxyRecordAction keeps a recorded action at least "audit" so an
// inspection gap is visible, without ever raising it to a block.
func strongerProxyRecordAction(action string) string {
	switch strings.ToLower(strings.TrimSpace(action)) {
	case "", "allow", "mask", "redact":
		return "audit"
	default:
		return action
	}
}

// clampFileDLPActionForAudit preserves findings but ensures audit mode never
// turns an observed security decision into an interrupted business request.
func clampFileDLPActionForAudit(action string, auditOnly bool) string {
	return securityexit.Clamp(securityexit.ModeFromAuditOnly(auditOnly), action)
}

// applyContext 调引擎 /apply-context/ 做缓存命中的上下文重放（契约 2）。
// 正代路径现状不掌握 agent_type/project/user/content_source → 留空（契约"可空"），
// 与首见全量送检的 context 一致，不引入档位偏差。
func (s *SecurityClient) applyContext(ctx context.Context, tenantID string, rawFindings json.RawMessage, provider LLMProviderMatch) (string, []map[string]interface{}, error) {
	applyURL := fmt.Sprintf("%s/apply-context/", strings.TrimRight(s.baseURL, "/"))
	payload := map[string]interface{}{
		"tenant_id":    tenantID,
		"raw_findings": rawFindings,
		"context": map[string]interface{}{
			"access_type": accessTypeForMatch(provider),
		},
		"principal": forwardProxyPrincipal(tenantID, provider),
	}
	resp, err := s.postJSON(ctx, applyURL, payload)
	if err != nil {
		return "", nil, err
	}
	action, findings := s.parseResponse(resp)
	return action, findings, nil
}

// storeFingerprint 从引擎响应提取版本回带与原始 findings 落指纹（契约 1/8）。
// 引擎未回带版本（P1-A 未部署/旧镜像）→ 不缓存，行为退化为现状。
func (s *SecurityClient) storeFingerprint(ctx context.Context, tenantID, requestID, sha string, resp map[string]interface{}) {
	if !cacheableSemanticResponse(resp) {
		return
	}
	build, _ := resp["engine_build"].(string)
	rulePack, _ := resp["rule_pack_version"].(string)
	if build == "" || rulePack == "" {
		return
	}
	raw := json.RawMessage("[]")
	if rf, ok := resp["raw_findings"]; ok && rf != nil {
		if b, merr := json.Marshal(rf); merr == nil {
			raw = b
		}
	}
	s.fingerprints.StoreResult(ctx, scanfp.Entry{
		TenantID:        tenantID,
		ContentSHA256:   sha,
		RulePackVersion: rulePack,
		EngineBuild:     build,
		RawFindings:     raw,
		FirstRequestID:  requestID,
	})
}

// CheckOutput checks the response output for security issues。
// match 用于给引擎侧补齐端点上下文(endpoint_kind/access_type/product),
// 让引擎能按流量类型(如 AI IDE 编码流量)做降级判定。
func (s *SecurityClient) CheckOutputDetailed(ctx context.Context, tenantID string, match LLMProviderMatch, body []byte, contentType ...string) (string, []map[string]interface{}, *FingerprintScanMeta) {
	if !s.inspectionPolicy(ctx).InspectModelOutput {
		return "allow", nil, nil
	}
	checkURL := fmt.Sprintf("%s/check-output/", strings.TrimRight(s.baseURL, "/"))
	responseContentType := ""
	if len(contentType) > 0 {
		responseContentType = contentType[0]
	}
	extracted := extractResponseContent(body, responseContentType)
	// Internal model output also contains reasoning and proposed tool arguments.
	// The separate retention projection continues to show only visible text.
	scanText := extracted.Text

	payload := map[string]interface{}{
		"request_id":   fmt.Sprintf("proxy-output-%d", time.Now().UnixNano()),
		"content":      scanText,
		"content_type": extracted.ContentType,
		"principal":    forwardProxyPrincipal(tenantID, match),
		"context": map[string]interface{}{
			"tenant_id":     tenantID,
			"source":        "forward_proxy",
			"endpoint_kind": match.EndpointKind,
			"provider":      match.Provider,
			"product":       match.Product,
			"access_type":   accessTypeForMatch(match),
			"attachments":   attachmentContext(extracted.Attachments),
		},
	}

	resp, err := s.postJSON(ctx, checkURL, payload)
	if err != nil {
		log.Printf("Security check failed: %v", err)
		return s.inspectionFailure(ctx, err, "security_engine_unavailable")
	}

	action, findings := s.parseResponse(resp)
	return clampFileDLPActionForAudit(action, s.securityAuditOnly(ctx)), findings, responseSemanticMeta(resp)
}

func (s *SecurityClient) CheckOutput(ctx context.Context, tenantID string, match LLMProviderMatch, body []byte, contentType ...string) (string, []map[string]interface{}) {
	action, findings, _ := s.CheckOutputDetailed(ctx, tenantID, match, body, contentType...)
	return action, findings
}

// objectIDThreshold 超过此大小的附件（解码后字节数）走 object_id 临时区，
// 不把完整 base64 放进 check-input JSON 跨服务传输（守设计§8 红线）。
// 小文件（≤此阈值）内联 data_base64，避免每文件一次上传往返。
const objectIDThreshold = 512 * 1024 // 512KB

// materializeObjects 把附件转成可送 check-input 的 context 项：
// 文件 DLP 关闭时 → 直接 attachmentContext（现状，零回归）。
// 文件 DLP 开启时 → 解码 data_base64 估算大小：
//   - 超过 objectIDThreshold → UploadScanObject 拿 object_id（不传 base64），检测后由调用方 ConsumeScanObject 清理。
//   - 未超 → 内联 data_base64（小文件，避免上传开销）。
//
// 上传失败 → 该附件转 object_id_unavailable（引擎侧按解析失败阻断），不回退内联大 base64（守红线）。
// 返回 (attachments, uploadedObjectIDs, materializationFailed) 供调用方 fail-closed 并清理。
func (s *SecurityClient) materializeObjects(ctx context.Context, tenantID, requestID, provider string, items []ExtractedAttachment) ([]map[string]interface{}, []string, bool) {
	return s.materializeObjectsWithSnapshot(ctx, tenantID, requestID, provider, items, s.fileDLPEnabled(ctx))
}

func (s *SecurityClient) materializeObjectsWithSnapshot(ctx context.Context, tenantID, requestID, provider string, items []ExtractedAttachment, fileDLPOn bool) ([]map[string]interface{}, []string, bool) {
	uploaded := []string{}
	failed := false
	if !fileDLPOn {
		return attachmentContext(items), uploaded, false
	}
	out := make([]map[string]interface{}, 0, len(items))
	for _, item := range items {
		entry := map[string]interface{}{
			"source":       item.Source,
			"field_name":   item.FieldName,
			"file_name":    item.FileName,
			"reference_id": item.ReferenceID,
			"content_type": item.ContentType,
			"size":         item.Size,
			"sha256":       item.SHA256,
			"text_preview": item.TextPreview,
		}
		b64 := item.DataBase64
		if b64 == "" {
			if item.ReferenceID != "" {
				// 纯引用（无字节）交引擎两阶段协议查 verdict
			}
			out = append(out, entry)
			continue
		}
		// 解码估算大小（不全 load：用 base64 长度估算，不实际解码以省内存）
		estBytes := (len(b64) * 3) / 4
		if estBytes <= objectIDThreshold {
			// 小文件内联
			entry["data_base64"] = b64
			out = append(out, entry)
			continue
		}
		// 大文件：解码 + 流式上传（这里需 bytes，已在 data_base64 内存中；真正的流式需
		// content_extractor 改造，见边界说明）。上传拿 object_id 替代 base64。
		raw, decErr := base64.StdEncoding.DecodeString(b64)
		if decErr != nil {
			entry["object_id_unavailable"] = "decode_failed"
			failed = true
			out = append(out, entry)
			continue
		}
		info, upErr := s.UploadScanObject(ctx, tenantID, requestID, "", provider, item.ReferenceID, item.FileName, item.ContentType, bytes.NewReader(raw))
		if upErr != nil || info == nil {
			// 上传失败：不回退内联大 base64；标记不可用，引擎按解析失败阻断（开启时不放行）
			entry["object_id_unavailable"] = "upload_failed"
			failed = true
			out = append(out, entry)
			continue
		}
		entry["object_id"] = info.ObjectID
		entry["sha256"] = info.SHA256
		delete(entry, "data_base64")
		uploaded = append(uploaded, info.ObjectID)
		out = append(out, entry)
	}
	return out, uploaded, failed
}

// consumeObjects 检测完成后删除一批 object（无论结果如何都清理，设计§4/§15 即焚）。
func (s *SecurityClient) consumeObjects(ctx context.Context, tenantID string, objectIDs []string) {
	for _, oid := range objectIDs {
		_ = s.ConsumeScanObject(ctx, tenantID, oid)
	}
}

func attachmentContext(items []ExtractedAttachment) []map[string]interface{} {
	attachments := make([]map[string]interface{}, 0, len(items))
	for _, item := range items {
		entry := map[string]interface{}{
			"source":       item.Source,
			"field_name":   item.FieldName,
			"file_name":    item.FileName,
			"reference_id": item.ReferenceID,
			"content_type": item.ContentType,
			"size":         item.Size,
			"sha256":       item.SHA256,
			"text_preview": item.TextPreview,
		}
		if item.DataBase64 != "" {
			entry["data_base64"] = item.DataBase64
		}
		attachments = append(attachments, entry)
	}
	return attachments
}

// postJSON sends a JSON POST request
func (s *SecurityClient) postJSON(ctx context.Context, url string, payload interface{}) (map[string]interface{}, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if s.internalSecret != "" {
		req.Header.Set(headeraudit.InternalTokenHeader, s.internalSecret)
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return nil, securityexit.HTTPInspectionError(resp.StatusCode, respBody)
	}
	var result map[string]interface{}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, err
	}

	return result, nil
}

// checkFileIDVerdicts 对附件里带 reference_id/file_id 的项查两阶段协议 verdict。
//
// 文件 DLP 关闭时：不查（零开销），返回 false。
// 文件 DLP 开启时（设计§10，fail-closed）：
//   - allow → 放行
//   - block / pending → 阻断
//   - not_found → 阻断（不得标通过：找不到可信关联的 file_id 绝不放行）
//   - 查询异常/引擎不可用 → 阻断（无法确认安全时不得放行）
//
// subject 在 proxy MITM 场景无 user 维度，统一用 ""（上传与查询一致即可）；
// provider 必须参与 file_id 绑定，避免跨厂商串扰。
func (s *SecurityClient) checkFileIDVerdicts(ctx context.Context, tenantID, provider string, attachments []ExtractedAttachment) bool {
	return s.fileIDVerdictGate(ctx, tenantID, provider, attachments).blocked
}

// fileIDVerdictGate 处置只带文件 id 的附件，另报告阻断是否只因客户端在查询期间断开。
// 不再看文件 DLP 开关（主路径原先写死 true），只看检测结论与租户文件策略（2.9.22）。
func (s *SecurityClient) fileIDVerdictGate(ctx context.Context, tenantID, provider string, attachments []ExtractedAttachment) fileIDGateResult {
	result := fileIDGateResult{tenantID: tenantID, provider: provider}
	var policy *filereference.Policy
	for _, att := range attachments {
		fid := att.ReferenceID
		if fid == "" {
			continue
		}
		// 上传时用 "" subject + provider 绑定；查询同样用 "" subject + provider 保持一致
		status := ""
		v, err := s.LookupFileVerdict(ctx, tenantID, "", provider, fid)
		if err == nil && v != nil {
			status = v.Status
		}
		if policy == nil {
			resolved := s.fileReferencePolicyFor(ctx, tenantID)
			policy = &resolved
		}
		outcome := filereference.Decide(status, err, *policy)
		if outcome.Action == filereference.Allow {
			continue
		}
		// 检测结论阻断、查询失败按 block 处置的不过例外：直接拦，后面的引用不再查。
		if outcome.Blocks() && !outcome.ExceptionEligible() {
			result.blocked = true
			result.clientGone = err != nil && proxyClientGone(ctx, err)
			result.findings = []map[string]interface{}{proxyReferenceFinding(outcome)}
			result.outcomes = nil
			return result
		}
		result.outcomes = append(result.outcomes, &outcome)
	}
	// 按 block 处置的未经扫描引用要先核对例外才能决定拦不拦（一次请求一次调用）。
	if batch := proxyReferenceBatch(result.outcomes); batch.Blocking() {
		s.applyFileReferenceExceptions(ctx, tenantID, provider, batch)
	}
	for _, outcome := range result.outcomes {
		if outcome.Blocks() {
			result.blocked = true
			result.findings = []map[string]interface{}{proxyReferenceFinding(*outcome)}
			return result
		}
	}
	result.findings = proxyReferenceFindings(result.outcomes)
	return result
}

// fileReferencePolicyFor 读租户文件策略里的文件引用两项处置；没注入读取器时缺省告警放行。
func (s *SecurityClient) fileReferencePolicyFor(ctx context.Context, tenantID string) filereference.Policy {
	if s.fileReferencePolicy != nil {
		return s.fileReferencePolicy.Policy(ctx, tenantID)
	}
	return filereference.DefaultPolicy()
}

// proxyReferenceFinding 把处置换成命中，形态与网关同一张表（filereference.Outcome.Finding）。
func proxyReferenceFinding(outcome filereference.Outcome) map[string]interface{} {
	shape := outcome.Finding()
	finding := map[string]interface{}{
		"type": "file", "category": shape.Category, "severity": shape.Severity,
		"rule_id": shape.RuleID, "rule_name": shape.RuleName, "rule_type": "file_reference",
		"action": shape.Action, "matched_text_preview": outcome.Message,
	}
	if shape.ExceptionID != "" {
		finding["exception_id"] = shape.ExceptionID
	}
	return finding
}

func proxyReferenceFindings(outcomes []*filereference.Outcome) []map[string]interface{} {
	findings := make([]map[string]interface{}, 0, len(outcomes))
	for _, outcome := range outcomes {
		findings = append(findings, proxyReferenceFinding(*outcome))
	}
	return findings
}

func proxyReferenceBatch(outcomes []*filereference.Outcome) *filereference.ExceptionBatch {
	batch := &filereference.ExceptionBatch{}
	for _, outcome := range outcomes {
		batch.Add(outcome)
	}
	return batch
}

// proxyFileReferenceExceptionTimeout 是一次请求核对内容例外的上限（测试可调短）。
var proxyFileReferenceExceptionTimeout = filereference.ExceptionCheckTimeout

// applyFileReferenceExceptions 把未经扫描的文件引用命中合成一次送引擎 /apply-context/ 过内容例外
// （与网关同一口径，按 rule_ref 匹配），单独限时 2 秒；引擎调不通或超时按文件策略原处置执行。
func (s *SecurityClient) applyFileReferenceExceptions(ctx context.Context, tenantID, provider string, batch *filereference.ExceptionBatch) {
	if batch == nil || batch.Len() == 0 {
		return
	}
	var results []filereference.ExceptionResult
	defer func() { batch.Apply(results) }()
	raw, err := json.Marshal(batch.Probes())
	if err != nil {
		return
	}
	checkCtx, cancel := context.WithTimeout(ctx, proxyFileReferenceExceptionTimeout)
	defer cancel()
	_, findings, err := s.applyContext(checkCtx, tenantID, raw, LLMProviderMatch{Provider: provider})
	if err != nil {
		log.Printf("file reference exception check failed (tenant=%s): %v", tenantID, err)
		return
	}
	for _, finding := range findings {
		result := filereference.ExceptionResult{}
		result.RuleID, _ = finding["rule_id"].(string)
		result.ExceptionID, _ = finding["exception_id"].(string)
		if index, ok := finding["attachment_index"].(float64); ok {
			seq := int(index)
			result.AttachmentIndex = &seq
		}
		results = append(results, result)
	}
}

// resolveReferenceAlerts 在拿到引擎检测结果后处理告警放行的未经扫描引用：核对例外只为压告警，
// 引擎这次已有会提升告警的命中时不必核对；返回并入检测结果的文件引用命中。
func (s *SecurityClient) resolveReferenceAlerts(ctx context.Context, gate *fileIDGateResult, engineFindings []map[string]interface{}) []map[string]interface{} {
	if gate == nil || gate.blocked {
		return nil
	}
	if batch := proxyReferenceBatch(gate.outcomes); batch.Len() > 0 && !proxyFindingsRaiseAlert(engineFindings) {
		s.applyFileReferenceExceptions(ctx, gate.tenantID, gate.provider, batch)
		gate.findings = proxyReferenceFindings(gate.outcomes)
	}
	return gate.findings
}

// proxyFindingsRaiseAlert 粗判这批检测命中是否会让本次事件提升告警：有计作安全发现、又没被例外
// 豁免的命中。
func proxyFindingsRaiseAlert(findings []map[string]interface{}) bool {
	for _, finding := range findings {
		if counts, ok := finding["counts_as_security_finding"].(bool); ok && !counts {
			continue
		}
		if exceptionID, _ := finding["exception_id"].(string); exceptionID != "" {
			continue
		}
		return true
	}
	return false
}

// ScanObjectInfo 是 /scan-objects/ 上传返回。
type ScanObjectInfo struct {
	ObjectID string `json:"object_id"`
	SHA256   string `json:"sha256"`
	Size     int64  `json:"size"`
}

// UploadScanObject 把附件字节流式 PUT 到 security-engine 受限临时区，返回 object_id。
// 用于 >2MB 大文件：不把完整 base64 放进 check-input JSON 跨服务传输（守设计 §8 红线）。
// reader 由调用方提供（文件句柄/bytes reader），content_length 已知则传入用于 Content-Length。
func (s *SecurityClient) UploadScanObject(ctx context.Context, tenantID, requestID, subject, provider, fileID, fileName, contentType string, reader io.Reader) (*ScanObjectInfo, error) {
	endpoint := fmt.Sprintf("%s/scan-objects/?tenant_id=%s&request_id=%s&subject=%s&provider=%s&file_id=%s&file_name=%s&content_type=%s",
		strings.TrimRight(s.baseURL, "/"),
		url.QueryEscape(tenantID), url.QueryEscape(requestID),
		url.QueryEscape(subject), url.QueryEscape(provider), url.QueryEscape(fileID),
		url.QueryEscape(fileName), url.QueryEscape(contentType))
	req, err := http.NewRequestWithContext(ctx, "PUT", endpoint, reader)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	if s.internalSecret != "" {
		req.Header.Set(headeraudit.InternalTokenHeader, s.internalSecret)
	}
	// 大文件上传放宽超时（单租户准入+引擎解析自有上限）
	slow := &http.Client{Timeout: 60 * time.Second}
	resp, err := slow.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("scan-objects upload status %d: %s", resp.StatusCode, string(respBody))
	}
	var info ScanObjectInfo
	if err := json.Unmarshal(respBody, &info); err != nil {
		return nil, fmt.Errorf("decode scan-objects response: %w", err)
	}
	return &info, nil
}

// ConsumeScanObject 检测完即焚：删除临时区对象。
func (s *SecurityClient) ConsumeScanObject(ctx context.Context, tenantID, objectID string) error {
	endpoint := fmt.Sprintf("%s/scan-objects/%s?tenant_id=%s",
		strings.TrimRight(s.baseURL, "/"), url.QueryEscape(objectID), url.QueryEscape(tenantID))
	req, err := http.NewRequestWithContext(ctx, "DELETE", endpoint, nil)
	if err != nil {
		return err
	}
	if s.internalSecret != "" {
		req.Header.Set(headeraudit.InternalTokenHeader, s.internalSecret)
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return nil
}

// FileVerdict 是两阶段 file_id 协议查询结果（status: allow|block|pending|not_found）。
type FileVerdict struct {
	Status        string   `json:"status"`
	HitCategories []string `json:"hit_categories"`
}

// LookupFileVerdict 查 file_id 的检测结果（设计 §10）。
// allow→可使用，block→拒绝，pending→未完成，not_found→不得标通过。
func (s *SecurityClient) LookupFileVerdict(ctx context.Context, tenantID, subject, provider, fileID string) (*FileVerdict, error) {
	endpoint := fmt.Sprintf("%s/scan-objects/verdict?tenant_id=%s&subject=%s&provider=%s&file_id=%s",
		strings.TrimRight(s.baseURL, "/"),
		url.QueryEscape(tenantID), url.QueryEscape(subject), url.QueryEscape(provider), url.QueryEscape(fileID))
	req, err := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
	if err != nil {
		return nil, err
	}
	if s.internalSecret != "" {
		req.Header.Set(headeraudit.InternalTokenHeader, s.internalSecret)
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("verdict lookup status %d: %s", resp.StatusCode, string(respBody))
	}
	var v FileVerdict
	if err := json.Unmarshal(respBody, &v); err != nil {
		return nil, fmt.Errorf("decode verdict response: %w", err)
	}
	return &v, nil
}

func inferSecurityContentType(header string, body []byte) string {
	if strings.Contains(strings.ToLower(header), "json") {
		return "json"
	}
	trimmed := strings.TrimSpace(string(body))
	if strings.HasPrefix(trimmed, "{") || strings.HasPrefix(trimmed, "[") {
		return "json"
	}
	return "text"
}

func requestHeaders(req *http.Request) map[string]string {
	headers := make(map[string]string, len(req.Header))
	for key, values := range req.Header {
		headers[key] = strings.Join(values, ",")
	}
	return headers
}

// parseResponse parses the security-engine response
func (s *SecurityClient) parseResponse(resp map[string]interface{}) (string, []map[string]interface{}) {
	action := "audit"
	findings := []map[string]interface{}{}

	if a, ok := resp["action"].(string); ok {
		action = a
	}

	if f, ok := resp["findings"].([]interface{}); ok {
		for _, item := range f {
			if m, ok := item.(map[string]interface{}); ok {
				findings = append(findings, m)
			}
		}
	}

	return action, findings
}

func responseSemanticMeta(resp map[string]interface{}) *FingerprintScanMeta {
	status, _ := resp["semantic_status"].(string)
	reason, _ := resp["semantic_reason"].(string)
	if status == "" {
		return nil
	}
	capacityRejected, _ := resp["inspection_capacity_rejected"].(bool)
	detectionRejected, _ := resp["inspection_detection_rejected"].(bool)
	return &FingerprintScanMeta{SemanticStatus: status, SemanticReason: reason, CapacityRejected: capacityRejected, DetectionRejected: detectionRejected}
}
func cacheableSemanticResponse(resp map[string]interface{}) bool {
	status, _ := resp["semantic_status"].(string)
	// Older engines do not provide proof that an empty result completed.
	reason, _ := resp["semantic_reason"].(string)
	return status == "completed" || status == "not_requested" || (status == "skipped" && reason != "deferred")
}

// Source comes from the selected protocol decoder, never an arbitrary request field.
// Retention may select the last human turn; security must inspect every source.
func (s *SecurityClient) checkInputSources(ctx context.Context, url string, payload map[string]interface{}, extracted ExtractedContent) (map[string]interface{}, error) {
	if len(extracted.Messages) > 0 || extracted.InspectionScopeKnown {
		return s.checkSelectedInputSources(ctx, url, payload, extracted)
	}
	return s.postJSON(ctx, url, payload)
}

func proxySemanticStatusRank(value interface{}) int {
	status, _ := value.(string)
	switch status {
	case "incomplete":
		return 4
	case "completed":
		return 3
	case "skipped":
		return 2
	case "not_requested":
		return 1
	default:
		return 0
	}
}
