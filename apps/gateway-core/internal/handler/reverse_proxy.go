package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/config"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/security"
	"github.com/yangjiyj/aiguard/packages/shared-go/headeraudit"
	"github.com/yangjiyj/aiguard/packages/shared-go/llmcatalog"
	"github.com/yangjiyj/aiguard/packages/shared-go/principal"
	"github.com/yangjiyj/aiguard/packages/shared-go/safetarget"
	"github.com/yangjiyj/aiguard/packages/shared-go/securityexit"
)

type ReverseProxyRoute struct {
	ID                 string
	PathPrefix         string
	TargetURL          string
	TargetPathPrefix   string
	AllowPrivateEgress bool
	PrivateEgressCIDRs []string
	// EgressOverrides 是路由的对象级出站放行（回环、链路本地、元数据、内部主机名），默认全拒。
	EgressOverrides safetarget.EgressOverrides
	SecurityEnabled bool
	StatsEnabled    bool
	Status          string
}

// reverseRetryEnqueuer 是持久化检测重试队列的写入面，*reverseInspectionQueue 实现它。
// 抽成接口只为让测试能观察「是否入队」（真实队列依赖 Postgres），不改变运行时行为。
type reverseRetryEnqueuer interface {
	enqueue(request, path string, payload []byte, requiresSemantic ...bool) (string, error)
}

type ReverseProxyHandler struct {
	retryQueue                reverseRetryEnqueuer
	db                        *pgxpool.Pool
	tenantID                  string
	securityURL               string
	internalSecret            string
	routes                    []ReverseProxyRoute
	allRoutes                 []ReverseProxyRoute
	mu                        sync.RWMutex
	lastReload                time.Time
	client                    *http.Client
	auditRecorder             reverseProxyAuditRecorder
	headerAudit               *headeraudit.Client
	runtimeConfigClient       *ToolRiskClient
	securityAuditOnlyFallback bool
	outputStreamConfig        *config.Config
	resolveEgressTarget       func(context.Context, string, int, bool, []string) (resolvedEgressTarget, error)
}

type reverseProxySecurityResponse struct {
	RedactionMapping map[string]string          `json:"redaction_mapping,omitempty"`
	InspectionStatus string                     `json:"inspection_status"`
	EngineBuild      string                     `json:"engine_build"`
	SemanticRevision string                     `json:"semantic_config_revision"`
	SemanticStatus   string                     `json:"semantic_status"`
	SemanticReason   string                     `json:"semantic_reason"`
	Action           string                     `json:"action"`
	MaskedContent    string                     `json:"masked_content"`
	Findings         []security.SecurityFinding `json:"findings"`
}

// reverseProxySecurityDecision 是一次 security-engine 调用的归一化结果：
// 不仅给出是否放行 / 改写后的 body，还携带命中的 findings，供独立安全事件落库。
type reverseProxySecurityDecision struct {
	RetryTaskIDs       []string
	RetryUnavailable   bool
	SemanticStatus     string
	SemanticReason     string
	Body               []byte
	Action             string
	RawAction          string
	Findings           []SecurityFinding
	Allowed            bool
	DetectionFailed    bool
	FileAttachmentRisk bool
	// MaskUnavailable: the configured action was mask but the attachment
	// could not be masked, so it was forwarded and recorded as an alert.
	MaskUnavailable bool
	ContentSource   string
	Stage           string
	VerifiedContent string
}

// reverseProxySecurityAudit 累积一次请求 input/output 两段安全检查的处置与命中，
// 由 writeReverseProxyAudit 在写完访问 / 内容留证后落 security_events（独立告警链路）。
type reverseProxySecurityAudit struct {
	inputRetryIDs, outputRetryIDs                 []string
	inputRetryUnavailable, outputRetryUnavailable bool
	inputSemanticStatus                           string
	inputSemanticReason                           string
	outputSemanticStatus                          string
	outputSemanticReason                          string
	auditOnly                                     bool
	inputAction                                   string
	inputRawAction                                string
	inputFindings                                 []SecurityFinding
	inputFileAttachmentRisk                       bool
	inputContent                                  string
	inputSource                                   string
	outputAction                                  string
	outputRawAction                               string
	outputGuarded                                 bool
	outputFindings                                []SecurityFinding
	outputFileAttachmentRisk                      bool
	outputContent                                 string
	outputSource                                  string
}

func NewReverseProxyHandler(db *pgxpool.Pool, tenantID, securityURL string) *ReverseProxyHandler {
	return NewReverseProxyHandlerWithSecret(db, tenantID, securityURL, "")
}

func NewReverseProxyHandlerWithSecret(db *pgxpool.Pool, tenantID, securityURL, internalSecret string) *ReverseProxyHandler {
	h := &ReverseProxyHandler{
		db:             db,
		tenantID:       tenantID,
		securityURL:    strings.TrimRight(securityURL, "/"),
		internalSecret: strings.TrimSpace(internalSecret),
		client: &http.Client{
			Timeout: 120 * time.Second,
		},
		lastReload: time.Now(),
	}
	if db != nil {
		h.auditRecorder = newReverseProxyDBAuditRecorder(db, configuredDeploymentEnvironmentScope())
	}
	if db != nil {
		if queue, err := newReverseInspectionQueue(h); err == nil {
			h.retryQueue = queue
			queue.start()
			log.Printf("Reverse inspection durable retry ready: workers=2 attempts=8 retention=24h")
		} else {
			log.Printf("Reverse inspection retry unavailable: %v", err)
		}
	}
	h.reloadRoutes()
	return h
}

func configuredDeploymentEnvironmentScope() string {
	return normalizeDeploymentEnvironmentScope(os.Getenv("GATEWAY_ENVIRONMENT_SCOPE"))
}

func normalizeDeploymentEnvironmentScope(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "customer", "home", "claude", "codex":
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return "legacy-unclassified"
	}
}

func (h *ReverseProxyHandler) SetHeaderAuditClient(client *headeraudit.Client) {
	h.headerAudit = client
}

func (h *ForwardProxyHandler) SetHeaderAuditClient(client *headeraudit.Client) {
	if h != nil && h.reverseProxy != nil {
		h.reverseProxy.SetHeaderAuditClient(client)
	}
}

func (h *ReverseProxyHandler) SetRuntimeConfigClient(client *ToolRiskClient, fallback bool) {
	h.runtimeConfigClient = client
	h.securityAuditOnlyFallback = fallback
}

func (h *ReverseProxyHandler) securityAuditOnly(ctx context.Context) bool {
	if h == nil {
		return securityAuditOnlyForcedByEnvironment()
	}
	if h.runtimeConfigClient != nil {
		// 部署变量只作初值，由运行配置客户端按“没有显式执行模式时取部署变量”判定（2.9.22 D7）。
		return h.runtimeConfigClient.SecurityAuditOnly(ctx, h.securityAuditOnlyFallback)
	}
	return h.securityAuditOnlyFallback || securityAuditOnlyForcedByEnvironment()
}

func (h *ReverseProxyHandler) reloadRoutes() {
	if h.db == nil {
		h.mu.Lock()
		h.lastReload = time.Now()
		h.mu.Unlock()
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	rows, err := h.db.Query(ctx, `
		SELECT id, path_prefix, target_url, target_path_prefix,
		       allow_private_egress, private_egress_cidrs, security_enabled, stats_enabled, status,
		       COALESCE(egress_overrides, '{}'::jsonb)::text
		FROM reverse_proxy_routes
		WHERE tenant_id = $1 AND status = 'active'
		ORDER BY length(path_prefix) DESC, path_prefix
	`, h.tenantID)
	if err != nil {
		log.Printf("Failed to load reverse proxy routes: %v", err)
		return
	}
	defer rows.Close()

	routes := make([]ReverseProxyRoute, 0)
	for rows.Next() {
		var route ReverseProxyRoute
		var overridesText string
		if err := rows.Scan(
			&route.ID,
			&route.PathPrefix,
			&route.TargetURL,
			&route.TargetPathPrefix,
			&route.AllowPrivateEgress,
			&route.PrivateEgressCIDRs,
			&route.SecurityEnabled,
			&route.StatsEnabled,
			&route.Status,
			&overridesText,
		); err != nil {
			log.Printf("Failed to scan reverse proxy route: %v", err)
			continue
		}
		overrides, err := safetarget.ParseEgressOverrides([]byte(overridesText))
		if err != nil {
			// 坏值按默认（全部拒绝）处理，不影响路由本身。
			log.Printf("Reverse proxy route %s egress_overrides invalid, ignored: %v", route.ID, err)
		}
		route.EgressOverrides = overrides.ForReverseProxy()
		routes = append(routes, route)
	}

	h.mu.Lock()
	h.routes = routes
	h.allRoutes = routes
	h.lastReload = time.Now()
	h.mu.Unlock()
}

func (h *ReverseProxyHandler) ensureRoutesLoaded() {
	h.mu.RLock()
	needsReload := h.db != nil && time.Since(h.lastReload) > 60*time.Second
	h.mu.RUnlock()
	if needsReload {
		h.reloadRoutes()
	}
}

func (h *ReverseProxyHandler) matchRoute(path string) *ReverseProxyRoute {
	h.ensureRoutesLoaded()

	h.mu.RLock()
	defer h.mu.RUnlock()

	var matched *ReverseProxyRoute
	for _, route := range h.routes {
		if pathMatchesPrefix(path, route.PathPrefix) {
			candidate := route
			if matched == nil || len(candidate.PathPrefix) > len(matched.PathPrefix) {
				matched = &candidate
			}
		}
	}
	return matched
}

func (h *ReverseProxyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) bool {
	route := h.matchRoute(r.URL.Path)
	if route == nil {
		return false
	}

	if !h.preflightHeaderContract(w, r) {
		return true
	}

	if err := h.forwardRequest(r.Context(), route, w, r); err != nil {
		log.Printf("Reverse proxy forwarding failed for %s: %v", route.PathPrefix, err)
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
	}
	return true
}

// reverseProxyStreamTimeout 给 8082 反代请求一个总时长上限。8082 不经过 chi
// middleware.Timeout, proxyServer.WriteTimeout 也为 0, 所以去掉出站 client 的 120s
// 整请求墙后, 必须由这个 ctx 上限兜底, 否则长流/上游挂死会无限占用连接。
var reverseProxyStreamTimeout = parseReverseProxyStreamTimeout()

func parseReverseProxyStreamTimeout() time.Duration {
	if v := strings.TrimSpace(os.Getenv("GATEWAY_REVERSE_PROXY_STREAM_TIMEOUT")); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			return d
		}
	}
	return 30 * time.Minute
}

const maxGatewayResponsesDiagnosticBytes = 2 * 1024 * 1024

var gatewayResponsesDiagnosticMu sync.Mutex

// captureGatewayResponsesDiagnostic 是一次性协议诊断开关，默认完全关闭。
// 它只允许 api.example-gateway.com 的 /v1/responses 保存一个上游响应正文，绝不保存请求；
// 保存失败不会影响转发。问题定位完毕后应删除目录并移除环境变量。
func captureGatewayResponsesDiagnostic(requestID, targetHost, targetPath, _ string, responseBody []byte) (bool, error) {
	dir := strings.TrimSpace(os.Getenv("GATEWAY_RAW_DUMP_DIR"))
	if dir == "" || strings.TrimSpace(os.Getenv("GATEWAY_RAW_DUMP_MAX_SAMPLES")) != "1" {
		return false, nil
	}
	if !strings.EqualFold(strings.TrimSuffix(targetHost, "."), "api.example-gateway.com") || targetPath != "/v1/responses" {
		return false, nil
	}
	if len(responseBody) == 0 || len(responseBody) > maxGatewayResponsesDiagnosticBytes {
		return false, nil
	}

	gatewayResponsesDiagnosticMu.Lock()
	defer gatewayResponsesDiagnosticMu.Unlock()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return false, err
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return false, err
	}
	for _, entry := range entries {
		if !entry.IsDir() && filepath.Ext(entry.Name()) == ".response" {
			return false, nil
		}
	}
	name := "responses-" + compactReverseProxyAuditID(requestID, 64) + ".response"
	file, err := os.OpenFile(filepath.Join(dir, name), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return false, err
	}
	defer file.Close()
	if _, err := file.Write(responseBody); err != nil {
		return false, err
	}
	return true, nil
}

// copySSEWithFlush 把上游 SSE 流逐块转发给客户端并立即 Flush(原 io.Copy 全程不 flush,
// SSE 小包可能被 ResponseWriter 攒着延迟到达), 同时镜像写入 capture 供事后安全审计。
func copySSEWithFlush(w http.ResponseWriter, capture io.Writer, body io.Reader) (int64, error) {
	flusher, _ := w.(http.Flusher)
	buf := make([]byte, 32*1024)
	var total int64
	for {
		n, rerr := body.Read(buf)
		if n > 0 {
			if _, werr := w.Write(buf[:n]); werr != nil {
				return total, werr
			}
			_, _ = capture.Write(buf[:n])
			total += int64(n)
			if flusher != nil {
				flusher.Flush()
			}
		}
		if rerr != nil {
			if rerr == io.EOF {
				return total, nil
			}
			return total, rerr
		}
	}
}

func (h *ReverseProxyHandler) forwardRequest(ctx context.Context, route *ReverseProxyRoute, w http.ResponseWriter, r *http.Request) error {
	startedAt := time.Now()
	requestID := newReverseProxyRequestID()
	ctx = withBlockLedger(ctx)
	w.Header().Set("X-Request-ID", requestID)
	w.Header().Set("X-JJDGuard-Request-ID", requestID)
	redactionEnvelope := &modelrouter.RequestEnvelope{RequestID: requestID, TenantID: h.tenantID, BillingIngress: "reverse_proxy"}
	// 见 reverseProxyStreamTimeout: 给整个反代请求一个总时长上限(默认 30min, 可经
	// GATEWAY_REVERSE_PROXY_STREAM_TIMEOUT 调), 替代被去掉的 120s client 墙。
	ctx, cancel := context.WithTimeout(ctx, reverseProxyStreamTimeout)
	defer cancel()
	auditOnly := h.securityAuditOnly(ctx)
	exitMode := securityexit.ModeFromAuditOnly(auditOnly)
	reqBody, err := io.ReadAll(r.Body)
	if err != nil {
		return fmt.Errorf("read request body: %w", err)
	}
	requestContentType := r.Header.Get("Content-Type")

	targetURL, err := buildReverseProxyTargetURL(route, r.URL)
	if err != nil {
		return fmt.Errorf("build target URL: %w", err)
	}
	targetHost, targetPort := upstreamHostPort(targetURL)
	// securityTargetPath 供检测上下文补齐用：与 newReverseProxyAuditRecord 的目录匹配同口径
	// （EscapedPath），三个安全检查调用点（输入/流式输出/非流式输出）共用。
	securityTargetPath := targetURL.EscapedPath()
	if securityTargetPath == "" {
		securityTargetPath = "/"
	}

	secAudit := reverseProxySecurityAudit{auditOnly: auditOnly}

	if route.SecurityEnabled && len(reqBody) > 0 {
		decision, err := h.checkRequestSecurityStructured(ctx, requestID, r, reqBody, requestContentType, targetHost, securityTargetPath)
		if clientGoneDuring(ctx, err) {
			// 客户端在输入检测期间断开（Esc / 中断）：没有响应可放行，也不是检测失败。不转发上游，
			// 不走 fail-closed，secAudit 不带 input incomplete，口径同下面目标解析被取消的分支。
			log.Printf("Reverse proxy request cancelled during input security check: %v", err)
			record, recordErr := newReverseProxyAuditRecord(requestID, h.tenantID, targetHost, targetURL, r, reqBody, nil, "cancelled", http.StatusRequestTimeout, 0, time.Since(startedAt))
			if recordErr != nil {
				return recordErr
			}
			h.writeReverseProxyAudit(context.WithoutCancel(ctx), record, reqBody, requestContentType, nil, "", secAudit)
			http.Error(w, "Reverse proxy request cancelled", http.StatusRequestTimeout)
			return nil
		}
		decision = h.applyReverseInspectionPolicy(ctx, decision)
		secAudit.inputRetryIDs, secAudit.inputRetryUnavailable = decision.RetryTaskIDs, decision.RetryUnavailable
		if err != nil {
			log.Printf("Reverse proxy request security check failed: %v", err)
		}
		secAudit.inputSemanticStatus, secAudit.inputSemanticReason = decision.SemanticStatus, decision.SemanticReason
		secAudit.inputAction = decision.Action
		secAudit.inputRawAction = decision.RawAction
		secAudit.inputFindings = decision.Findings
		secAudit.inputFileAttachmentRisk = decision.FileAttachmentRisk
		secAudit.inputContent = decision.VerifiedContent
		secAudit.inputSource = decision.ContentSource
		if !decision.Allowed {
			if h.applyReverseInspectionPolicy(ctx, decision).Allowed == false {
				code := http.StatusForbidden
				unavailable := decision.SemanticStatus == "incomplete" && !hasSecurityFindings(decision.Findings)
				if unavailable {
					code = http.StatusServiceUnavailable
				}
				record, recordErr := newReverseProxyAuditRecord(requestID, h.tenantID, targetHost, targetURL, r, reqBody, nil, "blocked", code, 0, time.Since(startedAt))
				if recordErr != nil {
					return recordErr
				}
				h.writeReverseProxyAudit(context.WithoutCancel(ctx), record, reqBody, requestContentType, nil, "", secAudit)
				if unavailable {
					writeGuardrailDetectionUnavailable(w, requestID, false)
				} else {
					notice := h.reverseBlockNotice(ctx, requestID, "input", decision.Findings)
					setBlockNoticeHeaders(w, notice)
					http.Error(w, notice.Text, code)
				}
				return nil
			}
		} else if exitMode == securityexit.Protect {
			reqBody = decision.Body
		}
	}

	resolveTarget := func(ctx context.Context, host string, port int, allow bool, cidrs []string) (resolvedEgressTarget, error) {
		return resolveSafeEgressTargetForRouteWithOverrides(ctx, host, port, allow, cidrs, route.EgressOverrides, nil)
	}
	if h.resolveEgressTarget != nil {
		resolveTarget = h.resolveEgressTarget
	}
	safeTarget, err := resolveTarget(ctx, targetHost, targetPort, route.AllowPrivateEgress, route.PrivateEgressCIDRs)
	if err != nil {
		// Only a verified address-policy violation is a denial. DNS and context
		// failures are operational failures, including when content checks audit only.
		status, code, message := "target_resolution_failed", http.StatusBadGateway, "Reverse proxy target resolution failed"
		if errors.Is(err, errUnsafeEgressTarget) {
			status, code, message = "egress_denied", http.StatusForbidden, "Forbidden: unsafe reverse proxy target"
		} else if errors.Is(err, context.DeadlineExceeded) {
			code = http.StatusGatewayTimeout
		} else if errors.Is(err, context.Canceled) {
			status, code, message = "cancelled", http.StatusRequestTimeout, "Reverse proxy request cancelled"
		}
		log.Printf("Reverse proxy target validation failed (%s): %v", status, err)
		record, recordErr := newReverseProxyAuditRecord(requestID, h.tenantID, targetHost, targetURL, r, reqBody, nil, status, code, 0, time.Since(startedAt))
		if recordErr != nil {
			return recordErr
		}
		h.writeReverseProxyAudit(context.WithoutCancel(ctx), record, reqBody, requestContentType, nil, "", secAudit)
		if status == "egress_denied" && h.auditRecorder != nil {
			// 防跳板出站拒绝记一条安全事件（观察留痕也照拒）。
			event := record
			event.InputSemanticStatus, event.InputSemanticReason = "incomplete", reverseProxyEgressDeniedReason
			h.auditRecorder.WriteReverseProxySecurityEvent(context.WithoutCancel(ctx), event, "input", "block", nil)
		}
		http.Error(w, message, code)
		return nil
	}

	outReq, err := http.NewRequestWithContext(ctx, r.Method, targetURL.String(), bytes.NewReader(reqBody)) // #nosec G107,G704 -- configured route target is DNS validated before request creation.
	if err != nil {
		return fmt.Errorf("create outbound request: %w", err)
	}

	copyHeaders(outReq.Header, r.Header)
	outReq.Host = targetURL.Host
	outReq.Header.Del("Proxy-Connection")
	// Rewrite Origin and Referer to match target domain (avoid CORS rejection by upstream)
	if origin := outReq.Header.Get("Origin"); origin != "" {
		outReq.Header.Set("Origin", strings.TrimRight(route.TargetURL, "/"))
	}
	if referer := outReq.Header.Get("Referer"); referer != "" {
		outReq.Header.Set("Referer", strings.TrimRight(route.TargetURL, "/")+"/")
	}
	outReq.Header.Set("X-Forwarded-Proto", forwardedProto(r))
	outReq.Header.Set("X-Forwarded-For", appendForwardedFor(r.Header.Get("X-Forwarded-For"), clientIPFromRemoteAddr(r.RemoteAddr)))

	// 流式中继用"无整请求 Timeout"的 client(总时长由上面的 ctx 控), 修掉 codex 等长流式
	// 响应被 120s wall-clock 硬断的根因。刻意不动 h.client —— 它被 checkSecurity 复用。
	client := streamingHTTPClientForReverseProxy(h.client, safeTarget)
	resp, err := client.Do(outReq) // #nosec G107,G704 -- configured route target is DNS validated and the client dials the pinned safe IP.
	if err != nil {
		if clientGoneDuring(ctx, err) {
			// 上游请求绑在请求 ctx 上：客户端在等上游响应头期间断开，不是上游失败。
			log.Printf("Reverse proxy request cancelled while waiting for upstream: %v", err)
			return h.finishReverseClientGone(ctx, w, r, requestID, targetHost, targetURL, reqBody, requestContentType, "", startedAt, secAudit)
		}
		record, recordErr := newReverseProxyAuditRecord(requestID, h.tenantID, targetHost, targetURL, r, reqBody, nil, "failed", 0, 0, time.Since(startedAt))
		if recordErr != nil {
			return recordErr
		}
		h.writeReverseProxyAudit(context.WithoutCancel(ctx), record, reqBody, requestContentType, nil, "", secAudit)
		return fmt.Errorf("call upstream: %w", err)
	}
	defer resp.Body.Close()

	bytesSent := int64(len(reqBody))
	contentType := strings.ToLower(resp.Header.Get("Content-Type"))
	responseContentType := resp.Header.Get("Content-Type")

	if strings.Contains(contentType, "text/event-stream") && !hasRequestRedaction(ctx, redactionEnvelope) {
		copyHeaders(w.Header(), resp.Header)
		w.Header().Set("X-Request-ID", requestID)
		w.Header().Set("X-JJDGuard-Request-ID", requestID)
		w.Header().Del("Content-Length") // SSE 流式响应不应带 Content-Length
		w.WriteHeader(resp.StatusCode)
		capture := &headTailReverseProxyCapture{limit: maxReverseProxyRetainedBodyBytes}
		var bytesReceived int64
		var copyErr error
		var decision reverseProxySecurityDecision
		blocked := false
		if route.SecurityEnabled {
			bytesReceived, decision, blocked, copyErr = h.copyGuardedReverseSSE(ctx, w, resp.Body, capture, requestID, targetHost, securityTargetPath)
		} else {
			bytesReceived, copyErr = copySSEWithFlush(w, capture, resp.Body)
		}
		status := "success"
		clientGone := route.SecurityEnabled && errors.Is(copyErr, errClientGoneDuringSecurity)
		if blocked {
			status = "blocked"
		} else if clientGone {
			// 客户端在输出检测期间断开：不是检测失败，也不是拦截。200 头已写出，
			// 这里只改审计状态；copyGuardedReverseSSE 已保证不写终止帧、不 flush 持有帧。
			status = "cancelled"
			copyErr = nil
		} else if copyErr != nil {
			status = "failed"
		}
		if captured, captureErr := captureGatewayResponsesDiagnostic(requestID, targetHost, securityTargetPath, responseContentType, capture.Bytes()); captureErr != nil {
			log.Printf("Gateway Responses diagnostic capture failed: %v", captureErr)
		} else if captured {
			log.Printf("Gateway Responses diagnostic captured one response for request %s", requestID)
		}

		if route.SecurityEnabled {
			if clientGone {
				// 断开不是检测失败。此分支可达：流末 checkStreamInspection 前面窗口真实失败（已标 incomplete、
				// 可能已入重试队列）后，后面窗口扫描期间客户端断开，会带着这次失败返回断开哨兵。
				// 清掉失败带来的标签，不对已中止的请求再写 security_check_failed，fail-closed 下也不写
				// 无命中的 security_blocked；已入队的重试任务、此前窗口的真实命中照常保留。
				if decision.SemanticStatus == "incomplete" {
					decision.SemanticStatus, decision.SemanticReason = "", ""
				}
				if decision.DetectionFailed && !hasSecurityFindings(decision.Findings) {
					decision.Action, decision.Allowed, decision.DetectionFailed = "allow", true, false
				}
			}
			secAudit.outputRetryIDs, secAudit.outputRetryUnavailable = decision.RetryTaskIDs, decision.RetryUnavailable
			secAudit.outputSemanticStatus, secAudit.outputSemanticReason = decision.SemanticStatus, decision.SemanticReason
			secAudit.outputContent = decision.VerifiedContent
			secAudit.outputSource = decision.ContentSource
			secAudit.outputAction = decision.Action
			secAudit.outputRawAction = decision.RawAction
			secAudit.outputGuarded = decision.ContentSource == "verified_final_output"
			secAudit.outputFindings = decision.Findings
			secAudit.outputFileAttachmentRisk = decision.FileAttachmentRisk
		}
		record, recordErr := newReverseProxyAuditRecord(requestID, h.tenantID, targetHost, targetURL, r, reqBody, capture.Bytes(), status, resp.StatusCode, bytesReceived, time.Since(startedAt))
		if recordErr != nil {
			return recordErr
		}
		record.OutputAlreadySent = true
		record.ResponseCaptureTruncated = capture.Truncated()
		h.writeReverseProxyAudit(context.WithoutCancel(ctx), record, reqBody, requestContentType, capture.Bytes(), responseContentType, secAudit)
		if route.StatsEnabled {
			h.recordUsageAsync(context.WithoutCancel(ctx), targetHost, targetPort, bytesSent, bytesReceived)
		}
		return copyErr
	}

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		if clientGoneDuring(ctx, err) {
			// 读响应体期间客户端断开：上游连接随请求 ctx 关闭，读失败是断开的结果，不记 failed；
			// 未读完的正文不写给客户端。总超时到期是 DeadlineExceeded，照旧走下面的 failed。
			log.Printf("Reverse proxy request cancelled while reading upstream response: %v", err)
			return h.finishReverseClientGone(ctx, w, r, requestID, targetHost, targetURL, reqBody, requestContentType, responseContentType, startedAt, secAudit)
		}
		record, recordErr := newReverseProxyAuditRecord(requestID, h.tenantID, targetHost, targetURL, r, reqBody, nil, "failed", resp.StatusCode, 0, time.Since(startedAt))
		if recordErr != nil {
			return recordErr
		}
		h.writeReverseProxyAudit(context.WithoutCancel(ctx), record, reqBody, requestContentType, nil, responseContentType, secAudit)
		return fmt.Errorf("read upstream response: %w", err)
	}

	auditedRespBody := respBody
	if route.SecurityEnabled && len(respBody) > 0 {
		decision, err := h.checkResponseSecurityStructured(ctx, requestID, respBody, responseContentType, targetHost, securityTargetPath)
		if clientGoneDuring(ctx, err) {
			// 客户端在输出检测期间断开：响应正文不写给客户端（本来就没有人在收，也未经扫描），
			// 不是检测失败。审计沿用 blocked 分支的参数形态（带 respBody，留证不比以前少），
			// 但 output 语义状态不标 incomplete，也不入重试队列。
			log.Printf("Reverse proxy request cancelled during output security check: %v", err)
			record, recordErr := newReverseProxyAuditRecord(requestID, h.tenantID, targetHost, targetURL, r, reqBody, respBody, "cancelled", http.StatusRequestTimeout, int64(len(respBody)), time.Since(startedAt))
			if recordErr != nil {
				return recordErr
			}
			h.writeReverseProxyAudit(context.WithoutCancel(ctx), record, reqBody, requestContentType, respBody, responseContentType, secAudit)
			http.Error(w, "Reverse proxy request cancelled", http.StatusRequestTimeout)
			return nil
		}
		decision = h.applyReverseInspectionPolicy(ctx, decision)
		secAudit.outputRetryIDs, secAudit.outputRetryUnavailable = decision.RetryTaskIDs, decision.RetryUnavailable
		if err != nil {
			log.Printf("Reverse proxy response security check failed: %v", err)
		}
		secAudit.outputContent = decision.VerifiedContent
		secAudit.outputSource = decision.ContentSource
		secAudit.outputSemanticStatus, secAudit.outputSemanticReason = decision.SemanticStatus, decision.SemanticReason
		secAudit.outputAction = decision.Action
		secAudit.outputRawAction = decision.RawAction
		secAudit.outputFindings = decision.Findings
		secAudit.outputFileAttachmentRisk = decision.FileAttachmentRisk
		if !decision.Allowed {
			if h.applyReverseInspectionPolicy(ctx, decision).Allowed == false {
				code := http.StatusForbidden
				unavailable := decision.SemanticStatus == "incomplete" && !hasSecurityFindings(decision.Findings)
				if unavailable {
					code = http.StatusServiceUnavailable
				}
				record, recordErr := newReverseProxyAuditRecord(requestID, h.tenantID, targetHost, targetURL, r, reqBody, respBody, "blocked", code, int64(len(respBody)), time.Since(startedAt))
				if recordErr != nil {
					return recordErr
				}
				h.writeReverseProxyAudit(context.WithoutCancel(ctx), record, reqBody, requestContentType, respBody, responseContentType, secAudit)
				if unavailable {
					writeGuardrailDetectionUnavailable(w, requestID, false)
				} else {
					notice := h.reverseBlockNotice(ctx, requestID, "output", decision.Findings)
					setBlockNoticeHeaders(w, notice)
					http.Error(w, notice.Text, code)
				}
				return nil
			}
		} else if exitMode == securityexit.Protect {
			respBody = decision.Body
			auditedRespBody = decision.Body
		}
	}

	if captured, captureErr := captureGatewayResponsesDiagnostic(requestID, targetHost, securityTargetPath, responseContentType, respBody); captureErr != nil {
		log.Printf("Gateway Responses diagnostic capture failed: %v", captureErr)
	} else if captured {
		log.Printf("Gateway Responses diagnostic captured one response for request %s", requestID)
	}

	// URL rewriting for HTML responses: replace target domain with proxy path
	respBody = rewriteResponseURLs(respBody, contentType, route, h.allRoutes, r.Host)

	copyHeaders(w.Header(), resp.Header)
	w.Header().Set("X-Request-ID", requestID)
	w.Header().Set("X-JJDGuard-Request-ID", requestID)
	w.Header().Del("Content-Length")
	// Strip security headers that break cross-origin reverse proxy
	w.Header().Del("Content-Security-Policy")
	w.Header().Del("Content-Security-Policy-Report-Only")
	w.Header().Del("Strict-Transport-Security")
	w.Header().Del("X-Frame-Options")
	// Rewrite Set-Cookie headers: strip Domain, Secure, SameSite restrictions
	if cookies := w.Header().Values("Set-Cookie"); len(cookies) > 0 {
		w.Header().Del("Set-Cookie")
		for _, cookie := range cookies {
			rewritten := rewriteSetCookie(cookie)
			w.Header().Add("Set-Cookie", rewritten)
		}
	}
	// Rewrite Location header for redirects (e.g., / -> /doubao/)
	if loc := resp.Header.Get("Location"); loc != "" {
		rewrittenLoc := rewriteURLString(loc, route.TargetURL, route.PathPrefix, r.Host)
		if rewrittenLoc != loc {
			w.Header().Set("Location", rewrittenLoc)
		}
	}
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(resp.StatusCode)
	respBody = restoreRedactionBody(ctx, redactionEnvelope, respBody)
	if _, err := w.Write(respBody); err != nil { // #nosec G705 // nosemgrep: go.lang.security.audit.xss.no-direct-write-to-responsewriter.no-direct-write-to-responsewriter -- reverse proxy intentionally relays upstream response after policy checks.
		record, recordErr := newReverseProxyAuditRecord(requestID, h.tenantID, targetHost, targetURL, r, reqBody, auditedRespBody, "failed", resp.StatusCode, int64(len(respBody)), time.Since(startedAt))
		if recordErr != nil {
			return recordErr
		}
		h.writeReverseProxyAudit(context.WithoutCancel(ctx), record, reqBody, requestContentType, auditedRespBody, responseContentType, secAudit)
		return fmt.Errorf("write downstream response: %w", err)
	}

	record, recordErr := newReverseProxyAuditRecord(requestID, h.tenantID, targetHost, targetURL, r, reqBody, auditedRespBody, "success", resp.StatusCode, int64(len(respBody)), time.Since(startedAt))

	if recordErr != nil {

		return recordErr

	}
	h.writeReverseProxyAudit(context.WithoutCancel(ctx), record, reqBody, requestContentType, auditedRespBody, responseContentType, secAudit)

	if route.StatsEnabled {
		h.recordUsageAsync(context.WithoutCancel(ctx), targetHost, targetPort, bytesSent, int64(len(respBody)))
	}
	return nil
}

// reverseBlockNotice shares the configured wording and request/event join keys
// with native gateway protocols. A live stream may only have a request ID until
// its final event is persisted after termination.
func (h *ReverseProxyHandler) reverseBlockNotice(ctx context.Context, requestID, stage string, findings []SecurityFinding) securityBlockNotice {
	settings := blockNoticeSettings{Mode: blockResponseModeError, Template: DefaultBlockNoticeTemplate}
	if h != nil && h.runtimeConfigClient != nil {
		settings = h.runtimeConfigClient.BlockNoticeSettings(ctx)
	}
	attribution := deriveBlockAttribution(withSecurityEventStage(ctx, stage), "", findings, "security_blocked", "")
	attribution.RequestID = requestID
	if persisted := requestBlockAttribution(ctx); persisted != nil {
		attribution = *persisted
	}
	return securityBlockNotice{
		Mode:         blockResponseModeError,
		Text:         renderBlockNotice(settings.Template, attribution),
		RetainedText: renderBlockNotice(settings.Template, retainedNoticeAttribution(attribution)),
		Attribution:  attribution,
	}
}

// finishReverseClientGone 收尾「等上游或读上游期间客户端断开」：记 cancelled/408（收尾写库脱离请求取消），
// 不写安全事件、不入重试队列，也不把任何上游内容写给客户端。
func (h *ReverseProxyHandler) finishReverseClientGone(ctx context.Context, w http.ResponseWriter, r *http.Request, requestID, targetHost string, targetURL *url.URL, reqBody []byte, requestContentType, responseContentType string, startedAt time.Time, secAudit reverseProxySecurityAudit) error {
	record, err := newReverseProxyAuditRecord(requestID, h.tenantID, targetHost, targetURL, r, reqBody, nil, "cancelled", http.StatusRequestTimeout, 0, time.Since(startedAt))
	if err != nil {
		return err
	}
	h.writeReverseProxyAudit(context.WithoutCancel(ctx), record, reqBody, requestContentType, nil, responseContentType, secAudit)
	http.Error(w, "Reverse proxy request cancelled", http.StatusRequestTimeout)
	return nil
}

func (h *ReverseProxyHandler) writeReverseProxyAudit(ctx context.Context, record reverseProxyAuditRecord, requestBody []byte, requestContentType string, responseBody []byte, responseContentType string, sec reverseProxySecurityAudit) {
	if h == nil || h.auditRecorder == nil {
		return
	}
	record.InputRetryIDs, record.OutputRetryIDs = sec.inputRetryIDs, sec.outputRetryIDs
	record.InputRetryUnavailable, record.OutputRetryUnavailable = sec.inputRetryUnavailable, sec.outputRetryUnavailable
	record.InputSemanticStatus, record.InputSemanticReason = sec.inputSemanticStatus, sec.inputSemanticReason
	record.OutputSemanticStatus, record.OutputSemanticReason = sec.outputSemanticStatus, sec.outputSemanticReason
	record.InputContentSource = sec.inputSource
	record.OutputContentSource = sec.outputSource
	record.InputRawSecurityAction, record.OutputRawSecurityAction = sec.inputRawAction, sec.outputRawAction
	record.OutputGuarded = sec.outputGuarded
	h.auditRecorder.WriteReverseProxyAccess(ctx, record)
	if record.ContentRetained {
		h.auditRecorder.WriteReverseProxyContent(ctx, record, requestBody, requestContentType, responseBody, responseContentType)
	}
	if shouldPersistSecurityEvent(sec.inputAction, sec.inputFindings) || sec.inputSemanticStatus == "incomplete" {
		h.auditRecorder.WriteReverseProxySecurityEvent(ctx, record, "input", reverseProxyEffectiveAuditAction(sec.inputAction, sec.auditOnly, sec.inputFileAttachmentRisk, sec.inputSemanticStatus, sec.inputFindings), sec.inputFindings)
		h.dispatchReverseProxyTriage(ctx, record, "input", sec.inputSource, sec.inputContent, sec.inputFindings)
	}
	if shouldPersistSecurityEvent(sec.outputAction, sec.outputFindings) || sec.outputSemanticStatus == "incomplete" {
		h.auditRecorder.WriteReverseProxySecurityEvent(ctx, record, "output", reverseProxyEffectiveAuditAction(sec.outputAction, sec.auditOnly, sec.outputFileAttachmentRisk, sec.outputSemanticStatus, sec.outputFindings), sec.outputFindings)
		h.dispatchReverseProxyTriage(ctx, record, "output", sec.outputSource, sec.outputContent, sec.outputFindings)
	}
}
func (h *ReverseProxyHandler) dispatchReverseProxyTriage(ctx context.Context, record reverseProxyAuditRecord, stage, contentSource, content string, findings []SecurityFinding) {
	if h == nil || h.securityURL == "" || h.auditRecorder == nil || len(findings) == 0 {
		return
	}
	if contentSource != "verified_user_input" && contentSource != "verified_final_output" {
		return
	}
	annotator, ok := h.auditRecorder.(reverseProxyTriageAnnotator)
	if !ok {
		return
	}
	select {
	case asyncSemaphore <- struct{}{}:
	default:
		log.Printf("[reverse-proxy-triage] dropped (semaphore full) req=%s", record.RequestID)
		return
	}
	fs := append([]SecurityFinding(nil), findings...)
	envRecord := record
	go func() {
		defer func() { <-asyncSemaphore }()
		defer func() {
			if recovered := recover(); recovered != nil {
				log.Printf("[reverse-proxy-triage] panic req=%s: %v", envRecord.RequestID, recovered)
			}
		}()
		triageCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
		defer cancel()
		client := security.NewClientWithSecret(h.securityURL, h.internalSecret)
		response, err := client.CheckTriage(triageCtx, &security.CheckTriageRequest{
			RequestID:     envRecord.RequestID,
			Content:       content,
			Findings:      handlerFindingsToSecurity(fs),
			ContentSource: contentSource,
			Stage:         stage,
		})
		if err != nil {
			for i := range fs {
				fs[i].Triage = map[string]any{
					"verdict": "needs_review", "review_state": "unavailable",
					"risk_level": "medium", "confidence": 0.0,
					"reason": "judge unavailable; manual review required",
				}
			}
			annotator.AnnotateReverseProxyTriage(triageCtx, envRecord, stage, fs, "unavailable", "medium")
			return
		}
		triaged := convertSecurityFindings(response.Findings)
		if len(triaged) == 0 {
			triaged = fs
		}
		state, effective := reverseProxyTriageState(triaged)
		annotator.AnnotateReverseProxyTriage(triageCtx, envRecord, stage, triaged, state, effective)
	}()
}

func reverseProxyTriageState(findings []SecurityFinding) (string, string) {
	state := "needs_review"
	for _, finding := range findings {
		verdict, _ := finding.Triage["verdict"].(string)
		switch verdict {
		case "confirmed_risk":
			return "confirmed_risk", getFindingsSeverity(findings)
		case "likely_false_positive":
			state = "likely_false_positive"
		case "audit_evidence":
			if state != "likely_false_positive" {
				state = "audit_evidence"
			}
		}
		if finding.Type == "semantic_attack" && len(finding.Triage) == 0 {
			state = "confirmed_risk"
		}
	}
	if state == "likely_false_positive" || state == "audit_evidence" {
		return state, "low"
	}
	return state, "medium"
}

// reverseProxySecurityActionTaken 将 security-engine 处置动作与 audit-only 开关映射为
// security_events.action_taken。audit-only 下即便引擎判 block 也未真正阻断，统一记为
// security_audit_only，避免事件页 / 告警误导客户以为流量被拦。
func reverseProxySecurityActionTaken(action string, auditOnly bool, fileAttachmentRisk bool) string {
	if auditOnly {
		return "security_audit_only"
	}
	// fileAttachmentRisk no longer escalates: an attachment finding is handled
	// by the action its rule is configured with, like any other finding.
	_ = fileAttachmentRisk
	if securityexit.Blocks(action) {
		return "security_blocked"
	}
	switch action {
	case "mask", "redact":
		return "security_masked"
	default:
		return "security_audit"
	}
}

func (h *ReverseProxyHandler) checkRequestSecurity(ctx context.Context, requestID string, body []byte, contentType, targetHost, targetPath string) (reverseProxySecurityDecision, error) {
	return h.checkRequestSecurityWithAttachments(ctx, requestID, body, contentType, targetHost, targetPath, extractRequestAttachmentsForProxy(body, contentType, targetPath))
}

func (h *ReverseProxyHandler) checkRequestSecurityWithAttachments(ctx context.Context, requestID string, body []byte, contentType, targetHost, targetPath string, attachments []map[string]interface{}) (reverseProxySecurityDecision, error) {
	var extraContext map[string]interface{}
	if len(attachments) > 0 {
		extraContext = map[string]interface{}{"attachments": attachments}
	}
	return h.checkSecurityWithExtras(ctx, requestID, "/check-input/", body, string(body), contentType, targetHost, targetPath, "", extraContext)
}

func (h *ReverseProxyHandler) checkResponseSecurity(ctx context.Context, requestID string, body []byte, contentType, targetHost, targetPath string) (reverseProxySecurityDecision, error) {
	return h.checkSecurity(ctx, requestID, "/check-output/", body, contentType, targetHost, targetPath)
}

// reverseProxySecurityContext 组装发给 security-engine 的检测上下文：在原有
// {tenant_id, source} 之上，复用目录匹配补齐端点画像（endpoint_kind/product/
// access_type/target_host，与 C 路正向代理同口径）。引擎降级层据此识别编码/AI IDE
// 流量（endpoint_kind==coding / access_type==ai_ide），对反代流量不再失明。
func (h *ReverseProxyHandler) reverseProxySecurityContext(targetHost, targetPath string) map[string]interface{} {
	secContext := map[string]interface{}{
		"tenant_id": h.tenantID,
		"source":    "reverse_proxy",
	}
	if targetHost == "" {
		return secContext
	}
	match := matchReverseProxyProvider(targetHost, targetPath)
	accessType, _, _ := reverseProxyAccessPolicy(match)
	secContext["access_type"] = accessType
	secContext["target_host"] = llmcatalog.NormalizeHost(targetHost)
	if match.EndpointKind != "" {
		secContext["endpoint_kind"] = match.EndpointKind
	}
	if match.Product != "" {
		secContext["product"] = match.Product
	}
	return secContext
}

func (h *ReverseProxyHandler) checkSecurity(ctx context.Context, requestID string, path string, body []byte, contentType, targetHost, targetPath string) (reverseProxySecurityDecision, error) {
	return h.checkSecurityWithExtras(ctx, requestID, path, body, string(body), contentType, targetHost, targetPath, "", nil)
}

func verifiedReverseProxyContentSource(contentSource string, extraContext map[string]interface{}) string {
	verified, _ := extraContext["verified_content"].(bool)
	if !verified {
		return contentSource
	}
	stage, _ := extraContext["verified_stage"].(string)
	switch strings.TrimSpace(stage) {
	case "input":
		return "verified_user_input"
	case "output":
		return "verified_final_output"
	default:
		return contentSource
	}
}

// checkSecurityWithExtras 在 checkSecurity 之上支持：content 与原始 body 分离（分组送检时
// content 是某一 source 的拼接文本，body 仍是整包原文用于 mask 回填）、顶层 content_source
// （共享契约第 3 条）、附加 context 键（agent_type / extraction 打标）。
// extraContext 中的 skip_semantic 是安全 API 顶层控制字段，不写入 context；用于已知 LLM
// 协议解析降级和 unknown 来源，确定性扫描继续、指令覆盖语义裁判跳过。
// contentSource=="" 且 extraContext==nil 时与旧 checkSecurity 行为完全一致。
func (h *ReverseProxyHandler) checkSecurityWithExtras(ctx context.Context, requestID, path string, body []byte, content, contentType, targetHost, targetPath, contentSource string, extraContext map[string]interface{}) (decision reverseProxySecurityDecision, retErr error) {
	if h.securityURL == "" || len(body) == 0 || content == "" {
		return reverseProxySecurityDecision{Body: body, Allowed: true}, nil
	}

	if requestID == "" {
		requestID = "reverse_proxy"
	}

	secContext := h.reverseProxySecurityContext(targetHost, targetPath)
	protocol, _ := secContext["provider"].(string)
	trustedPrincipal, _ := principal.Normalize(principal.Context{
		TenantID: h.tenantID, Protocol: strings.ToLower(strings.TrimSpace(protocol)),
		EntryPoint: "reverse_proxy", IdentitySource: principal.SourceReverseProxy,
		TrustLevel: principal.TrustUnknown, IdentityVersion: "1",
	})
	skipSemantic := false
	for key, value := range extraContext {
		if key == "skip_semantic" {
			if enabled, ok := value.(bool); ok {
				skipSemantic = enabled
			}
			continue
		}
		if s, ok := value.(string); ok && strings.TrimSpace(s) == "" {
			continue
		}
		secContext[key] = value
	}
	payload := map[string]interface{}{
		"request_id":   requestID,
		"content":      content,
		"content_type": securityContentType(contentType),
		"context":      secContext,
		"principal":    trustedPrincipal,
	}
	if contentSource != "" {
		payload["content_source"] = contentSource
	}
	if skipSemantic {
		payload["skip_semantic"] = true
	}

	jsonBody, err := json.Marshal(payload)
	if err != nil {
		d := h.reverseInspectionFailure(ctx, err, "inspection_payload_invalid")
		d.Body = body
		return d, err
	}

	result, err := h.postReverseInspection(ctx, path, jsonBody)
	requiresSemantic := path == "/check-input/" && result.SemanticStatus == "incomplete" && !skipSemantic
	// 客户端在安全检测期间断开（Esc / 中断）不是检测失败：ctx 必须是原始请求 ctx（或只加
	// value/超时的派生 ctx，父 ctx 取消时 Err() 必为 Canceled），不能是 postReverseInspection
	// 自己加的短超时 ctx。DeadlineExceeded、引擎不可达、引擎自己 cancel 而请求 ctx 存活都不算。
	clientGone := clientGoneDuring(ctx, err)
	defer func() {
		if reverseInspectionComplete(result, err) {
			return
		}
		// 断开时不入重试队列：输入侧内容从未转发上游；输出侧非流式整包未送达客户端、流式持有帧
		// 只有扫描通过后才放行，没有「未经扫描就送达」的内容，补扫没有留证价值，只会针对
		// 已中止的请求产生假告警。其它失败路径照旧入队。
		if clientGone {
			return
		}
		decision.RetryUnavailable = true
		if h.retryQueue != nil {
			if id, storeErr := h.retryQueue.enqueue(requestID, path, jsonBody, requiresSemantic); storeErr == nil {
				decision.RetryTaskIDs = []string{id}
				decision.RetryUnavailable = false
			} else {
				log.Printf("Failed to persist inspection retry: %v", storeErr)
			}
		}
	}()
	if clientGone {
		// 干净的 decision：不带 DetectionFailed / SemanticStatus / RetryUnavailable，不调
		// reverseInspectionFailure（不走 fail-closed、不产生 security_check_failed）。调用方看到
		// 哨兵错误后按 cancelled/408 收尾，不会使用这份 decision 去放行或拦截。
		return reverseProxySecurityDecision{Body: body, Allowed: true, Action: "allow"},
			fmt.Errorf("%w: reverse proxy %s", errClientGoneDuringSecurity, path)
	}
	if err != nil {
		d := h.reverseInspectionFailure(ctx, err, "security_engine_unavailable")
		d.Body = body
		return d, err
	}
	if !reverseInspectionComplete(result, nil) && result.SemanticStatus != "incomplete" {
		result.SemanticStatus = "incomplete"
		result.SemanticReason = "inspection_incomplete"
	}

	findings := convertSecurityFindings(result.Findings)
	decisionContentSource := verifiedReverseProxyContentSource(contentSource, extraContext)
	fileAttachment := reverseProxyContextHasAttachments(extraContext)
	fileAttachmentRisk := fileAttachment && (hasFileAttachmentFindings(findings) ||
		(len(findings) == 0 && reverseProxyActionRequiresIntervention(result.Action)))
	decision = reverseProxySecurityDecision{
		SemanticStatus: result.SemanticStatus,
		SemanticReason: result.SemanticReason,
		Body:           body,
		Action:         result.Action,
		Findings:       findings,
		Allowed:        true,
		Stage: func() string {
			if path == "/check-output/" {
				return "output"
			}
			return "input"
		}(),
		FileAttachmentRisk: fileAttachmentRisk,
		ContentSource:      decisionContentSource,
		VerifiedContent: func() string {
			if contentSource != "" {
				return content
			}
			return ""
		}(),
	}
	switch strings.ToLower(strings.TrimSpace(result.Action)) {
	case "mask", "redact":
		if fileAttachment {
			// 二进制或附件引用没有安全的整包 mask 语义。规则配置的是"脱敏"而不是
			// "阻断"：原文件照常外发，并按"无法脱敏"记为告警（不谎称已脱敏）。
			decision.Action = "audit"
			decision.MaskUnavailable = true
		} else if result.MaskedContent != "" {
			decision.Body = []byte(result.MaskedContent)
			if path == "/check-input/" && !h.securityAuditOnly(ctx) {
				addRequestRedaction(ctx, &modelrouter.RequestEnvelope{RequestID: requestID, TenantID: h.tenantID, BillingIngress: "reverse_proxy"}, result.MaskedContent, result.RedactionMapping)
			}
		}
	}
	return h.applyReverseInspectionPolicy(ctx, decision), nil
}

func reverseProxyActionRequiresIntervention(action string) bool {
	switch strings.ToLower(strings.TrimSpace(action)) {
	case "block", "reply", "deny", "quarantine", "mask", "redact":
		return true
	default:
		return false
	}
}

func reverseProxyContextHasAttachments(extraContext map[string]interface{}) bool {
	if extraContext == nil {
		return false
	}
	switch attachments := extraContext["attachments"].(type) {
	case []map[string]interface{}:
		return len(attachments) > 0
	case []interface{}:
		return len(attachments) > 0
	default:
		return false
	}
}

func (h *ReverseProxyHandler) recordUsageAsync(parent context.Context, host string, port int, bytesSent, bytesReceived int64) {
	if h.db == nil || (bytesSent == 0 && bytesReceived == 0) {
		return
	}
	go h.recordUsage(parent, host, port, bytesSent, bytesReceived)
}

func (h *ReverseProxyHandler) recordUsage(parent context.Context, host string, port int, bytesSent, bytesReceived int64) {
	ctx, cancel := context.WithTimeout(parent, 5*time.Second)
	defer cancel()

	_, err := h.db.Exec(ctx,
		`INSERT INTO proxy_usage_logs (tenant_id, host, port, bytes_sent, bytes_received)
		 VALUES ($1, $2, $3, $4, $5)`,
		h.tenantID, host, port, bytesSent, bytesReceived,
	)
	if err != nil {
		log.Printf("Failed to record reverse proxy usage: %v", err)
	}
}

func pathMatchesPrefix(path, prefix string) bool {
	if prefix == "" {
		return false
	}
	if prefix == "/" {
		return strings.HasPrefix(path, "/")
	}
	if !strings.HasPrefix(path, prefix) {
		return false
	}
	if len(path) == len(prefix) {
		return true
	}
	return path[len(prefix)] == '/'
}

func buildReverseProxyTargetURL(route *ReverseProxyRoute, requestURL *url.URL) (*url.URL, error) {
	targetURL, err := url.Parse(route.TargetURL)
	if err != nil {
		return nil, err
	}

	requestSuffix := strings.TrimPrefix(requestURL.Path, route.PathPrefix)
	if requestSuffix == "" {
		requestSuffix = "/"
	}

	basePath := joinURLPath(targetURL.Path, route.TargetPathPrefix)
	targetURL.Path = joinURLPath(basePath, requestSuffix)
	targetURL.RawQuery = requestURL.RawQuery
	return targetURL, nil
}

func joinURLPath(base, suffix string) string {
	base = strings.TrimSpace(base)
	suffix = strings.TrimSpace(suffix)

	if base == "" {
		if suffix == "" {
			return "/"
		}
		if strings.HasPrefix(suffix, "/") {
			return suffix
		}
		return "/" + suffix
	}
	if suffix == "" || suffix == "/" {
		if strings.HasPrefix(base, "/") {
			return strings.TrimRight(base, "/")
		}
		return "/" + strings.TrimRight(base, "/")
	}

	base = strings.TrimRight(base, "/")
	suffix = strings.TrimLeft(suffix, "/")
	if base == "" {
		return "/" + suffix
	}
	if strings.HasPrefix(base, "/") {
		return base + "/" + suffix
	}
	return "/" + base + "/" + suffix
}

func copyHeaders(dst, src http.Header) {
	for key, values := range src {
		if isLSECorrelationHeader(key) {
			continue
		}
		dst.Del(key)
		for _, value := range values {
			dst.Add(key, value)
		}
	}
}

func isLSECorrelationHeader(key string) bool {
	return strings.HasPrefix(strings.ToLower(key), "x-lse-")
}

func forwardedProto(r *http.Request) string {
	if r.TLS != nil {
		return "https"
	}
	return "http"
}

func clientIPFromRemoteAddr(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err == nil {
		return host
	}
	return remoteAddr
}

func appendForwardedFor(existing, clientIP string) string {
	if existing == "" {
		return clientIP
	}
	if clientIP == "" {
		return existing
	}
	return existing + ", " + clientIP
}

func upstreamHostPort(targetURL *url.URL) (string, int) {
	host := targetURL.Hostname()
	port := 80
	if strings.EqualFold(targetURL.Scheme, "https") {
		port = 443
	}
	if rawPort := targetURL.Port(); rawPort != "" {
		if parsedPort, err := strconv.Atoi(rawPort); err == nil {
			port = parsedPort
		}
	}
	return host, port
}

func securityContentType(contentType string) string {
	if strings.Contains(strings.ToLower(contentType), "json") {
		return "json"
	}
	return "text"
}

// rewriteResponseURLs replaces target domain URLs in HTML content with proxy gateway URLs.
// This enables full website proxying (e.g., proxy doubao.com through the gateway).
func rewriteResponseURLs(body []byte, contentType string, route *ReverseProxyRoute, allRoutes []ReverseProxyRoute, gatewayHost string) []byte {
	if len(body) == 0 {
		return body
	}
	// Only rewrite for HTML and CSS/JS content
	if !strings.Contains(contentType, "text/html") && !strings.Contains(contentType, "text/css") &&
		!strings.Contains(contentType, "application/javascript") && !strings.Contains(contentType, "text/javascript") &&
		!strings.Contains(contentType, "application/json") {
		return body
	}

	originalURL := strings.TrimRight(route.TargetURL, "/")
	proxyPrefix := route.PathPrefix
	gatewayAddr := gatewayHost

	newBody := string(body)

	// Replace https://targetdomain.com/path -> proxyPrefix/path
	// e.g., https://www.doubao.com/chat -> /doubao/chat
	newBody = strings.ReplaceAll(newBody, originalURL, proxyPrefix)

	// Replace //targetdomain.com/path -> //gateway/path
	// e.g., //www.doubao.com/chat -> //gateway:8082/doubao/chat
	targetHost := extractTargetHost(route.TargetURL)
	if targetHost != "" {
		newBody = strings.ReplaceAll(newBody, "//"+targetHost, "//"+gatewayAddr+proxyPrefix)
	}

	// Rewrite all other configured routes too (CDN subdomain support)
	for _, otherRoute := range allRoutes {
		if otherRoute.PathPrefix == route.PathPrefix && otherRoute.TargetURL == route.TargetURL {
			continue
		}
		otherTarget := strings.TrimRight(otherRoute.TargetURL, "/")
		if strings.Contains(newBody, otherTarget) {
			newBody = strings.ReplaceAll(newBody, otherTarget, otherRoute.PathPrefix)
		}
		otherHost := extractTargetHost(otherRoute.TargetURL)
		if otherHost != "" && strings.Contains(newBody, "//"+otherHost) {
			newBody = strings.ReplaceAll(newBody, "//"+otherHost, "//"+gatewayAddr+otherRoute.PathPrefix)
		}
	}

	// Inject runtime script to patch fetch/XHR for SPA websites
	// This handles API calls dynamically constructed by JavaScript at runtime
	if strings.Contains(contentType, "text/html") {
		injectedScript := buildProxyInjectScript(route, allRoutes, gatewayAddr)
		if injectedScript != "" {
			lowerBody := strings.ToLower(newBody)
			headStart := strings.Index(lowerBody, "<head")
			headEnd := strings.Index(lowerBody, "</head>")
			bodyStart := strings.Index(newBody, "<body")
			insertPos := -1

			// Inject as early as possible so head scripts observe the patched location/fetch behavior.
			if headStart >= 0 {
				headClose := strings.Index(lowerBody[headStart:], ">")
				if headClose >= 0 {
					insertPos = headStart + headClose + 1
				}
			}
			if insertPos < 0 && headEnd >= 0 {
				insertPos = headEnd
			} else if insertPos < 0 && bodyStart >= 0 {
				bodyClose := strings.Index(newBody[bodyStart:], ">")
				if bodyClose >= 0 {
					insertPos = bodyStart + bodyClose + 1
				}
			}
			if insertPos >= 0 {
				newBody = newBody[:insertPos] + injectedScript + newBody[insertPos:]
			}
		}
	}

	return []byte(newBody)
}

// rewriteURLString rewrites a single URL string (e.g., Location header) from target domain to proxy.
func rewriteURLString(urlStr, targetURL, pathPrefix, gatewayHost string) string {
	if urlStr == "" {
		return urlStr
	}
	trimmedTarget := strings.TrimRight(targetURL, "/")
	urlStr = strings.ReplaceAll(urlStr, trimmedTarget, pathPrefix)
	// Also handle protocol-relative
	targetHost := extractTargetHost(targetURL)
	if targetHost != "" && strings.Contains(urlStr, targetHost) {
		urlStr = strings.ReplaceAll(urlStr, "//"+targetHost, "//"+gatewayHost+pathPrefix)
	}
	return urlStr
}

// rewriteSetCookie strips Domain, Secure, and SameSite attributes from Set-Cookie headers
// so cookies work on the proxy gateway domain.
func rewriteSetCookie(cookie string) string {
	parts := strings.Split(cookie, ";")
	var result []string
	for _, part := range parts {
		trimmed := strings.TrimSpace(strings.ToLower(part))
		if strings.HasPrefix(trimmed, "domain=") {
			continue
		}
		if trimmed == "secure" {
			continue
		}
		if strings.HasPrefix(trimmed, "samesite=") {
			result = append(result, " SameSite=Lax")
			continue
		}
		result = append(result, part)
	}
	return strings.Join(result, ";")
}

// buildProxyInjectScript generates a <script> tag that patches fetch() and XMLHttpRequest
// to redirect API calls from the target domain through the proxy gateway.
// This enables SPA websites (like doubao.com, chatgpt.com) to work through the reverse proxy.
func buildProxyInjectScript(route *ReverseProxyRoute, allRoutes []ReverseProxyRoute, gatewayAddr string) string {
	targetHost := extractTargetHost(route.TargetURL)
	if targetHost == "" {
		return ""
	}

	proxyPrefix := route.PathPrefix

	// Collect all target hosts and their corresponding proxy prefixes
	type hostMapping struct {
		Host        string
		ProxyPrefix string
	}
	var hosts []hostMapping
	seenHosts := make(map[string]bool)
	seenPrefixes := make(map[string]bool)
	prefixes := make([]string, 0, len(allRoutes)+1)

	if targetHost != "" {
		hosts = append(hosts, hostMapping{targetHost, proxyPrefix})
		seenHosts[targetHost] = true
	}
	if proxyPrefix != "" {
		prefixes = append(prefixes, proxyPrefix)
		seenPrefixes[proxyPrefix] = true
	}

	for _, otherRoute := range allRoutes {
		if otherRoute.PathPrefix == route.PathPrefix && otherRoute.TargetURL == route.TargetURL {
			continue
		}
		oh := extractTargetHost(otherRoute.TargetURL)
		if oh != "" && !seenHosts[oh] {
			hosts = append(hosts, hostMapping{oh, otherRoute.PathPrefix})
			seenHosts[oh] = true
		}
		if otherRoute.PathPrefix != "" && !seenPrefixes[otherRoute.PathPrefix] {
			prefixes = append(prefixes, otherRoute.PathPrefix)
			seenPrefixes[otherRoute.PathPrefix] = true
		}
	}

	// Build the script
	var sb strings.Builder
	sb.WriteString("<script>")
	sb.WriteString("(function(){")

	// Build array of rewrite rules: [{h:"host", p:"/prefix"}, ...]
	sb.WriteString("var rr=[")
	for i, h := range hosts {
		if i > 0 {
			sb.WriteString(",")
		}
		sb.WriteString(fmt.Sprintf("{h:%q,p:%q}", h.Host, h.ProxyPrefix))
	}
	sb.WriteString("];")
	sb.WriteString("var rp=[")
	for i, prefix := range prefixes {
		if i > 0 {
			sb.WriteString(",")
		}
		sb.WriteString(fmt.Sprintf("%q", prefix))
	}
	sb.WriteString("];")
	sb.WriteString(fmt.Sprintf("var pp=%q;", proxyPrefix))
	sb.WriteString("var hasProxyPrefix=function(path){for(var i=0;i<rp.length;i++){if(path===rp[i]||path.indexOf(rp[i]+'/')===0){return true}}return false};")
	sb.WriteString("var stripToRelative=function(parsed){return parsed.pathname+parsed.search+parsed.hash};")
	sb.WriteString("var parseURL=function(u){try{return new URL(u,location.href)}catch(e){return null}};")
	sb.WriteString("var mapKnownHost=function(parsed){for(var i=0;i<rr.length;i++){if(parsed.host===rr[i].h){return rr[i].p+parsed.pathname+parsed.search+parsed.hash}}return ''};")
	sb.WriteString("var f=function(u){if(typeof u!=='string'){return u}if(u.indexOf('data:')===0||u.indexOf('blob:')===0||u.indexOf('javascript:')===0||u.indexOf('mailto:')===0){return u}var parsed=parseURL(u);if(!parsed){return u}var mapped=mapKnownHost(parsed);if(mapped){return mapped}if(parsed.host===location.host){if(hasProxyPrefix(parsed.pathname)){return stripToRelative(parsed)}return pp+parsed.pathname+parsed.search+parsed.hash}if(u.charAt(0)==='/'&&!hasProxyPrefix(parsed.pathname)){return pp+parsed.pathname+parsed.search+parsed.hash}return u};")
	sb.WriteString("try{var op=Object.getOwnPropertyDescriptor(Location.prototype,'pathname');if(op&&op.get&&op.configurable){Object.defineProperty(Location.prototype,'pathname',{configurable:true,enumerable:op.enumerable,get:function(){var v=op.get.call(this);if(v===pp){return '/'}return v.indexOf(pp+'/')===0?v.substring(pp.length)||'/':v},set:op.set?function(v){if(typeof v==='string'&&v.charAt(0)==='/'&&!hasProxyPrefix(v)){v=pp+v}return op.set.call(this,v)}:undefined})}}catch(e){}")
	sb.WriteString("try{var hp=history.pushState;history.pushState=function(s,t,u){var nu=typeof u==='string'?f(u):u;return hp.call(history,s,t,nu)};var hr=history.replaceState;history.replaceState=function(s,t,u){var nu=typeof u==='string'?f(u):u;return hr.call(history,s,t,nu)}}catch(e){}")
	sb.WriteString("try{var oa=location.assign;if(oa){location.assign=function(u){return oa.call(location,f(u))}}}catch(e){}")
	sb.WriteString("try{var or=location.replace;if(or){location.replace=function(u){return or.call(location,f(u))}}}catch(e){}")
	sb.WriteString("try{var of=window.fetch;if(of){window.fetch=function(u,i){if(typeof Request!=='undefined'&&u instanceof Request){var ru=f(u.url);if(ru!==u.url){u=new Request(ru,u)}}else{u=f(u)}return of.call(this,u,i)}}}catch(e){}")
	sb.WriteString("try{var ox=XMLHttpRequest.prototype.open;XMLHttpRequest.prototype.open=function(m,u){if(typeof u==='string'){arguments[1]=f(u)}return ox.apply(this,arguments)}}catch(e){}")
	sb.WriteString("try{var ob=navigator.sendBeacon;if(ob){navigator.sendBeacon=function(u,d){return ob.call(this,f(u),d)}}}catch(e){}")
	sb.WriteString("})();")
	sb.WriteString("</script>")

	return sb.String()
}

// extractTargetHost extracts the hostname from a URL string.
func extractTargetHost(targetURL string) string {
	if strings.HasPrefix(targetURL, "http://") || strings.HasPrefix(targetURL, "https://") {
		parts := strings.SplitN(targetURL, "://", 2)
		if len(parts) == 2 {
			hostPart := strings.SplitN(parts[1], "/", 2)[0]
			return hostPart
		}
	}
	return ""
}

func reverseProxyEffectiveAuditAction(action string, auditOnly, fileRisk bool, status string, findings []SecurityFinding) string {
	if status == "incomplete" && !hasSecurityFindings(findings) {
		if auditOnly {
			return "audit"
		}
		if deterministicBlockingAction(action) {
			return "block"
		}
		return "audit"
	}
	return reverseProxySecurityActionTaken(action, auditOnly, fileRisk)
}
