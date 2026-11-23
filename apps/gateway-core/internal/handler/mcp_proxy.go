package handler

// MCP 安全网关数据面（v1）：POST/GET /mcp/{serverID}，挂 :8080 chi（authMiddleware 之后，
// 身份六元组齐备），由 MCP_GATEWAY_ENABLED 门控注册（默认关）。
//
// SECURITY_AUDIT_ONLY 铁律（与 AgentGuard 同构，三层配合，一层都不能少）：
//  1. 最外层 mcpGuardMode(ctx)：securityAuditOnly(ctx)（DB 动态设置优先，env fallback）
//     为 true 时 CallerMode=ModeAudit；
//  2. agentguard.ApplyEffectivePolicy 内 clampModeToCeiling：CallerMode 是执行上限，
//     策略 strict 也被钳到 audit，红线拦截也不例外；
//  3. 执行动作前再被 auditOnly 短路（防御纵深）——audit-only 下任何决策只留痕、
//     不断流、不建确认单，raw_decision 全量留证。

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"mime"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/agentguard"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/auth"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
	"github.com/yangjiyj/aiguard/packages/shared-go/mcpconfirmation"
	"github.com/yangjiyj/aiguard/packages/shared-go/mcpprotocol"
	"github.com/yangjiyj/aiguard/packages/shared-go/mcpupstream"
	"github.com/yangjiyj/aiguard/packages/shared-go/retentionartifact"
	"github.com/yangjiyj/aiguard/packages/shared-go/safetarget"
	"github.com/yangjiyj/aiguard/packages/shared-go/secrets"
	"github.com/yangjiyj/aiguard/packages/shared-go/securityexit"
	"golang.org/x/net/http/httpguts"
)

const (
	// 支持的协议版本集合统一由 shared-go/mcpprotocol 维护（2025-11-25 / 2025-06-18 /
	// 2025-03-26 / 2024-11-05），与 control-plane 同源。
	mcpProtocolVersionLatest   = mcpprotocol.Latest
	mcpProtocolVersionPrevious = "2025-06-18"

	maxMCPRequestBodyBytes          = 4 << 20
	maxMCPNonStreamingResponseBytes = 8 << 20
	maxMCPSSEEventBytes             = 1 << 20
	maxMCPSSECumulativeBytes        = 16 << 20
)

var (
	errMCPCapacityRejected   = errors.New("MCP result inspection capacity rejected")
	errMCPBatchUnsupported   = errors.New("网关不支持 JSON-RPC batch 请求")
	errMCPResponseTooLarge   = errors.New("MCP 非流式响应超过容量上限")
	errMCPSSEEventTooLarge   = errors.New("MCP SSE 单事件超过容量上限")
	errMCPSSEStreamTooLarge  = errors.New("MCP SSE 累计响应超过容量上限")
	errMCPUpstreamCredential = errors.New("MCP 上游鉴权凭据不可用")
)

// mcpServerRoute 是 mcp_servers 表的一行热路径投影（60s 懒重载缓存）。
type mcpServerRoute struct {
	ID              string
	TenantID        string
	Name            string
	ServerURL       string
	Status          string
	Transport       string
	AuthCiphertext  string
	AuthKeyRef      string
	AuthHeaderName  string
	ProtocolVersion string
	// AllowPrivateEgress=true 时该 server 受控放行内网出站（管理员登记时显式授权，
	// 迁移 099 加列，默认 false）。只影响本 server 的 MCP 转发，不动全局 SSRF 开关。
	AllowPrivateEgress bool
	// EgressOverrides 是服务的对象级出站放行（迁移 999 的 egress_overrides 列，默认全拒）：
	// 回环、链路本地、元数据、内部主机名、自定义 CA/跳过证书校验、同主机重定向。
	EgressOverrides safetarget.EgressOverrides
	RouteHash       string
	// Capabilities 是 capabilities_json 整体：承载上游连接配置（鉴权位置/值模板/额外请求头、
	// auto 探测到的 transport 等），见 mcpupstream.ParseConfig。夹具可留空。
	Capabilities map[string]interface{}
}

// mcpServerCache 按「tenantID+serverID」缓存 server 行，60s TTL（仿 reverse_proxy
// reloadRoutes 的懒重载节奏）。租户硬隔离：键含 tenant，查询也带 tenant_id 条件。
type mcpServerCache struct {
	mu      sync.RWMutex
	entries map[string]mcpServerCacheEntry
	ttl     time.Duration
}

type mcpServerCacheEntry struct {
	route     *mcpServerRoute
	expiresAt time.Time
}

func (c *mcpServerCache) get(key string) (*mcpServerRoute, bool) {
	if c == nil {
		return nil, false
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	entry, ok := c.entries[key]
	if !ok || time.Now().After(entry.expiresAt) {
		return nil, false
	}
	return entry.route, true
}

func (c *mcpServerCache) set(key string, route *mcpServerRoute) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries[key] = mcpServerCacheEntry{route: route, expiresAt: time.Now().Add(c.ttl)}
}

type mcpTargetClientResolver func(context.Context, string, bool, *http.Client) (*http.Client, *url.URL, error)

// MCPProxyHandler 处理 /mcp/{serverID} 的 JSON-RPC 代理与 tools/call 权限判定。
type MCPProxyHandler struct {
	db             *pgxpool.Pool
	toolRiskClient *ToolRiskClient
	// securityAuditOnlyFallback 是 env SECURITY_AUDIT_ONLY 的启动值，仅作
	// control-plane 动态设置拉取失败时的 fallback（同 reverse_proxy 范式）。
	securityAuditOnlyFallback  bool
	client                     *http.Client
	serverCache                *mcpServerCache
	auditRecorder              *mcpProxyAuditRecorder
	targetClientResolver       mcpTargetClientResolver
	confirmationExecutionStore mcpConfirmationExecutionStore
	allowedOrigins             map[string]struct{}
	environmentScope           string
	// approvedToolsLoader 仅供测试注入；生产为 nil，走 loadMCPApprovedTools 查库。
	approvedToolsLoader mcpApprovedToolsLoader
	// toolResultChecker 非 nil 时检测 tools/call 返回的间接注入（W1 1.7，main.go 接线）。
	toolResultChecker mcpToolResultChecker
	// redlineSettings 缓存租户红线处置配置（W1 1.11）；nil 时红线只告警（基线行为）。
	redlineSettings *mcpRedlineSettingsCache
	// testForwardOverride 仅供测试：非 nil 时替代 forwardMCPUpstream 的结果，用来构造生产里暂不存在的合成响应形态。
	testForwardOverride func(*http.Request) *http.Response
	// sseBridge 承载旧 HTTP+SSE 上游的会话桥接（下游始终是 Streamable HTTP）。
	sseBridge *mcpSSEBridge
	// sessions 登记 Streamable 上游签发的 Mcp-Session-Id 及其归属（D3）。
	sessions                mcpSessionStoreHolder
	agentGuardBehavior      *agentguard.BehaviorWindow
	cacheInvalidatorWired   atomic.Bool
	cacheInvalidatorRunning atomic.Bool
}

// NewMCPProxyHandler 组装 MCP 代理。动态 audit_only 开关经 toolRiskClient 注入
// （照 forwardProxy.SetRuntimeConfigClient 同款语义，这里直接进构造器）。
func NewMCPProxyHandler(db *pgxpool.Pool, toolRiskClient *ToolRiskClient, securityAuditOnlyFallback bool, deploymentScope ...string) *MCPProxyHandler {
	environmentScope := retentionartifact.LegacyEnvironmentScope
	if len(deploymentScope) > 0 {
		environmentScope = retentionartifact.NormalizeEnvironmentScope(deploymentScope[0])
	}
	handler := &MCPProxyHandler{
		db:                        db,
		toolRiskClient:            toolRiskClient,
		securityAuditOnlyFallback: securityAuditOnlyFallback,
		client: &http.Client{
			// 基础 client 仅承载 Transport 语义；流式转发实际用
			// streamingHTTPClientForResolvedEgress（无整请求墙，总时长由 ctx 控）。
			Timeout: 120 * time.Second,
		},
		serverCache:        &mcpServerCache{entries: make(map[string]mcpServerCacheEntry), ttl: 60 * time.Second},
		auditRecorder:      newMCPProxyAuditRecorder(db),
		allowedOrigins:     make(map[string]struct{}),
		environmentScope:   environmentScope,
		redlineSettings:    newMCPRedlineSettingsCache(),
		sseBridge:          newMCPSSEBridge(),
		agentGuardBehavior: agentguard.NewBehaviorWindow(10*time.Second, defaultAgentGuardBehaviorThresholds),
	}
	if db != nil {
		handler.confirmationExecutionStore = newPGMCPConfirmationExecutionStore(db)
	}
	return handler
}

// securityAuditOnly 动态读取 audit-only 开关：真源是 control-plane DB 设置
// security_audit_only（10s TTL 缓存），env 只是拉取失败 fallback。绝不直接读 env。
func (h *MCPProxyHandler) securityAuditOnly(ctx context.Context) bool {
	if h == nil {
		return false
	}
	if h.toolRiskClient != nil {
		return h.toolRiskClient.SecurityAuditOnly(ctx, h.securityAuditOnlyFallback)
	}
	return h.securityAuditOnlyFallback
}

// mcpGuardMode 是 audit_only → CallerMode 的最外层钳制入口（镜像 chat_completions
// agentGuardMode）：audit-only 时 ModeAudit，否则 ModeStrict。
func (h *MCPProxyHandler) mcpGuardMode(ctx context.Context) agentguard.Mode {
	if h.securityAuditOnly(ctx) {
		return agentguard.ModeAudit
	}
	return agentguard.ModeStrict
}

// lookupServer 按租户 + serverID 查 mcp_servers（60s 缓存）。租户硬隔离：
// WHERE id AND tenant_id，绝不跨租户命中。返回 (nil, nil) 表示不存在。
func (h *MCPProxyHandler) lookupServer(ctx context.Context, tenantID, serverID string) (*mcpServerRoute, error) {
	if tenantID == "" || serverID == "" {
		return nil, nil
	}
	cacheKey := tenantID + "\x1f" + serverID
	if route, ok := h.serverCache.get(cacheKey); ok {
		return route, nil
	}
	if h.db == nil {
		return nil, nil
	}
	route, err := scanMCPServerRoute(h.db.QueryRow(ctx, mcpServerRouteSelect, serverID, tenantID))
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	h.serverCache.set(cacheKey, route)
	return route, nil
}

// mcpServerUsable 判断 server 是否处于在用态：active/approved 放行，
// disabled/pending 等其他状态一律拒绝。
func mcpServerUsable(status string) bool {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "active", "approved":
		return true
	default:
		return false
	}
}

// === JSON-RPC 解析 ===

// mcpRPCMessage 是一条 JSON-RPC 2.0 客户端消息（请求或通知）的最小投影。
type mcpRPCMessage struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  struct {
		Name            string          `json:"name"`
		Arguments       json.RawMessage `json:"arguments"`
		ProtocolVersion string          `json:"protocolVersion"`
		URI             string          `json:"uri"`
	} `json:"params"`
}

// parseMCPRPCMessages 只接受单条对象；2025-06-18 起协议已移除 batching，
// 数组载荷在进入工具决策前统一拒绝。解析是严格的（见 mcp_strict_jsonrpc.go）：
// 重复键 / 仅大小写不同的键 / 非法 UTF-8 一律拒绝，字段只认精确小写键。
func parseMCPRPCMessages(body []byte) ([]mcpRPCMessage, bool, error) {
	msgs, _, batch, err := parseMCPRPCMessagesCanonical(body)
	return msgs, batch, err
}

// parseMCPRPCMessagesCanonical 同 parseMCPRPCMessages，另返回网关重新序列化的规范载荷；
// 转发上游、建确认单重放上下文一律用它，绝不转发原始 body（W1 1.1）。
func parseMCPRPCMessagesCanonical(body []byte) ([]mcpRPCMessage, []byte, bool, error) {
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 {
		return nil, nil, false, fmt.Errorf("空请求体")
	}
	if trimmed[0] == '[' {
		return nil, nil, true, errMCPBatchUnsupported
	}
	if trimmed[0] == '{' {
		msg, canonical, err := parseMCPStrictMessage(trimmed)
		if err != nil {
			return nil, nil, false, err
		}
		return []mcpRPCMessage{msg}, canonical, false, nil
	}
	return nil, nil, false, fmt.Errorf("非法 JSON-RPC 载荷")
}

// mcpParseErrorCode：歧义载荷 / 结构非法 → -32600 Invalid Request；JSON 语法错误 → -32700。
func mcpParseErrorCode(err error) int {
	if errors.Is(err, errMCPBatchUnsupported) || errors.Is(err, errMCPAmbiguousPayload) || errors.Is(err, errMCPInvalidRequest) {
		return -32600
	}
	return -32700
}

func validateMCPProtocolVersion(version string) error {
	if mcpprotocol.IsSupported(version) {
		return nil
	}
	return fmt.Errorf("不支持的 MCP 协议版本 %q，网关支持 [%s]",
		strings.TrimSpace(version), strings.Join(mcpprotocol.SupportedVersions(), ", "))
}

func validateMCPProtocolRequest(r *http.Request, messages []mcpRPCMessage) error {
	headerVersion := strings.TrimSpace(r.Header.Get("MCP-Protocol-Version"))
	if headerVersion != "" {
		if err := validateMCPProtocolVersion(headerVersion); err != nil {
			return err
		}
	}
	for _, message := range messages {
		if message.Method == "initialize" {
			if err := validateMCPProtocolVersion(message.Params.ProtocolVersion); err != nil {
				return err
			}
		}
	}
	// 规范：2025-06-18 之前协商的客户端不会发送 MCP-Protocol-Version，缺头时服务端应假定
	// 2025-03-26，因此缺头不再拒绝；转发上游时由 buildMCPUpstreamRequest 按服务器已记录的
	// 协商版本（或默认 2025-03-26）补齐，见 mcpEffectiveProtocolVersion。
	return nil
}

func readMCPBoundedBody(reader io.Reader, limit int64) ([]byte, error) {
	body, err := io.ReadAll(io.LimitReader(reader, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > limit {
		return nil, errMCPResponseTooLarge
	}
	return body, nil
}

func validateAndCopyMCPSSE(dst io.Writer, flush func(), src io.Reader) error {
	reader := bufio.NewReaderSize(src, 64*1024)
	var cumulative, event int64
	for {
		fragment, err := reader.ReadBytes('\n')
		if len(fragment) > 0 {
			cumulative += int64(len(fragment))
			event += int64(len(fragment))
			if cumulative > maxMCPSSECumulativeBytes {
				return errMCPSSEStreamTooLarge
			}
			if event > maxMCPSSEEventBytes {
				return errMCPSSEEventTooLarge
			}
			if _, writeErr := dst.Write(fragment); writeErr != nil {
				return writeErr
			}
			if bytes.Equal(fragment, []byte("\n")) || bytes.Equal(fragment, []byte("\r\n")) {
				event = 0
				if flush != nil {
					flush()
				}
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
	}
}

type mcpCountingWriter struct {
	writer io.Writer
	count  int64
}

func (w *mcpCountingWriter) Write(p []byte) (int, error) {
	n, err := w.writer.Write(p)
	w.count += int64(n)
	return n, err
}

func stripMCPConnectionNamedHeaders(dst, src http.Header) {
	for _, value := range src.Values("Connection") {
		for _, token := range strings.Split(value, ",") {
			name := http.CanonicalHeaderKey(strings.TrimSpace(token))
			if httpguts.ValidHeaderFieldName(name) {
				dst.Del(name)
			}
		}
	}
}

func copyMCPResponseHeaders(dst, src http.Header) {
	copyHeaders(dst, src)
	stripMCPConnectionNamedHeaders(dst, src)
	for _, name := range []string{
		"Set-Cookie", "Connection", "Keep-Alive", "Proxy-Authenticate",
		"Proxy-Authorization", "TE", "Trailer", "Transfer-Encoding", "Upgrade",
	} {
		dst.Del(name)
	}
	dst.Del("Content-Length")
}

func mcpMediaType(header string) string {
	value, _, err := mime.ParseMediaType(header)
	if err != nil {
		return ""
	}
	return strings.ToLower(value)
}

func validateMCPJSONResponse(body []byte) error {
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 {
		return nil
	}
	if trimmed[0] == '[' {
		return errMCPBatchUnsupported
	}
	if trimmed[0] != '{' || !json.Valid(trimmed) {
		return fmt.Errorf("MCP 上游响应不是合法 JSON")
	}
	return nil
}

// === v1 红线检测（gateway-core Go 内联，编译期正则；不碰 security-engine）===

type mcpRedlineRule struct {
	Name    string
	Pattern *regexp.Regexp
}

var mcpRedlineRules = []mcpRedlineRule{
	{Name: "destructive_command", Pattern: regexp.MustCompile(`(?i)\brm\s+-rf\s+/|\bDROP\s+(?:TABLE|DATABASE)\b|\bTRUNCATE\s+TABLE\b|\bmkfs(?:\.[a-z0-9_]+)?\b|\bdd\s+if=`)},
	// 云元数据端点探测（SSRF 惯用目标）：AWS/GCP/Azure/华为 169.254.169.254 及其十进制/十六进制写法、
	// AWS IPv6、阿里云 100.100.100.200、腾讯云 metadata.tencentyun.com。
	{Name: "cloud_metadata", Pattern: regexp.MustCompile(`(?i)169\.254\.169\.254|metadata\.google\.internal|\b2852039166\b|\b0xa9fea9fe\b|fd00:ec2::254|\b100\.100\.100\.200\b|metadata\.tencentyun\.com`)},
	// 私钥外传
	{Name: "private_key_egress", Pattern: regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----|PuTTY-User-Key-File-\d`)},
	// W1 1.11 扩充：云/集群凭据文件
	{Name: "cloud_credential_file", Pattern: regexp.MustCompile(`/\.aws/credentials\b|/\.kube/config\b|/\.docker/config\.json\b|/var/run/secrets/kubernetes\.io/serviceaccount|/\.config/gcloud/(?:credentials\.db|application_default_credentials\.json)|/\.aliyun/config\.json\b`)},
	// 系统口令/进程环境文件
	{Name: "system_secret_file", Pattern: regexp.MustCompile(`/etc/shadow\b|/etc/gshadow\b|/proc/(?:self|\d+)/environ\b`)},
	// 容器运行时套接字（容器逃逸）
	{Name: "container_runtime_socket", Pattern: regexp.MustCompile(`/var/run/docker\.sock\b|/run/containerd/containerd\.sock\b|/var/run/crio/crio\.sock\b`)},
	// 反弹 shell
	{Name: "reverse_shell", Pattern: regexp.MustCompile(`(?i)/dev/(?:tcp|udp)/[^\s/]+/\d+|\b(?:nc|ncat|netcat)\b[^\n;|&]*\s-[a-z]*[ec]\s+\S*(?:sh|bash)\b|\bsocat\b[^\n]*\bexec:`)},
	// 管道直接执行远程脚本
	{Name: "remote_script_pipe", Pattern: regexp.MustCompile(`(?i)\b(?:curl|wget)\b[^\n|;&]*https?://[^\n|;&]*\|\s*(?:sudo\s+)?(?:ba|z|da)?sh\b`)},
}

// matchMCPRedlines 对 tools/call 的 arguments 做红线扫描，返回命中的规则名。
// belt+suspenders：既扫原始 JSON 串，也扫 JSON 解码后的字符串值——后者可命中
// 用 \u 转义（如 {"cmd":"rm -rf /"}）藏在参数里、原始串正则漏匹配的绕过。
func matchMCPRedlines(argumentsJSON string) []string {
	if strings.TrimSpace(argumentsJSON) == "" {
		return nil
	}
	scanTargets := []string{argumentsJSON}
	if decoded := decodeMCPJSONStringValues(argumentsJSON); decoded != "" {
		scanTargets = append(scanTargets, decoded)
	}
	seen := make(map[string]bool)
	var hits []string
	for _, rule := range mcpRedlineRules {
		for _, target := range scanTargets {
			if rule.Pattern.MatchString(target) {
				if !seen[rule.Name] {
					seen[rule.Name] = true
					hits = append(hits, rule.Name)
				}
				break
			}
		}
	}
	return hits
}

// decodeMCPJSONStringValues 把 arguments 反序列化后递归收集所有字符串叶子值拼成一个解码串，
// 使 JSON \u 转义/嵌套结构里的敏感内容还原成字面量再跑红线正则。非法 JSON 返回空串。
func decodeMCPJSONStringValues(argumentsJSON string) string {
	var v interface{}
	if err := json.Unmarshal([]byte(argumentsJSON), &v); err != nil {
		return ""
	}
	var b strings.Builder
	collectMCPJSONStrings(v, &b)
	return b.String()
}

func collectMCPJSONStrings(v interface{}, b *strings.Builder) {
	switch t := v.(type) {
	case string:
		b.WriteString(t)
		b.WriteByte('\n')
	case []interface{}:
		for _, e := range t {
			collectMCPJSONStrings(e, b)
		}
	case map[string]interface{}:
		for _, e := range t {
			collectMCPJSONStrings(e, b)
		}
	}
}

// === 决策合成 ===

// synthesizeMCPDecision 把「策略动作 + 风险检测」合成为 agentguard.Decision：
// 结构性风险命中 → raw=block，并保留准入下限与证据；策略动作经 GlobalDefault 进决策机；
// 最终动作统一受 policy mode 与 CallerMode 钳制。
// 复用 agentguard 决策机（ApplyEffectivePolicy/clampModeToCeiling/applyMode），
// 不自造钳制逻辑——callerMode 即 audit_only 铁律的执行上限。
func synthesizeMCPDecision(policy *MCPEffectivePolicy, toolName, argumentsJSON string, callerMode agentguard.Mode) agentguard.Decision {
	return synthesizeMCPDecisionWithConfirm(policy, toolName, argumentsJSON, callerMode, true)
}

// synthesizeMCPDecisionWithConfirm：confirmSupported=false 用于无法走确认重放的目标
// （resources/read、prompts/get 等），confirm 由决策机按模式降级。
func synthesizeMCPDecisionWithConfirm(policy *MCPEffectivePolicy, toolName, argumentsJSON string, callerMode agentguard.Mode, confirmSupported bool) agentguard.Decision {
	return synthesizeMCPDecisionWithRedlines(policy, toolName, argumentsJSON, callerMode, confirmSupported, nil)
}

// synthesizeMCPDecisionWithRedlines：redlineActions 为租户红线处置配置（W1 1.11）。
// 命中且配置为 block 的红线属于管理员显式配置：raw=block、ConfiguredEnforcement，
// 策略模式抬到 strict（仍受 callerMode 钳制，记录模式永不阻断），优先于该工具的普通策略动作；
// Unconfigured destructive hits retain raw block evidence and follow the tenant
// action. Independent AgentGuard protection is merged separately.
func synthesizeMCPDecisionWithRedlines(policy *MCPEffectivePolicy, toolName, argumentsJSON string, callerMode agentguard.Mode, confirmSupported bool, redlineActions map[string]string) agentguard.Decision {
	return synthesizeMCPDecisionForTenant(policy, toolName, argumentsJSON, callerMode, confirmSupported, redlineActions, mcpTenantContext{})
}

// synthesizeMCPDecisionForTenant 同 synthesizeMCPDecisionWithRedlines，另按租户的防护项设置与
// 例外处置供应链发现：管理员手动隔离、撤销照拦；其余（未准入、地址/Schema 变化、投毒、同名
// 不一致、扫描不可用）是 mcp.* 防护项命中，动作取租户配置（默认告警放行），可被指向该项、
// 目标为 mcp:<服务名>/<工具名> 的例外放开。
func synthesizeMCPDecisionForTenant(policy *MCPEffectivePolicy, toolName, argumentsJSON string, callerMode agentguard.Mode, confirmSupported bool, redlineActions map[string]string, tenant mcpTenantContext) agentguard.Decision {
	if policy == nil {
		policy = mcpDefaultEffectivePolicy()
	}
	raw := agentguard.Decision{}
	// policyMode 默认取策略自身 mode（策略 miss 时为 audit，普通策略动作沿用 observe-first
	// 上线姿态——默认拒绝交给策略中心配置，而非代码硬编码）。
	policyMode := agentguard.Mode(policy.Mode)
	target := mcpExceptionTarget(tenant.ServerName, toolName)
	adminBlock, supplyHits := mcpSupplyChainFindings(policy, target)
	if len(supplyHits) > 0 {
		raw.RawDecision = agentguard.DecisionAudit
		raw.ProtectionHits = supplyHits
		raw.Reason = supplyHits[0].Reason
		raw.RiskLevel = "high"
		raw.NormalizedTarget = target
		raw.Evidence = append(raw.Evidence, agentguard.Evidence{
			RuleID: "mcp_supply_chain_admission", Category: "mcp_supply_chain",
			Hash: policy.SupplyChainRevision,
		})
		if mcpHitsNeedStrictMode(supplyHits, tenant.Protections) {
			policyMode = agentguard.ModeStrict
		}
	}
	if adminBlock {
		// 管理员手动隔离、撤销是管理员配置：像红线阻断一样把模式抬到 strict，不受 MCP 策略未命中时
		// 的 audit 模式降级，只受 callerMode（全局观察留痕）约束。
		policyMode = agentguard.ModeStrict
		reasons := policy.SupplyChainReasons
		if len(reasons) == 0 {
			reasons = []string{policy.SupplyChainStatus}
		}
		raw.RawDecision = agentguard.DecisionBlock
		// Admission status (待准入/已隔离/已撤销) is shown and managed on the MCP
		// server page, so its block counts as console configuration.
		raw.ConfiguredEnforcement = true
		raw.Reason = "mcp_supply_chain:" + strings.Join(reasons, ",")
		raw.RiskLevel = "critical"
		raw.Evidence = append(raw.Evidence, agentguard.Evidence{
			RuleID: "mcp_supply_chain_admission", Category: "mcp_supply_chain",
			Hash: policy.SupplyChainRevision,
		})
	}
	// 红线四档（2.9.22）：off 不匹配；record 只留证不告警；alert（默认）告警；block 阻断。
	// 配成阻断的红线可被指向它的例外（rule_id=<红线名> 或 mcp_redline_<红线名>）放开，放开后按只留证处理。
	redlines, recordOnly := mcpEffectiveRedlines(matchMCPRedlines(argumentsJSON), redlineActions, tenant, target)
	destructiveHeuristic := false
	if len(redlines)+len(recordOnly) > 0 {
		raw.RiskLevel = "critical"
		for _, name := range recordOnly {
			raw.Evidence = append(raw.Evidence, agentguard.Evidence{RuleID: "mcp_redline_" + name, Category: mcpRedlineRecordCategory})
		}
	}
	if len(redlines) > 0 {
		// Keep signal evidence independent from tenant disposition. Destructive
		// heuristics retain raw block evidence even when the tenant action audits.
		if !adminBlock {
			raw.Reason = "mcp_redline:" + strings.Join(redlines, ",")
		}
		for _, name := range redlines {
			if name == "destructive_command" && !adminBlock {
				raw.RawDecision = agentguard.DecisionBlock
				destructiveHeuristic = true
			}
			raw.Evidence = append(raw.Evidence, agentguard.Evidence{
				RuleID:   "mcp_redline_" + name,
				Category: "mcp_redline",
			})
		}
		if blocked := mcpRedlineBlockHits(redlines, redlineActions); len(blocked) > 0 && !adminBlock {
			raw.RawDecision = agentguard.DecisionBlock
			raw.ConfiguredEnforcement = true
			raw.Reason = "mcp_redline_block:" + strings.Join(blocked, ",")
			policyMode = agentguard.ModeStrict
		}
	}
	effective := &agentguard.EffectivePolicy{
		ID:            policy.PolicyID,
		Name:          "MCP 权限策略",
		Mode:          policyMode,
		DefaultAction: agentguard.DecisionAction(policy.Action),
		// confirm 通道复用 agentguard_confirmations；只有 tools/call 支持批准后重放。
		ConfirmChannelEnabled: confirmSupported,
		// mcp.* 防护项的动作取租户配置；例外不放开管理员手动隔离、撤销。
		Protections: tenant.Protections,
	}
	if !adminBlock {
		effective.Exceptions = tenant.Exceptions
	}
	if len(supplyHits) > 0 && policy.Matched && !raw.ConfiguredEnforcement && !destructiveHeuristic {
		// 有供应链发现时分析结论是“告警”，命中的 MCP 策略动作要作为显式规则参与（与防护项取严），
		// 否则管理员的阻断/确认策略（含参数条件）会被告警结论盖掉。
		effective.Rules = []agentguard.PolicyRule{{
			ID: policy.PolicyID, ToolPattern: "*", Action: agentguard.DecisionAction(policy.Action), Enabled: true,
		}}
	}
	if destructiveHeuristic && !raw.ConfiguredEnforcement {
		// Retain the heuristic verdict while applying the tenant's chosen action.
		effective.Rules = []agentguard.PolicyRule{{
			ID: policy.PolicyID, ToolPattern: "*", Action: agentguard.DecisionAction(policy.Action), Enabled: true,
		}}
	}
	decision := agentguard.ApplyEffectivePolicy(raw, agentguard.PolicyEvaluationInput{
		ToolName:   toolName,
		Target:     target,
		Policy:     effective,
		CallerMode: callerMode,
	})
	return applyMCPPolicyFailureDecision(policy, decision, callerMode)
}

func enforceMCPGatewayRouteBinding(policy *MCPEffectivePolicy, gatewayRouteHash string) *MCPEffectivePolicy {
	if policy == nil {
		policy = mcpDefaultEffectivePolicy()
	}
	if policy.StructuralBlock || (gatewayRouteHash != "" && policy.RouteHash == gatewayRouteHash) {
		return policy
	}
	// D1：策略从未拉到过（控制面不可达）时没有可比对的路由哈希——这是覆盖缺口而不是
	// 路由绑定不一致，不能被合成为结构阻断（否则等价于 fail-closed，违背「拉不到就放行记缺口」）。
	if policy.SupplyChainStatus == "unavailable" {
		return policy
	}
	bound := *policy
	bound.SupplyChainReasons = append([]string{}, policy.SupplyChainReasons...)
	bound.SupplyChainReasons = append(bound.SupplyChainReasons, "gateway_route_binding_mismatch")
	bound.SupplyChainStatus = "quarantined"
	bound.StructuralBlock = true
	// 2.9.22：路由绑定不一致按 mcp.drift 防护项处置（默认告警放行），不再强改成 strict/block。
	return &bound
}

// mcpToolCallDecision 汇集一条 tools/call 的判定上下文，供执行与留痕。
type mcpToolCallDecision struct {
	Message             mcpRPCMessage
	ToolName            string // 原始 tool 名（非工具目标为 uri / prompt 名 / 方法名）
	TargetKind          string // "" 或 tool = tools/call；resource/prompt/method 见 mcp_method_policy.go
	Qualified           string // "<server_name>__<tool>" 组合名（审计口径）
	ArgsJSON            string
	PolicyID            string
	Decision            agentguard.Decision
	ResultExcerpt       string // 上游响应截断摘录（≤2KB），tool_call_logs.result 留痕
	MCPServerID         string
	MCPToolID           string
	SupplyChainRevision string
	ApprovedSchemaHash  string
	ServerRouteHash     string
	ExecutionForwarded  bool
	ResultObserved      bool
	// W1 1.3：tools/list 响应中与已批准快照不一致的条目；Enforced 表示已从响应中剔除。
	ToolsListDrops    []mcpToolsListDrop
	ToolsListEnforced bool
	// W1 1.7：工具返回命中的检测规则；WouldBlock=引擎给出阻断类动作；Enforced=已替换为错误。
	ToolResultFindings         []string
	ToolResultWouldBlock       bool
	ToolResultEnforced         bool
	ToolResultCapacityRejected bool
	// W1 1.8：true 表示这是上游在 SSE 流中发起的反向请求（sampling/elicitation/roots 等）。
	ServerInitiated bool
	OutcomeStatus   string
}

// === HTTP 入口 ===

// Register 在 chi 路由器上登记 MCP 代理端点（调用方负责挂 authMiddleware 与门控）。
func (h *MCPProxyHandler) Register(r chi.Router) {
	r.Post("/{serverID}", h.HandlePost)
	r.Get("/{serverID}", h.HandleGet)
	r.Delete("/{serverID}", h.HandleDelete)
}

// mcpRequestEnvelope 从鉴权后的 AuthInfo 构造六元组请求信封。
func mcpRequestEnvelope(info *auth.AuthInfo) *modelrouter.RequestEnvelope {
	if info == nil {
		return &modelrouter.RequestEnvelope{}
	}
	return &modelrouter.RequestEnvelope{
		// info.RequestID 已在 HandlePost/HandleGet 入口经 ensureMCPRequestID 统一 mint 为唯一
		// uuid（覆盖 auth 层按天截断的值），故 envelope 与所有审计留痕共用同一 request_id。
		RequestID:        info.RequestID,
		TenantID:         info.TenantID,
		ProjectID:        info.ProjectID,
		UserID:           info.UserID,
		ClientID:         info.KeyID,
		EnvironmentScope: info.EnvironmentScope,
		KeyPrefix:        info.KeyPrefix,
		AgentType:        info.AgentType,
		AgentInstanceID:  info.AgentInstanceID,
		SessionID:        info.SessionID,
		TraceID:          info.TraceID,
		SourceIP:         info.ClientIP,
		EndpointType:     "proxy",
		Principal:        principalForGatewayEndpoint(info.Principal, "mcp", "mcp_gateway", ""),
	}
}

// writeMCPJSONRPCError 回一条 JSON-RPC 2.0 error（HTTP 200，JSON-RPC 层语义错误）。
func writeMCPJSONRPCError(w http.ResponseWriter, id json.RawMessage, code int, message string) {
	if len(id) == 0 {
		id = json.RawMessage("null")
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"jsonrpc": "2.0",
		"id":      id,
		"error":   map[string]any{"code": code, "message": message},
	})
}

// writeMCPHTTPError 回一条非 JSON-RPC 层的网关错误（鉴权后、协议前的失败）。
func safeMCPConfirmationTicket(ticket MCPConfirmationTicket) map[string]any {
	out := map[string]any{
		"confirmation_id":     ticket.ConfirmationID,
		"invocation_id":       ticket.InvocationID,
		"status":              ticket.Status,
		"execution_status":    ticket.ExecutionStatus,
		"evidence_status":     ticket.EvidenceStatus,
		"expires_at":          ticket.ExpiresAt,
		"retry_after_ms":      ticket.RetryAfterMS,
		"result_available":    ticket.ResultAvailable,
		"error_code":          ticket.ErrorCode,
		"execution_forwarded": ticket.ExecutionForwarded,
	}
	if ticket.EvidenceStatus == "complete" {
		out["audit_request_id"] = ticket.AuditRequestID
		out["tool_log_id"] = ticket.ToolLogID
	}
	return out
}

func writeMCPJSONRPCErrorWithData(w http.ResponseWriter, id json.RawMessage, code int, message string, data map[string]any) {
	if len(id) == 0 {
		id = json.RawMessage("null")
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"jsonrpc": "2.0", "id": id,
		"error": map[string]any{"code": code, "message": message, "data": data},
	})
}

func writeMCPHTTPError(w http.ResponseWriter, status int, message string) {
	writeMCPTransportError(w, status, "mcp_gateway_error", message)
}

// writeMCPTransportError writes a non-security gateway error with an explicit
// code so clients never mistake a transport failure for a security block.
func writeMCPTransportError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Connection", "close")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"error": map[string]any{"code": code, "message": message},
	})
}

// mcpBlockMessage 组装阻断文案（中文、带策略 id，UI 零裸英文口径）。
// confirm=true 时按 confirmCreated 区分真实措辞：建单成功才说"已创建确认单"，
// 失败则如实告知"确认单创建失败"，绝不谎报一张不存在的单。
func mcpBlockMessage(d agentguard.Decision, policyID string, confirm, confirmCreated bool) string {
	policyLabel := policyID
	if policyLabel == "" {
		policyLabel = "默认策略"
	}
	if confirm {
		if !confirmCreated {
			return fmt.Sprintf("网关安全策略要求人工确认后方可执行该 MCP 工具调用，但确认单创建失败，请稍后重试或联系管理员（策略 %s）", policyLabel)
		}
		return fmt.Sprintf("网关安全策略要求人工确认后方可执行该 MCP 工具调用，已创建确认单，请联系管理员处置（策略 %s）", policyLabel)
	}
	return fmt.Sprintf("网关安全策略已阻断该 MCP 工具调用（策略 %s）", policyLabel)
}

// resolveMCPServer 是 POST/GET 共用的前置：鉴权信息 → server 行 → 在用态校验。
// 出错时已写响应，返回 nil。
func (h *MCPProxyHandler) resolveMCPServer(ctx context.Context, w http.ResponseWriter, r *http.Request, info *auth.AuthInfo) *mcpServerRoute {
	serverID := chi.URLParam(r, "serverID")
	if info == nil || info.TenantID == "" {
		writeMCPHTTPError(w, http.StatusUnauthorized, "缺少租户身份，无法路由 MCP 请求")
		return nil
	}
	server, err := h.lookupServer(ctx, info.TenantID, serverID)
	if err != nil {
		log.Printf("MCP server lookup failed: tenant=%s server=%s err=%v", info.TenantID, serverID, err)
		writeMCPHTTPError(w, http.StatusServiceUnavailable, "MCP 服务路由暂不可用，请稍后重试")
		return nil
	}
	if server == nil {
		writeMCPHTTPError(w, http.StatusNotFound, "MCP 服务不存在或不属于当前租户")
		return nil
	}
	if !mcpServerUsable(server.Status) {
		writeMCPHTTPError(w, http.StatusForbidden, "MCP 服务未处于在用状态，已拒绝转发")
		return nil
	}
	if strings.TrimSpace(server.ServerURL) == "" {
		writeMCPHTTPError(w, http.StatusBadGateway, "MCP 服务未配置上游地址")
		return nil
	}
	return server
}

// ensureMCPRequestID 为本次 MCP 请求 mint 唯一 request_id（同 chat_completions.go 的
// uuid.New()），覆盖 auth 层 generateRequestID 的按天截断值（hex 时间戳取前 16 位恰只剩
// 日期，同日所有请求撞同一 id）。统一到 info.RequestID 后，envelope、request_logs、
// security_events、tool_call_logs 全链共用唯一 id，避免 request_logs 按 request_id
// upsert 塌成一行、审计错误归并到同一父请求。
func ensureMCPRequestID(info *auth.AuthInfo) {
	if info != nil {
		info.RequestID = "req_" + uuid.New().String()
	}
}

// HandleGet 处理 GET /mcp/{serverID}：鉴权后 SSE 长流透传，v1 不拦
// （tools/call 都走 POST），只做轻审计。
func (h *MCPProxyHandler) HandleGet(w http.ResponseWriter, r *http.Request) {
	// :8080 chi 已有 middleware.Timeout 兜底，这里再自带一道与反代同款的流上限，
	// 防配置漂移后长流挂死连接。
	ctx, cancel := context.WithTimeout(r.Context(), reverseProxyStreamTimeout)
	defer cancel()
	startedAt := time.Now()
	info := auth.GetAuthInfo(r)
	ensureMCPRequestID(info)
	server := h.resolveMCPServer(ctx, w, r, info)
	if server == nil {
		return
	}
	if server.usesSSEBridge() {
		// 旧 HTTP+SSE 上游没有 Streamable 的 GET 长流（服务端通知/反向请求通道）。规范允许服务端对
		// GET 回 405；这也保证上游不会借客户端的 GET 通道绕过 POST 路径上的安全决策。
		w.Header().Set("Allow", "POST, DELETE")
		writeMCPHTTPError(w, http.StatusMethodNotAllowed, "该 MCP 服务使用旧版 SSE 上游，网关不提供 GET 长流，请仅使用 POST")
		return
	}
	resp, _, err := h.forwardMCPUpstream(ctx, server, r, nil)
	if err != nil {
		log.Printf("MCP GET upstream failed: server=%s err=%v", server.ID, err)
		h.writeMCPLightAudit(ctx, info, server, r, 0, 0, "failed", 0, time.Since(startedAt))
		writeMCPHTTPError(w, http.StatusBadGateway, "MCP 上游服务不可达")
		return
	}
	defer resp.Body.Close()
	if mcpResponseNotForwarded(resp) {
		// D3：会话 id 校验未通过等「根本没到上游」的合成响应，如实回给客户端（404 让其重新 initialize）。
		notForwardedBody, _ := readMCPBoundedBody(resp.Body, maxMCPNonStreamingResponseBytes)
		copyMCPResponseHeaders(w.Header(), resp.Header)
		w.Header().Set("Connection", "close")
		w.WriteHeader(resp.StatusCode)
		_, _ = w.Write(notForwardedBody)
		h.writeMCPLightAudit(context.WithoutCancel(ctx), info, server, r, 0, int64(len(notForwardedBody)), "failed", resp.StatusCode, time.Since(startedAt))
		return
	}
	if mcpMediaType(resp.Header.Get("Content-Type")) != "text/event-stream" {
		h.writeMCPLightAudit(ctx, info, server, r, 0, 0, "failed", resp.StatusCode, time.Since(startedAt))
		writeMCPHTTPError(w, http.StatusBadGateway, "MCP GET 上游必须返回 text/event-stream")
		return
	}

	copyMCPResponseHeaders(w.Header(), resp.Header)
	mcpStripInternalHeaders(w.Header())
	w.Header().Set("Connection", "close")
	w.WriteHeader(resp.StatusCode)
	capture := &boundedReverseProxyCapture{limit: maxReverseProxyRetainedBodyBytes}
	counter := &mcpCountingWriter{writer: w}
	flush := func() {
		if flusher, ok := w.(http.Flusher); ok {
			flusher.Flush()
		}
	}
	// W1 1.8：GET 长流是服务端反向请求的主要通道，同样按策略判定。
	envelope := mcpRequestEnvelope(info)
	auditOnly := h.securityAuditOnly(ctx)
	serverRequests := h.newMCPServerRequestGuard(ctx, envelope, server, r, h.mcpGuardMode(ctx), auditOnly)
	var copyErr error
	if transform := serverRequests.sseTransform(); transform != nil {
		copyErr = copyMCPSSEEvents(io.MultiWriter(counter, capture), flush, resp.Body, transform)
	} else {
		copyErr = validateAndCopyMCPSSE(io.MultiWriter(counter, capture), flush, resp.Body)
	}
	status := "success"
	if copyErr != nil {
		status = "failed"
	}
	if judged := serverRequests.decisions(); len(judged) > 0 {
		record := h.newMCPAuditRecord(info, server, r, 0, counter.count, status, resp.StatusCode, time.Since(startedAt))
		h.writeMCPProxyAudit(context.WithoutCancel(ctx), envelope, record, judged, auditOnly)
		return
	}
	h.writeMCPLightAudit(context.WithoutCancel(ctx), info, server, r, 0, counter.count, status, resp.StatusCode, time.Since(startedAt))
}

// HandlePost 处理 POST /mcp/{serverID}：JSON-RPC 解析 → tools/call 权限判定 →
// 决策执行（audit_only 最外层短路）→ 转发 → 留痕。
func (h *MCPProxyHandler) HandlePost(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), reverseProxyStreamTimeout)
	defer cancel()
	startedAt := time.Now()
	info := auth.GetAuthInfo(r)
	ensureMCPRequestID(info)
	envelope := mcpRequestEnvelope(info)
	if sessionID := strings.TrimSpace(r.Header.Get("Mcp-Session-Id")); sessionID != "" {
		envelope.SessionID, info.SessionID = sessionID, sessionID
	}
	server := h.resolveMCPServer(ctx, w, r, info)
	if server == nil {
		return
	}

	mediaType, _, mediaErr := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if mediaErr != nil || !strings.EqualFold(mediaType, "application/json") {
		writeMCPHTTPError(w, http.StatusUnsupportedMediaType, "MCP POST 请求必须使用 application/json")
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxMCPRequestBodyBytes))
	if err != nil {
		// Transport failure, not a security decision (securityexit package doc).
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			writeMCPTransportError(w, http.StatusRequestEntityTooLarge, "request_body_too_large", "MCP 请求体过大或读取失败")
			return
		}
		writeMCPTransportError(w, http.StatusBadRequest, "request_body_unavailable", "MCP 请求体过大或读取失败")
		return
	}
	msgs, canonicalBody, _, parseErr := parseMCPRPCMessagesCanonical(body)
	if parseErr != nil {
		if code := mcpParseErrorCode(parseErr); code == -32600 {
			writeMCPJSONRPCError(w, nil, code, parseErr.Error())
			return
		}
		// JSON-RPC 标准解析错误码 -32700
		writeMCPJSONRPCError(w, nil, -32700, "请求体不是合法的 JSON-RPC 载荷")
		return
	}
	// 从这里起 body 即网关判定过的规范载荷：转发、确认单重放上下文都只用它。
	body = canonicalBody
	if err := validateMCPProtocolRequest(r, msgs); err != nil {
		writeMCPJSONRPCError(w, nil, -32600, err.Error())
		return
	}

	// 请求开头取一次 auditOnly（骨架同 reverse_proxy forwardRequest）：决策先算完整
	// （raw/effective 全留痕），执行动作前最外层被 auditOnly 短路。
	auditOnly := h.securityAuditOnly(ctx)
	callerMode := h.mcpGuardMode(ctx)
	var destructivePolicy *agentguard.EffectivePolicy
	var analysisPolicyErr error
	if h.toolRiskClient != nil {
		destructivePolicy, analysisPolicyErr = h.toolRiskClient.GetAgentGuardPolicy(ctx, envelope)
	}

	// 判定单条 JSON-RPC 载荷中的 tools/call。
	// policyByTool 在单个请求内对 (server.ID, toolName) 做本地去重：同名工具只查一次策略，
	// 即便 batch 里重复出现也不会重复打 control-plane（红线仍逐条按各自 arguments 扫描）。
	var decisions []mcpToolCallDecision
	policyByTool := make(map[string]*MCPEffectivePolicy)
	argChainByTool := make(map[string][]mcpArgChainEntry)
	var redlineActions map[string]string
	redlineActionsLoaded := false
	for _, msg := range msgs {
		kind, targetName, judged := mcpPolicyTarget(msg)
		if !judged {
			continue
		}
		if kind != mcpTargetTool {
			decisions = append(decisions, h.decideMCPNonToolTarget(ctx, envelope, server, msg, kind, targetName, callerMode))
			continue
		}
		toolName := strings.TrimSpace(msg.Params.Name)
		argsJSON := string(msg.Params.Arguments)
		policy, ok := policyByTool[toolName]
		if !ok {
			var chain []mcpArgChainEntry
			policy, chain = h.toolRiskClient.GetMCPToolPolicyWithArgChain(ctx, envelope, server.ID, toolName)
			policy = enforceMCPGatewayRouteBinding(policy, server.RouteHash)
			policyByTool[toolName] = policy
			argChainByTool[toolName] = chain
		}
		// 参数条件（W1 1.12）逐条按本条 arguments 求值：同名工具可因参数不同命中不同策略。
		policy = applyMCPArgChain(policy, argChainByTool[toolName], argsJSON)
		redlineHits := matchMCPRedlines(argsJSON)
		if len(redlineHits) > 0 && !redlineActionsLoaded {
			// 只有命中红线时才拉租户处置配置，未命中的请求零额外开销。
			redlineActions = h.mcpRedlineActions(ctx, envelope.TenantID)
			redlineActionsLoaded = true
		}
		decision := synthesizeMCPDecisionForTenant(policy, toolName, argsJSON, callerMode, true, redlineActions, newMCPTenantContext(server.Name, destructivePolicy))
		decision.TraceID = envelope.TraceID
		var args map[string]interface{}
		argsErr := json.Unmarshal(msg.Params.Arguments, &args)
		if args == nil {
			argsErr = fmt.Errorf("tools/call arguments must be an object")
			args = map[string]interface{}{}
		}
		decision.OperationID = operationID(destructiveOperationIdentity{
			TenantID: envelope.TenantID, Protocol: "mcp", SessionID: r.Header.Get("Mcp-Session-Id"),
			RequestID: envelope.RequestID, OutputItemID: "mcp:" + server.ID, ToolCallID: mcpToolCallID(msg.ID),
			ToolName: toolName, CanonicalArgs: canonicalOperationArguments(args), IdentityRejected: argsErr != nil,
		})
		decision = h.evaluateMCPAgentGuardToolCall(ctx, envelope, server.Name+"__"+toolName, structuredToolCallInput{
			RequestID: envelope.RequestID, TenantID: envelope.TenantID, Protocol: "mcp",
			SessionID: r.Header.Get("Mcp-Session-Id"), OutputItemID: "mcp:" + server.ID,
			ToolCallID: mcpToolCallID(msg.ID), ToolName: toolName,
			ToolType: inferToolTypeFromName(toolName), Arguments: args,
			RawArguments:           argsJSON,
			ArgumentsParseRejected: argsErr != nil, ProtocolIdentityRejected: argsErr != nil,
			AgentType: envelope.AgentType,
			Policy:    destructivePolicy, Mode: callerMode, ConfirmSupported: true, BaseDecision: decision,
			ExceptionScope: mcpExceptionTarget(server.Name, toolName),
		}, decision, analysisPolicyErr)
		decisions = append(decisions, mcpToolCallDecision{
			Message:             msg,
			ToolName:            toolName,
			Qualified:           server.Name + "__" + toolName,
			ArgsJSON:            argsJSON,
			PolicyID:            policy.PolicyID,
			Decision:            decision,
			MCPServerID:         server.ID,
			MCPToolID:           policy.ToolID,
			SupplyChainRevision: policy.SupplyChainRevision,
			ApprovedSchemaHash:  policy.ApprovedSchemaHash,
			ServerRouteHash:     policy.RouteHash,
			OutcomeStatus:       "proposed",
		})
	}

	// 决策执行：任一 tools/call 的 effective 为 block/confirm 即阻断整个请求。
	// audit_only 是执行上限：即使下游异常返回强动作也必须放行并完整留证。
	for i := range decisions {
		d := &decisions[i]
		eff := d.Decision.EffectiveDecision
		if eff != agentguard.DecisionBlock && eff != agentguard.DecisionConfirm {
			continue
		}
		if !securityexit.Decide(securityexit.ModeFromAuditOnly(auditOnly), "block", securityexit.ToolPolicy).Enforce {
			// Record mode never interrupts, including the destructive-operation
			// gate: the decision is recorded and the call is forwarded.
			log.Printf("MCP decision recorded under record mode: effective=%s, forwarding (server=%s tool=%s)", eff, server.ID, d.ToolName)
			continue
		}
		confirmCreated := true
		var confirmationTicket *MCPConfirmationTicket
		var confirmationReplay *mcpconfirmation.ReplayContext
		var confirmationErr error
		if eff == agentguard.DecisionConfirm && h.toolRiskClient != nil && (d.TargetKind == "" || d.TargetKind == mcpTargetTool) {
			// MCP 的批准单携带单条 tools/call 的加密重放上下文；普通 AgentGuard
			// 仍保持客户端重试边界。建单失败继续 fail-closed，且不谎报已建单。
			protocolVersion := strings.TrimSpace(r.Header.Get("MCP-Protocol-Version"))
			if protocolVersion == "" {
				protocolVersion = strings.TrimSpace(server.ProtocolVersion)
			}
			if protocolVersion == "" {
				protocolVersion = mcpProtocolVersionLatest
			}
			replay := buildMCPConfirmationReplayContext(
				envelope, server.ID, d.ToolName, mcpToolCallID(d.Message.ID), d.Decision.OperationID, d.MCPToolID,
				d.SupplyChainRevision, d.ApprovedSchemaHash, d.ServerRouteHash,
				body, protocolVersion, r.Header.Get("Mcp-Session-Id"),
			)
			confirmationReplay = &replay
			confirmationTicket, confirmationErr = h.toolRiskClient.CreateMCPConfirmation(
				ctx, envelope, d.Decision, server.ID, d.Qualified, d.ToolName,
				mcpToolCallID(d.Message.ID), d.MCPToolID, d.SupplyChainRevision,
				d.ApprovedSchemaHash, d.ServerRouteHash, body, protocolVersion, r.Header.Get("Mcp-Session-Id"),
			)
			if confirmationErr != nil {
				confirmCreated = false
				var createError *MCPConfirmationCreateError
				conflict := errors.As(confirmationErr, &createError) && createError.Code == "replay_conflict"
				if !conflict {
					// 确认单建不出来按 mcp.confirm_unavailable 处置：默认告警放行，设为阻断才拦。
					downgraded, enforce := mcpProtectionFallback(d.Decision, "mcp_confirmation_unavailable", newMCPTenantContext(server.Name, destructivePolicy), d.ToolName, auditOnly)
					// 设为阻断时结论归因到 mcp.confirm_unavailable（拦截记录写下该项）。
					d.Decision = downgraded
					if !enforce {
						log.Printf("MCP confirm 建单失败，按 mcp.confirm_unavailable 继续: server=%s tool=%s policy=%s action=%s err=%v", server.ID, d.ToolName, d.PolicyID, downgraded.ProtectionAction, confirmationErr)
						continue
					}
				}
				log.Printf("MCP confirm 建单失败（阻断本次请求）: server=%s tool=%s policy=%s err=%v", server.ID, d.ToolName, d.PolicyID, confirmationErr)
			}
		}
		record := h.newMCPAuditRecord(info, server, r, int64(len(body)), 0, "blocked", http.StatusOK, time.Since(startedAt))
		h.writeMCPProxyAudit(context.WithoutCancel(ctx), envelope, record, decisions, auditOnly)
		if eff == agentguard.DecisionConfirm && confirmationTicket != nil && confirmationReplay != nil {
			// W1 1.9：默认短等待；MCP_CONFIRM_WAIT_MODE=hold 时挂起到审批结束。
			waitMode := mcpConfirmationWaitMode()
			ticket, replay := *confirmationTicket, *confirmationReplay
			wait := func() mcpConfirmationPollResult {
				return h.waitMCPConfirmationResult(ctx, ticket, replay, mcpConfirmationWaitBudget(waitMode, ticket, time.Now()))
			}
			if waitMode == mcpConfirmWaitModeHold && mcpAcceptsSSE(r) {
				writeHeldMCPConfirmationSSE(w, d.Message.ID, d.Decision, d.PolicyID, wait, mcpConfirmKeepalive)
				return
			}
			writeMCPConfirmationOutcome(w, d.Message.ID, wait(), d.Decision, d.PolicyID)
			return
		}
		if eff == agentguard.DecisionConfirm {
			if confirmationTicket != nil {
				writeMCPJSONRPCErrorWithData(w, d.Message.ID, -32000,
					mcpBlockMessage(d.Decision, d.PolicyID, true, true), safeMCPConfirmationTicket(*confirmationTicket))
				return
			}
			var createError *MCPConfirmationCreateError
			if errors.As(confirmationErr, &createError) && createError.Code == "replay_conflict" {
				writeMCPJSONRPCErrorWithData(w, d.Message.ID, -32009,
					"MCP invocation 与已存在请求内容冲突，已拒绝创建新的确认单", safeMCPConfirmationTicket(createError.Ticket))
				return
			}
		}
		writeMCPJSONRPCError(w, d.Message.ID, -32000, mcpBlockMessage(d.Decision, d.PolicyID, eff == agentguard.DecisionConfirm, confirmCreated))
		return
	}

	// allow/audit → 转发上游
	resp, _, err := h.forwardMCPUpstream(ctx, server, r, body)
	if err != nil {
		markMCPOutcomeFacts(decisions, "failed", false, false)
		log.Printf("MCP POST upstream failed: server=%s err=%v", server.ID, err)
		record := h.newMCPAuditRecord(info, server, r, int64(len(body)), 0, "failed", 0, time.Since(startedAt))
		h.writeMCPProxyAudit(context.WithoutCancel(ctx), envelope, record, decisions, auditOnly)
		writeMCPForwardError(w, err)
		return
	}
	defer resp.Body.Close()

	// 桥接合成的 404 / 503 / 405 等响应表示请求根本没有到达上游：审计必须按“未转发”如实记录
	// （execution_forwarded=false、result_observed=false），不能在后面的成功分支里被记成已转发已观察。
	notForwarded := mcpResponseNotForwarded(resp)

	contentType := mcpMediaType(resp.Header.Get("Content-Type"))
	toolsListFilter := h.prepareMCPToolsListFilter(ctx, server, envelope.TenantID, decisions, auditOnly, newMCPTenantContext(server.Name, destructivePolicy))
	toolResultGuard := h.prepareMCPToolResultGuard(ctx, envelope, server, decisions, auditOnly)
	rewriters := mcpPayloadRewriters{toolsListFilter.payloadRewriter(), toolResultGuard.payloadRewriter()}.active()

	if contentType == "text/event-stream" && !(mcpAllNotifications(msgs) && !notForwarded) {
		copyMCPResponseHeaders(w.Header(), resp.Header)
		mcpStripInternalHeaders(w.Header())
		w.Header().Set("Connection", "close")
		// SSE 直通（仿 copySSEWithFlush）：逐块转发 + Flush，镜像捕获副本做输出留痕。
		// 流已逐字节发往客户端，事后不可回卷，留痕只记 audit 语义、绝不伪称拦截。
		// 需要改写响应（tools/list 过滤 W1 1.3、工具返回检测 W1 1.7、服务端反向请求
		// W1 1.8）时改为按完整事件缓冲，事件级处理后再写出。
		serverRequests := h.newMCPServerRequestGuard(ctx, envelope, server, r, callerMode, auditOnly)
		transform := mcpComposeSSETransforms(serverRequests.sseTransform(), rewriters.sseTransform())
		w.WriteHeader(resp.StatusCode)
		capture := &boundedReverseProxyCapture{limit: maxReverseProxyRetainedBodyBytes}
		counter := &mcpCountingWriter{writer: w}
		flush := func() {
			if flusher, ok := w.(http.Flusher); ok {
				flusher.Flush()
			}
		}
		var copyErr error
		if transform != nil {
			dst := &mcpCapacityResultWriter{writer: io.MultiWriter(counter, capture), decisions: decisions}
			copyErr = copyMCPSSEEvents(dst, flush, resp.Body, transform)
		} else {
			copyErr = validateAndCopyMCPSSE(io.MultiWriter(counter, capture), flush, resp.Body)
		}
		status := "success"
		if errors.Is(copyErr, errMCPCapacityRejected) {
			status = "stream_aborted"
		} else if copyErr != nil {
			status = "failed"
		}
		markMCPOutcomeFacts(decisions, status, true, false)
		observeMCPToolResults(decisions, capture.Bytes(), true)
		decisions = append(decisions, serverRequests.decisions()...)
		record := h.newMCPAuditRecord(info, server, r, int64(len(body)), counter.count, status, resp.StatusCode, time.Since(startedAt))
		h.writeMCPProxyAudit(context.WithoutCancel(ctx), envelope, record, decisions, auditOnly)
		return
	}

	// R2：通知（没有 id 的 JSON-RPC）按 MCP 规范不需要响应体。对通知类请求的上游响应不再做 JSON / Content-Type 校验：
	// 2xx 统一回下游 202（空体）；4xx/5xx 透传状态码（5xx 映射为 502），body 为空或固定的脱敏 JSON 错误，
	// 绝不回显上游原文，更不以 Content-Type 校验失败作为报错原因。审计照常写，按上游真实结果记 success / failed。
	if mcpAllNotifications(msgs) && !notForwarded {
		status := mcpNotificationDownstreamStatus(resp.StatusCode)
		outcome := "success"
		if status >= http.StatusBadRequest {
			outcome = "failed"
		}
		var discarded []mcpToolCallDecision
		if contentType == "text/event-stream" {
			// L-1：通知不该有响应流。不转发，但留下痕迹并记录丢弃的消息数；反向请求按 server_request 口径记「已丢弃」。
			var messages, reverse int
			messages, reverse, discarded = h.discardNotificationStream(ctx, envelope, server, r, resp, callerMode, auditOnly)
			log.Printf("MCP 通知收到了非预期的响应流，已丢弃 %d 条消息（服务端反向请求 %d 条）: server=%s request_id=%s", messages, reverse, server.ID, envelope.RequestID)
		} else {
			_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxMCPNonStreamingResponseBytes))
		}
		markMCPOutcomeFacts(decisions, outcome, true, false)
		// 被丢弃的反向请求没有转发给客户端：在 markMCPOutcomeFacts 之后并入，保留 blocked / execution_forwarded=false。
		decisions = append(decisions, discarded...)
		record := h.newMCPAuditRecord(info, server, r, int64(len(body)), 0, outcome, resp.StatusCode, time.Since(startedAt))
		h.writeMCPProxyAudit(context.WithoutCancel(ctx), envelope, record, decisions, auditOnly)
		if sid := strings.TrimSpace(resp.Header.Get("Mcp-Session-Id")); sid != "" && status < http.StatusBadRequest {
			w.Header().Set("Mcp-Session-Id", sid)
		}
		if status >= http.StatusBadRequest {
			writeMCPNotificationDeliveryError(w, status)
			return
		}
		w.Header().Set("Connection", "close")
		w.WriteHeader(http.StatusAccepted)
		return
	}

	// 非流式 Streamable HTTP 只接受 application/json；202/204 通知响应可为空。
	if contentType != "application/json" &&
		resp.StatusCode != http.StatusAccepted && resp.StatusCode != http.StatusNoContent {
		markMCPOutcomeFacts(decisions, "failed", true, false)
		record := h.newMCPAuditRecord(info, server, r, int64(len(body)), 0, "failed", resp.StatusCode, time.Since(startedAt))
		h.writeMCPProxyAudit(context.WithoutCancel(ctx), envelope, record, decisions, auditOnly)
		writeMCPHTTPError(w, http.StatusBadGateway, "MCP 上游返回了不受支持的 Content-Type")
		return
	}
	respBody, readErr := readMCPBoundedBody(resp.Body, maxMCPNonStreamingResponseBytes)
	if readErr != nil || validateMCPJSONResponse(respBody) != nil {
		markMCPOutcomeFacts(decisions, "failed", true, false)
		record := h.newMCPAuditRecord(info, server, r, int64(len(body)), 0, "failed", resp.StatusCode, time.Since(startedAt))
		h.writeMCPProxyAudit(context.WithoutCancel(ctx), envelope, record, decisions, auditOnly)
		message := "MCP 上游响应无效或超过容量上限"
		if errors.Is(readErr, errMCPDecodedTooLarge) {
			message = "MCP 上游压缩响应解压后超过容量上限"
		}
		writeMCPHTTPError(w, http.StatusBadGateway, message)
		return
	}
	respBody = rewriters.payload(respBody)
	for _, decision := range decisions {
		if decision.ToolResultCapacityRejected {
			resp.StatusCode = http.StatusServiceUnavailable
			break
		}
	}
	copyMCPResponseHeaders(w.Header(), resp.Header)
	mcpStripInternalHeaders(w.Header())
	w.Header().Set("Connection", "close")
	w.WriteHeader(resp.StatusCode)
	_, _ = w.Write(respBody)

	if notForwarded {
		markMCPOutcomeFacts(decisions, "failed", false, false)
		record := h.newMCPAuditRecord(info, server, r, int64(len(body)), int64(len(respBody)), "failed", resp.StatusCode, time.Since(startedAt))
		h.writeMCPProxyAudit(context.WithoutCancel(ctx), envelope, record, decisions, auditOnly)
		return
	}
	markMCPOutcomeFacts(decisions, "success", true, false)
	observeMCPToolResults(decisions, respBody, false)
	record := h.newMCPAuditRecord(info, server, r, int64(len(body)), int64(len(respBody)), "success", resp.StatusCode, time.Since(startedAt))
	h.writeMCPProxyAudit(context.WithoutCancel(ctx), envelope, record, decisions, auditOnly)
}

type mcpCapacityResultWriter struct {
	writer    io.Writer
	decisions []mcpToolCallDecision
}

func (w *mcpCapacityResultWriter) Write(payload []byte) (int, error) {
	n, err := w.writer.Write(payload)
	if err != nil {
		return n, err
	}
	for _, decision := range w.decisions {
		if decision.ToolResultCapacityRejected {
			return n, errMCPCapacityRejected
		}
	}
	return n, nil
}

func markMCPOutcomeFacts(decisions []mcpToolCallDecision, status string, executionForwarded, resultObserved bool) {
	for i := range decisions {
		decisions[i].OutcomeStatus = status
		decisions[i].ExecutionForwarded = executionForwarded
		decisions[i].ResultObserved = resultObserved
	}
}

type mcpRPCResponseObservation struct {
	idKey     string
	raw       json.RawMessage
	hasResult bool
}

// observeMCPToolResults 只把合法 JSON-RPC result 归到同类型、同 ID 且唯一的
// tools/call。请求 ID 重复、响应 ID 重复、error、非 JSON 与 SSE keepalive 均保持
// result_observed=false，避免用“响应体非空”制造执行结果事实。
func observeMCPToolResults(decisions []mcpToolCallDecision, respBody []byte, sse bool) {
	if len(decisions) == 0 || len(respBody) == 0 {
		return
	}
	requestCounts := make(map[string]int, len(decisions))
	requestIndex := make(map[string]int, len(decisions))
	for i := range decisions {
		key, ok := mcpRPCIDKey(decisions[i].Message.ID)
		if !ok {
			continue
		}
		requestCounts[key]++
		requestIndex[key] = i
	}

	var observations []mcpRPCResponseObservation
	if sse {
		for _, payload := range parseMCPSSEDataPayloads(respBody) {
			observations = append(observations, parseMCPJSONRPCResponseItems(payload)...)
		}
	} else {
		observations = parseMCPJSONRPCResponseItems(respBody)
	}
	responseCounts := make(map[string]int, len(observations))
	resultByID := make(map[string]json.RawMessage, len(observations))
	for _, observation := range observations {
		responseCounts[observation.idKey]++
		if observation.hasResult {
			resultByID[observation.idKey] = observation.raw
		}
	}
	for key, index := range requestIndex {
		result, ok := resultByID[key]
		if !ok || requestCounts[key] != 1 || responseCounts[key] != 1 {
			continue
		}
		decisions[index].ResultObserved = true
		decisions[index].ResultExcerpt = mcpResultExcerpt(result)
	}
}

func parseMCPJSONRPCResponseItems(payload []byte) []mcpRPCResponseObservation {
	trimmed := bytes.TrimSpace(payload)
	if len(trimmed) == 0 {
		return nil
	}
	var items []json.RawMessage
	switch trimmed[0] {
	case '{':
		items = []json.RawMessage{append(json.RawMessage(nil), trimmed...)}
	case '[':
		if err := json.Unmarshal(trimmed, &items); err != nil {
			return nil
		}
	default:
		return nil
	}
	observations := make([]mcpRPCResponseObservation, 0, len(items))
	for _, item := range items {
		var object map[string]json.RawMessage
		if err := json.Unmarshal(item, &object); err != nil {
			continue
		}
		var version string
		if err := json.Unmarshal(object["jsonrpc"], &version); err != nil || version != "2.0" {
			continue
		}
		idKey, ok := mcpRPCIDKey(object["id"])
		if !ok {
			continue
		}
		if _, hasMethod := object["method"]; hasMethod {
			continue
		}
		_, hasResult := object["result"]
		_, hasError := object["error"]
		observations = append(observations, mcpRPCResponseObservation{
			idKey:     idKey,
			raw:       append(json.RawMessage(nil), bytes.TrimSpace(item)...),
			hasResult: hasResult && !hasError,
		})
	}
	return observations
}

func parseMCPSSEDataPayloads(body []byte) [][]byte {
	normalized := strings.ReplaceAll(string(body), "\r\n", "\n")
	normalized = strings.ReplaceAll(normalized, "\r", "\n")
	var payloads [][]byte
	var dataLines []string
	flush := func() {
		if len(dataLines) == 0 {
			return
		}
		payloads = append(payloads, []byte(strings.Join(dataLines, "\n")))
		dataLines = dataLines[:0]
	}
	for _, line := range strings.Split(normalized, "\n") {
		if line == "" {
			flush()
			continue
		}
		if !strings.HasPrefix(line, "data:") {
			continue
		}
		value := strings.TrimPrefix(line, "data:")
		value = strings.TrimPrefix(value, " ")
		dataLines = append(dataLines, value)
	}
	flush()
	return payloads
}

func mcpRPCIDKey(raw json.RawMessage) (string, bool) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return "", false
	}
	decoder := json.NewDecoder(bytes.NewReader(trimmed))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return "", false
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return "", false
	}
	switch typed := value.(type) {
	case string:
		return "string:" + typed, true
	case json.Number:
		return "number:" + typed.String(), true
	case nil:
		// JSON-RPC 允许 error 响应在无法关联请求时携带 null id。把 null 当作
		// 可归因 ID 会把这种未知错误误挂到请求上，因此保守地保持未归因。
		return "", false
	default:
		return "", false
	}
}

var mcpResultSensitiveStringPatterns = []struct {
	pattern     *regexp.Regexp
	replacement string
}{
	{regexp.MustCompile(`(?i)\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})\b`), "<redacted:secret>"},
	{regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b`), "<redacted:secret>"},
	{regexp.MustCompile(`(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b`), "<redacted:email>"},
	{regexp.MustCompile(`\b1[3-9][0-9]{9}\b`), "<redacted:phone>"},
	{regexp.MustCompile(`\b[0-9]{17}[0-9Xx]\b`), "<redacted:id_card>"},
	{regexp.MustCompile(`\b[0-9]{13,19}\b`), "<redacted:bank_card>"},
}

func mcpResultSensitiveKey(key string) bool {
	var normalized strings.Builder
	for _, char := range strings.ToLower(key) {
		if (char >= 'a' && char <= 'z') || (char >= '0' && char <= '9') {
			normalized.WriteRune(char)
		}
	}
	normalizedKey := normalized.String()
	switch normalizedKey {
	case "password", "passwd", "secret", "secrets", "token", "tokens",
		"apikey", "authorization", "cookie", "cookies", "credential", "credentials",
		"privatekey", "clientsecret", "accesskey", "refreshtoken", "accesstoken",
		"idtoken", "bearertoken":
		return true
	default:
		return strings.Contains(normalizedKey, "password") ||
			strings.Contains(normalizedKey, "secret") ||
			strings.Contains(normalizedKey, "credential") ||
			strings.HasSuffix(normalizedKey, "token") ||
			strings.HasSuffix(normalizedKey, "authorization") ||
			strings.HasSuffix(normalizedKey, "cookie") ||
			strings.HasPrefix(normalizedKey, "apikey") ||
			strings.HasPrefix(normalizedKey, "accesskey") ||
			strings.HasPrefix(normalizedKey, "privatekey")
	}
}

func redactMCPResultString(value string) string {
	value = redactReverseProxyRetainedText(value)
	for _, redactor := range mcpResultSensitiveStringPatterns {
		value = redactor.pattern.ReplaceAllString(value, redactor.replacement)
	}
	return value
}

func redactMCPResultValue(value any) any {
	switch typed := value.(type) {
	case map[string]any:
		for key, child := range typed {
			if mcpResultSensitiveKey(key) {
				typed[key] = "<redacted:secret>"
				continue
			}
			typed[key] = redactMCPResultValue(child)
		}
		return typed
	case []any:
		for index := range typed {
			typed[index] = redactMCPResultValue(typed[index])
		}
		return typed
	case string:
		return redactMCPResultString(typed)
	default:
		return value
	}
}

func redactMCPResultJSON(result json.RawMessage) string {
	decoder := json.NewDecoder(bytes.NewReader(result))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return redactMCPResultString(string(result))
	}
	var redacted bytes.Buffer
	encoder := json.NewEncoder(&redacted)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(redactMCPResultValue(value)); err != nil {
		return redactMCPResultString(string(result))
	}
	return strings.TrimSuffix(redacted.String(), "\n")
}

func mcpResultExcerpt(result json.RawMessage) string {
	const (
		limit  = 2048
		marker = "...[truncated]"
	)
	redacted := redactMCPResultJSON(result)
	if len(redacted) <= limit {
		return redacted
	}
	return truncateReverseProxyUTF8Text(redacted, limit-len(marker)) + marker
}

func validMCPAuthHeaderName(name string) (string, bool) {
	if strings.TrimSpace(name) == "" {
		return "Authorization", true
	}
	canonical := http.CanonicalHeaderKey(strings.TrimSpace(name))
	if !httpguts.ValidHeaderFieldName(canonical) {
		return "", false
	}
	switch strings.ToLower(canonical) {
	case "host", "cookie", "set-cookie", "content-length", "content-type",
		"connection", "proxy-authorization", "proxy-connection", "transfer-encoding",
		"mcp-session-id", "mcp-protocol-version":
		return "", false
	default:
		return canonical, true
	}
}

// mcpEffectiveProtocolVersion 返回客户端缺头时应补给上游的版本：优先用 control-plane 同步时
// 记录的协商版本（须在支持列表内），否则取规范默认值 2025-03-26。
func mcpEffectiveProtocolVersion(server *mcpServerRoute) string {
	if server != nil {
		if v := strings.TrimSpace(server.ProtocolVersion); mcpprotocol.IsSupported(v) {
			return v
		}
	}
	return mcpprotocol.DefaultAssumedWhenHeaderAbsent
}

// mcpBodyIsInitialize 判断请求体是否为 initialize（空体按非 initialize 处理，如 GET/DELETE）。
func mcpBodyIsInitialize(body []byte) bool {
	if len(body) == 0 {
		return false
	}
	var probe struct {
		Method string `json:"method"`
	}
	if json.Unmarshal(body, &probe) != nil {
		return false
	}
	return probe.Method == "initialize"
}

func buildMCPUpstreamRequest(ctx context.Context, server *mcpServerRoute, inbound *http.Request, body []byte) (*http.Request, error) {
	targetURL, err := url.Parse(strings.TrimSpace(server.ServerURL))
	if err != nil || targetURL.Scheme == "" || targetURL.Host == "" ||
		(targetURL.Scheme != "http" && targetURL.Scheme != "https") ||
		targetURL.User != nil || targetURL.Fragment != "" {
		return nil, fmt.Errorf("非法的 MCP 上游地址")
	}
	pathCfg, pathCfgErr := server.upstreamConfig()
	if pathCfgErr != nil {
		return nil, errMCPUpstreamCredential
	}
	// 鉴权位置 path：库里的 server_url 只含 {secret} 占位；此处才解密并替换为路径段编码后的真实密钥。
	// 真实 URL 只用于本次请求，不进入日志 / 错误 / 缓存。
	if pathCfg.AuthLocation == mcpupstream.AuthPath {
		if strings.TrimSpace(server.AuthCiphertext) == "" {
			return nil, errMCPUpstreamCredential
		}
		plain, decErr := secrets.DecryptProviderSecret(server.AuthCiphertext)
		if decErr != nil || plain == "" {
			return nil, errMCPUpstreamCredential
		}
		real, subErr := mcpupstream.SubstitutePathSecret(targetURL, plain)
		if subErr != nil {
			return nil, errMCPUpstreamCredential
		}
		targetURL = real
	}
	var bodyReader io.Reader
	if body != nil {
		bodyReader = bytes.NewReader(body)
	}
	outReq, err := http.NewRequestWithContext(ctx, inbound.Method, targetURL.String(), bodyReader)
	if err != nil {
		// 路径密钥模式下 targetURL 含真实密钥；*url.Error 会带完整 URL，只保留根因，绝不拼接 URL。
		return nil, sanitizeMCPRequestBuildError(err)
	}
	copyHeaders(outReq.Header, inbound.Header)
	// 复审 High-1：会话头只发出校验通过的那一个值（上游绝不会看到第二个值）。
	if sid := strings.TrimSpace(inbound.Header.Get("Mcp-Session-Id")); sid != "" {
		outReq.Header.Set("Mcp-Session-Id", sid)
	}
	// 握手之后的请求必须带 MCP-Protocol-Version：客户端没带（旧版本客户端）时补协商版本。
	// initialize 本身不带（版本在其 params 里协商）。
	if strings.TrimSpace(outReq.Header.Get("MCP-Protocol-Version")) == "" && !mcpBodyIsInitialize(body) {
		outReq.Header.Set("MCP-Protocol-Version", mcpEffectiveProtocolVersion(server))
	}
	outReq.Host = targetURL.Host
	outReq.Close = true
	stripMCPConnectionNamedHeaders(outReq.Header, inbound.Header)
	for _, name := range []string{
		"Authorization", "X-Api-Key", "Api-Key", "Cookie", "Set-Cookie",
		"Proxy-Authenticate", "Proxy-Authorization", "Proxy-Connection", "Connection", "Keep-Alive",
		"TE", "Trailer", "Transfer-Encoding", "Upgrade",
	} {
		outReq.Header.Del(name)
	}
	outReq.Header.Set("Accept", "application/json, text/event-stream")
	// 显式要求不压缩：下游的 Accept-Encoding（gzip / br …）由 copyHeaders 透传过来，上游据此回压缩体，
	// 而网关需要逐字节校验 JSON / SSE 事件。同时 Go 的 Transport 只有在“自己添加 gzip 头”时才透明解压，
	// 下游带了该头就不会解压，于是压缩字节被当成 JSON 校验而 502（验收缺陷 D2）。
	outReq.Header.Set("Accept-Encoding", "identity")
	if inbound.Method == http.MethodPost {
		outReq.Header.Set("Content-Type", "application/json")
	}

	cfg, cfgErr := server.upstreamConfig()
	if cfgErr != nil {
		// 配置无效（头名黑名单 / 模板 / 额外头）一律 fail-closed，且不回显配置细节。
		return nil, errMCPUpstreamCredential
	}
	// 下游调用方绝不能借 query 覆盖上游鉴权参数。
	mcpupstream.StripCallerCredentials(outReq.URL, cfg)
	// 管理员配置的额外静态头与统一 User-Agent：先删后设，调用方同名头不能覆盖。
	mcpupstream.ApplyCommon(outReq, cfg)
	if strings.TrimSpace(server.AuthCiphertext) != "" {
		plaintext, decryptErr := secrets.DecryptProviderSecret(server.AuthCiphertext)
		if decryptErr != nil || plaintext == "" {
			return nil, errMCPUpstreamCredential
		}
		// 头值约束只对 header / query 模式适用：path 模式的密钥是 URL 路径段，已按路径段编码。
		if cfg.AuthLocation != mcpupstream.AuthPath && !httpguts.ValidHeaderFieldValue(plaintext) {
			return nil, errMCPUpstreamCredential
		}
		if err := mcpupstream.ApplyAuth(outReq, cfg, plaintext); err != nil {
			return nil, errMCPUpstreamCredential
		}
	}
	return outReq, nil
}

// resolveMCPUpstreamClient 只按内网放行开关解析（没有对象级放行），保留给测试与旧调用方。
func resolveMCPUpstreamClient(ctx context.Context, rawURL string, allowPrivate bool, base *http.Client) (*http.Client, *url.URL, error) {
	return resolveMCPUpstreamClientWithOptions(ctx, rawURL, safetarget.Options{AllowPrivate: allowPrivate}, base)
}

func sanitizeMCPUpstreamError(err error) error {
	var urlError *url.Error
	if errors.As(err, &urlError) && urlError.Err != nil {
		return fmt.Errorf("MCP 上游请求失败: %w", urlError.Err)
	}
	return errors.New("MCP 上游请求失败")
}

// forwardMCPUpstream 的所有路径都先经 safetarget 校验并固定到同一个 IP；
// allow_private_egress 只允许 RFC1918/ULA/CGNAT，环回、link-local、metadata 等硬红线
// 即使显式放行也拒绝。原始 Host/SNI 保留，代理与重定向一律关闭。
func (h *MCPProxyHandler) forwardMCPUpstream(ctx context.Context, server *mcpServerRoute, r *http.Request, body []byte) (*http.Response, *url.URL, error) {
	if h.testForwardOverride != nil {
		if resp := h.testForwardOverride(r); resp != nil {
			targetURL, _ := url.Parse(server.ServerURL)
			return resp, targetURL, nil
		}
	}
	// 复审 High-1：关键头多值即拒（Streamable 与 SSE 桥接、POST/GET/DELETE、HITL 重放共用这一道门）。
	if name := mcpDuplicateCriticalHeader(r.Header); name != "" {
		targetURL, _ := url.Parse(server.ServerURL)
		return mcpNotForwardedResponse(http.StatusBadRequest, mcpDuplicateHeaderBody), targetURL, nil
	}
	if server.usesSSEBridge() {
		return h.forwardMCPViaSSEBridge(ctx, server, r, body)
	}
	client, targetURL, err := h.resolveUpstreamClient(ctx, server, r)
	if err != nil {
		return nil, nil, err
	}

	// D3：客户端带来的 Mcp-Session-Id 必须是本网关见过的上游签发、且属于当前调用方的会话。
	if denied := h.checkStreamableSession(ctx, server, r, targetURL); denied != nil {
		return denied, targetURL, nil
	}
	outReq, err := buildMCPUpstreamRequest(ctx, server, r, body)
	if err != nil {
		return nil, nil, err
	}
	resp, err := client.Do(outReq)
	if err != nil {
		return nil, targetURL, sanitizeMCPUpstreamError(err)
	}
	// 纵深防御：上游响应里不应出现网关内部的标记头；出现就是伪造，入口处直接剥掉。
	mcpStripInternalHeaders(resp.Header)
	// 已显式要求 identity，但上游仍可能强制压缩：这里统一做有界解压，让后面的校验 / 改写 / 审计 / 透传
	// 全部面对明文（非流式与 SSE 两条分支共用）。
	if err := mcpDecodeUpstreamResponse(resp); err != nil {
		_ = resp.Body.Close()
		return nil, targetURL, err
	}
	if err := h.recordStreamableSession(ctx, server, r, body, resp); err != nil {
		_ = resp.Body.Close()
		return mcpNotForwardedResponseAfterForward(http.StatusServiceUnavailable, mcpSessionTableFullBody), targetURL, nil
	}
	return resp, targetURL, nil
}

// sanitizeMCPRequestBuildError 去掉 *url.Error 里携带的完整请求 URL（可能含路径密钥），只保留根因。
func sanitizeMCPRequestBuildError(err error) error {
	var ue *url.Error
	if errors.As(err, &ue) && ue.Err != nil {
		return fmt.Errorf("构造 MCP 上游请求失败: %w", ue.Err)
	}
	return fmt.Errorf("构造 MCP 上游请求失败: %w", err)
}
