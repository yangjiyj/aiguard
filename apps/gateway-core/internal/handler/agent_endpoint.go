package handler

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/yangjiyj/aiguard/packages/shared-go/endpointevents"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/agentguard"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/config"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/endpointpolicy"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/relay"
	"github.com/yangjiyj/aiguard/packages/shared-go/filerestrict"
	"github.com/yangjiyj/aiguard/packages/shared-go/protection"
)

const (
	maxEndpointEvents       = 200
	maxEndpointEventDepth   = 8
	maxEndpointEventKeyLen  = 64
	maxEndpointEventTextLen = 4096
	endpointDecideBodyLimit = 1 << 20
	endpointEventsPerMinute = 120
	endpointDecidePerSecond = 20
)

type endpointRateWindow struct {
	started time.Time
	count   int
}

// endpointRateLimiter bounds memory and uses a shared mutex for atomic admission.
// Each endpoint has independent windows for events (batches/min) and decide (QPS).
// Expired windows are removed periodically so revoked endpoints cannot accumulate.
type endpointRateLimiter struct {
	mu      sync.Mutex
	now     func() time.Time
	windows map[string]endpointRateWindow
	checks  uint64
}

func newEndpointRateLimiter() *endpointRateLimiter {
	return &endpointRateLimiter{now: time.Now, windows: make(map[string]endpointRateWindow)}
}

func (l *endpointRateLimiter) allow(endpointID, operation string, limit int, window time.Duration) (bool, int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	l.checks++
	if l.checks%1024 == 0 {
		for key, value := range l.windows {
			if !now.Before(value.started.Add(time.Minute)) {
				delete(l.windows, key)
			}
		}
	}
	key := endpointID + "\x00" + operation
	current, exists := l.windows[key]
	if !exists || !now.Before(current.started.Add(window)) {
		current = endpointRateWindow{started: now}
	}
	if current.count >= limit {
		remaining := current.started.Add(window).Sub(now)
		retry := int((remaining + time.Second - 1) / time.Second)
		if retry < 1 {
			retry = 1
		}
		return false, retry
	}
	current.count++
	l.windows[key] = current
	return true, 0
}

type endpointAuthCacheEntry struct {
	value    map[string]any
	expires  time.Time
	negative bool
}
type AgentEndpointGateway struct {
	controlURL, secret string
	client             *http.Client
	toolClient         *ToolRiskClient
	// runtime 是网关主流程共用的控制面客户端：租户有效策略（防护项、例外、规则）与全局执行
	// 模式都从它取。未接线（单元测试）时不取租户策略、不按全局模式钳制。
	runtime        *ToolRiskClient
	securityClient SecurityChecker
	enabled        bool
	bodyLimit      int64
	mu             sync.Mutex
	auth           map[string]endpointAuthCacheEntry
	metrics        *relay.Metrics
	auditFailures  atomic.Uint64
	rateLimiter    *endpointRateLimiter
	resolveNow     func() time.Time
	licenseExpires time.Time
	licenseValue   bool
	// policyLogAt：取不到租户策略的告警日志每个租户每分钟最多一条。
	policyLogMu sync.Mutex
	policyLogAt map[string]time.Time
}

func NewAgentEndpointGateway(cfg *config.Config) *AgentEndpointGateway {
	return &AgentEndpointGateway{toolClient: NewToolRiskClient(cfg.ControlPlaneURL, cfg.InternalAPISecret), controlURL: strings.TrimRight(cfg.ControlPlaneURL, "/"), secret: cfg.InternalAPISecret, client: &http.Client{Timeout: 5 * time.Second}, enabled: cfg.AgentEndpointEnabled, bodyLimit: 8 << 20, auth: make(map[string]endpointAuthCacheEntry), rateLimiter: newEndpointRateLimiter()}
}

// SetMetrics shares the gateway runtime counter registry with endpoint APIs.
func (g *AgentEndpointGateway) SetMetrics(metrics *relay.Metrics) {
	g.metrics = metrics
}

// SetRuntimeClient 接上网关主流程的控制面客户端（它的运行时配置有后台刷新）：decide 用它取
// 租户有效策略和全局执行模式。端点网关自带的 toolClient 没有运行时刷新，不能用来判全局模式。
func (g *AgentEndpointGateway) SetRuntimeClient(client *ToolRiskClient) {
	g.runtime = client
}

// SetIntentSemanticChecker wires the existing gated semantic-stage checker
// into T16. Its output is supplemental and can never change authorization.
func (g *AgentEndpointGateway) SetIntentSemanticChecker(checker SecurityChecker) {
	g.securityClient = checker
}

func (g *AgentEndpointGateway) auditFailureCount() uint64 {
	return g.auditFailures.Load()
}

func endpointTokenHash(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}
func (g *AgentEndpointGateway) resolveTime() time.Time {
	if g.resolveNow != nil {
		return g.resolveNow()
	}
	return time.Now()
}
func (g *AgentEndpointGateway) resolve(ctx context.Context, token string) (map[string]any, error) {
	key := endpointTokenHash(token)
	g.mu.Lock()
	if e, ok := g.auth[key]; ok && g.resolveTime().Before(e.expires) {
		g.mu.Unlock()
		if e.negative {
			return nil, fmt.Errorf("unauthorized")
		}
		return e.value, nil
	}
	g.mu.Unlock()
	b, _ := json.Marshal(map[string]string{"token_hash": key})
	req, e := http.NewRequestWithContext(ctx, http.MethodPost, g.controlURL+"/admin/v1/internal/agent/endpoints/resolve", strings.NewReader(string(b)))
	if e != nil {
		return nil, e
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-JJDGuard-Internal-Token", g.secret)
	resp, e := g.client.Do(req)
	if e != nil {
		return nil, e
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		g.mu.Lock()
		g.auth[key] = endpointAuthCacheEntry{expires: g.resolveTime().Add(5 * time.Second), negative: true}
		g.mu.Unlock()
		return nil, fmt.Errorf("resolve status")
	}
	var v map[string]any
	if e = json.NewDecoder(resp.Body).Decode(&v); e != nil {
		return nil, e
	}
	g.mu.Lock()
	g.auth[key] = endpointAuthCacheEntry{value: v, expires: g.resolveTime().Add(30 * time.Second)}
	g.mu.Unlock()
	return v, nil
}
func (g *AgentEndpointGateway) registrationLicensed(ctx context.Context) (bool, error) {
	g.mu.Lock()
	if g.resolveTime().Before(g.licenseExpires) {
		licensed := g.licenseValue
		g.mu.Unlock()
		return licensed, nil
	}
	g.mu.Unlock()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, g.controlURL+"/admin/v1/internal/agent/license-status", nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("X-JJDGuard-Internal-Token", g.secret)
	resp, err := g.client.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("license status %d", resp.StatusCode)
	}
	var result struct {
		Licensed bool `json:"licensed"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return false, err
	}
	g.mu.Lock()
	g.licenseValue = result.Licensed
	g.licenseExpires = g.resolveTime().Add(30 * time.Second)
	g.mu.Unlock()
	return result.Licensed, nil
}

func jsonError(w http.ResponseWriter, status int, code, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"code": code, "message": msg})
}
func (g *AgentEndpointGateway) admitEndpointRequest(w http.ResponseWriter, ctx map[string]any, operation string, limit int, window time.Duration) bool {
	endpointID := stringValue(ctx["endpoint_id"])
	if endpointID == "" || stringValue(ctx["tenant_id"]) == "" {
		jsonError(w, http.StatusUnauthorized, "AGENT_UNAUTHORIZED", "端点身份无效")
		return false
	}
	allowed, retry := g.rateLimiter.allow(stringValue(ctx["tenant_id"])+"\x00"+endpointID, operation, limit, window)
	if !allowed {
		w.Header().Set("Retry-After", strconv.Itoa(retry))
		jsonError(w, http.StatusTooManyRequests, "AGENT_RATE_LIMITED", "端点请求频率超限")
		return false
	}
	return true
}

func (g *AgentEndpointGateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !g.enabled {
		http.NotFound(w, r)
		return
	}
	auth := strings.TrimSpace(r.Header.Get("Authorization"))
	if len(auth) < 7 || !strings.EqualFold(auth[:7], "Bearer ") {
		jsonError(w, 401, "AGENT_UNAUTHORIZED", "缺少端点令牌")
		return
	}
	tok := strings.TrimSpace(auth[7:])
	if tok == "" {
		jsonError(w, 401, "AGENT_UNAUTHORIZED", "端点令牌无效")
		return
	}
	if r.URL.Path == "/agent/v1/endpoints/register" {
		licensed, err := g.registrationLicensed(r.Context())
		if err != nil {
			jsonError(w, http.StatusServiceUnavailable, "AGENT_LICENSE_CHECK_FAILED", "授权状态暂不可用")
			return
		}
		if !licensed {
			jsonError(w, http.StatusForbidden, "AGENT_UNLICENSED", "未授权智能体安全功能")
			return
		}
		g.proxy(w, r, "/admin/v1/internal/agent/endpoints/register", tok)
		return
	}
	ctx, e := g.resolve(r.Context(), tok)
	if e != nil {
		jsonError(w, 401, "AGENT_UNAUTHORIZED", "端点令牌无效")
		return
	}
	if licensed, ok := ctx["licensed"].(bool); !ok || !licensed {
		jsonError(w, http.StatusForbidden, "AGENT_UNLICENSED", "未授权智能体安全功能")
		return
	}
	if revoked, _ := ctx["revoked"].(bool); revoked {
		jsonError(w, 403, "AGENT_ENDPOINT_REVOKED", "端点已吊销")
		return
	}
	switch r.URL.Path {
	case "/agent/v1/endpoints/heartbeat":
		g.proxy(w, r, "/admin/v1/internal/agent/endpoints/heartbeat", tok)
	case "/agent/v1/events":
		if g.admitEndpointRequest(w, ctx, "events", endpointEventsPerMinute, time.Minute) {
			g.events(w, r, tok, ctx)
		}
	case "/agent/v1/probe-reports":
		if g.admitEndpointRequest(w, ctx, "probe_reports", endpointEventsPerMinute, time.Minute) {
			g.probeReports(w, r, tok, ctx)
		}
	case "/agent/v1/identity-events":
		if g.admitEndpointRequest(w, ctx, "identity_events", endpointEventsPerMinute, time.Minute) {
			g.nativeIdentityEvents(w, r, tok)
		}
	case "/agent/v1/kubernetes/snapshot-runs":
		if g.admitEndpointRequest(w, ctx, "kubernetes_snapshot_runs", 30, time.Minute) {
			g.kubernetesSnapshot(w, r, tok, ctx, "/admin/v1/internal/agent/kubernetes/snapshot-runs")
		}
	case "/agent/v1/kubernetes/snapshots":
		if g.admitEndpointRequest(w, ctx, "kubernetes_snapshots", 12, time.Minute) {
			g.kubernetesSnapshot(w, r, tok, ctx, "/admin/v1/internal/agent/kubernetes/snapshots")
		}
	case "/agent/v1/decide":
		if g.admitEndpointRequest(w, ctx, "decide", endpointDecidePerSecond, time.Second) {
			g.decide(w, r, tok, ctx)
		}
	case "/agent/v1/policy":
		g.policy(w, r, tok, ctx)
	default:
		http.NotFound(w, r)
	}
}
func (g *AgentEndpointGateway) boundedBody(r *http.Request) (io.ReadCloser, error) {
	var rd io.Reader = r.Body
	if strings.EqualFold(r.Header.Get("Content-Encoding"), "gzip") {
		z, e := gzip.NewReader(r.Body)
		if e != nil {
			return nil, e
		}
		rd = z
	}
	return struct {
		io.Reader
		io.Closer
	}{Reader: io.LimitReader(rd, g.bodyLimit+1), Closer: funcCloser(func() error { return nil })}, nil
}

type funcCloser func() error

func (f funcCloser) Close() error { return f() }
func (g *AgentEndpointGateway) events(w http.ResponseWriter, r *http.Request, tok string, ctx map[string]any) {
	encoding := strings.TrimSpace(r.Header.Get("Content-Encoding"))
	if encoding != "" && !strings.EqualFold(encoding, "gzip") {
		jsonError(w, http.StatusUnsupportedMediaType, "AGENT_CONTENT_ENCODING_UNSUPPORTED", "不支持的内容编码")
		return
	}
	if r.ContentLength > g.bodyLimit {
		jsonError(w, http.StatusRequestEntityTooLarge, "AGENT_PAYLOAD_TOO_LARGE", "事件批次过大")
		return
	}
	compressed := http.MaxBytesReader(w, r.Body, g.bodyLimit)
	var reader io.Reader = compressed
	if strings.EqualFold(encoding, "gzip") {
		z, err := gzip.NewReader(compressed)
		if err != nil {
			jsonError(w, http.StatusUnprocessableEntity, "AGENT_INVALID_REQUEST", "压缩请求无效")
			return
		}
		defer z.Close()
		reader = z
	}
	b, err := io.ReadAll(io.LimitReader(reader, g.bodyLimit+1))
	if err != nil || int64(len(b)) > g.bodyLimit {
		jsonError(w, http.StatusRequestEntityTooLarge, "AGENT_PAYLOAD_TOO_LARGE", "事件批次过大")
		return
	}
	q, err := endpointevents.Decode(b)
	if err != nil {
		jsonError(w, http.StatusUnprocessableEntity, "AGENT_INVALID_REQUEST", "事件结构无效")
		return
	}
	if len(q) == 2 {
		// Preserve legacy validation; downstream still requires authenticated batch metadata.
		if code, err := validateEndpointEvents(q); err != nil {
			jsonError(w, http.StatusUnprocessableEntity, code, err.Error())
			return
		}
	} else {
		if q["schema_version"] != "events.v1" {
			jsonError(w, http.StatusUnprocessableEntity, "AGENT_SCHEMA_UNSUPPORTED", "schema_version")
			return
		}
		if err := endpointevents.ValidateHeader(q); err != nil {
			jsonError(w, http.StatusUnprocessableEntity, "AGENT_INVALID_REQUEST", "事件批次无效")
			return
		}
		if q["endpoint_id"] != stringValue(ctx["endpoint_id"]) {
			jsonError(w, http.StatusUnauthorized, "AGENT_UNAUTHORIZED", "端点身份不匹配")
			return
		}
		for _, item := range q["events"].([]any) {
			event, ok := item.(map[string]any)
			if !ok {
				jsonError(w, http.StatusUnprocessableEntity, "AGENT_INVALID_REQUEST", "事件无效")
				return
			}
			if endpointevents.IsNested(event) {
				if err := endpointevents.ValidateEvent(event, time.Now(), stringValue(ctx["capture_level"])); err != nil {
					jsonError(w, http.StatusUnprocessableEntity, "AGENT_PRIVACY_REJECTED", "事件不符合字段或采集级别约束")
					return
				}
			} else {
				if code, err := validateEndpointEvents(map[string]any{"schema_version": "events.v1", "events": []any{event}}); err != nil {
					jsonError(w, http.StatusUnprocessableEntity, code, err.Error())
					return
				}
			}
		}
	}
	for _, item := range q["events"].([]any) {
		event, _ := item.(map[string]any)
		if !endpointevents.IsNested(event) {
			if err := endpointevents.ValidateLegacyCapture(event, stringValue(ctx["capture_level"])); err != nil {
				jsonError(w, http.StatusUnprocessableEntity, "AGENT_PRIVACY_REJECTED", "事件不符合采集级别约束")
				return
			}
		}
	}
	g.proxyBody(w, r, "/admin/v1/internal/agent/events", tok, b)
}

var endpointEventRootFields = map[string]struct{}{
	"event_id": {}, "event_type": {}, "occurred_at": {}, "endpoint_id": {},
	"session_id": {}, "prompt_id": {}, "tool_use_id": {}, "tool_call_id": {},
	"tool_name": {}, "tool_type": {}, "status": {}, "result": {}, "payload": {},
	"result_hash": {}, "result_length": {}, "command": {}, "command_hash": {}, "command_length": {},
	"arguments_hash": {}, "arguments_length": {}, "decision": {}, "risk_level": {}, "reason": {},
	"provenance": {}, "duration_ms": {}, "exit_code": {}, "success": {}, "metadata": {},
	"local_decision": {}, "server_decision": {}, "severity": {}, "mcp_server": {},
	"asset_type": {}, "asset_name": {}, "asset_version": {}, "asset_source": {},
	"asset_hash": {}, "asset_present": {}, "asset_evidence": {}, "scan_status": {}, "scan_decision": {},
}

var endpointEventPayloadFields = map[string]struct{}{
	"tool_call_id": {}, "tool_use_id": {}, "tool_name": {}, "tool_type": {},
	"status": {}, "result": {}, "result_hash": {}, "result_length": {},
	"command": {}, "command_hash": {}, "command_length": {}, "arguments_hash": {},
	"arguments_length": {}, "decision": {}, "risk_level": {}, "reason": {},
	"provenance": {}, "duration_ms": {}, "exit_code": {}, "success": {},
	"mcp_server": {}, "metadata": {}, "severity": {},
	"asset_type": {}, "asset_name": {}, "asset_version": {}, "asset_source": {},
	"asset_hash": {}, "asset_present": {}, "asset_evidence": {}, "scan_status": {}, "scan_decision": {},
}

var endpointDecisionFields = map[string]struct{}{
	"decision": {}, "raw_decision": {}, "effective_decision": {}, "risk_level": {},
	"reason": {}, "provenance": {}, "policy_version": {}, "rule_id": {},
}

var endpointMetadataFields = map[string]struct{}{
	"source": {}, "adapter": {}, "version": {}, "category": {}, "name": {}, "value": {},
}

var endpointEventTypes = map[string]struct{}{
	"tool.pre":  {},
	"tool.post": {},
}

func endpointSensitiveKey(key string) bool {
	normalized := strings.ToLower(strings.NewReplacer("-", "_", ".", "_").Replace(key))
	for _, bad := range []string{
		"password", "passwd", "secret", "api_key", "apikey", "authorization", "cookie",
		"access_token", "refresh_token", "private_key", "credential", "raw_prompt",
		"raw_argument", "raw_output", "prompt_text", "response_body",
	} {
		if strings.Contains(normalized, bad) {
			return true
		}
	}
	return normalized == "token" || strings.HasSuffix(normalized, "_token")
}

func validateEndpointValue(value any, depth int, allowed map[string]struct{}) error {
	if depth > maxEndpointEventDepth {
		return fmt.Errorf("event nesting too deep")
	}
	switch x := value.(type) {
	case map[string]any:
		for key, child := range x {
			if len(key) == 0 || len(key) > maxEndpointEventKeyLen || endpointSensitiveKey(key) {
				return fmt.Errorf("unsafe event field")
			}
			if _, ok := allowed[key]; !ok {
				return fmt.Errorf("unknown event field")
			}
			next := allowed
			switch key {
			case "payload":
				next = endpointEventPayloadFields
			case "local_decision", "server_decision":
				next = endpointDecisionFields
			case "metadata", "asset_evidence":
				next = endpointMetadataFields
			}
			if err := validateEndpointValue(child, depth+1, next); err != nil {
				return err
			}
		}
	case []any:
		for _, child := range x {
			if err := validateEndpointValue(child, depth+1, allowed); err != nil {
				return err
			}
		}
	case string:
		if len(x) > maxEndpointEventTextLen {
			return fmt.Errorf("event string too long")
		}
	case json.Number, bool, nil:
	default:
		return fmt.Errorf("invalid event value")
	}
	return nil
}

func validateEndpointEvents(q map[string]any) (string, error) {
	if len(q) != 2 {
		return "AGENT_INVALID_REQUEST", fmt.Errorf("batch fields")
	}
	for key := range q {
		if key != "schema_version" && key != "events" {
			return "AGENT_INVALID_REQUEST", fmt.Errorf("batch fields")
		}
	}
	version, ok := q["schema_version"].(string)
	if !ok || version != "events.v1" {
		return "AGENT_SCHEMA_UNSUPPORTED", fmt.Errorf("schema_version")
	}
	events, ok := q["events"].([]any)
	if !ok || len(events) == 0 || len(events) > maxEndpointEvents {
		return "AGENT_INVALID_REQUEST", fmt.Errorf("events")
	}
	now := time.Now()
	for _, raw := range events {
		event, ok := raw.(map[string]any)
		if !ok {
			return "AGENT_INVALID_REQUEST", fmt.Errorf("event")
		}
		if err := validateEndpointValue(event, 1, endpointEventRootFields); err != nil {
			if strings.Contains(err.Error(), "unsafe") {
				return "AGENT_PRIVACY_REJECTED", err
			}
			return "AGENT_INVALID_REQUEST", err
		}
		id, ok := event["event_id"].(string)
		if !ok || id == "" || len(id) > 256 {
			return "AGENT_INVALID_REQUEST", fmt.Errorf("event_id")
		}
		typ, ok := event["event_type"].(string)
		if !ok {
			return "AGENT_INVALID_REQUEST", fmt.Errorf("event_type")
		}
		if _, ok = endpointEventTypes[typ]; !ok {
			return "AGENT_INVALID_REQUEST", fmt.Errorf("event_type")
		}
		ts, ok := event["occurred_at"].(string)
		if !ok {
			return "AGENT_INVALID_REQUEST", fmt.Errorf("occurred_at")
		}
		occurredAt, err := time.Parse(time.RFC3339Nano, ts)
		if err != nil {
			return "AGENT_INVALID_REQUEST", fmt.Errorf("occurred_at")
		}
		if occurredAt.Before(now.Add(-30*24*time.Hour)) || occurredAt.After(now.Add(24*time.Hour)) {
			return "AGENT_EVENT_TIME_SKEW", fmt.Errorf("occurred_at")
		}
	}
	return "", nil
}

type endpointDecideRequest struct {
	IntentTaskID  string                       `json:"intent_task_id,omitempty"`
	EndpointID    string                       `json:"endpoint_id"`
	SessionID     string                       `json:"session_id"`
	PromptID      string                       `json:"prompt_id"`
	ToolUseID     string                       `json:"tool_use_id"`
	Agent         *endpointDecideAgent         `json:"agent"`
	Tool          *endpointDecideTool          `json:"tool"`
	Arguments     map[string]any               `json:"arguments"`
	Context       *endpointDecideContext       `json:"context"`
	LocalDecision *endpointDecideLocalDecision `json:"local_decision"`
}

type endpointDecideAgent struct {
	Product string `json:"product"`
	Version string `json:"version"`
}

type endpointDecideTool struct {
	Name      string `json:"name"`
	Type      string `json:"type"`
	MCPServer string `json:"mcp_server"`
}

type endpointDecideContext struct {
	CWDHash        string                   `json:"cwd_hash"`
	PermissionMode string                   `json:"permission_mode"`
	Fragments      []endpointDecideFragment `json:"fragments"`
}

type endpointDecideFragment struct {
	Trust     string `json:"trust"`
	Source    string `json:"source"`
	ToolUseID string `json:"tool_use_id"`
	Hash      string `json:"hash"`
	Preview   string `json:"preview"`
}

type endpointDecideLocalDecision struct {
	Raw       string `json:"raw"`
	RuleID    string `json:"rule_id"`
	LatencyMS *int64 `json:"latency_ms"`
}

type endpointJSONContainer struct {
	kind    json.Delim
	keys    map[string]struct{}
	wantKey bool
}

func rejectDuplicateEndpointJSONKeys(raw []byte) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	token, err := dec.Token()
	if err != nil {
		return err
	}
	root, ok := token.(json.Delim)
	if !ok || root != '{' {
		return errors.New("request object required")
	}
	stack := []endpointJSONContainer{{kind: '{', keys: make(map[string]struct{}), wantKey: true}}
	for len(stack) > 0 {
		token, err = dec.Token()
		if err != nil {
			return err
		}
		top := &stack[len(stack)-1]
		delim, isDelim := token.(json.Delim)
		if top.kind == '{' && top.wantKey {
			if isDelim && delim == '}' {
				stack = stack[:len(stack)-1]
				continue
			}
			key, ok := token.(string)
			if !ok {
				return errors.New("object key required")
			}
			if _, exists := top.keys[key]; exists {
				return errors.New("duplicate request field")
			}
			top.keys[key] = struct{}{}
			top.wantKey = false
			continue
		}
		if top.kind == '[' && isDelim && delim == ']' {
			stack = stack[:len(stack)-1]
			continue
		}
		if isDelim && (delim == '}' || delim == ']') {
			return errors.New("unexpected JSON delimiter")
		}
		if top.kind == '{' {
			top.wantKey = true
		}
		if isDelim {
			switch delim {
			case '{':
				stack = append(stack, endpointJSONContainer{kind: '{', keys: make(map[string]struct{}), wantKey: true})
			case '[':
				stack = append(stack, endpointJSONContainer{kind: '['})
			default:
				return errors.New("unexpected JSON delimiter")
			}
		}
	}
	if _, err = dec.Token(); err != io.EOF {
		if err == nil {
			return errors.New("trailing JSON value")
		}
		return err
	}
	return nil
}

func endpointDecideJSONObject(raw json.RawMessage, allowed ...string) (map[string]json.RawMessage, error) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil || fields == nil {
		return nil, errors.New("object required")
	}
	if len(allowed) > 0 {
		known := make(map[string]struct{}, len(allowed))
		for _, key := range allowed {
			known[key] = struct{}{}
		}
		for key := range fields {
			if _, ok := known[key]; !ok {
				return nil, errors.New("unknown request field")
			}
		}
	}
	return fields, nil
}

func requireEndpointDecideFields(fields map[string]json.RawMessage, required ...string) error {
	for _, key := range required {
		if _, ok := fields[key]; !ok {
			return errors.New("required request field missing")
		}
	}
	return nil
}

func rejectEndpointDecideNullFields(fields map[string]json.RawMessage, keys ...string) error {
	for _, key := range keys {
		if raw, ok := fields[key]; ok && bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
			return errors.New("null request field")
		}
	}
	return nil
}

func validateEndpointDecideEnum(fields map[string]json.RawMessage, key string, allowed ...string) error {
	raw, ok := fields[key]
	if !ok {
		return nil
	}
	var value string
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) || json.Unmarshal(raw, &value) != nil {
		return errors.New("invalid enum field")
	}
	for _, candidate := range allowed {
		if value == candidate {
			return nil
		}
	}
	return errors.New("invalid enum field")
}

func validateEndpointDecideJSONShape(raw []byte) error {
	root, err := endpointDecideJSONObject(json.RawMessage(raw),
		"endpoint_id", "session_id", "prompt_id", "tool_use_id", "intent_task_id", "agent", "tool", "arguments", "context", "local_decision")
	if err != nil {
		return err
	}
	if err := requireEndpointDecideFields(root, "endpoint_id", "session_id", "tool_use_id", "agent", "tool", "arguments", "context"); err != nil {
		return err
	}
	if err := rejectEndpointDecideNullFields(root, "endpoint_id", "session_id", "prompt_id", "tool_use_id", "intent_task_id"); err != nil {
		return err
	}
	agentFields, err := endpointDecideJSONObject(root["agent"], "product", "version")
	if err != nil {
		return err
	}
	if err := rejectEndpointDecideNullFields(agentFields, "product", "version"); err != nil {
		return err
	}
	toolFields, err := endpointDecideJSONObject(root["tool"], "name", "type", "mcp_server")
	if err != nil {
		return err
	}
	if err := rejectEndpointDecideNullFields(toolFields, "name", "type", "mcp_server"); err != nil {
		return err
	}
	if err := requireEndpointDecideFields(toolFields, "name", "type"); err != nil {
		return err
	}
	if err := validateEndpointDecideEnum(toolFields, "type", "system", "file", "network", "database", "mcp", "skill", "agent", "browser", "other"); err != nil {
		return err
	}
	contextFields, err := endpointDecideJSONObject(root["context"], "cwd_hash", "permission_mode", "fragments")
	if err != nil {
		return err
	}
	if err := rejectEndpointDecideNullFields(contextFields, "cwd_hash", "permission_mode", "fragments"); err != nil {
		return err
	}
	if _, err := endpointDecideJSONObject(root["arguments"]); err != nil {
		return err
	}
	if local, ok := root["local_decision"]; ok {
		localFields, err := endpointDecideJSONObject(local, "raw", "rule_id", "latency_ms")
		if err != nil {
			return err
		}
		if err := rejectEndpointDecideNullFields(localFields, "raw", "rule_id", "latency_ms"); err != nil {
			return err
		}
		if err := validateEndpointDecideEnum(localFields, "raw", "allow", "audit", "confirm", "block"); err != nil {
			return err
		}
	}
	if fragmentsRaw, ok := contextFields["fragments"]; ok {
		var fragments []json.RawMessage
		if err := json.Unmarshal(fragmentsRaw, &fragments); err != nil || fragments == nil || len(fragments) > 32 {
			return errors.New("invalid context fragments")
		}
		for _, rawFragment := range fragments {
			fragment, err := endpointDecideJSONObject(rawFragment, "trust", "source", "tool_use_id", "hash", "preview")
			if err != nil {
				return err
			}
			if err := requireEndpointDecideFields(fragment, "trust", "source", "hash"); err != nil {
				return err
			}
			if err := rejectEndpointDecideNullFields(fragment, "trust", "source", "tool_use_id", "hash", "preview"); err != nil {
				return err
			}
			if err := validateEndpointDecideEnum(fragment, "trust", "trusted", "untrusted", "unknown"); err != nil {
				return err
			}
			if err := validateEndpointDecideEnum(fragment, "source", "user_prompt", "tool_result", "instruction_file", "mcp_description", "web"); err != nil {
				return err
			}
		}
	}
	return nil
}

func (g *AgentEndpointGateway) decide(w http.ResponseWriter, r *http.Request, tok string, ctx map[string]any) {
	body := http.MaxBytesReader(w, r.Body, endpointDecideBodyLimit)
	raw, err := io.ReadAll(body)
	if err != nil {
		status := http.StatusUnprocessableEntity
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			status = http.StatusRequestEntityTooLarge
		}
		jsonError(w, status, "AGENT_INVALID_REQUEST", "请求结构无效")
		return
	}
	if err := rejectDuplicateEndpointJSONKeys(raw); err != nil {
		jsonError(w, http.StatusUnprocessableEntity, "AGENT_INVALID_REQUEST", "请求结构无效")
		return
	}
	if err := validateEndpointDecideJSONShape(raw); err != nil {
		jsonError(w, http.StatusUnprocessableEntity, "AGENT_INVALID_REQUEST", "请求结构无效")
		return
	}
	var q endpointDecideRequest
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&q); err != nil {
		jsonError(w, http.StatusUnprocessableEntity, "AGENT_INVALID_REQUEST", "请求结构无效")
		return
	}
	if len(q.IntentTaskID) > 64 || strings.TrimSpace(q.EndpointID) == "" || strings.TrimSpace(q.SessionID) == "" ||
		strings.TrimSpace(q.ToolUseID) == "" || q.Agent == nil ||
		strings.TrimSpace(q.Agent.Product) == "" || q.Tool == nil ||
		strings.TrimSpace(q.Tool.Name) == "" || strings.TrimSpace(q.Tool.Type) == "" ||
		q.Arguments == nil || q.Context == nil {
		jsonError(w, http.StatusUnprocessableEntity, "AGENT_INVALID_REQUEST", "请求结构无效")
		return
	}
	for _, fragment := range q.Context.Fragments {
		if fragment.Trust == "" || fragment.Source == "" || fragment.Hash == "" || utf8.RuneCountInString(fragment.Preview) > 512 {
			jsonError(w, http.StatusUnprocessableEntity, "AGENT_INVALID_REQUEST", "请求结构无效")
			return
		}
	}
	endpointID := stringValue(ctx["endpoint_id"])
	if endpointID == "" || q.EndpointID != endpointID {
		jsonError(w, http.StatusUnauthorized, "AGENT_UNAUTHORIZED", "端点身份不匹配")
		return
	}
	bundle, err := g.fetchEndpointPolicy(r.Context(), tok)
	if err != nil {
		jsonError(w, http.StatusServiceUnavailable, "AGENT_POLICY_UNAVAILABLE", "端点策略暂不可评估，请使用本地策略")
		return
	}
	// 端点模式与全局执行模式取更宽松者：全局观察留痕下端点设阻断也不拦（设计 D6）。
	mode := agentguard.ModeStrict
	switch ctx["mode"] {
	case "monitor":
		mode = agentguard.ModeObserve
	case "would_block":
		mode = agentguard.ModeAudit
	}
	// T13 授权拒绝是授权事实（D10 授权不动）：只看端点模式，不受全局观察留痕约束（与 2.9.21 一致）。
	authorizationMode := mode
	recordOnly := g.globalRecordOnly(r.Context())
	if mode == agentguard.ModeStrict && recordOnly {
		mode = agentguard.ModeAudit
	}
	fragments := make([]agentguard.ContextFragment, 0, len(q.Context.Fragments))
	for _, fragment := range q.Context.Fragments {
		fragments = append(fragments, agentguard.ContextFragment{ID: fragment.ToolUseID, Trust: agentguard.Provenance(fragment.Trust), Text: fragment.Preview})
	}
	tenantPolicy := g.endpointTenantPolicy(r.Context(), stringValue(ctx["tenant_id"]), q)
	d, target := agentguard.AnalyzeToolCallFindings(r.Context(), agentguard.ToolCallAnalysisInput{ToolName: q.Tool.Name, ToolType: q.Tool.Type, Arguments: q.Arguments, ContextFragments: fragments, Mode: mode, Policy: tenantPolicy})
	analyzerRaw := d.RawDecision
	evaluation := endpointpolicy.Evaluate(bundle, endpointpolicy.ToolInput{Name: q.Tool.Name, Type: q.Tool.Type, Arguments: q.Arguments})
	explicit, reportedRaw := mergeEndpointBundleHits(&d, evaluation, target, analyzerRaw)
	if endpointpolicy.UnknownMayChange(evaluation, string(reportedRaw), d.RiskLevel) {
		jsonError(w, http.StatusServiceUnavailable, "AGENT_POLICY_UNAVAILABLE", "端点策略包含当前请求无法可靠评估的条件，请使用本地策略")
		return
	}
	var intentReport map[string]any
	t13Denied := false
	if g.toolClient != nil && q.ToolUseID != "" {
		intentReport, t13Denied = g.assessEndpointToolIntent(r.Context(), tok, endpointID,
			stringValue(ctx["tenant_id"]), stringValue(ctx["agent_product"]), q)
	}
	matchedRuleID := d.MatchedRuleID
	d = agentguard.ApplyEffectivePolicy(d, agentguard.PolicyEvaluationInput{
		ToolName: q.Tool.Name, ToolType: q.Tool.Type, Target: target,
		Policy: endpointEvaluationPolicy(tenantPolicy, explicit), CallerMode: mode,
	})
	if matchedRuleID != "" {
		d.MatchedRuleID = matchedRuleID
	}
	if t13Denied {
		reportedRaw = applyEndpointT13Denial(&d, reportedRaw, authorizationMode)
	}
	d.RawDecision = reportedRaw
	effective := d.EffectiveDecision
	if effective == "" {
		effective = d.RawDecision
	}
	traceID := "agent-" + q.ToolUseID
	if g.toolClient != nil && q.ToolUseID != "" {
		status := "audited"
		switch strings.ToLower(strings.TrimSpace(string(effective))) {
		case "block", "blocked", "deny", "denied":
			status = "blocked"
		}
		evidence := map[string]any{"policy_checksum": bundle.Checksum}
		if evaluation.Matched {
			evidence["policy_rule_id"] = evaluation.Hit.RuleID
		}
		// 2.9.22：端侧的工具日志是这次判定唯一的留痕，写下决定处置的防护项（拦截归因、加例外入口），
		// 告警放行时标要告警；全局观察留痕下只记录、不告警（与 chat 路径的告警事件同口径）。
		if item := agentguard.DecidingProtectionItem(d); item != "" {
			evidence["protection_item"] = item
		}
		notify := d.NotificationRequired && effective == agentguard.DecisionAudit && !recordOnly
		evidence["t16_intent"] = intentReport
		payload := ToolAuditLogPayload{EndpointID: endpointID, PromptID: q.PromptID, ToolName: q.Tool.Name, ToolType: q.Tool.Type, Parameters: q.Arguments, Status: status, RiskLevel: d.RiskLevel, RawDecision: string(d.RawDecision), EffectiveDecision: string(effective), EffectiveReason: d.EffectiveReason, PolicyVersion: strconv.FormatInt(bundle.Version, 10), EvidenceJSON: evidence, Mode: string(mode), TraceID: traceID, ToolCallID: q.ToolUseID, IntentTaskID: q.IntentTaskID, MCPServer: q.Tool.MCPServer, IntentTaskSources: intentTaskSourceClaims(q.Context.Fragments), EventKind: "invocation_proposed", AttributionMode: "endpoint_hook", AttributionConfidence: 1, Provenance: "agent_endpoint", NotificationRequired: notify}
		// 审计写入失败不改变已做出的决策：端侧仍按 effective_decision 执行，事件稍后经 /events 补齐。
		if _, err := g.toolClient.LogToolCallWithID(r.Context(), &modelrouter.RequestEnvelope{SessionID: q.SessionID, TenantID: stringValue(ctx["tenant_id"]), AgentType: q.Agent.Product, AgentRuntime: "agent_hook"}, payload); err != nil {
			g.auditFailures.Add(1)
			if g.metrics != nil {
				g.metrics.Inc("agent_endpoint_tool_audit_failed")
			}
			log.Printf("WARN agent endpoint: tool audit log failed trace=%s tool_call_id=%s audit_failures=%d: %v", traceID, q.ToolUseID, g.auditFailureCount(), err)
		}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"trace_id": traceID, "raw_decision": d.RawDecision, "effective_decision": effective, "mode": ctx["mode"], "risk_level": d.RiskLevel, "reason": d.Reason, "provenance": d.Provenance, "policy_version": bundle.Version, "policy_checksum": bundle.Checksum, "rule_id": d.MatchedRuleID, "user_message": "已完成端侧工具调用安全评估"})
}

// mergeEndpointBundleHits 合并策略包命中：注册表端侧组的防护项（endpoint.rule.<规则 ID>）是端侧
// 内置规则，记为防护项命中（动作、例外按租户配置）；策略包里其余规则是管理员配置的显式规则，与租户
// 规则同等对待（允许降级分析器结论，放不开防护项），取最严的一条返回。策略包有确定命中时，上报的
// 原始结论取分析器与策略包中更严者。
func mergeEndpointBundleHits(d *agentguard.Decision, evaluation endpointpolicy.Evaluation, target string, analyzerRaw agentguard.DecisionAction) (*endpointpolicy.Hit, agentguard.DecisionAction) {
	var explicit *endpointpolicy.Hit
	for _, hit := range evaluation.Hits {
		if item, ok := protection.ItemForReason(hit.RuleID); ok && item.Group == protection.GroupEndpoint {
			if len(hit.Paths) > 0 {
				// 按路径命中的内置规则（.env、SSH 私钥、授权公钥）：每个命中路径一条，例外按路径层级比对
				// （agentguard 的 fileTargetReasons，与 agent.env_file 等同口径）。
				for _, path := range hit.Paths {
					d.ProtectionHits = append(d.ProtectionHits, agentguard.ProtectionHit{Reason: hit.RuleID, RiskLevel: hit.Risk, Confidence: 0.9, MatchTarget: filerestrict.ExceptionTarget(path)})
				}
			} else {
				d.ProtectionHits = append(d.ProtectionHits, agentguard.ProtectionHit{Reason: hit.RuleID, RiskLevel: hit.Risk, Confidence: 0.9, MatchTarget: target})
			}
			d.Evidence = append(d.Evidence, agentguard.Evidence{RuleID: hit.RuleID, Category: "endpoint_builtin_rule"})
			continue
		}
		if explicit == nil || endpointDecisionRank(hit.Decision) > endpointDecisionRank(explicit.Decision) {
			h := hit
			explicit = &h
		}
	}
	reportedRaw := analyzerRaw
	if evaluation.Matched {
		if endpointDecisionRank(evaluation.Hit.Decision) > endpointDecisionRank(string(analyzerRaw)) {
			d.Reason = "endpoint_policy_rule"
		}
		reportedRaw = maxEndpointDecision(string(analyzerRaw), evaluation.Hit.Decision)
		d.RiskLevel = maxEndpointRisk(d.RiskLevel, evaluation.Hit.Risk)
		d.MatchedRuleID = evaluation.Hit.RuleID
	}
	if explicit != nil {
		d.Evidence = append(d.Evidence, agentguard.Evidence{RuleID: explicit.RuleID, Category: "endpoint_policy_rule"})
	}
	return explicit, reportedRaw
}

// applyEndpointT13Denial：持久化、复核过的 T13 决定明确拒绝了这次调用需要的某项授权。这是授权事实，
// 不是意图/语义判断：结论下限是阻断（规则放不开）；效果只看端点（授权）模式，不受只管检测类结论的
// 全局观察留痕约束（D10）。返回上报的原始结论。
func applyEndpointT13Denial(d *agentguard.Decision, reportedRaw agentguard.DecisionAction, authorizationMode agentguard.Mode) agentguard.DecisionAction {
	if endpointDecisionRank(string(reportedRaw)) < endpointDecisionRank("block") {
		d.Reason = "t13_authorization_denied"
	}
	d.ConfiguredEnforcement = true
	d.RiskLevel = maxEndpointRisk(d.RiskLevel, "high")
	d.Evidence = append(d.Evidence, agentguard.Evidence{RuleID: "t13_authorization_denied", Category: "authorization"})
	switch {
	case authorizationMode == agentguard.ModeStrict:
		d.EffectiveDecision, d.EffectiveReason = agentguard.DecisionBlock, "t13_authorization_denied"
	case d.EffectiveDecision == agentguard.DecisionAllow || d.EffectiveDecision == "":
		d.EffectiveDecision, d.EffectiveReason = agentguard.DecisionAudit, "would-block"
	}
	return agentguard.DecisionBlock
}

// globalRecordOnly 报告全局执行模式是不是观察留痕（未接主流程客户端时不钳制）。
// SecurityAuditOnly 读运行时缓存的全局执行模式快照，两个参数都不使用：第二个参数是接口遗留的
// 兜底值，实际兜底在快照里。快照与控制面 executionmode.FromValues 同口径：控制台显式模式优先；
// 没有显式模式时部署变量 SECURITY_AUDIT_ONLY=true 作初值（D7）；启动时还没取到配置按观察留痕。
func (g *AgentEndpointGateway) globalRecordOnly(ctx context.Context) bool {
	return g.runtime != nil && g.runtime.SecurityAuditOnly(ctx, false)
}

// logTenantPolicyUnavailable 记取不到租户策略的告警：每个租户每分钟最多一条，控制面不可用时不刷屏。
func (g *AgentEndpointGateway) logTenantPolicyUnavailable(tenantID string, err error) {
	now := g.resolveTime()
	g.policyLogMu.Lock()
	if last, seen := g.policyLogAt[tenantID]; seen && now.Sub(last) < time.Minute {
		g.policyLogMu.Unlock()
		return
	}
	if g.policyLogAt == nil {
		g.policyLogAt = map[string]time.Time{}
	}
	if len(g.policyLogAt) >= 10000 {
		for tenant, at := range g.policyLogAt {
			if now.Sub(at) >= time.Minute {
				delete(g.policyLogAt, tenant)
			}
		}
	}
	g.policyLogAt[tenantID] = now
	g.policyLogMu.Unlock()
	log.Printf("WARN agent endpoint: tenant AgentGuard policy unavailable tenant=%s, using registry defaults (at most once a minute per tenant): %v", tenantID, err)
}

// endpointTenantPolicy 取租户有效策略（防护项、例外、规则）；拉不到时返回 nil，按注册表默认值判定。
func (g *AgentEndpointGateway) endpointTenantPolicy(ctx context.Context, tenantID string, q endpointDecideRequest) *agentguard.EffectivePolicy {
	if g.runtime == nil || strings.TrimSpace(tenantID) == "" {
		return nil
	}
	envelope := &modelrouter.RequestEnvelope{TenantID: tenantID, SessionID: q.SessionID, AgentRuntime: "agent_hook"}
	if q.Agent != nil {
		envelope.AgentType = q.Agent.Product
	}
	policy, err := g.runtime.GetAgentGuardPolicy(ctx, envelope)
	if err != nil {
		g.logTenantPolicyUnavailable(tenantID, err)
		return nil
	}
	return policy
}

// endpointEvaluationPolicy 是 decide 判定用的策略：租户策略的副本加上策略包命中的显式规则；
// 端侧没有确认票据通道，需要确认时按 agent.confirm_without_channel 处置。
func endpointEvaluationPolicy(tenant *agentguard.EffectivePolicy, explicit *endpointpolicy.Hit) *agentguard.EffectivePolicy {
	if tenant == nil && explicit == nil {
		return nil
	}
	policy := &agentguard.EffectivePolicy{RuleMode: agentguard.ModeStrict}
	if tenant != nil {
		policy = cloneAgentGuardEffectivePolicy(tenant)
	}
	policy.ConfirmChannelEnabled = false
	if explicit != nil {
		policy.Rules = append(policy.Rules, agentguard.PolicyRule{
			ID: explicit.RuleID, ToolPattern: "*", Action: agentguard.DecisionAction(explicit.Decision), Enabled: true,
		})
	}
	return policy
}

func endpointDecisionRank(value string) int {
	switch value {
	case "block":
		return 4
	case "confirm":
		return 3
	case "audit":
		return 2
	case "allow":
		return 1
	default:
		return 0
	}
}

func maxEndpointDecision(left, right string) agentguard.DecisionAction {
	if endpointDecisionRank(right) > endpointDecisionRank(left) {
		return agentguard.DecisionAction(right)
	}
	return agentguard.DecisionAction(left)
}

func endpointRiskRank(value string) int {
	switch value {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}

func maxEndpointRisk(left, right string) string {
	if endpointRiskRank(right) > endpointRiskRank(left) {
		return right
	}
	return left
}

func (g *AgentEndpointGateway) policy(w http.ResponseWriter, r *http.Request, tok string, ctx map[string]any) {
	g.proxy(w, r, "/admin/v1/internal/agent/policy-bundle", tok)
}
func (g *AgentEndpointGateway) proxy(w http.ResponseWriter, r *http.Request, path, tok string) {
	b, e := io.ReadAll(r.Body)
	if e != nil {
		jsonError(w, 400, "AGENT_INVALID_REQUEST", "请求无效")
		return
	}
	g.proxyBody(w, r, path, tok, b)
}
func (g *AgentEndpointGateway) proxyBody(w http.ResponseWriter, r *http.Request, path, tok string, b []byte) {
	req, e := http.NewRequestWithContext(r.Context(), r.Method, g.controlURL+path, strings.NewReader(string(b)))
	if e != nil {
		jsonError(w, 400, "AGENT_INVALID_REQUEST", "请求无效")
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("X-JJDGuard-Internal-Token", g.secret)
	if value := r.Header.Get("If-None-Match"); value != "" {
		req.Header.Set("If-None-Match", value)
	}
	req.URL.RawQuery = r.URL.RawQuery
	resp, e := g.client.Do(req)
	if e != nil {
		jsonError(w, 502, "AGENT_INVALID_REQUEST", "控制面暂不可用")
		return
	}
	defer resp.Body.Close()
	for k, v := range resp.Header {
		for _, x := range v {
			w.Header().Add(k, x)
		}
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

var _ = strconv.IntSize

func stringValue(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}
