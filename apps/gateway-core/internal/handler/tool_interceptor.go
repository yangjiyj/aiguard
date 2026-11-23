package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/agentguard"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
	"github.com/yangjiyj/aiguard/packages/shared-go/agentintent"
	"github.com/yangjiyj/aiguard/packages/shared-go/errclass"
	"github.com/yangjiyj/aiguard/packages/shared-go/filerestrict"
	"github.com/yangjiyj/aiguard/packages/shared-go/headeraudit"
	"github.com/yangjiyj/aiguard/packages/shared-go/inspectionscope"
	"github.com/yangjiyj/aiguard/packages/shared-go/protection"
	"github.com/yangjiyj/aiguard/packages/shared-go/ratelog"
	"github.com/yangjiyj/aiguard/packages/shared-go/runtimeoptions"
	"golang.org/x/sync/singleflight"
)

// ToolRiskClient calls control-plane API to check tool risk configuration
type ToolRiskClient struct {
	controlPlaneURL              string
	internalAPISecret            string
	semanticConfigAttestationKey string
	mcpConfirmationScopeSecret   string
	httpClient                   *http.Client
	cache                        *toolRiskCache
	agentGuardPolicyCache        *agentGuardPolicyCache
	agentGuardPolicyFailureHook  func(context.Context, *modelrouter.RequestEnvelope, error, bool)
	semanticRefreshGroup         singleflight.Group
	mcpPolicyCache               *mcpPolicyCache
	skillAdmissionCache          *skillAdmissionCache
	runtimeCache                 *runtimeSettingsCache
	// mcpPolicyFailMode 决定 MCP 策略拉取失败时的兜底取向（"open" 默认 / "closed"）。
	// 自 env MCP_POLICY_FAIL_MODE 初始化，可经 SetMCPPolicyFailMode 覆盖。
	mcpPolicyFailMode string
	postureProvider   func(context.Context, semanticRuntimeConfig) *inspectionscope.GatewaySecurityPosture
	// blockNoticeCache holds the console's block-notice mode and template.
	blockNoticeCache blockNoticeSettingsCache
	// aiContentLabelCache 保存 AI 生成内容标识配置，与阻断提示同一次轮询刷新。
	aiContentLabelCache aiContentLabelSettingsCache
	// responseCacheCache 保存响应缓存配置，与阻断提示同一次轮询刷新。
	responseCacheCache responseCacheSettingsCache
	// modeLog 记录上次已报告的生效执行模式，用于只在变化时打日志（D4）。
	modeLog executionModeLogState
	// reportedToolResults 记录已上报过 result_observed 的 tool_call_id，避免客户端每轮
	// 重发的历史工具结果被重复上报（控制面本就按 tool_call_id 幂等合并，入库结果不变）。
	reportedToolResults *toolResultReportedSet
	// semanticRefreshLog 给语义运行时刷新失败日志限频（首条必打，之后每 10 条一条）。
	semanticRefreshLog *ratelog.Logger
	// namelessToolReported 保证同一请求 + choice + 工具位置的无名工具只上报一次（兜底，防止放大写入）。
	namelessToolReported *toolResultReportedSet
	// ignoredRuntimeOptions 记住签名配置里上次被忽略的取值，日志只在变化时打。
	ignoredRuntimeOptions runtimeoptions.IgnoredValues
}

// toolResultReportedSet 是有上限的「已上报 tool_call_id」集合；满了按插入顺序淘汰最早的。
// 淘汰只会导致某条历史结果再上报一次（控制面幂等），不会丢失审计。
type toolResultReportedSet struct {
	mu       sync.Mutex
	limit    int
	seen     map[string]struct{}
	order    []string
	failures map[string]int // 上报失败次数，用于给"下一轮重试"设上限（见 retryOrGiveUp）
}

func newToolResultReportedSet(limit int) *toolResultReportedSet {
	return &toolResultReportedSet{limit: limit, seen: make(map[string]struct{}, limit)}
}

// markIfNew 返回 true 表示第一次见到该租户的这个 tool_call_id，应当上报。
func (s *toolResultReportedSet) markIfNew(tenantID, toolCallID string) bool {
	if s == nil {
		return true
	}
	key := tenantID + "\x00" + toolCallID
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.seen[key]; ok {
		return false
	}
	for len(s.order) >= s.limit && len(s.order) > 0 {
		delete(s.seen, s.order[0])
		s.order = s.order[1:]
	}
	s.seen[key] = struct{}{}
	s.order = append(s.order, key)
	return true
}

// forget 在上报失败时撤销标记，下一轮请求会重试上报。
func (s *toolResultReportedSet) forget(tenantID, toolCallID string) {
	if s == nil {
		return
	}
	key := tenantID + "\x00" + toolCallID
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.seen, key)
}

// toolResultMaxReportAttempts 是同一租户同一 tool_call_id 允许"失败后下一轮重试"的次数上限（含首次）。
//
// 背景（客户现场）：客户端每轮重发整段历史里的工具结果，网关上报失败就 forget，下一轮整批再报；
// 控制面若对这条数据是确定性拒绝（约束违约，重试一万次结果不变），就会随会话轮次无限放大写入
// （PostgreSQL 日志里每分钟一批 200 条、峰值每小时 5897 次）。重试必须有上限。
// 取 5：足够扛一次控制面短暂抖动（连接池打满、重启），又不会把永久失败放大成持续写入。
const toolResultMaxReportAttempts = 5

// retryOrGiveUp 在上报失败后调用：返回 true 表示重试预算用尽，应放弃（保留已上报标记，之后不再重投）；
// 返回 false 表示撤销标记，下一轮请求会再试一次。
func (s *toolResultReportedSet) retryOrGiveUp(tenantID, toolCallID string, maxAttempts int) bool {
	if s == nil {
		return false
	}
	key := tenantID + "\x00" + toolCallID
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failures == nil {
		s.failures = make(map[string]int)
	}
	// 失败计数表同样有上限，防止异常流量撑爆内存；满了整体清空（最坏只是让个别条目多重试几次）。
	if len(s.failures) >= s.limit && s.limit > 0 {
		s.failures = make(map[string]int)
	}
	s.failures[key]++
	if s.failures[key] >= maxAttempts {
		delete(s.failures, key)
		return true
	}
	delete(s.seen, key)
	return false
}

func (s *toolResultReportedSet) size() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.seen)
}

// normalizeMCPPolicyFailMode 归一化 MCP 策略失败模式：closed/close -> "closed"，其余 -> "open"。
func normalizeMCPPolicyFailMode(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "closed", "close":
		return "closed"
	default:
		return "open"
	}
}

// SetMCPPolicyFailMode 显式设置失败模式（供装配期从 config 注入或测试覆盖）。
func (c *ToolRiskClient) SetMCPPolicyFailMode(mode string) {
	if c == nil {
		return
	}
	c.mcpPolicyFailMode = normalizeMCPPolicyFailMode(mode)
}

// SetMCPConfirmationScopeSecret separates exact-once invocation identity from
// the rotatable internal API authentication token.
func (c *ToolRiskClient) SetMCPConfirmationScopeSecret(secret string) {
	if c == nil {
		return
	}
	c.mcpConfirmationScopeSecret = secret
}

func (c *ToolRiskClient) mcpConfirmationSecret() string {
	if c == nil {
		return ""
	}
	return c.mcpConfirmationScopeSecret
}

// toolRiskCache provides simple in-memory caching with TTL
type toolRiskCache struct {
	mu      sync.RWMutex
	entries map[string]*cacheEntry
	ttl     time.Duration
}

type cacheEntry struct {
	config    *ToolRiskConfigResponse
	expiresAt time.Time
}

// unconfiguredToolCacheTTL 是「该工具没有专门配置」这一答复的缓存时长。比已配置的 5 分钟短，
// 管理员新加的工具配置能较快生效；但足以避免一个请求带几十个工具就向控制面发几十次查询
// （客户现场每小时约 2 万次，配合磁盘抖动打满数据库连接）。
const unconfiguredToolCacheTTL = time.Minute

type agentGuardPolicyCache struct {
	mu      sync.RWMutex
	entries map[string]*agentGuardPolicyCacheEntry
	ttl     time.Duration
}

type agentGuardPolicyCacheEntry struct {
	policy    *agentguard.EffectivePolicy
	expiresAt time.Time
}

// MCPEffectivePolicy 是 control-plane /admin/v1/internal/mcp/effective-policy 下发的
// 扁平化 MCP 权限策略（六元组解析结果）。mode 原样下发不做 audit_only 钳制——
// 钳制唯一发生在 gateway 决策器（CallerMode，见 mcp_proxy.go）。
type MCPEffectivePolicy struct {
	Matched               bool     `json:"matched"`
	PolicyID              string   `json:"policy_id"`
	ToolID                string   `json:"tool_id"`
	Mode                  string   `json:"mode"`
	Action                string   `json:"action"`
	ScopeType             string   `json:"scope_type"`
	Priority              int      `json:"priority"`
	SupplyChainStatus     string   `json:"supply_chain_status"`
	SupplyChainReasons    []string `json:"supply_chain_reasons"`
	SupplyChainRevision   string   `json:"supply_chain_revision"`
	StructuralBlock       bool     `json:"structural_block"`
	ServerAdmissionStatus string   `json:"server_admission_status"`
	ToolAdmissionStatus   string   `json:"tool_admission_status"`
	// ServerAdmissionSource/ToolAdmissionSource：隔离、撤销的来源（system/administrator），见 mcpadmission。
	// 旧控制面不下发时为空，按管理员处置（不比 2.9.21 宽）。
	ServerAdmissionSource string `json:"server_admission_source,omitempty"`
	ToolAdmissionSource   string `json:"tool_admission_source,omitempty"`
	RouteHash             string `json:"route_hash"`
	ApprovedRouteHash     string `json:"approved_route_hash"`
	ApprovedSchemaHash    string `json:"approved_schema_hash"`
	SchemaHash            string `json:"schema_hash"`
	policyUnavailable     bool
	policyFailClosed      bool
}

// mcpPolicyCache 与 agentGuardPolicyCache 同款：30s TTL、miss（matched=false）也缓存（负缓存）。
type mcpPolicyCache struct {
	mu      sync.RWMutex
	entries map[string]*mcpPolicyCacheEntry
	ttl     time.Duration
}

type mcpPolicyCacheEntry struct {
	policy    *MCPEffectivePolicy
	expiresAt time.Time
}

type runtimeSettingsCache struct {
	mu                   sync.RWMutex
	securityAuditOnly    *bool
	guardrailFailureMode *string
	semanticConfig       *semanticRuntimeConfig
	gfmExpiresAt         time.Time
	semanticExpiresAt    time.Time
	expiresAt            time.Time
	ttl                  time.Duration
}

// ToolRiskConfigResponse represents the response from control-plane API
type ToolRiskConfigResponse struct {
	ID          string `json:"id"`
	TenantID    string `json:"tenant_id"`
	ToolName    string `json:"tool_name"`
	ToolType    string `json:"tool_type"`
	RiskLevel   string `json:"risk_level"`
	Action      string `json:"action"`
	Description string `json:"description"`
}

type agentGuardPolicyAPIResponse struct {
	Data *agentGuardPolicyData `json:"data"`
}

type agentGuardPolicyData struct {
	ID                     string                     `json:"id"`
	Name                   string                     `json:"name"`
	PolicyVersion          string                     `json:"policy_version"`
	Mode                   string                     `json:"mode"`
	DefaultAction          string                     `json:"default_action"`
	FailPolicy             string                     `json:"fail_policy"`
	ConfirmChannelEnabled  bool                       `json:"confirm_channel_enabled"`
	Rules                  []agentguard.PolicyRule    `json:"rules"`
	Exceptions             []agentGuardExceptionData  `json:"exceptions"`
	Behavior               *agentGuardBehaviorData    `json:"behavior"`
	Destructive            *agentGuardDestructiveData `json:"destructive"`
	ConfigSource           string                     `json:"config_source"`
	Protocol               string                     `json:"protocol"`
	DiscardablePaths       []string                   `json:"discardable_paths"`
	NotifyChannelIDs       []string                   `json:"notify_channel_ids"`
	RestrictedFilePatterns []string                   `json:"restricted_file_patterns"`
	RestrictedFileAction   string                     `json:"restricted_file_action"`
	// RestrictedFileScopes 是受限文件生效的环节；没下发（旧控制面）时三个环节都生效。
	RestrictedFileScopes *[]string `json:"restricted_file_scopes"`
	// Protections 是租户保存的防护项配置，形如 {"agent.ssh_private_key":{"action":"block","params":{}}}；
	// 缺键或非法动作在网关按注册表默认值处理。
	Protections protection.Settings `json:"protections"`
}

type agentGuardDestructiveData struct {
	Mode      string `json:"mode"`
	Action    string `json:"action"`
	ScopeType string `json:"scope_type"`
	ScopeRef  string `json:"scope_ref"`
	Protocol  string `json:"protocol"`
}

const (
	maxAgentGuardDiscardablePaths = 32
	maxAgentGuardPathLength       = 256
	maxAgentGuardPathDepth        = 8
	maxAgentGuardNotifyChannelIDs = 16
	maxAgentGuardChannelIDLength  = 128
)

type agentGuardBehaviorData struct {
	FileReadBurst       int `json:"file_read_burst_10s"`
	NetworkEgressBurst  int `json:"network_egress_burst_10s"`
	CommandExecuteBurst int `json:"command_execute_burst_10s"`
	// W5 5.5: sensitive-read -> egress sequence window; 0/absent = off.
	SensitiveReadEgressWindowSeconds int `json:"sensitive_read_egress_window_seconds"`
	present                          map[string]bool
}

type agentGuardExceptionData struct {
	ID            string    `json:"id"`
	RuleID        string    `json:"rule_id"`
	TargetPattern string    `json:"target_pattern"`
	Decision      string    `json:"decision"`
	ExpiresAt     time.Time `json:"expires_at"`
}

// ToolCheckResult represents the result of a tool risk check
type ToolCheckResult struct {
	RiskLevel string
	Action    string
	Blocked   bool
	Message   string
	Config    *ToolRiskConfigResponse // nil if no config found
}

// ToolCallInfo represents information about a detected tool call
type ToolCallInfo struct {
	Name string
	Type string
}

// ToolAuditLogPayload 是 gateway-core 发往工具审计内部 API 的事实载荷。
// EventKind=definition_exposed 仅表示网关观察到客户端提交工具定义，不证明定义已送达模型。
type ToolAuditLogPayload struct {
	ToolName               string
	ToolType               string
	RiskLevel              string
	Parameters             map[string]interface{}
	Result                 string
	Status                 string
	MatchedPolicyID        string
	MatchedPolicyName      string
	MatchedAction          string
	MatchReason            string
	RawDecision            string
	EffectiveDecision      string
	Mode                   string
	OperationID            string
	EffectiveReason        string
	PolicyVersion          string
	TraceID                string
	EndpointID             string
	PromptID               string
	IntentTaskID           string
	MCPServer              string
	IntentTaskSources      []agentintent.IntentTaskSourceClaim
	Confidence             float64
	EvidenceJSON           interface{}
	NormalizedTarget       string
	Provenance             string
	TaintedArguments       []string
	EventKind              string
	ExecutionForwarded     bool
	ExecutionObserved      bool
	ResultObserved         bool
	ToolCallID             string
	AssetID                string
	SkillInvocationID      string
	MCPServerID            string
	MCPToolID              string
	DefinitionHash         string
	AttributionMode        string
	AttributionConfidence  float64
	EventType              string
	RiskCategory           string
	RiskSubcategory        string
	ReasonSummary          string
	TargetSummary          string
	ModeDefaultAction      string
	CustomAction           string
	FinalAction            string
	NotificationRequired   bool
	NotifyChannelIDs       []string
	NotificationStatus     string
	DiscardablePathMatched bool
	DiscardablePathReason  string
}

// NewToolRiskClient creates a new tool risk client
func NewToolRiskClient(controlPlaneURL string, internalAPISecret string, semanticAttestationKey ...string) *ToolRiskClient {
	log.Printf("tool risk client internal secret configured=%t length=%d", strings.TrimSpace(internalAPISecret) != "", len(internalAPISecret))
	attestationKey := strings.TrimSpace(os.Getenv("JJD_SEMANTIC_GATEWAY_ATTESTATION_KEY"))
	if len(semanticAttestationKey) > 0 {
		attestationKey = strings.TrimSpace(semanticAttestationKey[0])
	}
	return &ToolRiskClient{
		controlPlaneURL:              controlPlaneURL,
		internalAPISecret:            internalAPISecret,
		semanticConfigAttestationKey: attestationKey,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
		cache: &toolRiskCache{
			entries: make(map[string]*cacheEntry),
			ttl:     5 * time.Minute, // Cache TTL
		},
		agentGuardPolicyCache: &agentGuardPolicyCache{
			entries: make(map[string]*agentGuardPolicyCacheEntry),
			ttl:     30 * time.Second,
		},
		mcpPolicyCache: &mcpPolicyCache{
			entries: make(map[string]*mcpPolicyCacheEntry),
			ttl:     30 * time.Second,
		},
		skillAdmissionCache: newSkillAdmissionCache(),
		runtimeCache: &runtimeSettingsCache{
			ttl: 10 * time.Second,
		},
		// 从 env 自初始化，保证不改装配层也能生效；装配层可用 SetMCPPolicyFailMode 覆盖。
		mcpPolicyFailMode:   normalizeMCPPolicyFailMode(os.Getenv("MCP_POLICY_FAIL_MODE")),
		reportedToolResults: newToolResultReportedSet(50000),
		semanticRefreshLog:  ratelog.New(10),

		namelessToolReported: newToolResultReportedSet(20000),
	}
}

func (c *ToolRiskClient) SecurityAuditOnly(_ context.Context, _ bool) bool {
	auditOnly, _ := c.securityExecutionModeSnapshot()
	return auditOnly
}

func (c *ToolRiskClient) securityExecutionModeSnapshot() (bool, string) {
	if c == nil || c.runtimeCache == nil {
		if securityAuditOnlyForcedByEnvironment() {
			return true, "deployment"
		}
		return true, "startup"
	}
	cache := c.runtimeCache
	cache.mu.RLock()
	defer cache.mu.RUnlock()
	if cache.semanticConfig != nil && cache.semanticConfig.SecurityExecutionModeManaged {
		return cache.semanticConfig.SecurityAuditOnly, "signed"
	}
	// 部署变量 SECURITY_AUDIT_ONLY=true 只在控制台没有显式执行模式时作初值（2.9.22 D7）。
	if securityAuditOnlyForcedByEnvironment() {
		return true, "deployment"
	}
	if cache.securityAuditOnly != nil && !time.Now().After(cache.expiresAt) {
		source := "legacy"
		if cache.semanticConfig != nil && cache.securityAuditOnly == &cache.semanticConfig.SecurityAuditOnly {
			source = "signed"
		}
		return *cache.securityAuditOnly, source
	}
	if cache.semanticConfig != nil {
		return cache.semanticConfig.SecurityAuditOnly, "signed"
	}
	return true, "startup"
}

func securityAuditOnlyForcedByEnvironment() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("SECURITY_AUDIT_ONLY"))) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

func (c *ToolRiskClient) fetchSecurityAuditOnly(ctx context.Context) (bool, error) {
	endpoint := fmt.Sprintf("%s/admin/v1/internal/system/settings", strings.TrimRight(c.controlPlaneURL, "/"))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return false, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if c.internalAPISecret != "" {
		req.Header.Set(headeraudit.InternalTokenHeader, c.internalAPISecret)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return false, fmt.Errorf("failed to call control-plane: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return false, fmt.Errorf("control-plane returned status %d: %s", resp.StatusCode, string(body))
	}

	var settings map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&settings); err != nil {
		return false, fmt.Errorf("failed to decode runtime settings: %w", err)
	}

	raw, ok := settings["security_audit_only"]
	if !ok || raw == "" {
		return false, fmt.Errorf("security_audit_only not configured")
	}
	value, err := strconv.ParseBool(raw)
	if err != nil {
		return false, fmt.Errorf("invalid security_audit_only value: %w", err)
	}
	return value, nil
}

func (c *ToolRiskClient) GuardrailFailureMode(ctx context.Context, fallback string) string {
	if c == nil {
		return fallback
	}
	if value, ok := c.runtimeCache.getGuardrailFailureMode(); ok {
		return value
	}
	value, err := c.fetchGuardrailFailureMode(ctx)
	if err != nil {
		return fallback
	}
	c.runtimeCache.setGuardrailFailureMode(value)
	return value
}

func (c *ToolRiskClient) fetchGuardrailFailureMode(ctx context.Context) (string, error) {
	endpoint := fmt.Sprintf("%s/admin/v1/internal/system/settings", strings.TrimRight(c.controlPlaneURL, "/"))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if c.internalAPISecret != "" {
		req.Header.Set(headeraudit.InternalTokenHeader, c.internalAPISecret)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to call control-plane: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("control-plane returned status %d: %s", resp.StatusCode, string(body))
	}

	var settings map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&settings); err != nil {
		return "", fmt.Errorf("failed to decode runtime settings: %w", err)
	}

	raw, ok := settings["guardrail_failure_mode"]
	if !ok || raw == "" {
		return "", fmt.Errorf("guardrail_failure_mode not configured")
	}
	return normalizeGuardrailFailureMode(raw), nil
}

// CheckToolRisk checks if a tool call is allowed for a tenant
// Returns the risk level, action, and whether the tool should be blocked

func (c *ToolRiskClient) GetAgentGuardPolicy(ctx context.Context, envelope *modelrouter.RequestEnvelope) (*agentguard.EffectivePolicy, error) {
	if c == nil || envelope == nil || envelope.TenantID == "" {
		return nil, nil
	}
	cacheKey := agentGuardPolicyScopeCacheKey(envelope)
	if policy, ok := c.agentGuardPolicyCache.get(cacheKey); ok {
		return policy, nil
	}
	fallback := func(refreshErr error) (*agentguard.EffectivePolicy, error) {
		if freshPolicy, freshAvailable := c.agentGuardPolicyCache.get(cacheKey); freshAvailable {
			c.reportAgentGuardPolicyRefreshFailure(ctx, envelope, refreshErr, true)
			return freshPolicy, nil
		}
		stalePolicy, staleAvailable := c.agentGuardPolicyCache.getStale(cacheKey)
		c.reportAgentGuardPolicyRefreshFailure(ctx, envelope, refreshErr, staleAvailable)
		if staleAvailable {
			return stalePolicy, nil
		}
		return nil, refreshErr
	}
	endpoint := fmt.Sprintf("%s/admin/v1/internal/agentguard/effective-policy", strings.TrimRight(c.controlPlaneURL, "/"))
	params := url.Values{}
	params.Set("project_id", envelope.ProjectID)
	params.Set("user_id", envelope.UserID)
	params.Set("key_prefix", envelope.KeyPrefix)
	params.Set("agent_id", envelope.AgentType)
	params.Set("session_id", envelope.SessionID)
	params.Set("protocol", agentOperationProtocol(envelope.EndpointType))
	if encoded := params.Encode(); encoded != "" {
		endpoint += "?" + encoded
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return fallback(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Tenant-ID", envelope.TenantID)
	if c.internalAPISecret != "" {
		req.Header.Set(headeraudit.InternalTokenHeader, c.internalAPISecret)
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fallback(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		// 不再把响应正文拼进错误：它会流入日志/安全事件描述，而且可能含对端的内部细节。
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return fallback(&errclass.HTTPStatusError{Op: "agentguard policy", Status: resp.StatusCode})
	}
	var apiResp agentGuardPolicyAPIResponse
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return fallback(err)
	}
	if apiResp.Data == nil {
		c.agentGuardPolicyCache.set(cacheKey, nil)
		return nil, nil
	}
	policy := convertAgentGuardPolicy(apiResp.Data)
	c.agentGuardPolicyCache.set(cacheKey, policy)
	return policy, nil
}

func (c *ToolRiskClient) reportAgentGuardPolicyRefreshFailure(ctx context.Context, envelope *modelrouter.RequestEnvelope, refreshErr error, staleAvailable bool) {
	tenantID := ""
	if envelope != nil {
		tenantID = envelope.TenantID
	}
	// 每个请求在缓存过期后都会重试，故障期间会成千上万次；按「租户+类别+是否有旧策略」限频，累计次数在 total= 里。
	agentGuardRefreshFailureLog.Printf(
		tenantID+"|"+errclass.Classify(refreshErr)+"|"+strconv.FormatBool(staleAvailable),
		"AgentGuard policy refresh failed: tenant=%s stale_available=%t %s",
		tenantID, staleAvailable, errclass.Summary(refreshErr))
	if c != nil && c.agentGuardPolicyFailureHook != nil {
		c.agentGuardPolicyFailureHook(ctx, envelope, refreshErr, staleAvailable)
	}
}

func agentGuardPolicyScopeCacheKey(envelope *modelrouter.RequestEnvelope) string {
	return strings.Join([]string{
		envelope.TenantID,
		envelope.ProjectID,
		envelope.UserID,
		envelope.KeyPrefix,
		envelope.AgentType,
		envelope.SessionID,
		agentOperationProtocol(envelope.EndpointType),
	}, "\x1f")
}

func agentOperationProtocol(endpointType string) string {
	switch strings.ToLower(strings.TrimSpace(endpointType)) {
	case "mcp", "proxy":
		return "mcp"
	case "responses":
		return "responses"
	default:
		return "chat"
	}
}

// mcpDefaultEffectivePolicy 是控制面明确返回“策略未命中”时的普通审计默认值。
// 它不用于控制面故障；供应链状态不可证明时由 mcpSupplyChainUnavailablePolicy 强制阻断。
func mcpDefaultEffectivePolicy() *MCPEffectivePolicy {
	return &MCPEffectivePolicy{Matched: false, Mode: "audit", Action: "audit"}
}

// An unavailable lookup is a coverage gap, not a supply-chain verdict.
// markMCPPolicyUnavailable applies the configured failure mode separately.
func mcpSupplyChainUnavailablePolicy() *MCPEffectivePolicy {
	return &MCPEffectivePolicy{
		Matched: false, Mode: "audit", Action: "audit",
		SupplyChainStatus: "unavailable", SupplyChainReasons: []string{mcpPolicyUnavailableReason},
	}
}

// GetMCPEffectivePolicy 按「六元组主体 + server + tool」向 control-plane 拉取 MCP 生效策略。
// 永远返回非 nil。见 GetMCPTargetPolicy。
func (c *ToolRiskClient) GetMCPEffectivePolicy(ctx context.Context, envelope *modelrouter.RequestEnvelope, serverID, toolName string) *MCPEffectivePolicy {
	return c.GetMCPTargetPolicy(ctx, envelope, serverID, mcpTargetTool, toolName)
}

// GetMCPTargetPolicy 按目标类别（tool/resource/prompt/method）拉取生效策略。
// 只有结构阻断结果进短 TTL 缓存；approved/普通策略结果每次重拉，确保下一次调用立即看见
// quarantine/revoke/removed。每次成功拉取都记为该目标的 last-known-good。
// A failed lookup retains last-known-good evidence and is decided through
// MCP_POLICY_FAIL_MODE. Closed rejects stale approvals; open retains old blocks.
func (c *ToolRiskClient) GetMCPTargetPolicy(ctx context.Context, envelope *modelrouter.RequestEnvelope, serverID, kind, name string) *MCPEffectivePolicy {
	if c == nil || envelope == nil || envelope.TenantID == "" {
		return c.markMCPPolicyUnavailable(mcpSupplyChainUnavailablePolicy())
	}
	cacheKey := mcpTargetPolicyCacheKey(envelope, serverID, kind, name)
	if policy, ok := c.mcpPolicyCache.get(cacheKey); ok && policy != nil && policy.StructuralBlock {
		return policy
	}
	policy, err := c.fetchMCPTargetPolicy(ctx, envelope, serverID, kind, name)
	if err != nil {
		if lkg, ok := c.mcpPolicyCache.lastKnownGood(cacheKey); ok {
			log.Printf("MCP effective policy fetch failed; using last-known-good policy: tenant=%s server=%s kind=%s target=%s err=%v",
				envelope.TenantID, serverID, kind, name, err)
			return c.markMCPPolicyUnavailable(mcpMarkLastKnownGood(lkg))
		}
		log.Printf("MCP effective policy fetch failed and no policy was ever fetched; coverage gap %s (failure_mode=%s): tenant=%s server=%s kind=%s target=%s err=%v",
			mcpPolicyUnavailableReason, c.mcpPolicyFailMode, envelope.TenantID, serverID, kind, name, err)
		return c.markMCPPolicyUnavailable(mcpSupplyChainUnavailablePolicy())
	}
	c.mcpPolicyCache.rememberLastKnownGood(cacheKey, policy)
	if policy.StructuralBlock {
		c.mcpPolicyCache.set(cacheKey, policy)
	}
	return policy
}

func (c *ToolRiskClient) fetchMCPEffectivePolicy(ctx context.Context, envelope *modelrouter.RequestEnvelope, serverID, toolName string) (*MCPEffectivePolicy, error) {
	endpoint := fmt.Sprintf("%s/admin/v1/internal/mcp/effective-policy", strings.TrimRight(c.controlPlaneURL, "/"))
	params := url.Values{}
	params.Set("server_id", serverID)
	params.Set("tool_name", toolName)
	params.Set("project_id", envelope.ProjectID)
	params.Set("user_id", envelope.UserID)
	params.Set("key_prefix", envelope.KeyPrefix)
	// 与 AgentGuard 同款：AgentType（UA 指纹推断）即事实上的 agent 维度。
	params.Set("agent_id", envelope.AgentType)
	params.Set("session_id", envelope.SessionID)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint+"?"+params.Encode(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Tenant-ID", envelope.TenantID)
	if c.internalAPISecret != "" {
		req.Header.Set(headeraudit.InternalTokenHeader, c.internalAPISecret)
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("mcp effective policy status %d: %s", resp.StatusCode, string(body))
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	// 兼容裸对象与 {"data": {...}} 两种包裹（control-plane 内部端点两种风格并存）。
	raw := body
	var probe struct {
		Data json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(body, &probe); err == nil && len(probe.Data) > 0 && string(probe.Data) != "null" {
		raw = probe.Data
	}
	var payload MCPEffectivePolicy
	if err := json.Unmarshal(raw, &payload); err != nil {
		return nil, fmt.Errorf("decode mcp effective policy: %w", err)
	}
	if payload.Mode == "" {
		payload.Mode = "audit"
	}
	if payload.Action == "" {
		payload.Action = "audit"
	}
	return &payload, nil
}

// mcpPolicyScopeCacheKey 在 AgentGuard 六元组缓存键之上追加 server/tool 两段，
// 仍用 \x1f 拼接避免字段串位。
func mcpPolicyScopeCacheKey(envelope *modelrouter.RequestEnvelope, serverID, toolName string) string {
	return strings.Join([]string{
		envelope.TenantID,
		envelope.ProjectID,
		envelope.UserID,
		envelope.KeyPrefix,
		envelope.AgentType,
		envelope.SessionID,
		serverID,
		toolName,
	}, "\x1f")
}

// CreateAgentGuardConfirmation 经内部端点建一张确认单（复用 agentguard_confirmations 通道）。
// source 标记来源：MCP 网关侧传 "mcp"，AgentGuard 侧传 ""（内部 handler decode 结构体自动透传落库）。
func (c *ToolRiskClient) CreateAgentGuardConfirmation(ctx context.Context, envelope *modelrouter.RequestEnvelope, decision agentguard.Decision, toolName, toolCallID, toolCallArguments string, choiceIndex int, source string) error {
	if c == nil || envelope == nil || envelope.TenantID == "" {
		return nil
	}
	payload := map[string]any{
		"tool_call_id":        toolCallID,
		"tool_call_arguments": toolCallArguments,
		"choice_index":        choiceIndex,
		"request_id":          envelope.RequestID,
		"trace_id":            decision.TraceID,
		"tool_name":           toolName,
		"raw_decision":        decision.RawDecision,
		"effective_decision":  decision.EffectiveDecision,
		"timeout_action":      "block",
		"reason":              decision.Reason,
		"evidence_json":       map[string]any{"evidence": decision.Evidence},
		"expires_at":          time.Now().Add(10 * time.Minute),
		"source":              source,
		// W5 5.2/5.3: bind the confirmation to its requester.
		"requester_user_id":   envelope.UserID,
		"requester_client_id": envelope.ClientID,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	endpoint := fmt.Sprintf("%s/admin/v1/internal/agentguard/confirmations", strings.TrimRight(c.controlPlaneURL, "/"))
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Tenant-ID", envelope.TenantID)
	if c.internalAPISecret != "" {
		req.Header.Set(headeraudit.InternalTokenHeader, c.internalAPISecret)
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("agentguard confirmation status %d", resp.StatusCode)
	}
	return nil
}

func convertValidatedDestructivePolicy(data *agentGuardPolicyData) (*agentguard.DestructivePolicy, agentguard.ConfigSource, bool) {
	if data == nil || data.Destructive == nil {
		return nil, "", false
	}
	mode, modeOK := normalizeAgentGuardDestructiveMode(data.Mode)
	destructiveMode, destructiveModeOK := normalizeAgentGuardDestructiveMode(data.Destructive.Mode)
	action := agentguard.DestructiveAction(strings.TrimSpace(data.Destructive.Action))
	if !validAgentGuardDestructiveAction(action) {
		return nil, "", false
	}
	source := agentguard.ConfigSource(strings.TrimSpace(data.ConfigSource))
	scopeType := strings.TrimSpace(data.Destructive.ScopeType)
	scopeRef := strings.TrimSpace(data.Destructive.ScopeRef)
	unscoped := scopeType == "" && scopeRef == ""

	valid := false
	switch source {
	case agentguard.ConfigSourceApplicationPolicy:
		valid = modeOK && destructiveModeOK && mode == destructiveMode && scopeType == "application" && scopeRef != ""
	case agentguard.ConfigSourceAgentPolicy:
		valid = modeOK && destructiveModeOK && mode == destructiveMode && scopeType == "agent" && scopeRef != ""
	case agentguard.ConfigSourceTenantPolicy:
		valid = modeOK && destructiveModeOK && mode == destructiveMode && scopeType == "tenant" && scopeRef == ""
	case agentguard.ConfigSourceModePreset:
		preset, ok := agentGuardDestructiveModePreset(mode)
		valid = modeOK && destructiveModeOK && mode == destructiveMode && unscoped && ok && action == preset
	case agentguard.ConfigSourceSystemDefault:
		valid = destructiveModeOK && destructiveMode == agentguard.ModeAudit &&
			action == agentguard.DestructiveActionRecord && unscoped && (!modeOK || mode == agentguard.ModeAudit)
	case agentguard.ConfigSourceLegacyEnvFallback:
		valid = modeOK && destructiveModeOK && mode == agentguard.ModeAudit && destructiveMode == agentguard.ModeAudit &&
			action == agentguard.DestructiveActionRecord && unscoped
	}
	if !valid {
		return nil, "", false
	}
	protocol := strings.ToLower(strings.TrimSpace(data.Protocol))
	if nestedProtocol := strings.ToLower(strings.TrimSpace(data.Destructive.Protocol)); nestedProtocol != protocol {
		return nil, "", false
	}
	// protocol 为空表示所有协议，mcp 只对“确认”行有区别：控制面解析有效策略时只对确认行按协议过滤
	// （确认行 protocol=mcp 只管 MCP 请求），其余动作的行对所有协议生效。2.9.22 起“确认”不再限定 MCP：
	// 非 MCP 协议在策略开了确认通道时走普通确认票据，没有时按 agent.confirm_without_channel（见结构化工具门）。
	if protocol != "" && protocol != "mcp" {
		return nil, "", false
	}
	discardablePaths, ok := validateAgentGuardDiscardablePaths(data.DiscardablePaths)
	if !ok {
		return nil, "", false
	}
	notifyChannelIDs, ok := validateAgentGuardNotifyChannelIDs(data.NotifyChannelIDs)
	if !ok {
		return nil, "", false
	}
	return &agentguard.DestructivePolicy{
		Mode:             destructiveMode,
		Action:           action,
		ScopeType:        scopeType,
		ScopeRef:         scopeRef,
		Protocol:         protocol,
		DiscardablePaths: discardablePaths,
		NotifyChannelIDs: notifyChannelIDs,
	}, source, true
}

func validateAgentGuardDiscardablePaths(paths []string) ([]string, bool) {
	if len(paths) > maxAgentGuardDiscardablePaths {
		return nil, false
	}
	validated := make([]string, 0, len(paths))
	seen := make(map[string]struct{}, len(paths))
	for _, candidate := range paths {
		candidate = strings.TrimSpace(candidate)
		if candidate == "" || len(candidate) > maxAgentGuardPathLength ||
			strings.ContainsRune(candidate, '\x00') || strings.Contains(candidate, "\\") ||
			strings.HasPrefix(candidate, "/") || strings.HasPrefix(candidate, "~") {
			return nil, false
		}
		segments := strings.Split(candidate, "/")
		if len(segments) > maxAgentGuardPathDepth {
			return nil, false
		}
		for _, segment := range segments {
			if !validAgentGuardPathSegment(segment) {
				return nil, false
			}
			switch strings.ToLower(segment) {
			case ".git", ".ssh", "home", "repo":
				return nil, false
			}
		}
		if _, duplicate := seen[candidate]; duplicate {
			return nil, false
		}
		seen[candidate] = struct{}{}
		validated = append(validated, candidate)
	}
	return validated, true
}

func validAgentGuardPathSegment(segment string) bool {
	if segment == "" || segment == "." || segment == ".." {
		return false
	}
	for _, r := range segment {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') || r == '-' || r == '_' || r == '.' {
			continue
		}
		return false
	}
	return true
}

func validateAgentGuardNotifyChannelIDs(ids []string) ([]string, bool) {
	if len(ids) > maxAgentGuardNotifyChannelIDs {
		return nil, false
	}
	validated := make([]string, 0, len(ids))
	seen := make(map[string]struct{}, len(ids))
	for _, id := range ids {
		id = strings.TrimSpace(id)
		if id == "" || len(id) > maxAgentGuardChannelIDLength || strings.ContainsRune(id, '\x00') {
			return nil, false
		}
		if _, duplicate := seen[id]; duplicate {
			return nil, false
		}
		seen[id] = struct{}{}
		validated = append(validated, id)
	}
	return validated, true
}

func normalizeAgentGuardDestructiveMode(raw string) (agentguard.Mode, bool) {
	switch agentguard.Mode(strings.TrimSpace(raw)) {
	case agentguard.ModeObserve, agentguard.ModeAudit:
		return agentguard.ModeAudit, true
	case agentguard.ModeLight:
		return agentguard.ModeLight, true
	case agentguard.ModeStrict:
		return agentguard.ModeStrict, true
	default:
		return agentguard.ModeAudit, false
	}
}

func validAgentGuardDestructiveAction(action agentguard.DestructiveAction) bool {
	switch action {
	case agentguard.DestructiveActionRecord, agentguard.DestructiveActionAlertAllow,
		agentguard.DestructiveActionConfirm, agentguard.DestructiveActionBlock:
		return true
	default:
		return false
	}
}

func agentGuardDestructiveModePreset(mode agentguard.Mode) (agentguard.DestructiveAction, bool) {
	switch mode {
	case agentguard.ModeAudit:
		return agentguard.DestructiveActionRecord, true
	case agentguard.ModeLight:
		return agentguard.DestructiveActionAlertAllow, true
	case agentguard.ModeStrict:
		return agentguard.DestructiveActionBlock, true
	default:
		return "", false
	}
}

// convertValidatedRestrictedFilePolicy 校验受限文件模式。任一条非法则整体丢弃该列表
// 并记一条 agentguard_policy_invalid_field 日志——不让一条坏模式拖垮整条策略。
func convertValidatedRestrictedFilePolicy(data *agentGuardPolicyData) (*agentguard.RestrictedFilePolicy, bool) {
	patterns := data.RestrictedFilePatterns
	if patterns == nil {
		patterns = []string{}
	}
	if err := filerestrict.Validate(patterns); err != nil {
		log.Printf("agentguard_policy_invalid_field field=restricted_file_patterns tenant_policy=%s error=%v", data.ID, err)
		return nil, false
	}
	action := strings.TrimSpace(data.RestrictedFileAction)
	if action == "" {
		action = string(filerestrict.ActionBlock)
	}
	validated, err := filerestrict.ValidateAction(action)
	if err != nil {
		log.Printf("agentguard_policy_invalid_field field=restricted_file_action tenant_policy=%s error=%v", data.ID, err)
		return nil, false
	}
	restricted := &agentguard.RestrictedFilePolicy{Patterns: patterns, Action: string(validated)}
	if data.RestrictedFileScopes != nil {
		restricted.ScopesConfigured = true
		restricted.Scopes = []string{}
		for _, scope := range *data.RestrictedFileScopes {
			switch scope {
			case agentguard.RestrictedFileScopeToolCall, agentguard.RestrictedFileScopeUserMention, agentguard.RestrictedFileScopeProxyOutput:
				restricted.Scopes = append(restricted.Scopes, scope)
			}
		}
	}
	return restricted, true
}

func convertAgentGuardPolicy(data *agentGuardPolicyData) *agentguard.EffectivePolicy {
	mode, modeOK := normalizeAgentGuardDestructiveMode(data.Mode)
	if !modeOK {
		mode = ""
	}
	policy := &agentguard.EffectivePolicy{
		ID:            data.ID,
		Name:          data.Name,
		PolicyVersion: data.PolicyVersion,
		Mode:          mode,
		// The mode delivered here is the destructive policy's; AgentGuard rules
		// are enforced by their own action under the global posture.
		RuleMode:              agentguard.ModeStrict,
		DefaultAction:         agentguard.DecisionAction(data.DefaultAction),
		FailPolicy:            data.FailPolicy,
		ConfirmChannelEnabled: data.ConfirmChannelEnabled,
		Protections:           data.Protections,
	}
	for _, rule := range data.Rules {
		policy.Rules = append(policy.Rules, rule)
	}
	for _, exception := range data.Exceptions {
		policy.Exceptions = append(policy.Exceptions, agentguard.PolicyException{ID: exception.ID, RuleID: exception.RuleID, TargetPattern: exception.TargetPattern, Decision: agentguard.DecisionAction(exception.Decision), ExpiresAt: exception.ExpiresAt})
	}
	if data.Behavior != nil {
		policy.Behavior = &agentguard.BehaviorThresholds{FileReadBurst: data.Behavior.FileReadBurst, NetworkEgressBurst: data.Behavior.NetworkEgressBurst, CommandExecuteBurst: data.Behavior.CommandExecuteBurst}
		applyAgentGuardSequenceBehavior(policy.Behavior, data.Behavior) // W5 5.5
	}
	if data.RestrictedFilePatterns != nil || data.RestrictedFileAction != "" {
		if restricted, ok := convertValidatedRestrictedFilePolicy(data); ok {
			policy.RestrictedFiles = restricted
		}
	}
	if destructive, source, ok := convertValidatedDestructivePolicy(data); ok {
		policy.Destructive = destructive
		policy.ConfigSource = source
	}
	return policy
}

func (c *ToolRiskClient) CheckToolRisk(ctx context.Context, tenantID, toolName string) (*ToolCheckResult, error) {
	// Check cache first
	cacheKey := fmt.Sprintf("%s:%s", tenantID, toolName)
	if cached, hit := c.cache.lookup(cacheKey); hit {
		return c.buildResultFromConfig(cached), nil
	}

	// Call control-plane API to get tool config
	config, err := c.fetchToolConfig(ctx, tenantID, toolName)
	if err != nil {
		// On error, return default (audit) - fail-open for availability
		return &ToolCheckResult{
			RiskLevel: "medium",
			Action:    "audit",
			Blocked:   false,
			Message:   "",
		}, nil
	}

	// Cache the result; 「未配置」也缓存（时间更短），控制面出错的情况在上面已返回、不缓存。
	if config != nil {
		c.cache.set(cacheKey, config)
	} else {
		c.cache.setUnconfigured(cacheKey)
	}

	return c.buildResultFromConfig(config), nil
}

// fetchToolConfig calls control-plane API to get tool risk configuration
func (c *ToolRiskClient) fetchToolConfig(ctx context.Context, tenantID, toolName string) (*ToolRiskConfigResponse, error) {
	// control-plane API endpoint for tool config lookup
	// Note: The API supports query parameter for tool_name lookup
	endpoint := fmt.Sprintf("%s/admin/v1/internal/tools/config?tool_name=%s", c.controlPlaneURL, url.QueryEscape(toolName))

	req, err := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Set tenant context header for auth (control-plane expects tenant context)
	req.Header.Set("X-Tenant-ID", tenantID)
	req.Header.Set("Content-Type", "application/json")
	if c.internalAPISecret != "" {
		req.Header.Set(headeraudit.InternalTokenHeader, c.internalAPISecret)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to call control-plane: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		// No config found for this tool - return nil (will use default)
		return nil, nil
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("control-plane returned status %d: %s", resp.StatusCode, string(body))
	}

	// Parse response - control-plane returns a list format
	var apiResp struct {
		Data []ToolRiskConfigResponse `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	// Find matching config for the tenant
	for _, cfg := range apiResp.Data {
		if cfg.TenantID == tenantID && cfg.ToolName == toolName {
			return &cfg, nil
		}
	}

	// No matching config found
	return nil, nil
}

// buildResultFromConfig builds a ToolCheckResult from the config
func (c *ToolRiskClient) buildResultFromConfig(config *ToolRiskConfigResponse) *ToolCheckResult {
	if config == nil {
		// Default policy: audit (log but allow)
		return &ToolCheckResult{
			RiskLevel: "medium",
			Action:    "audit",
			Blocked:   false,
			Message:   "",
			Config:    nil,
		}
	}

	result := &ToolCheckResult{
		RiskLevel: config.RiskLevel,
		Action:    config.Action,
		Config:    config,
	}

	// Determine if blocked
	if config.Action == "block" {
		result.Blocked = true
		result.Message = fmt.Sprintf("tool '%s' (risk: %s) is blocked by policy", config.ToolName, config.RiskLevel)
	}

	return result
}

// DetectToolCalls analyzes request body to detect tool calls
// This is used to identify tools before execution
func DetectToolCalls(reqBody []byte) []ToolCallInfo {
	var req map[string]interface{}
	if err := json.Unmarshal(reqBody, &req); err != nil {
		return nil
	}

	// Check for tools definition (OpenAI-style)
	tools, ok := req["tools"].([]interface{})
	if !ok {
		return nil
	}

	calls := []ToolCallInfo{}
	for _, t := range tools {
		tool, ok := t.(map[string]interface{})
		if !ok {
			continue
		}

		// Extract tool name from function definition
		if fn, ok := tool["function"].(map[string]interface{}); ok {
			name, _ := fn["name"].(string)
			if name != "" {
				calls = append(calls, ToolCallInfo{
					Name: name,
					Type: inferToolType(name),
				})
			}
		}
	}

	return calls
}

// inferToolType uses the same classifier for exposed definitions and proposed calls.
func inferToolType(name string) string {
	return agentguard.ClassifyToolType(name)
}

// CheckToolCallsForRequest checks all tool calls in a request and returns blocked status
// This is a convenience method that iterates through all detected tools
func (c *ToolRiskClient) CheckToolCallsForRequest(ctx context.Context, envelope *modelrouter.RequestEnvelope, reqBody []byte) ([]ToolCheckResult, error) {
	toolCalls := DetectToolCalls(reqBody)
	if len(toolCalls) == 0 {
		return nil, nil
	}

	results := []ToolCheckResult{}
	for _, tc := range toolCalls {
		result, err := c.CheckToolRisk(ctx, envelope.TenantID, tc.Name)
		if err != nil {
			// Log error but continue checking other tools
			result = &ToolCheckResult{
				RiskLevel: "medium",
				Action:    "audit",
				Blocked:   false,
				Message:   fmt.Sprintf("error checking tool '%s': %v", tc.Name, err),
			}
		}
		results = append(results, *result)

		// If any tool is blocked, we can return early
		if result.Blocked {
			return results, fmt.Errorf("%s", result.Message)
		}
	}

	return results, nil
}

var errToolLogIDUnavailable = errors.New("tool log id unavailable")

// errToolLogRejected 表示控制面对这条审计做了确定性拒绝（HTTP 422 tool_log_rejected：
// 生命周期事实违反库表约束，SQLSTATE 23514）。同样的输入重试结果不变，调用方应丢弃并限频记日志，不得重投。
var errToolLogRejected = errors.New("tool log rejected by control-plane (not retryable)")

// toolLogStatusError 保留控制面返回的 HTTP 状态码，文案与改造前一致（"control-plane logging returned status %d"）。
type toolLogStatusError struct{ status int }

func (e *toolLogStatusError) Error() string {
	return fmt.Sprintf("control-plane logging returned status %d", e.status)
}

func (e *toolLogStatusError) Is(target error) bool {
	return target == errToolLogRejected && e.status == http.StatusUnprocessableEntity
}

func toolAuditProtocol(envelope *modelrouter.RequestEnvelope, payload ToolAuditLogPayload) string {
	if payload.Provenance == "mcp_gateway" || payload.ToolType == "mcp" {
		return "mcp"
	}
	if envelope == nil {
		return ""
	}
	return envelope.EndpointType
}

// LogToolCall writes a lifecycle event. Callers must explicitly state whether
// execution or a result was actually observed; status alone is never proof.
func (c *ToolRiskClient) LogToolCall(ctx context.Context, envelope *modelrouter.RequestEnvelope, payload ToolAuditLogPayload) error {
	_, err := c.LogToolCallWithID(ctx, envelope, payload)
	if errors.Is(err, errToolLogIDUnavailable) {
		return nil
	}
	return err
}

// 失败日志限频：首条必打，之后每 20 条一条。
var agentGuardRefreshFailureLog = ratelog.New(20)

// toolAuditNotesKey 是写入 parameters 的审计标记键：网关为保证记录能入库而补过默认值时，在这里留痕，
// 审计方据此知道 tool_name / tool_type 不是上游原值。以下划线开头，避免与真实工具参数重名。
const toolAuditNotesKey = "_audit_notes"

// toolAuditNamelessUnknownEnv 控制无名工具的处置：默认（开）补 "unknown" 入库并留 _audit_notes 标记；
// 设为 off/false/0 恢复旧行为：不上报（旧行为是上报后被控制面 400 拒收，同样不入库，但会白白打一次请求）。
const toolAuditNamelessUnknownEnv = "UAG_TOOL_AUDIT_NAMELESS_UNKNOWN"

func toolAuditNamelessUnknownEnabled() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(toolAuditNamelessUnknownEnv))) {
	case "off", "false", "0", "no", "disabled":
		return false
	}
	return true
}

// shouldReportNamelessTool 决定一个无名工具是否应上报：开关关闭则不报；同一 请求+choice+工具位置 只报一次。
// scope 是调用方给出的位置标识（OutputItemID / tool id）。有名工具不经过这里。
func (c *ToolRiskClient) shouldReportNamelessTool(envelope *modelrouter.RequestEnvelope, choiceIndex int, scope string) bool {
	if !toolAuditNamelessUnknownEnabled() {
		return false
	}
	if c == nil || envelope == nil || c.namelessToolReported == nil {
		return true
	}
	return c.namelessToolReported.markIfNew(envelope.TenantID, fmt.Sprintf("%s|%d|%s", envelope.RequestID, choiceIndex, scope))
}

const (
	toolAuditUnknownName = "unknown"
	toolAuditNoteName    = "tool_name_missing"
	toolAuditNoteType    = "tool_type_missing"
)

// normalizeToolAuditPayload 保证上报载荷满足控制面的必填校验（tool_name、tool_type 非空），
// 同时不丢审计：补默认值的同时在 parameters 里留标记，原始参数原样保留。
//
// 背景（客户现场）：空名工具来自上游（流式只发参数增量而没有带名字的 start、
// 原生 Messages 的 tool_use 块缺 name 等），旧实现原样上报，控制面返回 400，整条审计丢失（24 小时 13374 条）。
// 不丢弃这类调用：它恰恰是需要被看见的异常行为，补 "unknown" 入库比 400 丢弃更符合审计完整性。
func normalizeToolAuditPayload(payload ToolAuditLogPayload) ToolAuditLogPayload {
	var notes []string
	if strings.TrimSpace(payload.ToolName) == "" {
		payload.ToolName = toolAuditUnknownName
		notes = append(notes, toolAuditNoteName)
	}
	if strings.TrimSpace(payload.ToolType) == "" {
		payload.ToolType = inferToolType(payload.ToolName)
		if payload.ToolType == "" {
			payload.ToolType = toolAuditUnknownName
		}
		notes = append(notes, toolAuditNoteType)
	}
	if len(notes) == 0 {
		return payload
	}
	// 复制一份再写标记：调用方的 map 可能被复用或并发读取。
	params := make(map[string]interface{}, len(payload.Parameters)+1)
	for k, v := range payload.Parameters {
		params[k] = v
	}
	params[toolAuditNotesKey] = notes
	payload.Parameters = params
	return payload
}

func (c *ToolRiskClient) LogToolCallWithID(ctx context.Context, envelope *modelrouter.RequestEnvelope, payload ToolAuditLogPayload) (string, error) {
	if strings.TrimSpace(payload.ToolName) == "" && !toolAuditNamelessUnknownEnabled() {
		return "", errToolLogIDUnavailable // 开关关闭：恢复旧行为，不上报无名工具
	}
	// 输出阶段的工具审计可能发生在客户端断开之后，不能因此丢失。
	ctx, cancel := detachAuditContext(ctx)
	defer cancel()
	payload = normalizeToolAuditPayload(payload)
	// Call control-plane to log the tool call
	requestBody := map[string]interface{}{
		"request_id":               envelope.RequestID,
		"tenant_id":                envelope.TenantID,
		"user_id":                  envelope.UserID,
		"session_id":               envelope.SessionID,
		"endpoint_id":              payload.EndpointID,
		"intent_task_id":           payload.IntentTaskID,
		"mcp_server":               payload.MCPServer,
		"intent_task_sources":      payload.IntentTaskSources,
		"application_id":           envelope.ProjectID, // ProjectID is the current customer application/project scope identity.
		"agent_type":               envelope.AgentType,
		"model":                    envelope.Model,
		"protocol":                 toolAuditProtocol(envelope, payload),
		"tool_name":                payload.ToolName,
		"tool_type":                payload.ToolType,
		"risk_level":               payload.RiskLevel,
		"parameters":               payload.Parameters,
		"result":                   payload.Result,
		"status":                   payload.Status,
		"matched_policy_id":        payload.MatchedPolicyID,
		"matched_policy_name":      payload.MatchedPolicyName,
		"matched_action":           payload.MatchedAction,
		"match_reason":             payload.MatchReason,
		"raw_decision":             payload.RawDecision,
		"effective_decision":       payload.EffectiveDecision,
		"mode":                     payload.Mode,
		"effective_reason":         payload.EffectiveReason,
		"operation_id":             payload.OperationID,
		"policy_version":           payload.PolicyVersion,
		"trace_id":                 payload.TraceID,
		"confidence":               payload.Confidence,
		"evidence_json":            payload.EvidenceJSON,
		"normalized_target":        payload.NormalizedTarget,
		"provenance":               payload.Provenance,
		"tainted_arguments":        payload.TaintedArguments,
		"event_kind":               payload.EventKind,
		"execution_forwarded":      payload.ExecutionForwarded,
		"execution_observed":       payload.ExecutionObserved,
		"result_observed":          payload.ResultObserved,
		"tool_call_id":             payload.ToolCallID,
		"asset_id":                 payload.AssetID,
		"skill_invocation_id":      payload.SkillInvocationID,
		"mcp_server_id":            payload.MCPServerID,
		"mcp_tool_id":              payload.MCPToolID,
		"definition_hash":          payload.DefinitionHash,
		"attribution_mode":         payload.AttributionMode,
		"attribution_confidence":   payload.AttributionConfidence,
		"event_type":               payload.EventType,
		"risk_category":            payload.RiskCategory,
		"risk_subcategory":         payload.RiskSubcategory,
		"reason_summary":           payload.ReasonSummary,
		"target_summary":           payload.TargetSummary,
		"mode_default_action":      payload.ModeDefaultAction,
		"custom_action":            payload.CustomAction,
		"final_action":             payload.FinalAction,
		"notify_channel_ids":       payload.NotifyChannelIDs,
		"notification_required":    payload.NotificationRequired,
		"notification_status":      payload.NotificationStatus,
		"discardable_path_matched": payload.DiscardablePathMatched,
		"discardable_path_reason":  payload.DiscardablePathReason,
	}
	if payload.PromptID != "" {
		requestBody["prompt_id"] = payload.PromptID
	}

	body, err := json.Marshal(requestBody)
	if err != nil {
		return "", fmt.Errorf("failed to marshal log payload: %w", err)
	}

	endpoint := fmt.Sprintf("%s/admin/v1/internal/tools/logs", c.controlPlaneURL)
	req, err := http.NewRequestWithContext(ctx, "POST", endpoint, bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("failed to create log request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Tenant-ID", envelope.TenantID)
	if c.internalAPISecret != "" {
		req.Header.Set(headeraudit.InternalTokenHeader, c.internalAPISecret)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to log tool call: %w", err)
	}
	defer resp.Body.Close()

	// Logging is non-critical, so we don't fail on errors
	if resp.StatusCode >= 400 {
		return "", &toolLogStatusError{status: resp.StatusCode}
	}

	var stored struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&stored); err != nil {
		return "", fmt.Errorf("%w: decode response: %v", errToolLogIDUnavailable, err)
	}
	if stored.ID == "" {
		return "", errToolLogIDUnavailable
	}
	return stored.ID, nil
}

// === Cache methods ===

func (c *toolRiskCache) get(key string) *ToolRiskConfigResponse {
	config, _ := c.lookup(key)
	return config
}

// lookup 返回缓存的配置；hit=true 且 config=nil 表示缓存的是「该工具未配置」。
func (c *toolRiskCache) lookup(key string) (*ToolRiskConfigResponse, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	entry, ok := c.entries[key]
	if !ok || time.Now().After(entry.expiresAt) {
		return nil, false
	}

	return entry.config, true
}

// setUnconfigured 缓存「该工具没有专门配置」，时长较短。
func (c *toolRiskCache) setUnconfigured(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.entries[key] = &cacheEntry{expiresAt: time.Now().Add(unconfiguredToolCacheTTL)}
}

func (c *toolRiskCache) set(key string, config *ToolRiskConfigResponse) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.entries[key] = &cacheEntry{
		config:    config,
		expiresAt: time.Now().Add(c.ttl),
	}
}

func cloneAgentGuardEffectivePolicy(policy *agentguard.EffectivePolicy) *agentguard.EffectivePolicy {
	if policy == nil {
		return nil
	}
	cloned := *policy
	if policy.Destructive != nil {
		destructive := *policy.Destructive
		cloned.Destructive = &destructive
	}
	if policy.Behavior != nil {
		behavior := *policy.Behavior
		cloned.Behavior = &behavior
	}
	if policy.RestrictedFiles != nil {
		restricted := *policy.RestrictedFiles
		restricted.Patterns = append([]string(nil), policy.RestrictedFiles.Patterns...)
		restricted.Scopes = append([]string(nil), policy.RestrictedFiles.Scopes...)
		cloned.RestrictedFiles = &restricted
	}
	if policy.Protections != nil {
		cloned.Protections = make(protection.Settings, len(policy.Protections))
		for key, setting := range policy.Protections {
			cloned.Protections[key] = setting
		}
	}
	cloned.Rules = append([]agentguard.PolicyRule(nil), policy.Rules...)
	cloned.Exceptions = append([]agentguard.PolicyException(nil), policy.Exceptions...)
	return &cloned
}

func (c *agentGuardPolicyCache) get(key string) (*agentguard.EffectivePolicy, bool) {
	if c == nil {
		return nil, false
	}
	c.mu.RLock()
	defer c.mu.RUnlock()

	entry, ok := c.entries[key]
	if !ok || time.Now().After(entry.expiresAt) {
		return nil, false
	}
	return cloneAgentGuardEffectivePolicy(entry.policy), true
}

func (c *agentGuardPolicyCache) getStale(key string) (*agentguard.EffectivePolicy, bool) {
	if c == nil {
		return nil, false
	}
	c.mu.RLock()
	defer c.mu.RUnlock()

	entry, ok := c.entries[key]
	if !ok {
		return nil, false
	}
	return cloneAgentGuardEffectivePolicy(entry.policy), true
}

func (c *agentGuardPolicyCache) set(key string, policy *agentguard.EffectivePolicy) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	c.entries[key] = &agentGuardPolicyCacheEntry{
		policy:    cloneAgentGuardEffectivePolicy(policy),
		expiresAt: time.Now().Add(c.ttl),
	}
}

func (c *agentGuardPolicyCache) invalidate() {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries = make(map[string]*agentGuardPolicyCacheEntry)
}

func (c *mcpPolicyCache) get(key string) (*MCPEffectivePolicy, bool) {
	if c == nil {
		return nil, false
	}
	c.mu.RLock()
	defer c.mu.RUnlock()

	entry, ok := c.entries[key]
	if !ok || time.Now().After(entry.expiresAt) {
		return nil, false
	}
	return entry.policy, true
}

func (c *mcpPolicyCache) set(key string, policy *MCPEffectivePolicy) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	c.entries[key] = &mcpPolicyCacheEntry{
		policy:    policy,
		expiresAt: time.Now().Add(c.ttl),
	}
}

func (c *mcpPolicyCache) invalidate() {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries = make(map[string]*mcpPolicyCacheEntry)
}

func (c *runtimeSettingsCache) getSecurityAuditOnly() (bool, bool) {
	if c == nil {
		return false, false
	}
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.securityAuditOnly == nil || time.Now().After(c.expiresAt) {
		if c.semanticConfig != nil {
			return c.semanticConfig.SecurityAuditOnly, true
		}
		return false, false
	}
	return *c.securityAuditOnly, true
}

func (c *runtimeSettingsCache) setSecurityAuditOnly(value bool) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	c.securityAuditOnly = &value
	c.expiresAt = time.Now().Add(c.ttl)
}

func (c *runtimeSettingsCache) getSemanticConfig() (semanticRuntimeConfig, bool) {
	if c == nil {
		return semanticRuntimeConfig{}, false
	}
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.semanticConfig == nil {
		return semanticRuntimeConfig{}, false
	}
	return *c.semanticConfig, true
}

func (c *runtimeSettingsCache) setSemanticConfig(value semanticRuntimeConfig) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	copied := value
	c.semanticConfig = &copied
	c.securityAuditOnly = &copied.SecurityAuditOnly
	c.semanticExpiresAt = time.Time{}
}

// setSemanticAgentEnabled 保留给旧调用方/测试；显式预置时总开关视为开启。
func (c *runtimeSettingsCache) setSemanticAgentEnabled(value bool) {
	auditOnly, _ := c.getSecurityAuditOnly()
	c.setSemanticConfig(semanticRuntimeConfig{
		Revision:          "00000000000000000000000000000000",
		Enabled:           true,
		InputEnabled:      true,
		AgentEnabled:      value,
		SecurityAuditOnly: auditOnly,
	})
}

func (c *runtimeSettingsCache) getGuardrailFailureMode() (string, bool) {
	if c == nil {
		return "", false
	}
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.guardrailFailureMode == nil || time.Now().After(c.gfmExpiresAt) {
		return "", false
	}
	return *c.guardrailFailureMode, true
}

func (c *runtimeSettingsCache) setGuardrailFailureMode(value string) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	c.guardrailFailureMode = &value
	c.gfmExpiresAt = time.Now().Add(c.ttl)
}

// InvalidateCache clears the cache (useful for testing or when configs change)
func (c *ToolRiskClient) InvalidateCache() {
	c.cache.mu.Lock()
	defer c.cache.mu.Unlock()
	c.cache.entries = make(map[string]*cacheEntry)
	c.agentGuardPolicyCache.invalidate()
	c.mcpPolicyCache.invalidate()
	if c.runtimeCache != nil {
		c.runtimeCache.mu.Lock()
		c.runtimeCache.securityAuditOnly = nil
		c.runtimeCache.expiresAt = time.Time{}
		c.runtimeCache.guardrailFailureMode = nil
		c.runtimeCache.gfmExpiresAt = time.Time{}
		c.runtimeCache.semanticConfig = nil
		c.runtimeCache.semanticExpiresAt = time.Time{}
		c.runtimeCache.mu.Unlock()
	}
}

// ToolInterceptor integrates with ChatCompletionsHandler to check tool calls
type ToolInterceptor struct {
	client *ToolRiskClient
}

// NewToolInterceptor creates a new tool interceptor
func NewToolInterceptor(client *ToolRiskClient) *ToolInterceptor {
	return &ToolInterceptor{client: client}
}

// InterceptRequest checks tool calls before request execution
// Returns error if any tool is blocked, nil otherwise
func (i *ToolInterceptor) InterceptRequest(ctx context.Context, envelope *modelrouter.RequestEnvelope, reqBody []byte) error {
	_, err := i.client.CheckToolCallsForRequest(ctx, envelope, reqBody)
	if err != nil {
		return err // Blocked tool
	}

	// All tools passed - could log audit results here
	return nil
}
