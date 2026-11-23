package security

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/yangjiyj/aiguard/packages/shared-go/headeraudit"
	"github.com/yangjiyj/aiguard/packages/shared-go/principal"
	"github.com/yangjiyj/aiguard/packages/shared-go/securityexit"
)

// Client handles communication with the security engine
type Client struct {
	baseURL        string
	internalSecret string
	httpClient     *http.Client
	// baseTimeout 是小请求的基准超时；大 payload 由 timeoutForPayload 线性放宽。
	baseTimeout time.Duration
	// 批量条目恢复的退避参数；sleep/now/jitter 可注入，便于测试不真睡。
	retryBackoff time.Duration
	sleep        func(context.Context, time.Duration) error
	now          func() time.Time
	jitter       func() float64
}

// NewClient creates a new security engine client
func NewClient(baseURL string) *Client {
	return NewClientWithSecret(baseURL, "")
}

func NewClientWithSecret(baseURL, internalSecret string) *Client {
	base := resolveBaseTimeout()
	return &Client{
		baseURL:        baseURL,
		internalSecret: internalSecret,
		httpClient: &http.Client{
			// 不在 http.Client 上设 Timeout：它是「含读体的总墙钟」，无法按请求区分。
			// 超时统一由 check() 用 context.WithTimeout 按 payload 体量施加。
			Timeout: 0,
		},
		baseTimeout:  base,
		retryBackoff: resolveRetryBackoff(),
		sleep:        sleepCtx,
		now:          time.Now,
		jitter:       rand.Float64,
	}
}

// 超时分级参数。默认值来自 home security-engine 实测（约 16ms/KB 线性）,
// 取 3 倍余量折算为 50ms/KB，避免规则库抖动时误判引擎不可用。
const (
	// Managed semantic scans may spend 15s inside the engine. The outer client
	// must allow transport/queue overhead instead of cancelling them at 10s.
	// The request-level deadline and explicit operator overrides still win.
	defaultSecurityBaseTimeout = 20 * time.Second
	defaultSecurityMaxTimeout  = 180 * time.Second
	securityTimeoutPerKB       = 50 * time.Millisecond
)

// resolveBaseTimeout 读 SECURITY_ENGINE_TIMEOUT，非法或未设时用默认值。
// 保留 env 出口是为了现场能在不重编译的前提下应急调整。
func resolveBaseTimeout() time.Duration {
	raw := strings.TrimSpace(os.Getenv("SECURITY_ENGINE_TIMEOUT"))
	if raw == "" {
		return defaultSecurityBaseTimeout
	}
	parsed, err := time.ParseDuration(raw)
	if err != nil || parsed <= 0 {
		return defaultSecurityBaseTimeout
	}
	return parsed
}

// resolveMaxTimeout 读 SECURITY_ENGINE_MAX_TIMEOUT，作为分级后的上限硬顶。
func resolveMaxTimeout() time.Duration {
	raw := strings.TrimSpace(os.Getenv("SECURITY_ENGINE_MAX_TIMEOUT"))
	if raw == "" {
		return defaultSecurityMaxTimeout
	}
	parsed, err := time.ParseDuration(raw)
	if err != nil || parsed <= 0 {
		return defaultSecurityMaxTimeout
	}
	return parsed
}

// WantSecretTextHeader 声明调用方需要引擎返回 secret_text（秘密本体）。
// 只有网关需要；复核等其他接口不带，引擎对没带头的请求一律返回空串。
const WantSecretTextHeader = "X-JJD-Want-Secret-Text"

// timeoutForPayload 按待检字节数线性放宽超时，并夹在 [base, max] 之间。
//
// 为什么必须按体量分级：检测耗时与文本长度成正比（实测约 16ms/KB），
// 单一写死值必然两头不讨好——对纯文本过松（引擎真挂了也要等 30s），
// 对 codex 长上下文过紧（2MB 必然超时，进而被 fail-close 判成 403）。
func (c *Client) timeoutForPayload(size int) time.Duration {
	base := c.baseTimeout
	if base <= 0 {
		base = defaultSecurityBaseTimeout
	}
	return payloadTimeoutBudget(base, size)
}

// TimeoutBudget shares the engine client's graded timeout with other transports.
func TimeoutBudget(size int) time.Duration {
	return payloadTimeoutBudget(resolveBaseTimeout(), size)
}

func payloadTimeoutBudget(base time.Duration, size int) time.Duration {
	budget := base + time.Duration(size/1024)*securityTimeoutPerKB
	if max := resolveMaxTimeout(); budget > max {
		return max
	}
	return budget
}

// withPayloadTimeout 给单次请求施加按体量分级的超时预算。
//
// http.Client 上不设 Timeout（它无法按请求区分预算），因此每个出向请求都必须
// 显式拿到 deadline，否则引擎挂住时会无限等待。调用方 ctx 已有更短 deadline 时，
// context.WithTimeout 不会延长它。
func (c *Client) withPayloadTimeout(ctx context.Context, size int) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, c.timeoutForPayload(size))
}

// CheckInputRequest represents a security check request
type CheckInputRequest struct {
	RequestID   string                 `json:"request_id"`
	Content     string                 `json:"content"`
	ContentType string                 `json:"content_type"`
	ProjectID   string                 `json:"project_id,omitempty"`
	Model       string                 `json:"model,omitempty"`
	AgentType   string                 `json:"agent_type,omitempty"`
	ClientType  string                 `json:"client_type,omitempty"`
	Context     map[string]interface{} `json:"context,omitempty"`
	// SkipSemantic 跑快层但跳过语义块（同步主链异步旁路模式用：sync 不等语义）。
	SkipSemantic bool `json:"skip_semantic,omitempty"`
	// SemanticOnly 只跑语义块、仅返回语义 findings（异步旁路另起的 goroutine 用）。
	SemanticOnly bool `json:"semantic_only,omitempty"`
	// SemanticStage 语义专用阶段，仅允许 input 或 agent；由 engine 按独立开关门控。
	SemanticStage string `json:"semantic_stage,omitempty"`
	// ContentSource 内容来源档位（system_prompt|user|assistant_history|tool_result|tool_def，空=不区分走全量）。
	ContentSource string `json:"content_source,omitempty"`
	// UserID scope 例外/裁剪透传（引擎按 user scope 匹配例外）。
	UserID    string             `json:"user_id,omitempty"`
	Principal *principal.Context `json:"principal,omitempty"`
}

// CheckInputResponse represents a security check response
type CheckInputResponse struct {
	RedactionMapping map[string]string `json:"redaction_mapping,omitempty"`
	RequestID        string            `json:"request_id"`
	Findings         []SecurityFinding `json:"findings"`
	Action           string            `json:"action"`
	MaskedContent    string            `json:"masked_content,omitempty"`
	LatencyMs        int               `json:"latency_ms"`
	// P1-B 指纹缓存（契约 1，P1-A 起引擎回带）：构建版本、规则包版本、
	// 降档/例外之前的原始 findings（原样透传，缓存值）。
	EngineBuild            string             `json:"engine_build,omitempty"`
	RulePackVersion        string             `json:"rule_pack_version,omitempty"`
	SemanticConfigRevision string             `json:"semantic_config_revision,omitempty"`
	SemanticStatus         string             `json:"semantic_status,omitempty"`
	SemanticReason         string             `json:"semantic_reason,omitempty"`
	RawFindings            json.RawMessage    `json:"raw_findings,omitempty"`
	FileBindings           []FileBindingToken `json:"file_bindings,omitempty"`
	InspectionStatus       string             `json:"inspection_status,omitempty"`
	InspectionReason       string             `json:"inspection_reason,omitempty"`
}

// FileBindingToken is an opaque one-time capability issued after a byte scan.
// It is not a customer-visible file_id and must only be sent back to the
// security engine after the gateway has verified an upstream object=file
// response.
type FileBindingToken struct {
	Token  string `json:"token"`
	SHA256 string `json:"sha256"`
}

// CheckTriageRequest 误报压制请求：把规则 findings 交 security-engine 做类型感知 triage。
type CheckTriageRequest struct {
	RequestID     string            `json:"request_id"`
	Content       string            `json:"content"`
	Findings      []SecurityFinding `json:"findings"`
	ContentSource string            `json:"content_source,omitempty"`
	Stage         string            `json:"stage,omitempty"`
}

// CheckTriageResponse 返回同款 findings，意图类的填了 .triage。
type CheckTriageResponse struct {
	RequestID string            `json:"request_id"`
	Findings  []SecurityFinding `json:"findings"`
}

// SecurityFinding represents a security finding
type SecurityFinding struct {
	Type                string   `json:"type"`
	Category            string   `json:"category"`
	Severity            string   `json:"severity"`
	MatchedTextPreview  string   `json:"matched_text_preview"`
	RuleID              string   `json:"rule_id"`
	Confidence          float64  `json:"confidence"`
	RuleName            string   `json:"rule_name"`
	RuleType            string   `json:"rule_type"`
	Action              string   `json:"action"`
	PolicyCode          string   `json:"policy_code,omitempty"`
	PolicyScene         string   `json:"policy_scene,omitempty"`
	SourceRuleID        string   `json:"source_rule_id,omitempty"`
	MatchedCapabilities []string `json:"matched_capabilities,omitempty"`
	// nil 表示旧引擎未提供该字段，按历史语义计作安全发现；false 表示仅为运行异常审计。
	CountsAsSecurityFinding *bool  `json:"counts_as_security_finding,omitempty"`
	MatchedLocation         string `json:"matched_location"`
	RedactedEvidence        string `json:"redacted_evidence"`
	// ExceptionID 命中的例外 ID（引擎侧规则例外豁免标注，空串=未豁免）。
	// finding 保留不丢弃，仅供安全事件展示「已豁免」与按例外过滤。
	ExceptionID     string         `json:"exception_id"`
	Triage          map[string]any `json:"triage,omitempty"`
	RawEvidence     string         `json:"raw_evidence"`
	EvidenceContext string         `json:"evidence_context,omitempty"`
	SecretText      string         `json:"secret_text,omitempty"`
	EvidenceKind    string         `json:"evidence_kind,omitempty"`
	ContentSource   string         `json:"content_source,omitempty"`
	EvidenceReason  string         `json:"evidence_reason,omitempty"`
	MessageIndex    *int           `json:"message_index,omitempty"`
	MessageRole     string         `json:"message_role,omitempty"`
	AttachmentIndex *int           `json:"attachment_index,omitempty"`
}

// CheckInput checks input content for security issues
func (c *Client) CheckInput(ctx context.Context, req *CheckInputRequest) (*CheckInputResponse, error) {
	return c.check(ctx, "/check-input/", req)
}

// CheckInputBatch sends independent message checks through the engine's bounded
// batch endpoint. A 207 response is transport success with per-item completion
// state; callers must apply their configured failure policy to incomplete items.
func (c *Client) CheckInputBatch(ctx context.Context, requests []*CheckInputRequest) ([]*CheckInputResponse, error) {
	if len(requests) == 0 {
		return []*CheckInputResponse{}, nil
	}
	const maxItems = 128
	results := make([]*CheckInputResponse, 0, len(requests))
	for start := 0; start < len(requests); start += maxItems {
		if err := ctx.Err(); err != nil {
			return nil, fmt.Errorf("security batch request canceled: %w", err)
		}
		end := start + maxItems
		if end > len(requests) {
			end = len(requests)
		}
		chunk, err := c.checkInputBatchChunk(ctx, requests[start:end])
		if err != nil {
			return nil, err
		}
		results = append(results, chunk...)
	}
	return results, nil
}

func (c *Client) checkInputBatchChunk(ctx context.Context, requests []*CheckInputRequest) ([]*CheckInputResponse, error) {
	copies := make([]*CheckInputRequest, len(requests))
	for i, req := range requests {
		copies[i] = withCredentialContext(ctx, req)
	}
	requests = copies
	body, err := json.Marshal(requests)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal security batch request: %w", err)
	}
	reqCtx, cancel := c.withPayloadTimeout(ctx, len(body))
	defer cancel()
	httpReq, err := http.NewRequestWithContext(reqCtx, http.MethodPost, c.baseURL+"/check-input/batch", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create security batch request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set(WantSecretTextHeader, "1")
	// Advisory C2 metrics only; emitted once for the whole logical batch.
	applyFingerprintStatsHeaders(reqCtx, httpReq)
	if c.internalSecret != "" {
		httpReq.Header.Set(headeraudit.InternalTokenHeader, c.internalSecret)
	}
	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("failed to call security batch endpoint: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusMultiStatus {
		body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		if err != nil {
			return nil, fmt.Errorf("failed to read security batch error: %w", err)
		}
		return nil, securityexit.HTTPInspectionError(resp.StatusCode, body)
	}
	var results []*CheckInputResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 16<<20)).Decode(&results); err != nil {
		return nil, fmt.Errorf("failed to decode security batch response: %w", err)
	}
	if len(results) != len(requests) {
		return nil, fmt.Errorf("security batch response count mismatch: got %d want %d", len(results), len(requests))
	}
	for i := range results {
		if results[i] == nil || results[i].RequestID != requests[i].RequestID {
			return nil, fmt.Errorf("security batch response order mismatch at item %d", i)
		}
		if results[i].InspectionStatus == "" {
			results[i].InspectionStatus = "completed"
		}
	}
	c.recoverIncompleteItems(ctx, requests, results)
	return results, nil
}

// CheckSemanticOnly 只跑语义检测（输入侧语义异步旁路用：主链已先跑快层，此处另起一程仅补语义 findings）。
func (c *Client) CheckSemanticOnly(ctx context.Context, req *CheckInputRequest) (*CheckInputResponse, error) {
	return c.CheckSemanticStage(ctx, req, "input")
}

// CheckSemanticStage 只跑指定阶段的语义检测。客户端侧严格枚举，服务端仍会二次校验。
func (c *Client) CheckSemanticStage(ctx context.Context, req *CheckInputRequest, stage string) (*CheckInputResponse, error) {
	if stage != "input" && stage != "agent" {
		return nil, fmt.Errorf("unsupported semantic stage %q", stage)
	}
	req.SemanticOnly = true
	req.SemanticStage = stage
	return c.check(ctx, "/check-input/", req)
}

// CheckTriage 调 security-engine /check-triage/ 做误报压制，返回带 triage 标注的 findings。
func (c *Client) CheckTriage(ctx context.Context, req *CheckTriageRequest) (*CheckTriageResponse, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal triage request: %w", err)
	}
	reqCtx, cancel := c.withPayloadTimeout(ctx, len(body))
	defer cancel()

	httpReq, err := http.NewRequestWithContext(reqCtx, "POST", c.baseURL+"/check-triage/", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create triage request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if c.internalSecret != "" {
		httpReq.Header.Set(headeraudit.InternalTokenHeader, c.internalSecret)
	}
	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("failed to call triage endpoint: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("triage endpoint returned status %d: %s", resp.StatusCode, string(respBody))
	}
	var out CheckTriageResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("failed to decode triage response: %w", err)
	}
	return &out, nil
}

// CheckOutput checks output content for security issues
func (c *Client) CheckOutput(ctx context.Context, requestID, content string, context map[string]interface{}) (*CheckInputResponse, error) {
	var trustedPrincipal *principal.Context
	if value, ok := context["principal"].(*principal.Context); ok {
		trustedPrincipal = value
		delete(context, "principal")
	}
	req := &CheckInputRequest{
		RequestID:   requestID,
		Content:     content,
		ContentType: "text",
		Context:     context,
		Principal:   trustedPrincipal,
	}

	return c.check(ctx, "/check-output/", req)
}

// FileVerdict is the result of a two-phase file_id lookup.
type FileVerdict struct {
	Status        string   `json:"status"`
	HitCategories []string `json:"hit_categories"`
}

// LookupFileVerdict resolves the previously recorded security verdict for a file reference.
// Only an explicit allow result permits reuse; callers must treat every other status as unsafe.
func (c *Client) LookupFileVerdict(ctx context.Context, tenantID, subject, provider, fileID string) (*FileVerdict, error) {
	endpoint := fmt.Sprintf("%s/scan-objects/verdict?tenant_id=%s&subject=%s&provider=%s&file_id=%s",
		strings.TrimRight(c.baseURL, "/"),
		url.QueryEscape(tenantID), url.QueryEscape(subject), url.QueryEscape(provider), url.QueryEscape(fileID))
	reqCtx, cancel := c.withPayloadTimeout(ctx, 0)
	defer cancel()

	httpReq, err := http.NewRequestWithContext(reqCtx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create file verdict request: %w", err)
	}
	if c.internalSecret != "" {
		httpReq.Header.Set(headeraudit.InternalTokenHeader, c.internalSecret)
	}
	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("failed to call file verdict endpoint: %w", err)
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("failed to read file verdict response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("file verdict endpoint returned status %d: %s", resp.StatusCode, string(respBody))
	}
	var verdict FileVerdict
	if err := json.Unmarshal(respBody, &verdict); err != nil {
		return nil, fmt.Errorf("failed to decode file verdict response: %w", err)
	}
	return &verdict, nil
}

// BindScannedFile consumes a one-time scan binding token and associates it
// with the real upstream file_id. The security engine performs the exact
// tenant/subject/provider scope check and rejects token replay.
func (c *Client) BindScannedFile(ctx context.Context, tenantID, subject, provider, token, fileID string) error {
	payload := map[string]string{
		"tenant_id":     tenantID,
		"subject":       subject,
		"provider":      provider,
		"binding_token": token,
		"file_id":       fileID,
		"object":        "file",
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal file binding request: %w", err)
	}
	endpoint := strings.TrimRight(c.baseURL, "/") + "/scan-objects/bind"
	reqCtx, cancel := c.withPayloadTimeout(ctx, len(body))
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("failed to create file binding request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if c.internalSecret != "" {
		req.Header.Set(headeraudit.InternalTokenHeader, c.internalSecret)
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to call file binding endpoint: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		return fmt.Errorf("file binding endpoint returned status %d: %s", resp.StatusCode, string(respBody))
	}
	return nil
}

func (c *Client) check(ctx context.Context, path string, req *CheckInputRequest) (*CheckInputResponse, error) {
	endpoint := c.baseURL + path
	req = withCredentialContext(ctx, req)

	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	// 超时按待检 payload 体量给预算：大上下文需要更长窗口，
	// 否则会被误判为「引擎不可用」并触发 fail-close。
	// 调用方 ctx 已有更短 deadline 时，WithTimeout 不会延长它。
	reqCtx, cancel := c.withPayloadTimeout(ctx, len(body))
	defer cancel()

	httpReq, err := http.NewRequestWithContext(reqCtx, "POST", endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set(WantSecretTextHeader, "1")
	if c.internalSecret != "" {
		httpReq.Header.Set(headeraudit.InternalTokenHeader, c.internalSecret)
	}

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("failed to call security engine: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return nil, securityexit.HTTPInspectionError(resp.StatusCode, respBody)
	}

	var checkResp CheckInputResponse
	if err := json.NewDecoder(resp.Body).Decode(&checkResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &checkResp, nil
}

// ShouldBlock determines if the security action requires blocking
func (r *CheckInputResponse) ShouldBlock() bool {
	return r.Action == "block"
}

// ShouldMask determines if the security action requires masking
func (r *CheckInputResponse) ShouldMask() bool {
	return r.Action == "mask"
}

// HasFindings determines if any security findings were detected
func (r *CheckInputResponse) HasFindings() bool {
	return len(r.Findings) > 0
}

// GetCriticalFindings returns all critical severity findings
func (r *CheckInputResponse) GetCriticalFindings() []SecurityFinding {
	findings := []SecurityFinding{}
	for _, f := range r.Findings {
		if f.Severity == "critical" {
			findings = append(findings, f)
		}
	}
	return findings
}

// GetHighFindings returns all high severity findings
func (r *CheckInputResponse) GetHighFindings() []SecurityFinding {
	findings := []SecurityFinding{}
	for _, f := range r.Findings {
		if f.Severity == "high" {
			findings = append(findings, f)
		}
	}
	return findings
}

// ApplyContextRequest 契约 2：POST /apply-context/ 入参。raw_findings 原样回传引擎，
// 引擎内部重放 编码降档→内容例外→_determine_action（不重跑正则）。
type ApplyContextRequest struct {
	TenantID    string              `json:"tenant_id"`
	RawFindings json.RawMessage     `json:"raw_findings"`
	Context     ApplyContextContext `json:"context"`
	Principal   *principal.Context  `json:"principal,omitempty"`
}

// ApplyContextContext 契约 2 的重放上下文。空值字段序列化省略（契约：可空）。
type ApplyContextContext struct {
	IntegrationDLPBlockKeyIDs []string `json:"integration_dlp_block_key_ids,omitempty"`
	KeyID                     string   `json:"key_id,omitempty"`
	TenantID                  string   `json:"tenant_id,omitempty"`
	EffectiveDLPEnforcement   string   `json:"effective_dlp_enforcement,omitempty"`
	IntegrationCredential     bool     `json:"integration_credential,omitempty"`
	AgentType                 string   `json:"agent_type,omitempty"`
	ProjectID                 string   `json:"project_id,omitempty"`
	UserID                    string   `json:"user_id,omitempty"`
	ContentSource             string   `json:"content_source,omitempty"`
	AccessType                string   `json:"access_type,omitempty"`
}

// ApplyContextResponse 契约 2 出参。
type ApplyContextResponse struct {
	Findings []SecurityFinding `json:"findings"`
	Action   string            `json:"action"`
}

// ApplyContext 调引擎 /apply-context/ 对缓存的原始 findings 做廉价上下文重放
// （指纹缓存命中路径专用；HTTP 形态与 CheckTriage 同款）。
func (c *Client) ApplyContext(ctx context.Context, req *ApplyContextRequest) (*ApplyContextResponse, error) {
	copy := *req
	trusted := withCredentialContext(ctx, &CheckInputRequest{})
	copy.Context.KeyID, _ = trusted.Context["key_id"].(string)
	copy.Context.TenantID, _ = trusted.Context["tenant_id"].(string)
	copy.Context.EffectiveDLPEnforcement, _ = trusted.Context["effective_dlp_enforcement"].(string)
	copy.Context.IntegrationCredential, _ = trusted.Context["integration_credential"].(bool)
	copy.Context.IntegrationDLPBlockKeyIDs, _ = trusted.Context["integration_dlp_block_key_ids"].([]string)
	req = &copy
	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal apply-context request: %w", err)
	}
	reqCtx, cancel := c.withPayloadTimeout(ctx, len(body))
	defer cancel()

	httpReq, err := http.NewRequestWithContext(reqCtx, "POST", c.baseURL+"/apply-context/", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create apply-context request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set(WantSecretTextHeader, "1")
	if c.internalSecret != "" {
		httpReq.Header.Set(headeraudit.InternalTokenHeader, c.internalSecret)
	}
	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("failed to call apply-context endpoint: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("apply-context endpoint returned status %d: %s", resp.StatusCode, string(respBody))
	}
	var out ApplyContextResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("failed to decode apply-context response: %w", err)
	}
	return &out, nil
}
