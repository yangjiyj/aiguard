package modelrouter

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/yangjiyj/aiguard/packages/shared-go/principal"
	"github.com/yangjiyj/aiguard/packages/shared-go/secrets"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type RequestEnvelope struct {
	// RequestStartedAt 与 Timing 仅用于本次请求的审计计时，不转发给上游。
	RequestStartedAt time.Time        `json:"-"`
	Timing           map[string]int64 `json:"-"`

	BillingIngress           string `json:"-"` // trusted ingress: model_api, forward_proxy or reverse_proxy
	AgentInstanceID          string `json:"agent_instance_id,omitempty"`
	AgentIdentityHeaders     string
	UserAgent                string
	RequestID                string
	ClientRetryID            string
	TenantID                 string
	TeamID                   string // 所属部门 ID，从 projects.team_id 反查；空表示未分配
	ProjectID                string
	UserID                   string
	ClientID                 string // stable internal_keys.id for authenticated API keys
	EnvironmentScope         string
	KeyPrefix                string // compatibility-only prefix; never the key-scope primary identity
	AgentType                string
	AgentRuntime             string
	AgentDetectionSource     string
	AgentDetectionConfidence float64
	SessionID                string
	WorkspaceID              string
	// EvidenceRunID is a tenant-scoped one-way digest of an exact protocol
	// correlation key. The raw prompt cache/thread key is never persisted.
	EvidenceRunID     string
	EvidenceRunSource string
	// EvidenceRunSubjectHash freezes the strict caller/model identity used by
	// chat tool-call correlation before route attempts can mutate the envelope.
	// It is process-local and is never persisted or returned to clients.
	EvidenceRunSubjectHash string `json:"-"`
	// EvidenceRunPrefixHash anchors a proposed tool call to the exact ordered
	// request transcript and tool definitions that preceded it.
	EvidenceRunPrefixHash string `json:"-"`
	TraceID               string
	LSEEvalRunID          string
	LSETaskID             string
	LSESampleID           string
	LSETargetID           string
	Provider              string
	ProviderID            string
	ModelID               string
	Model                 string
	// ClientModel 是客户端请求里写的原始模型名。仅在与 Model 不同（唯一后缀别名补全了供应商前缀）时设置；
	// 失败请求落审计时若为空则以 Model 为准。只写入 routing_decision_json，绝不进入上游请求。
	ClientModel string `json:"-"`
	// ModelResolution 记录模型名是怎么解析的：suffix_alias / not_found / ambiguous / inactive；精确命中为空。
	ModelResolution string `json:"-"`
	// ModelCandidates 是后缀别名有多个匹配时的候选全名（最多几个，仅审计用，不回给客户端）。
	ModelCandidates []string `json:"-"`
	// RejectReason 记录请求被拒的具体原因（如 feature_contract:cache_tokens、key_allowlist），不含敏感信息。
	RejectReason         string               `json:"-"`
	ProtocolCapabilities ProtocolCapabilities `json:"-"`
	UpstreamModelID      string               // forwarded to upstream when non-empty (replaces Model in request body)
	EndpointType         string
	// ResponsesCompatibility is set only by the server after normalization.
	// Raw native request extensions must never opt a route into a Chat bridge.
	ResponsesCompatibility bool `json:"-"`
	// UpstreamProtocol is selected per attempt from the request feature
	// fingerprint. It is never inferred from the public model name.
	UpstreamProtocol string
	SourceIP         string // P2: 客户端源 IP（只读审计增强；非拦截）
	// ConversationKey 会话归组键（aiconvo.ConversationKey，安全三视图 P1-D 契约第 6 条）：
	// A 路在 processSharedRequestPath 构造 envelope 后计算；写 security_events 时物化落列。
	// 非 A 路（反代/proxy）恒为空——计数口径回退 request_id。
	ConversationKey string
	// InspectionSessionKey 是输入检测折叠用的会话键（进程内，不落库、不回给客户端）：
	// 显式 X-JJDGuard-Session-Id，或 Codex 原生 thread-id / session_id 头（按租户和调用方隔离）。
	// 为空时不做会话内事件折叠，行为与以前一致。
	InspectionSessionKey string `json:"-"`
	ContentSegments      []ContentSegment
	PolicyContext        PolicyContext
	Principal            *principal.Context
	// R8: routing-layer hints populated by hot-path before ModelSelector
	RouteHint    string // optional hint from X-Route-Hint header
	PromptTokens int    // pre-counted input tokens for prompt_aware scoring
	// R14: routing decision assembled by hot-path; persisted as routing_decision_json
	RoutingDecision *RoutingDecision
	// Streaming selects TTFT rather than total latency for smart routing.
	Streaming bool
	// UpstreamTTFTMs is set once by streaming adapters after the first valid
	// SSE event. Non-streaming calls leave it nil.
	UpstreamTTFTMs *int64
	// QuotaAdmissionManaged means the atomic organization-quota lease owns token
	// accounting. Audit fanout must not add the same tokens a second time.
	QuotaAdmissionManaged      bool  `json:"-"`
	QuotaEstimatedTokens       int64 `json:"-"`
	QuotaEstimatedCostMicros   int64 `json:"-"`
	QuotaCostEstimateAvailable bool  `json:"-"`
	// QuotaCostCurrency 是控制面询价/预占时返回的计价币种，只用于断流提示的金额符号。
	QuotaCostCurrency        string `json:"-"`
	QuotaActualCostMicros    int64  `json:"-"`
	QuotaActualCostAvailable bool   `json:"-"`
	QuotaUsageSource         string `json:"-"`
	// BillingUsageSource is the authoritative usage_source marker for the
	// BILLING path, derived from the raw provider body, the request status and
	// the real admission tracking state. It is persisted into
	// request_logs.output_audit_result.response_metadata.usage_source and is what
	// control-plane reconciliation reads to decide settle vs pending.
	//
	// It is deliberately NOT QuotaUsageSource: that field means "the quota lease
	// owns these tokens" and is only populated when a quota admission actually
	// ran. Reusing it made the persisted usage_source depend on an unrelated
	// feature switch, so with billing on and quota off no source was ever written
	// and reconciliation could not settle any of those requests.
	BillingUsageSource    string                                                `json:"-"`
	BillingOutcome        string                                                `json:"-"`
	QuotaAccountingScopes []QuotaAccountingScope                                `json:"-"`
	QuotaFinalize         func(context.Context, int64, int64, bool, bool) error `json:"-"`
	QuotaHeartbeatStop    func()                                                `json:"-"`

	// QuotaCostEstimateMissingPrice is set by billing when no estimate exists
	// because the model has no configured price (D6), as opposed to an outage.
	QuotaCostEstimateMissingPrice bool `json:"-"`

	// CacheHit 表示本次回复来自网关响应缓存，没有调用上游；收尾时写入 request_logs.cache_hit。
	CacheHit bool `json:"-"`
}

type QuotaAccountingScope struct {
	Scope string
	ID    string
}

type RouteAttemptLedgerEntry struct {
	AttemptID             string
	LogicalRequestID      string
	ClientRetryID         string
	TenantID              string
	ProviderID            string
	ModelID               string
	EndpointType          string
	StartedAt             time.Time
	FinishedAt            time.Time
	DispatchState         string
	UpstreamOutcome       string
	ResultUnknown         bool
	DownstreamCommitState string
	DeliveryOutcome       string
}

type AttemptLedgerRecorder interface {
	StartRouteAttempt(context.Context, RouteAttemptLedgerEntry) error
	FinishRouteAttempt(context.Context, RouteAttemptLedgerEntry) error
}

type SharedRouteHealthSnapshot struct {
	RouteKey
	State           string
	Version         int64
	ObservedAt      time.Time
	ExpiresAt       time.Time
	SourceInstance  string
	FailureCategory string
}

type SharedRouteHealthStore interface {
	WriteSharedRouteHealth(context.Context, SharedRouteHealthSnapshot) error
	ListSharedRouteHealth(context.Context) ([]SharedRouteHealthSnapshot, error)
}

type ContentSegment struct {
	Type    string // text, image, audio, file
	Content string
}

type PolicyContext struct {
	QuotaRemaining   int64
	ModelAllowed     bool
	SecurityPassed   bool
	SecurityAction   string
	RPMLimit         int
	ConcurrencyLimit int
}

// ModelRouter handles model to provider routing with database lookup
type ModelRouter struct {
	db *pgxpool.Pool
}

const outboundProxyURLSettingKey = "outbound_proxy_url"

// loadConfiguredOutboundProxyURL resolves the global customer egress proxy from
// the control-plane database. The value is encrypted at rest; any decrypt error
// is returned to the request path so a broken configuration cannot silently
// bypass the customer's required outbound proxy.
func (m *ModelRouter) loadConfiguredOutboundProxyURL(ctx context.Context) (string, error) {
	var ciphertext string
	err := m.db.QueryRow(ctx, `SELECT value FROM system_settings WHERE key = $1`, outboundProxyURLSettingKey).Scan(&ciphertext)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("load outbound proxy setting: %w", err)
	}
	if strings.TrimSpace(ciphertext) == "" {
		return "", nil
	}
	proxyURL, err := secrets.DecryptProviderSecret(ciphertext)
	if err != nil {
		return "", fmt.Errorf("decrypt outbound proxy setting: %w", err)
	}
	return strings.TrimSpace(proxyURL), nil
}

// NewModelRouter creates a new model router with database connection
func NewModelRouter(db *pgxpool.Pool) *ModelRouter {
	return &ModelRouter{db: db}
}

func (m *ModelRouter) StartRouteAttempt(ctx context.Context, entry RouteAttemptLedgerEntry) error {
	_, err := m.db.Exec(ctx, `
INSERT INTO model_route_attempts (
 attempt_id,logical_request_id,client_retry_id,tenant_id,provider_id,model_id,
 endpoint_type,started_at,dispatch_state,upstream_outcome,result_unknown,
 downstream_commit_state,delivery_outcome,ledger_schema_version,rollout_marker
) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,'pending',false,$10,'pending',1,'forwarding-governance-v1')
ON CONFLICT (attempt_id) DO NOTHING
`, entry.AttemptID, entry.LogicalRequestID, entry.ClientRetryID, entry.TenantID,
		nullableLedgerID(entry.ProviderID), nullableLedgerID(entry.ModelID), entry.EndpointType,
		entry.StartedAt, entry.DispatchState, entry.DownstreamCommitState)
	if err != nil {
		return fmt.Errorf("start route attempt ledger: %w", err)
	}
	return nil
}

func (m *ModelRouter) FinishRouteAttempt(ctx context.Context, entry RouteAttemptLedgerEntry) error {
	_, err := m.db.Exec(ctx, `
UPDATE model_route_attempts
SET finished_at=$2,dispatch_state=$3,upstream_outcome=$4,result_unknown=$5,
    downstream_commit_state=$6,delivery_outcome=$7,updated_at=NOW()
WHERE attempt_id=$1 AND finished_at IS NULL
`, entry.AttemptID, entry.FinishedAt, entry.DispatchState, entry.UpstreamOutcome,
		entry.ResultUnknown, entry.DownstreamCommitState, entry.DeliveryOutcome)
	if err != nil {
		return fmt.Errorf("finish route attempt ledger: %w", err)
	}
	return nil
}

func nullableLedgerID(value string) any {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	return value
}

func (m *ModelRouter) WriteSharedRouteHealth(ctx context.Context, snapshot SharedRouteHealthSnapshot) error {
	_, err := m.db.Exec(ctx, `
INSERT INTO model_route_health_snapshots
 (tenant_id,model_name,provider_id,state,version,observed_at,expires_at,source_instance,failure_category,updated_at)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,NOW())
ON CONFLICT (tenant_id,model_name,provider_id) DO UPDATE
SET state=EXCLUDED.state,version=EXCLUDED.version,observed_at=EXCLUDED.observed_at,
    expires_at=EXCLUDED.expires_at,source_instance=EXCLUDED.source_instance,
    failure_category=EXCLUDED.failure_category,updated_at=NOW()
WHERE EXCLUDED.version > model_route_health_snapshots.version
`, snapshot.TenantID, snapshot.ModelName, snapshot.ProviderID, snapshot.State,
		snapshot.Version, snapshot.ObservedAt, snapshot.ExpiresAt, snapshot.SourceInstance, snapshot.FailureCategory)
	if err != nil {
		return fmt.Errorf("write shared route health: %w", err)
	}
	return nil
}

func (m *ModelRouter) ListSharedRouteHealth(ctx context.Context) ([]SharedRouteHealthSnapshot, error) {
	rows, err := m.db.Query(ctx, `
SELECT tenant_id,model_name,provider_id,state,version,observed_at,expires_at,source_instance,failure_category
FROM model_route_health_snapshots
WHERE expires_at > NOW()
ORDER BY tenant_id,model_name,provider_id
LIMIT 10000
`)
	if err != nil {
		return nil, fmt.Errorf("list shared route health: %w", err)
	}
	defer rows.Close()
	result := make([]SharedRouteHealthSnapshot, 0)
	for rows.Next() {
		var snapshot SharedRouteHealthSnapshot
		if err := rows.Scan(&snapshot.TenantID, &snapshot.ModelName, &snapshot.ProviderID,
			&snapshot.State, &snapshot.Version, &snapshot.ObservedAt, &snapshot.ExpiresAt,
			&snapshot.SourceInstance, &snapshot.FailureCategory); err != nil {
			return nil, fmt.Errorf("scan shared route health: %w", err)
		}
		result = append(result, snapshot)
	}
	return result, rows.Err()
}

// ResolveProvider is retained only for source compatibility. A model name is
// not enough information to select a provider or protocol adapter.
func ResolveProvider(model string) string {
	_ = model
	return "unknown"
}

// ErrModelNotFound 表示请求的模型名在租户「可用模型目录」里查不到：
// 目录里没有这个名字，或者它所在的模型/供应商已停用、已删除。
// 它只代表「名字解析不到」，与「模型存在但没有可用线路」（熔断、全部不健康、缺凭证）无关；
// 数据库连接失败等基础设施错误不会包成它，调用方据此决定返回 404 还是 503。
var ErrModelNotFound = errors.New("model_not_found")

// ModelRecord represents a model configuration from database
type ModelRecord struct {
	ID                           string
	ProviderID                   string
	ProviderName                 string
	ModelName                    string
	ModelLabel                   string
	UpstreamModelID              string
	ProviderType                 string
	ProviderBaseURL              string
	ProviderAuthMode             string
	UpstreamProxyURL             string
	FallbackProviderID           string
	FallbackProviderType         string
	FallbackProviderBaseURL      string
	FallbackProviderAuthMode     string
	FallbackModelID              string
	FallbackUpstreamModelID      string
	FallbackProtocolCapabilities ProtocolCapabilities
	ContextWindow                int
	Status                       string
	ProxyConfig                  string // JSON-encoded proxy model configuration
	ProtocolCapabilities         ProtocolCapabilities
	ResponsesNative              bool
	FallbackResponsesNative      bool
	CreatedAt                    time.Time
	// AliasFrom 非空表示：客户端写的是不带供应商前缀的名字，被唯一的「最后一段相等」匹配补全成了 ModelName。
	// 精确命中时为空。调用方据此把后续流程（授权、计费、路由、上游请求体）全部切到 ModelName。
	AliasFrom string
}

// ProviderRecord represents a provider configuration from database
type ProviderRecord struct {
	ID               string
	TenantID         string
	Name             string
	ProviderType     string
	BaseURL          string
	AuthMode         string
	UpstreamProxyURL string
	IsDefault        bool
	Status           string
}

// resolveModelExact 只做精确名字查询（模型与供应商都 active）。查不到时原样返回 pgx.ErrNoRows。
func (m *ModelRouter) resolveModelExact(ctx context.Context, tenantID, modelName string) (*ModelRecord, error) {
	// Query models table with provider join
	query := `
			SELECT m.id, m.provider_id, m.model_name, COALESCE(m.model_label, ''), COALESCE(m.upstream_model_id, ''), p.provider_type, p.base_url, p.auth_mode,
			       COALESCE(m.context_window, 0), m.status, m.proxy_config, m.created_at,
			       fp.id, fp.provider_type, fp.base_url, fp.auth_mode
			       , COALESCE(m.capabilities_json, '{}'::jsonb)
			       , fm.id, COALESCE(fm.upstream_model_id, ''), COALESCE(fm.capabilities_json, '{}'::jsonb)
			       , COALESCE(ec.capabilities, '{}'::jsonb), COALESCE(fec.capabilities, '{}'::jsonb)
			FROM models m
			JOIN providers p ON m.provider_id = p.id
			LEFT JOIN providers fp
			  ON fp.id = m.capabilities_json->'routing'->>'fallback_provider_id'
			 AND fp.tenant_id = $1
			 AND fp.status = 'active'
			LEFT JOIN LATERAL (
			  SELECT fallback_model.id, fallback_model.upstream_model_id, fallback_model.capabilities_json
			  FROM models fallback_model
			  WHERE fallback_model.provider_id = fp.id
			    AND fallback_model.model_name = m.model_name
			    AND fallback_model.status = 'active'
			  ORDER BY fallback_model.created_at DESC, fallback_model.id
			  LIMIT 1
			) fm ON TRUE
			LEFT JOIN LATERAL (
			  SELECT jsonb_object_agg(endpoint_type, jsonb_build_object(
			    'state', state, 'source', source, 'source_version', source_version,
			    'provider_config_digest', provider_config_digest, 'verified_at', verified_at,
			    'expires_at', expires_at, 'is_override', is_override
			  )) AS capabilities
			  FROM model_endpoint_capability_effective WHERE model_id = m.id
			) ec ON TRUE
			LEFT JOIN LATERAL (
			  SELECT jsonb_object_agg(endpoint_type, jsonb_build_object(
			    'state', state, 'source', source, 'source_version', source_version,
			    'provider_config_digest', provider_config_digest, 'verified_at', verified_at,
			    'expires_at', expires_at, 'is_override', is_override
			  )) AS capabilities
			  FROM model_endpoint_capability_effective WHERE model_id = fm.id
			) fec ON TRUE
			WHERE p.tenant_id = $1 AND m.model_name = $2 AND m.status = 'active' AND p.status = 'active'
		`

	row := m.db.QueryRow(ctx, query, tenantID, modelName)
	var model ModelRecord
	var fallbackProviderID, fallbackProviderType, fallbackProviderBaseURL, fallbackProviderAuthMode sql.NullString
	var fallbackModelID, fallbackUpstreamModelID sql.NullString
	var capabilitiesJSON, fallbackCapabilitiesJSON, effectiveCapabilitiesJSON, fallbackEffectiveCapabilitiesJSON []byte
	err := row.Scan(
		&model.ID,
		&model.ProviderID,
		&model.ModelName,
		&model.ModelLabel,
		&model.UpstreamModelID,
		&model.ProviderType,
		&model.ProviderBaseURL,
		&model.ProviderAuthMode,
		&model.ContextWindow,
		&model.Status,
		&model.ProxyConfig,
		&model.CreatedAt,
		&fallbackProviderID,
		&fallbackProviderType,
		&fallbackProviderBaseURL,
		&fallbackProviderAuthMode,
		&capabilitiesJSON,
		&fallbackModelID,
		&fallbackUpstreamModelID,
		&fallbackCapabilitiesJSON,
		&effectiveCapabilitiesJSON,
		&fallbackEffectiveCapabilitiesJSON,
	)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, err
		}
		return nil, fmt.Errorf("model %s is not configured for tenant %s: %w", modelName, tenantID, err)
	}

	proxyURL, err := m.loadConfiguredOutboundProxyURL(ctx)
	if err != nil {
		return nil, err
	}
	model.UpstreamProxyURL = proxyURL

	model.FallbackProviderID = fallbackProviderID.String
	model.FallbackProviderType = fallbackProviderType.String
	model.FallbackProviderBaseURL = fallbackProviderBaseURL.String
	model.FallbackProviderAuthMode = fallbackProviderAuthMode.String
	model.FallbackModelID = fallbackModelID.String
	model.FallbackUpstreamModelID = fallbackUpstreamModelID.String
	model.ProtocolCapabilities = ApplyEffectiveEndpointCapabilities(
		ParseProtocolCapabilities(capabilitiesJSON), effectiveCapabilitiesJSON,
		ProviderConfigDigest(model.ProviderType, model.ProviderBaseURL, model.ProviderAuthMode), time.Now(),
		LegacyProviderConfigDigest(model.ProviderType, model.ProviderBaseURL, model.ProviderAuthMode),
	)
	model.ResponsesNative = model.ProtocolCapabilities.ResponsesNative
	model.FallbackResponsesNative = responsesNativeCapability(fallbackCapabilitiesJSON)
	model.FallbackProtocolCapabilities = ApplyEffectiveEndpointCapabilities(
		ParseProtocolCapabilities(fallbackCapabilitiesJSON), fallbackEffectiveCapabilitiesJSON,
		ProviderConfigDigest(model.FallbackProviderType, model.FallbackProviderBaseURL, model.FallbackProviderAuthMode), time.Now(),
		LegacyProviderConfigDigest(model.FallbackProviderType, model.FallbackProviderBaseURL, model.FallbackProviderAuthMode),
	)

	return &model, nil
}

// ResolveModelWithDB 把请求里的模型名解析成租户可用目录里的一条模型记录。
//
//  1. 精确名字命中（模型与供应商都 active）：原样返回，行为与以前完全一致。
//  2. 精确查不到，且请求名不含 "/"：看可用目录里「最后一段（最后一个 / 之后）与请求名完全相等」的模型全名。
//     恰好只有一个不同的全名 → 解析到它，返回记录的 AliasFrom 记下原始请求名；
//     有多个 → 不猜，返回 ambiguous。只做这一种精确的后缀匹配，不做去日期、跨版本等任何模糊映射。
//  3. 其余一律返回 *ModelNotFoundError（errors.Is(err, ErrModelNotFound)）。
//
// 数据库故障等基础设施错误不会包成 ErrModelNotFound，调用方据此区分 404 与 503。
func (m *ModelRouter) ResolveModelWithDB(ctx context.Context, tenantID, modelName string) (*ModelRecord, error) {
	record, err := m.resolveModelExact(ctx, tenantID, modelName)
	if err == nil {
		return record, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return nil, err
	}
	miss, err := m.explainModelMiss(ctx, tenantID, modelName)
	if err != nil {
		return nil, fmt.Errorf("model %s lookup failed for tenant %s: %w", modelName, tenantID, err)
	}
	if miss.Reason == "" && miss.Alias != "" {
		record, err = m.resolveModelExact(ctx, tenantID, miss.Alias)
		if err == nil {
			record.AliasFrom = modelName
			return record, nil
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return nil, err
		}
		// 刚查到又被停用/删除：按查不到处理。
		miss.Reason = ModelMissNotFound
	}
	if miss.Reason == "" {
		miss.Reason = ModelMissNotFound
	}
	return nil, &ModelNotFoundError{TenantID: tenantID, Requested: modelName, Reason: miss.Reason, Candidates: miss.Candidates}
}

type modelMiss struct {
	Alias      string
	Reason     string
	Candidates []string
}

// explainModelMiss 只在精确查询落空之后调用（冷路径）：判断是「已停用」「唯一后缀匹配」「多个后缀匹配」还是「查不到」。
// 已删除（status=deleted）的模型/供应商一律当作不存在。
func (m *ModelRouter) explainModelMiss(ctx context.Context, tenantID, modelName string) (modelMiss, error) {
	const query = `
		SELECT m.model_name, (m.status = 'active' AND p.status = 'active') AS usable
		FROM models m
		JOIN providers p ON p.id = m.provider_id
		WHERE p.tenant_id = $1::text
		  AND m.status <> 'deleted' AND p.status <> 'deleted'
		  AND (
		    m.model_name = $2::text
		    OR ($2::text <> '' AND position('/' in $2::text) = 0
		        AND position('/' in m.model_name) > 0
		        AND substring(m.model_name from '[^/]*$') = $2::text)
		  )`
	rows, err := m.db.Query(ctx, query, tenantID, modelName)
	if err != nil {
		return modelMiss{}, err
	}
	defer rows.Close()
	usableSuffix := map[string]bool{}
	exactInactive := false
	for rows.Next() {
		var name string
		var usable bool
		if err := rows.Scan(&name, &usable); err != nil {
			return modelMiss{}, err
		}
		if name == modelName {
			if !usable {
				exactInactive = true
			}
			continue
		}
		if usable {
			usableSuffix[name] = true
		}
	}
	if err := rows.Err(); err != nil {
		return modelMiss{}, err
	}
	switch {
	case len(usableSuffix) == 1:
		for name := range usableSuffix {
			return modelMiss{Alias: name}, nil
		}
	case len(usableSuffix) > 1:
		names := make([]string, 0, len(usableSuffix))
		for name := range usableSuffix {
			names = append(names, name)
		}
		sort.Strings(names)
		if len(names) > 5 {
			names = names[:5]
		}
		return modelMiss{Reason: ModelMissAmbiguous, Candidates: names}, nil
	case exactInactive:
		return modelMiss{Reason: ModelMissInactive}, nil
	}
	return modelMiss{Reason: ModelMissNotFound}, nil
}

// ListModelRoutes resolves modelRef inside the tenant, then returns every usable
// upstream line for that exact logical model. It never broadens the lookup to a
// different model name.
func (m *ModelRouter) ListModelRoutes(ctx context.Context, tenantID, modelRef string) ([]ModelRecord, error) {
	modelName, found, err := m.ResolveLogicalModelName(ctx, tenantID, modelRef)
	if err != nil || !found {
		return nil, err
	}
	return m.listModelRoutesByName(ctx, tenantID, modelName)
}

// ResolveLogicalModelName resolves both public logical names and internal model
// IDs. An exact logical-name match wins if the same string is also another
// row's ID, so a caller-supplied model name can never silently change models.
// Credential state is intentionally not part of resolution.
func (m *ModelRouter) ResolveLogicalModelName(ctx context.Context, tenantID, modelRef string) (string, bool, error) {
	const query = `
		SELECT m.model_name
		FROM models m
		JOIN providers p ON p.id = m.provider_id
		WHERE p.tenant_id = $1 AND (m.model_name = $2 OR m.id = $2)
		ORDER BY CASE WHEN m.model_name = $2 THEN 0 ELSE 1 END, m.id
		LIMIT 1`
	var modelName string
	err := m.db.QueryRow(ctx, query, tenantID, modelRef).Scan(&modelName)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("resolve logical model name: %w", err)
	}
	return modelName, true, nil
}

func (m *ModelRouter) listModelRoutesByName(ctx context.Context, tenantID, modelName string) ([]ModelRecord, error) {
	const query = `
		SELECT DISTINCT ON (p.id) m.id, m.provider_id, p.name, m.model_name,
		       COALESCE(m.model_label, ''), COALESCE(m.upstream_model_id, ''),
		       p.provider_type, COALESCE(p.base_url, ''), COALESCE(p.auth_mode, ''),
		       COALESCE(m.context_window, 0), m.status,
		       COALESCE(m.proxy_config, '{}'::jsonb),
		       COALESCE(m.capabilities_json, '{}'::jsonb), m.created_at,
		       COALESCE(ec.capabilities, '{}'::jsonb)
		FROM models m
		JOIN providers p ON p.id = m.provider_id
		LEFT JOIN LATERAL (
		  SELECT jsonb_object_agg(endpoint_type, jsonb_build_object(
		    'state', state, 'source', source, 'source_version', source_version,
		    'provider_config_digest', provider_config_digest, 'verified_at', verified_at,
		    'expires_at', expires_at, 'is_override', is_override
		  )) AS capabilities
		  FROM model_endpoint_capability_effective WHERE model_id = m.id
		) ec ON TRUE
		WHERE p.tenant_id = $1 AND m.model_name = $2
		  AND p.status = 'active' AND m.status = 'active'
		  AND EXISTS (
			SELECT 1 FROM provider_credentials pc
			WHERE pc.provider_id = p.id AND pc.status = 'active'
			  AND COALESCE(pc.secret_ciphertext, '') <> ''
		  )
		ORDER BY p.id, m.id`

	rows, err := m.db.Query(ctx, query, tenantID, modelName)
	if err != nil {
		return nil, fmt.Errorf("list model routes: %w", err)
	}
	defer rows.Close()
	proxyURL, err := m.loadConfiguredOutboundProxyURL(ctx)
	if err != nil {
		return nil, err
	}
	routes := make([]ModelRecord, 0)
	for rows.Next() {
		var route ModelRecord
		var proxyJSON, capabilitiesJSON, effectiveCapabilitiesJSON []byte
		if err := rows.Scan(
			&route.ID, &route.ProviderID, &route.ProviderName, &route.ModelName,
			&route.ModelLabel, &route.UpstreamModelID, &route.ProviderType,
			&route.ProviderBaseURL, &route.ProviderAuthMode, &route.ContextWindow,
			&route.Status, &proxyJSON, &capabilitiesJSON, &route.CreatedAt, &effectiveCapabilitiesJSON,
		); err != nil {
			return nil, fmt.Errorf("scan model route: %w", err)
		}
		route.ProxyConfig = string(proxyJSON)
		route.UpstreamProxyURL = proxyURL
		route.ProtocolCapabilities = ApplyEffectiveEndpointCapabilities(
			ParseProtocolCapabilities(capabilitiesJSON), effectiveCapabilitiesJSON,
			ProviderConfigDigest(route.ProviderType, route.ProviderBaseURL, route.ProviderAuthMode), time.Now(),
			LegacyProviderConfigDigest(route.ProviderType, route.ProviderBaseURL, route.ProviderAuthMode),
		)
		route.ResponsesNative = route.ProtocolCapabilities.ResponsesNative
		routes = append(routes, route)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list model routes rows: %w", err)
	}
	return routes, nil
}

func responsesNativeCapability(raw []byte) bool {
	var capabilities struct {
		Protocols struct {
			ResponsesNative bool `json:"responses_native"`
		} `json:"protocols"`
	}
	if err := json.Unmarshal(raw, &capabilities); err != nil {
		return false
	}
	return capabilities.Protocols.ResponsesNative
}

// GetProviderCredential retrieves the API key for a provider
func (m *ModelRouter) GetProviderCredential(ctx context.Context, providerID string) (string, error) {
	query := `
		SELECT secret_ciphertext
		FROM provider_credentials
		WHERE provider_id = $1 AND status = 'active'
		ORDER BY created_at DESC
		LIMIT 1
	`

	row := m.db.QueryRow(ctx, query, providerID)
	var secretCiphertext string
	err := row.Scan(&secretCiphertext)
	if err != nil {
		return "", fmt.Errorf("no credential found for provider %s", providerID)
	}

	secretValue, err := secrets.DecryptProviderSecret(secretCiphertext)
	if err != nil {
		return "", fmt.Errorf("decrypt provider credential for %s: %w", providerID, err)
	}

	return secretValue, nil
}

func (m *ModelRouter) GetProvider(ctx context.Context, tenantID, providerID string) (*ProviderRecord, error) {
	query := `
		SELECT id, tenant_id, name, provider_type, base_url, auth_mode, is_default, status
		FROM providers
		WHERE id = $1 AND tenant_id = $2 AND status = 'active'
		LIMIT 1
	`

	row := m.db.QueryRow(ctx, query, providerID, tenantID)
	var provider ProviderRecord
	err := row.Scan(
		&provider.ID,
		&provider.TenantID,
		&provider.Name,
		&provider.ProviderType,
		&provider.BaseURL,
		&provider.AuthMode,
		&provider.IsDefault,
		&provider.Status,
	)
	if err != nil {
		return nil, fmt.Errorf("provider %s is not configured: %w", providerID, err)
	}
	proxyURL, err := m.loadConfiguredOutboundProxyURL(ctx)
	if err != nil {
		return nil, err
	}
	provider.UpstreamProxyURL = proxyURL
	return &provider, nil
}

// GetDefaultProviderForTenant retrieves the default provider for a tenant
func (m *ModelRouter) GetDefaultProviderForTenant(ctx context.Context, tenantID string) (*ProviderRecord, error) {
	query := `
		SELECT id, tenant_id, name, provider_type, base_url, auth_mode, is_default, status
		FROM providers
		WHERE tenant_id = $1 AND is_default = true AND status = 'active'
		LIMIT 1
	`

	row := m.db.QueryRow(ctx, query, tenantID)
	var provider ProviderRecord
	err := row.Scan(
		&provider.ID,
		&provider.TenantID,
		&provider.Name,
		&provider.ProviderType,
		&provider.BaseURL,
		&provider.AuthMode,
		&provider.IsDefault,
		&provider.Status,
	)

	if err != nil {
		return nil, fmt.Errorf("no default provider for tenant %s", tenantID)
	}

	proxyURL, err := m.loadConfiguredOutboundProxyURL(ctx)
	if err != nil {
		return nil, err
	}
	provider.UpstreamProxyURL = proxyURL
	return &provider, nil
}

// ModelPolicy represents model policy from database
type ModelPolicy struct {
	ID        string
	TenantID  string
	ProjectID string
	AllowList []string
	DenyList  []string
}

// GetModelPolicy retrieves the model policy for a project
func (m *ModelRouter) GetModelPolicy(ctx context.Context, projectID string) (*ModelPolicy, error) {
	query := `
		SELECT id, tenant_id, project_id, allow_models_json, deny_models_json
		FROM model_policies
		WHERE project_id = $1 AND scope_type = 'project'
	`

	row := m.db.QueryRow(ctx, query, projectID)
	var policy ModelPolicy
	var allowJSON, denyJSON []byte

	err := row.Scan(
		&policy.ID,
		&policy.TenantID,
		&policy.ProjectID,
		&allowJSON,
		&denyJSON,
	)

	if err != nil {
		// No policy found - return default (all allowed)
		return &ModelPolicy{
			AllowList: []string{},
			DenyList:  []string{},
		}, nil
	}

	// Parse JSON arrays properly
	if len(allowJSON) > 0 {
		json.Unmarshal(allowJSON, &policy.AllowList)
	} else {
		policy.AllowList = []string{}
	}
	if len(denyJSON) > 0 {
		json.Unmarshal(denyJSON, &policy.DenyList)
	} else {
		policy.DenyList = []string{}
	}

	return &policy, nil
}

// IsModelAllowed checks if a model is allowed by policy
func (p *ModelPolicy) IsModelAllowed(modelName string) bool {
	// Check deny list first
	for _, m := range p.DenyList {
		if m == modelName {
			return false
		}
	}

	// If allow list is empty, all models are allowed (except deny list)
	if len(p.AllowList) == 0 {
		return true
	}

	// Check allow list
	for _, m := range p.AllowList {
		if m == modelName {
			return true
		}
	}

	return false
}

// QuotaPolicy represents quota policy from database
type QuotaPolicy struct {
	ID                 string
	TenantID           string
	ProjectID          string
	DailyTokenLimit    int64
	MonthlyTokenLimit  int64
	MonthlyBudgetLimit float64
	RPMLimit           int
	TPMLimit           *int64
	TPMBlocked         bool
	ConcurrencyLimit   int
	EnforcementMode    string
}

// GetQuotaPolicy retrieves the quota policy for a project
func (m *ModelRouter) GetQuotaPolicy(ctx context.Context, projectID string) (*QuotaPolicy, error) {
	query := `
			SELECT id, tenant_id, project_id, daily_token_limit, monthly_token_limit, monthly_budget_limit, rpm_limit, tpm_limit, COALESCE(tpm_blocked, false), concurrency_limit,
		       COALESCE(enforcement_mode, 'soft')
		FROM quota_policies
		WHERE project_id = $1 AND scope_type = 'project' AND status = 'active'
	`

	row := m.db.QueryRow(ctx, query, projectID)
	var policy QuotaPolicy

	err := row.Scan(
		&policy.ID,
		&policy.TenantID,
		&policy.ProjectID,
		&policy.DailyTokenLimit,
		&policy.MonthlyTokenLimit,
		&policy.MonthlyBudgetLimit,
		&policy.RPMLimit,
		&policy.TPMLimit,
		&policy.TPMBlocked,
		&policy.ConcurrencyLimit,
		&policy.EnforcementMode,
	)

	if errors.Is(err, pgx.ErrNoRows) {
		// No policy found - return default (no limits)
		return &QuotaPolicy{
			DailyTokenLimit:   0,
			MonthlyTokenLimit: 0,
			RPMLimit:          0,
			ConcurrencyLimit:  0,
			EnforcementMode:   "soft",
		}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get project quota policy: %w", err)
	}

	return &policy, nil
}

// GetProjectTeamID returns the team_id for a project from the projects table.
// Returns empty string if the project has no team assigned or does not exist.
func (m *ModelRouter) GetProjectTeamID(ctx context.Context, projectID string) (string, error) {
	if projectID == "" {
		return "", nil
	}
	var teamID *string
	err := m.db.QueryRow(ctx,
		`SELECT team_id FROM projects WHERE id = $1`,
		projectID,
	).Scan(&teamID)
	if err != nil {
		// Not found or no team_id column yet — fail-open with empty string
		return "", nil
	}
	if teamID == nil {
		return "", nil
	}
	return *teamID, nil
}

// Legacy GetModelPolicy (static fallback)
func GetModelPolicy(tenantID, projectID, model string) (*ModelPolicy, error) {
	return &ModelPolicy{
		AllowList: []string{},
		DenyList:  []string{},
	}, nil
}
