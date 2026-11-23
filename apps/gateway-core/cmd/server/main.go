package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/redis/go-redis/v9"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/auth"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/config"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/governor"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/governor/providers"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/handler"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/httpmw"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/relay"

	"github.com/yangjiyj/aiguard/packages/shared-go/buildinfo"
	sharedDB "github.com/yangjiyj/aiguard/packages/shared-go/dbhelpers"
	"github.com/yangjiyj/aiguard/packages/shared-go/filereference"
	"github.com/yangjiyj/aiguard/packages/shared-go/headeraudit"
	"github.com/yangjiyj/aiguard/packages/shared-go/modelaccess"
	"github.com/yangjiyj/aiguard/packages/shared-go/outbox"
	"github.com/yangjiyj/aiguard/packages/shared-go/scanfp"
)

const (
	defaultGatewayHTTPReadHeaderTimeout = 10 * time.Second
	defaultGatewayHTTPReadTimeout       = 5 * time.Minute
	defaultGatewayHTTPIdleTimeout       = 30 * time.Second
)

// 这两个超时控制单个请求的最长存活时间。大模型(尤其高推理 gpt-5.5)生成长文档时，
// 单次上游请求可能持续数分钟；原先硬编码 5m 会把长流掐断(上游报 context deadline
// exceeded)。改为可经环境变量调节、默认放宽到 30m，避免再为此重建镜像。
// GATEWAY_REQUEST_TIMEOUT / GATEWAY_HTTP_WRITE_TIMEOUT 接受 Go duration 字符串(如 "30m"、"1800s")。
// 写超时默认取 请求超时+1m，保证始终大于请求超时(满足 main_test.go 的不变式)。
var (
	gatewayRuntimeRequestTimeout = envDuration("GATEWAY_REQUEST_TIMEOUT", 30*time.Minute)
	gatewayHTTPWriteTimeout      = envDuration("GATEWAY_HTTP_WRITE_TIMEOUT", gatewayRuntimeRequestTimeout+time.Minute)
)

// envDuration 读取一个 Go duration 字符串环境变量；为空、解析失败或非正值时回退到 def。
func envDuration(key string, def time.Duration) time.Duration {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			return d
		}
	}
	return def
}

func gatewayHTTPReadTimeouts() (time.Duration, time.Duration) {
	headerTimeout := envDuration("GATEWAY_HTTP_READ_HEADER_TIMEOUT", defaultGatewayHTTPReadHeaderTimeout)
	readTimeout := envDuration("GATEWAY_HTTP_READ_TIMEOUT", defaultGatewayHTTPReadTimeout)

	if readTimeout < defaultGatewayHTTPReadTimeout || readTimeout <= headerTimeout {
		return defaultGatewayHTTPReadHeaderTimeout, defaultGatewayHTTPReadTimeout
	}
	return headerTimeout, readTimeout
}

func newGatewayHTTPServer(addr string, handler http.Handler) *http.Server {
	headerTimeout, readTimeout := gatewayHTTPReadTimeouts()

	return &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: headerTimeout,
		ReadTimeout:       readTimeout,
		WriteTimeout:      gatewayHTTPWriteTimeout,
		IdleTimeout:       defaultGatewayHTTPIdleTimeout,
	}
}

func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}
	version := buildinfo.Current()
	log.Printf("gateway-core version=%s commit=%s built_at=%s", version.Version, version.Commit, version.BuiltAt)

	// Initialize PostgreSQL connection pool
	ctx, cancelProcess := context.WithCancel(context.Background())
	defer cancelProcess()
	db, err := sharedDB.NewPoolForService(ctx, sharedDB.ServiceGateway, cfg.DatabaseURL)
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	defer db.Close()
	log.Println("Connected to PostgreSQL")

	// Initialize Redis client
	redisOptions, err := redis.ParseURL(cfg.RedisURL)
	if err != nil {
		log.Fatalf("Failed to parse Redis URL: %v", err)
	}
	redisClient := redis.NewClient(redisOptions)
	if err := redisClient.Ping(ctx).Err(); err != nil {
		log.Fatalf("Failed to connect to Redis: %v", err)
	}
	log.Println("Connected to Redis")

	governorDisabled := os.Getenv("UAG_GOVERNOR_DISABLED") == "true"
	// 启动接流量前从 DB 回填当日和当月 budget 计数到 Redis，避免重启归零。
	bootstrapCtx, bootstrapCancel := context.WithTimeout(ctx, 30*time.Second)
	bootstrapErr := providers.BootstrapUsageFromDB(bootstrapCtx, db, redisClient)
	bootstrapCancel()
	if err := validateBudgetBootstrap(governorDisabled, bootstrapErr); err != nil {
		log.Fatalf("[startup] %v", err)
	}
	if bootstrapErr != nil {
		log.Printf("[startup] budget bootstrap skipped by governor kill switch: %v", bootstrapErr)
	}

	// One critical-audit client is shared by all customer-reachable boundaries.
	headerAuditClient := headeraudit.NewClient(cfg.ControlPlaneURL, cfg.InternalAPISecret)

	// Initialize auth middleware with database
	authMiddleware := auth.NewAuthMiddleware(db, redisClient, headerAuditClient)

	// Initialize real implementations for production
	modelResolver := handler.NewRealModelResolver(db)
	rateLimiter := handler.NewRealRateLimitChecker(redisClient)
	securityChecker := handler.NewRealSecurityChecker(cfg)
	// 只带文件 id 的附件按租户文件策略处置（与独立代理同口径，2.9.22）。
	securityChecker.SetFileReferencePolicyReader(filereference.NewCachedReader(handler.SystemSettingLoader(db), 30*time.Second))
	baseAuditWriter := handler.NewRealAuditWriter(db, redisClient)
	var auditWriter handler.AuditWriter = baseAuditWriter
	if cfg.AuditAsyncEnabled {
		auditWriter = handler.NewAsyncAuditWriter(baseAuditWriter, outbox.NewStore(db))
		log.Println("Audit async outbox enabled")
	}
	modelAPIAuditWriter := auditWriter
	var billingClient *handler.BillingClient
	if cfg.BillingEnabled {
		billingClient = handler.NewBillingClientWithMode(cfg.ControlPlaneURL, cfg.InternalAPISecret, cfg.BillingGroup, cfg.BillingMode)
		billingClient.ModelPriceConfigured = func(ctx context.Context, tenantID, modelName string) (bool, error) {
			var priced bool
			err := db.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM billing_model_prices WHERE tenant_id=$1 AND model_name=$2 AND customer_group='default' AND status='active' AND effective_at<=NOW() AND (expires_at IS NULL OR expires_at>NOW()))`, tenantID, modelName).Scan(&priced)
			return priced, err
		}

		billingClient.AllowanceRequired = func(ctx context.Context, tenantID, userID string) (bool, error) {
			if userID == "" {
				return false, nil
			}
			var limited bool
			err := db.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM users u LEFT JOIN billing_employee_settings c ON c.tenant_id=u.tenant_id LEFT JOIN billing_employee_allowances a ON a.tenant_id=u.tenant_id AND a.user_id=u.id WHERE u.tenant_id=$1 AND u.id=$2 AND COALESCE(a.monthly_micros,c.default_monthly_micros) IS NOT NULL) OR EXISTS(SELECT 1 FROM billing_wallets WHERE tenant_id=$1 AND user_id=$2 AND (prepaid_configured OR balance_micros<>0)) OR EXISTS(SELECT 1 FROM quota_policies WHERE tenant_id=$1 AND status='active' AND enforcement_mode='enforce' AND overage_action<>'notify' AND (scope_type='tenant' OR (scope_type='user' AND user_id=$2) OR (scope_type='key' AND key_id IN (SELECT id FROM internal_keys WHERE tenant_id=$1 AND user_id=$2)) OR (scope_type='team' AND scope_ref IN (SELECT unnest(string_to_array(trim(BOTH '/' FROM t.path),'/')) FROM users u JOIN teams t ON t.id=u.department_id AND t.tenant_id=u.tenant_id WHERE u.tenant_id=$1 AND u.id=$2))) AND (COALESCE(monthly_budget_micros,0)>0 OR COALESCE(daily_budget_micros,0)>0 OR monthly_budget_blocked OR daily_budget_blocked))`, tenantID, userID).Scan(&limited)
			return limited, err
		}
		modelAPIAuditWriter = handler.NewBillingAuditWriter(auditWriter, billingClient)
		log.Printf("Billing initialized mode=%s", cfg.BillingMode)
	}

	// Initialize governor (cost/quota enforcement) -- disabled by ENV kill switch
	var govDecider handler.GovernorDecider
	var quotaAdmission handler.QuotaAdmission
	if !governorDisabled {
		snap := providers.NewSnapshotReader(redisClient)
		quotaCache := providers.NewQuotaCache(db, 1*time.Minute)
		atomicAdmission := providers.NewAtomicAdmission(redisClient, quotaCache)
		atomicAdmission.SetMaxRequestDuration(gatewayRuntimeRequestTimeout)
		quotaAdmission = atomicAdmission
		dec := governor.New(snap, quotaCache)
		dec.SetTimeoutMs(50)
		// C1: team model whitelist enforcement
		teamModelsCache := providers.NewTeamModelsCache(db, 5*time.Minute)
		dec.WithModelChecker(teamModelsCache)
		govDecider = dec
		log.Println("Governor initialized (enforcement active, model whitelist enabled)")
	} else {
		log.Println("Governor DISABLED (UAG_GOVERNOR_DISABLED=true)")
	}

	// Initialize tool risk client for tool call interception
	toolRiskClient := handler.NewToolRiskClient(cfg.ControlPlaneURL, cfg.InternalAPISecret, cfg.SemanticGatewayAttestationKey)
	toolRiskClient.SetMCPConfirmationScopeSecret(cfg.MCPConfirmationScopeSecret)
	// MCP 策略拉取失败的兜底姿态统一从 config 注入（单一来源），避免与构造器自读 env 双源。
	toolRiskClient.SetMCPPolicyFailMode(cfg.MCPPolicyFailMode)
	// 阻断提示方式与文案（控制台「阻断提示」设置），后台刷新，请求路径只读缓存。
	toolRiskClient.StartBlockNoticeRefresh(context.Background(), 30*time.Second)
	log.Println("Tool risk client initialized")

	// Initialize proxy rate limiter for no-token proxy model requests
	proxyRateLimiter := handler.NewRealProxyRateLimiter(redisClient)
	log.Println("Proxy rate limiter initialized")

	// Initialize forward proxy handler
	forwardProxy := handler.NewForwardProxyHandlerWithSecret(db, cfg.ProxyDefaultTenantID, cfg.SecurityEngineURL, cfg.InternalAPISecret)
	forwardProxy.SetForwardProxyMode(cfg.GatewayForwardProxyMode)
	forwardProxy.SetWhitelistFailMode(cfg.ProxyWhitelistFailMode)
	forwardProxy.SetHeaderAuditClient(headerAuditClient)
	forwardProxy.SetRuntimeConfigClient(toolRiskClient, cfg.SecurityAuditOnly)
	forwardProxy.SetOutputStreamConfig(cfg)
	log.Println("Forward proxy handler initialized")

	// Initialize handlers with injectable dependencies (using real implementations)
	streamMetrics := relay.NewMetrics()
	chatHandler := handler.NewChatCompletionsHandler(cfg, modelResolver, rateLimiter, securityChecker, modelAPIAuditWriter, nil, toolRiskClient, proxyRateLimiter)
	chatHandler.SetRelayMetrics(streamMetrics)
	messagesHandler := handler.NewMessagesHandler(cfg, modelResolver, rateLimiter, securityChecker, modelAPIAuditWriter, nil, toolRiskClient, proxyRateLimiter)
	responsesHandler := handler.NewResponsesHandler(cfg, modelResolver, rateLimiter, securityChecker, modelAPIAuditWriter, nil, toolRiskClient, proxyRateLimiter)
	messagesHandler.SetRelayMetrics(streamMetrics)
	responsesHandler.SetRelayMetrics(streamMetrics)
	embeddingsHandler := handler.NewEmbeddingsHandler(cfg, modelResolver, rateLimiter, securityChecker, modelAPIAuditWriter, nil)
	imagesHandler := handler.NewImagesHandler(cfg, modelResolver, rateLimiter, securityChecker, modelAPIAuditWriter, nil, toolRiskClient)
	chatHandler.SetQuotaAdmission(quotaAdmission)
	messagesHandler.SetQuotaAdmission(quotaAdmission)
	responsesHandler.SetQuotaAdmission(quotaAdmission)
	embeddingsHandler.SetQuotaAdmission(quotaAdmission)
	imagesHandler.SetQuotaAdmission(quotaAdmission)
	fileUploadHandler := handler.NewFileUploadHandler(cfg, modelResolver, securityChecker, auditWriter, nil, toolRiskClient)
	if billingClient != nil {
		chatHandler.SetBillingPreflight(billingClient)
		messagesHandler.SetBillingPreflight(billingClient)
		responsesHandler.SetBillingPreflight(billingClient)
		embeddingsHandler.SetBillingPreflight(billingClient)
		imagesHandler.SetBillingPreflight(billingClient)
	}
	embeddingsHandler.SetRuntimeConfigClient(toolRiskClient)
	modelsHandler := handler.NewModelsHandler(db)
	retentionStatus := configureGatewayArtifactRetentionStore(ctx, db, cfg.RetentionStorePath, forwardProxy, chatHandler, messagesHandler, responsesHandler)
	// 日志留存失败模式按请求读控制台设置，没存时用 RETENTION_FAILURE_MODE 初值（2.9.22）。
	retentionFailureMode := func() string { return toolRiskClient.RetentionFailureMode(cfg.RetentionFailureMode) }
	// 日志留存不可用、按设置放行时记一条运行告警（平台租户，10 分钟一条；2.9.22 审查第 3 项）。
	retentionFaults := handler.NewRuntimeFaultEventWriter(auditWriter)
	retentionGuard := retentionRuntimeGuard(retentionStatus, retentionFailureMode, func(ctx context.Context) {
		retentionFaults.Record(ctx, "retention_unavailable", "日志留存不可用，按 retention_failure_mode=open 放行请求")
	})
	chatHandler.SetProxyAuth(handler.NewDBProxyKeyVerifier(db), handler.NewDBProxyUsageRecorder(db))

	// Inject routing layer (R12) -- disabled by UAG_ROUTING_DISABLED=true kill switch
	var modelRouteEngine modelrouter.Engine
	var modelRouteAlertSink *modelrouter.AlertSink
	if os.Getenv("UAG_ROUTING_DISABLED") != "true" {
		modelSelector := modelrouter.NewModelSelector()
		providerSelector := modelrouter.NewProviderSelector()
		policyCache := modelrouter.NewPolicyCache(db, 2*time.Minute)
		modelRouteAlertSink = modelrouter.NewDBAlertSink(db)
		modelRouteEngine = modelrouter.NewModelRouteEngineWithAlertSink(modelrouter.NewModelRouter(db), policyCache, modelRouteAlertSink)
		chatHandler.SetRouting(modelSelector, providerSelector, policyCache, modelRouteEngine)
		messagesHandler.SetModelRoutingEngine(modelRouteEngine)
		responsesHandler.SetModelRoutingEngine(modelRouteEngine)
		embeddingsHandler.SetModelRoutingEngine(modelRouteEngine)
		imagesHandler.SetModelRoutingEngine(modelRouteEngine)
		log.Println("Routing layer initialized (policy-based model+provider selection active)")
	} else {
		log.Println("Routing layer DISABLED (UAG_ROUTING_DISABLED=true)")
	}

	// Inject governor into handlers that call processSharedRequestPath
	if govDecider != nil {
		modelsHandler.SetGovernor(govDecider)
		chatHandler.SetGovernor(govDecider)
		messagesHandler.SetGovernor(govDecider)
		responsesHandler.SetGovernor(govDecider)
		embeddingsHandler.SetGovernor(govDecider)
		imagesHandler.SetGovernor(govDecider)
	}
	// Inject DB pool for governor alert_inbox writes
	chatHandler.SetDB(db)
	messagesHandler.SetDB(db)
	responsesHandler.SetDB(db)
	embeddingsHandler.SetDB(db)
	imagesHandler.SetDB(db)

	// P1-B 已检指纹缓存（安全三视图重构 模块 2a）：代码默认关（新能力默认关惯例），
	// compose/升级交付显式置 SECURITY_SCAN_FP_ENABLED=true。三入口共享同一 store。
	if os.Getenv("SECURITY_SCAN_FP_ENABLED") == "true" {
		lruSize := 4096
		if v, err := strconv.Atoi(os.Getenv("SECURITY_SCAN_FP_LRU_SIZE")); err == nil && v > 0 {
			lruSize = v
		}
		fpStore := scanfp.NewStore(db, lruSize)
		chatHandler.SetFingerprintStore(fpStore)
		messagesHandler.SetFingerprintStore(fpStore)
		responsesHandler.SetFingerprintStore(fpStore)
		log.Println("Scan fingerprint cache enabled (SECURITY_SCAN_FP_ENABLED=true)")
	} else {
		log.Println("Scan fingerprint cache disabled (default; set SECURITY_SCAN_FP_ENABLED=true to enable)")
	}

	// 响应缓存：只接 RESPONSE_CACHE_REDIS_URL 指向的独立实例（不持久化、有内存上限），
	// 不复用限流/预算所在的主 Redis。连接失败只记日志：每次查找都会失败并按未命中处理。
	// 是否真正生效由控制台系统设置 response_cache_enabled 决定，默认关闭。
	if cacheURL := strings.TrimSpace(os.Getenv("RESPONSE_CACHE_REDIS_URL")); cacheURL != "" {
		if cacheOptions, err := redis.ParseURL(cacheURL); err != nil {
			log.Printf("Response cache disabled: invalid RESPONSE_CACHE_REDIS_URL")
		} else {
			cacheOptions.DialTimeout = 2 * time.Second
			cacheOptions.ReadTimeout = 200 * time.Millisecond
			cacheOptions.WriteTimeout = 500 * time.Millisecond
			cacheOptions.MaxRetries = 0
			cacheClient := redis.NewClient(cacheOptions)
			pingCtx, pingCancel := context.WithTimeout(ctx, 2*time.Second)
			if err := cacheClient.Ping(pingCtx).Err(); err != nil {
				log.Printf("Response cache store not reachable yet; lookups will miss until it is: %v", err)
			} else {
				log.Println("Response cache store connected")
			}
			pingCancel()
			chatHandler.SetResponseCache(handler.NewRedisResponseCache(cacheClient))
		}
	}

	r := chi.NewRouter()
	r.Use(handler.GeminiURLCredentialGuard)
	r.Use(middleware.RequestID)
	// 注意：不再使用 chi middleware.RealIP（无条件信任 XFF/X-Real-IP，裸暴露下可被伪造）。
	// 改用基于 TRUSTED_PROXY_CIDRS 的可信代理中间件：默认不改写 RemoteAddr。
	r.Use(httpmw.TrustedRealIP)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Timeout(gatewayRuntimeRequestTimeout))

	if cfg.AgentEndpointEnabled {
		agentAPI := handler.NewAgentEndpointGateway(cfg)
		agentAPI.SetMetrics(streamMetrics)
		// decide 取租户有效策略与全局执行模式：用主流程那个有运行时刷新的客户端。
		agentAPI.SetRuntimeClient(toolRiskClient)
		agentAPI.SetIntentSemanticChecker(securityChecker)
		r.Route("/agent/v1", func(ar chi.Router) {
			ar.Post("/endpoints/register", agentAPI.ServeHTTP)
			ar.Post("/endpoints/heartbeat", agentAPI.ServeHTTP)
			ar.Post("/events", agentAPI.ServeHTTP)
			ar.Post("/probe-reports", agentAPI.ServeHTTP)
			ar.Post("/identity-events", agentAPI.ServeHTTP)
			ar.Post("/kubernetes/snapshot-runs", agentAPI.ServeHTTP)
			ar.Post("/kubernetes/snapshots", agentAPI.ServeHTTP)
			ar.Post("/decide", agentAPI.ServeHTTP)
			ar.Get("/policy", agentAPI.ServeHTTP)
		})
		// T13/T15 机器路由：hookd 以网关对外地址访问 authorize 与 approval request/claim。
		registerAgentAuthorizationRoutes(r, cfg.ControlPlaneURL)
	}

	r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		dbStatus := "ok"
		redisStatus := "ok"

		if err := db.Ping(r.Context()); err != nil {
			dbStatus = "error"
		}
		if err := redisClient.Ping(r.Context()).Err(); err != nil {
			redisStatus = "error"
		}

		status := http.StatusOK
		if dbStatus != "ok" || redisStatus != "ok" {
			status = http.StatusServiceUnavailable
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		// 未鉴权端点只返回最小存活信息；运行姿态见 /admin/v1/internal/runtime-status（复审 M-1）。
		_ = json.NewEncoder(w).Encode(handler.GatewayHealthPayload(dbStatus, redisStatus, status))
	})
	r.Get("/live", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "alive", "service": "gateway-core"})
	})
	r.Get("/ready", func(w http.ResponseWriter, r *http.Request) {
		databaseStatus, redisStatus := "ok", "ok"
		if err := db.Ping(r.Context()); err != nil {
			databaseStatus = "error"
		}
		if err := redisClient.Ping(r.Context()).Err(); err != nil {
			redisStatus = "degraded"
		}
		schemaStatus := "ok"
		if ready, err := modelaccess.SchemaReady(r.Context(), db); err != nil || !ready {
			schemaStatus = "missing_or_unavailable"
		}
		status := http.StatusOK
		if schemaStatus != "ok" || databaseStatus != "ok" || (retentionFailureMode() == "close" && retentionStatus != "ok") {
			status = http.StatusServiceUnavailable
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status": map[bool]string{true: "ready", false: "not_ready"}[status == http.StatusOK],
			"capabilities": map[string]string{
				"database": databaseStatus, "model_access_schema": schemaStatus, "redis_optional": redisStatus,
				"retention": retentionStatus, "security": "policy_managed", "billing": cfg.BillingMode,
			},
		})
	})
	r.Get("/admin/v1/internal/metrics", streamMetrics.Handler(cfg.InternalAPISecret))

	// 集成 API 透传：把 /admin/v1/eval-integration/* 反代到 control-plane，
	// 让评估平台只用网关对外端口即可访问 token 保护的集成接口（control-plane:8081 不对外）。
	r.Handle("/admin/v1/eval-integration/*", handler.EvalIntegrationProxy(cfg.ControlPlaneURL))

	integrationPolicies := handler.NewIntegrationPolicyRuntime(db, func(c context.Context) bool { return toolRiskClient.SecurityAuditOnly(c, cfg.SecurityAuditOnly) }, auditWriter)
	integrationPolicies.Start(ctx)
	userModels := auth.UserModelAuthorization(func(c context.Context, tenantID, userID string) (*modelaccess.Access, error) {
		return modelaccess.ReadAccess(c, db, tenantID, userID)
	})
	dataPlaneChain := newDataPlaneChains(authMiddleware.Middleware(cfg), userModels, integrationPolicies.Middleware)
	dataPlaneAuth := dataPlaneChain.model

	// Runtime endpoints
	registerRuntimeRoutes(
		r,
		dataPlaneAuth,
		retentionGuard,
		messagesHandler.Handler(),
		chatHandler.Handler(),
		responsesHandler.Handler(),
		embeddingsHandler.Handler(),
		imagesHandler.Handler(),
		modelsHandler.Handler(),
		fileUploadHandler.Handler(),
	)

	registerGeminiRuntimeRoutes(r, dataPlaneAuth, retentionGuard, chatHandler.Handler(), modelsHandler.Handler(), cfg)

	// MCP 批准执行端点始终注册并以内部共享密钥 fail-closed 鉴权。即使公开
	// MCP_GATEWAY_ENABLED 已关闭，也会把既有批准单明确落 failed，绝不变成 404
	mcpProxy := handler.NewMCPProxyHandler(db, toolRiskClient, cfg.SecurityAuditOnly, cfg.EnvironmentScope)
	// 运行姿态（生效执行模式、红线拉取状态）：需内部密钥，不对匿名开放。
	r.Get("/admin/v1/internal/runtime-status", handler.RuntimeStatusHandler(cfg.InternalAPISecret, toolRiskClient, mcpProxy))
	configureMCPRuntimeGuards(ctx, mcpProxy, securityChecker, cfg.MCPToolResultGuardEnabled)
	toolRiskClient.ConfigureSecurityPosture(cfg, mcpProxy, forwardProxy)
	toolRiskClient.StartSemanticRuntimeRefresh(ctx, 30*time.Second)
	mcpProxy.SetAllowedOrigins(cfg.MCPAllowedOrigins)
	if strings.EqualFold(strings.TrimSpace(os.Getenv("MCP_SESSION_STORE")), "redis") {
		// 多副本部署：Streamable 会话登记表放共享 Redis，避免 initialize 与后续请求落在不同副本时被误判为未知会话。
		mcpProxy.SetMCPSessionStore(handler.NewMCPRedisSessionStore(redisClient))
		log.Printf("MCP Streamable 会话登记表：共享 Redis（多副本）")
	} else {
		log.Printf("MCP Streamable 会话登记表：进程内存（单副本；多副本部署请设置 MCP_SESSION_STORE=redis）")
	}
	mcpExecutionHandler := handler.NewMCPConfirmationExecutionHandler(db, mcpProxy, cfg.InternalAPISecret, cfg.MCPGatewayEnabled)
	r.Post("/admin/v1/internal/mcp/confirmations/{id}/execute", mcpExecutionHandler.ServeHTTP)
	if cfg.MCPGatewayEnabled {
		// MCP 不经个人模型使用权限（见 data_plane_chains.go），仍有认证与集成策略。
		registerMCPRoutes(r, dataPlaneChain.mcp, mcpProxy)
		log.Println("MCP security gateway enabled (/mcp/{serverID})")
	}

	server := newGatewayHTTPServer(cfg.ListenAddr, r)

	go func() {
		log.Printf(
			"gateway-core starting on %s version=%s read_header_timeout=%s read_timeout=%s write_timeout=%s idle_timeout=%s api_body_limit_bytes=%d",
			cfg.ListenAddr, version.Version,
			server.ReadHeaderTimeout, server.ReadTimeout, server.WriteTimeout, server.IdleTimeout,
			cfg.APIRequestBodyLimitBytes,
		)
		// 用带 TLS 握手识别的监听器：客户端把 https:// 配到明文端口时给出明确提示，
		// 普通 HTTP 流量不受影响（见 plaintext_tls_guard.go）。
		listener, listenErr := listenGateway(server.Addr)
		if listenErr != nil {
			log.Fatalf("Server error: %v", listenErr)
		}
		if err := server.Serve(listener); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Server error: %v", err)
		}
	}()

	// Start forward proxy server on separate port
	proxyServer := &http.Server{
		Addr:         cfg.ProxyListenAddr,
		Handler:      forwardProxy,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 0, // No timeout for tunnel
	}
	var proxyWg sync.WaitGroup
	proxyWg.Add(1)
	go func() {
		defer proxyWg.Done()
		log.Printf("Forward proxy listening on %s", cfg.ProxyListenAddr)
		if err := proxyServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Proxy server error: %v", err)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	cancelProcess()

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	server.Shutdown(shutdownCtx)
	proxyServer.Shutdown(shutdownCtx)
	proxyWg.Wait()
	mcpProxy.Close() // 关闭旧 SSE 桥接的上游长流
	if modelRouteAlertSink != nil {
		alertCtx, alertCancel := context.WithTimeout(context.Background(), 2*time.Second)
		if err := modelRouteAlertSink.Close(alertCtx); err != nil {
			log.Printf("model routing alert sink shutdown: %v", err)
		}
		alertCancel()
	}
	// 排空原文留证队列（必须在关闭连接池之前）：排队中的留证写完再关库，最多等 10 秒。
	if !baseAuditWriter.DrainRawEvidence(10 * time.Second) {
		log.Printf("raw evidence queue not fully drained before shutdown; queued evidence may be lost")
	}
	db.Close()
	redisClient.Close()
	log.Println("gateway-core stopped")
}

func validateBudgetBootstrap(governorDisabled bool, bootstrapErr error) error {
	if bootstrapErr != nil && !governorDisabled {
		return fmt.Errorf("budget bootstrap failed while governor enforcement is enabled: %w", bootstrapErr)
	}
	return nil
}

func registerRuntimeRoutes(
	r chi.Router,
	authMiddleware func(http.Handler) http.Handler,
	runtimeGuard func(http.Handler) http.Handler,
	messagesHandler http.HandlerFunc,
	chatHandler http.HandlerFunc,
	responsesHandler http.HandlerFunc,
	embeddingsHandler http.HandlerFunc,
	imagesHandler http.HandlerFunc,
	modelsHandler http.HandlerFunc,
	fileUploadHandlers ...http.HandlerFunc,
) {
	r.Route("/v1", func(r chi.Router) {
		r.Use(authMiddleware)
		if runtimeGuard != nil {
			r.Use(runtimeGuard)
		}
		r.Post("/messages", messagesHandler)
		r.Post("/chat/completions", chatHandler)
		r.Post("/responses", responsesHandler)
		r.Post("/embeddings", embeddingsHandler)
		r.Post("/images/generations", imagesHandler)
		if len(fileUploadHandlers) > 0 && fileUploadHandlers[0] != nil {
			r.Post("/files", fileUploadHandlers[0])
		}
		r.Get("/models", modelsHandler)
		r.Get("/models/{model}", modelsHandler)
	})
}

// Google native requests reuse the exact protected Chat data plane after strict
// conversion. Canonicalizing the internal path also enforces the existing chat scope.
func registerGeminiRuntimeRoutes(r chi.Router, authenticate func(http.Handler) http.Handler, guard func(http.Handler) http.Handler, chat http.HandlerFunc, models http.HandlerFunc, cfg *config.Config) {
	bridgeHandler := handler.NewGeminiIngressHandler(cfg, chat, models)
	var generate http.Handler = bridgeHandler.Handler()
	if guard != nil {
		generate = guard(generate)
	}
	generate = handler.GeminiAuthentication(authenticate, generate, false)
	catalog := handler.GeminiAuthentication(authenticate, bridgeHandler.ModelsHandler(), true)
	r.Get("/v1beta/models", catalog.ServeHTTP)
	r.Get("/v1beta/models/*", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(404)
		_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]any{"code": 404, "status": "NOT_FOUND", "message": "This Google API method is not supported."}})
	})
	r.Post("/v1beta/models/*", generate.ServeHTTP)
	r.Post("/v1/models/*", generate.ServeHTTP)
	r.Handle("/v1beta/*", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(404)
		_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]any{"code": 404, "status": "NOT_FOUND", "message": "This Google API method is not supported."}})
	}))
}

// retentionRuntimeGuard：日志留存不可用时按控制台 retention_failure_mode 处置（按请求读取）；
// 放行时调 onOpenRelease 记运行告警（由 RuntimeFaultEventWriter 限频，不按请求刷屏）。
func retentionRuntimeGuard(status string, failureMode func() string, onOpenRelease func(context.Context)) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if status != "ok" && failureMode() != "close" && onOpenRelease != nil {
				onOpenRelease(r.Context())
			}
			if failureMode() == "close" && status != "ok" {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusServiceUnavailable)
				_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]string{
					"code": "retention_unavailable", "message": "required retention storage is unavailable",
				}})
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
