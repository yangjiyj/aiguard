package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"os/signal"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/alert"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/anomaly"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/audit_chain"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/billing"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/bootstrap"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/budget"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/catalog"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/config"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/diagnostics"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/directoryldap"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/forecast"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/fx"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/handler"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/identity"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/identityruntime"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/localidentity"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/modelops"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/notify"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/onboarding"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/opsalert"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/org"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/permission"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/portalbaseline"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/saving"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/saving_v2"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/skillscan"
	"github.com/yangjiyj/aiguard/packages/shared-go/buildinfo"
	sharedDB "github.com/yangjiyj/aiguard/packages/shared-go/dbhelpers"
	"github.com/yangjiyj/aiguard/packages/shared-go/logretention"
	"github.com/yangjiyj/aiguard/packages/shared-go/retentionstore"
)

const (
	standardControlPlaneRequestTimeout  = 30 * time.Second
	modelSyncControlPlaneRequestTimeout = 10 * time.Minute
	// 训练语料扫描的分片上传（每片 8 MiB）与报告/副本下载：慢速链路上一次传不完，放宽请求超时。
	// 下载 handler 还会用 http.NewResponseController 逐块延长写超时。
	corpusScanTransferRequestTimeout = 10 * time.Minute
)

var corpusScanTransferPath = regexp.MustCompile(`^/admin/v1/security/corpus-scans/[^/]+/(chunks/[0-9]+|report|masked)$`)

func controlPlaneRequestTimeout(r *http.Request) time.Duration {
	if r != nil && r.Method == http.MethodPost {
		path := r.URL.Path
		if path == "/admin/v1/models/sync" || strings.HasPrefix(path, "/admin/v1/models/sync/") {
			return modelSyncControlPlaneRequestTimeout
		}
	}
	if r != nil {
		if match := corpusScanTransferPath.FindStringSubmatch(r.URL.Path); match != nil {
			upload := strings.HasPrefix(match[1], "chunks/")
			if (upload && r.Method == http.MethodPut) || (!upload && r.Method == http.MethodGet) {
				return corpusScanTransferRequestTimeout
			}
		}
	}
	return standardControlPlaneRequestTimeout
}

func controlPlaneTimeoutMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		middleware.Timeout(controlPlaneRequestTimeout(r))(next).ServeHTTP(w, r)
	})
}

func loadIdentityRuntime(getenv func(string) string) (
	handler.IdentityRuntime,
	handler.IdentityRuntimeConfig,
	error,
) {
	cfg, err := identityruntime.LoadConfig(identityruntime.ConfigInput{
		PublicURL:          getenv("JJD_SSO_PUBLIC_URL"),
		RuntimeURL:         getenv("JJD_IDENTITY_RUNTIME_URL"),
		AllowedRuntimeURLs: getenv("JJD_IDENTITY_RUNTIME_ALLOWED_URLS"),
		ClientID:           getenv("JJD_IDENTITY_RUNTIME_CLIENT_ID"),
		ClientSecret:       getenv("JJD_IDENTITY_RUNTIME_CLIENT_SECRET"),
		AllowInsecurePublicURL: strings.EqualFold(
			strings.TrimSpace(getenv("JJD_SSO_ALLOW_INSECURE_PUBLIC_URL")), "true",
		),
	})
	if err != nil {
		return nil, handler.IdentityRuntimeConfig{}, err
	}
	client, err := identityruntime.NewClient(cfg, nil)
	if err != nil {
		return nil, handler.IdentityRuntimeConfig{}, err
	}
	return identityruntime.NewOrchestrator(client), handler.IdentityRuntimeConfig{CallbackURL: cfg.CallbackURL, IssuerURL: cfg.IssuerURL}, nil
}

func loadLocalIdentityClient(getenv func(string) string) (*localidentity.HTTPClient, string, error) {
	cfg, err := identityruntime.LoadConfig(identityruntime.ConfigInput{
		PublicURL:          getenv("JJD_SSO_PUBLIC_URL"),
		RuntimeURL:         getenv("JJD_IDENTITY_RUNTIME_URL"),
		AllowedRuntimeURLs: getenv("JJD_IDENTITY_RUNTIME_ALLOWED_URLS"),
		ClientID:           getenv("JJD_IDENTITY_RUNTIME_CLIENT_ID"),
		ClientSecret:       getenv("JJD_IDENTITY_RUNTIME_CLIENT_SECRET"),
		AllowInsecurePublicURL: strings.EqualFold(
			strings.TrimSpace(getenv("JJD_SSO_ALLOW_INSECURE_PUBLIC_URL")), "true",
		),
	})
	if err != nil {
		return nil, "", err
	}
	client, err := localidentity.NewClient(localidentity.Config{
		BaseURL: cfg.RuntimeURL, Realm: identityruntime.RealmName,
		ClientID:     getenv("JJD_IDENTITY_RUNTIME_CLIENT_ID"),
		ClientSecret: getenv("JJD_IDENTITY_RUNTIME_CLIENT_SECRET"),
	})
	if err != nil {
		return nil, "", err
	}
	return client, cfg.IssuerURL, nil
}

// secEventBridgeBatchCount bounds each ten-minute drain. The default advances
// 4,000 rows/tick without monopolising the control-plane; malformed values fail
// closed to the safe default rather than disabling backlog progress.
func secEventBridgeBatchCount() int {
	const fallback = 20
	v := strings.TrimSpace(os.Getenv("SECEVENT_BRIDGE_MAX_BATCHES_PER_TICK"))
	if v == "" {
		return fallback
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 1 || n > 100 {
		return fallback
	}
	return n
}

func main() {
	cfg, err := config.Load()

	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}
	directoryTargetPolicy, err := directoryldap.LoadTargetPolicyFromEnvironment()
	if err != nil {
		log.Fatalf("Failed to load directory LDAP target policy: %v", err)
	}
	rulePackAttestationTokens, err := loadRulePackAttestationTokens()
	if err != nil {
		log.Fatalf("Failed to load rule-pack attestation config: %v", err)
	}
	version := buildinfo.Current()
	log.Printf("control-plane version=%s commit=%s built_at=%s", version.Version, version.Commit, version.BuiltAt)

	// Initialize PostgreSQL connection pool
	ctx, stopWorkers := context.WithCancel(context.Background())
	defer stopWorkers()
	db, err := sharedDB.NewPoolForService(ctx, sharedDB.ServiceControlPlane, cfg.DatabaseURL)
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

	// Initialize repositories
	sessionRepo := repository.NewSessionRepository(redisClient)
	userRepo := repository.NewUserRepository(db)
	tenantRepo := repository.NewTenantRepository(db)
	projectRepo := repository.NewProjectRepository(db)
	projectUserRepo := repository.NewProjectUserRepository(db)
	keyRepo := repository.NewInternalKeyRepository(db)
	providerRepo := repository.NewProviderRepository(db)
	modelRepo := repository.NewModelRepository(db)
	modelPolicyRepo := repository.NewModelPolicyRepository(db)
	groupMappingRuleRepo := repository.NewGroupMappingRuleRepository(db)
	quotaPolicyRepo := repository.NewQuotaPolicyRepository(db)
	requestLogRepo := repository.NewRequestLogRepository(db)
	alertOccurrenceRepo := repository.NewAlertOccurrenceRepository(db)
	securityEventRepo := repository.NewSecurityEventRepository(db)
	portalUploadEventRepo := repository.NewPortalUploadEventRepository(db)
	chatLoginTickets := repository.NewChatLoginTicketRepository(db)
	auditDispositionRepo := repository.NewAuditDispositionRepository(db)
	usageDailyRepo := repository.NewUsageDailyRepository(db)
	rollupReadRepo := repository.NewRollupReadModelRepository(db)
	ruleSetRepo := repository.NewRuleSetRepository(db)
	ruleRepo := repository.NewRuleRepository(db)
	agentSessionRepo := repository.NewAgentSessionRepository(db)
	contentLogRepo := repository.NewContentLogRepository(db, cfg.EnvironmentScope)
	toolCallLogRepo := repository.NewToolCallLogRepository(db)
	agentEndpointRepo := repository.NewAgentEndpointRepository(db)
	agentAdminRepo := repository.NewAgentAdminRepository(db)
	agentAuthorizationRepo := repository.NewAgentAuthorizationRepository(db)
	agentDelegationRepo := repository.NewAgentDelegationRepository(db)
	agentEndpointAPI := handler.NewAgentEndpointAPI(agentEndpointRepo, toolCallLogRepo)
	kubernetesSnapshotAPI := handler.NewAgentKubernetesSnapshotAPI(repository.NewAgentKubernetesAssetRepository(db))
	agentOperationRepo := repository.NewAgentOperationRepository(db)
	toolRiskConfigRepo := repository.NewToolRiskConfigRepository(db)
	agentGuardPolicyRepo := repository.NewAgentGuardPolicyRepository(db)
	systemRepo := repository.NewSystemRepository(db)
	proxyWhitelistRepo := repository.NewProxyWhitelistRepository(db)
	reverseProxyRouteRepo := repository.NewReverseProxyRouteRepository(db)
	caCertificatesRepo := repository.NewCACertificateRepository(db)
	teamRepo := repository.NewTeamRepository(db)
	teamMemberRepo := repository.NewTeamMemberRepository(db)
	teamModelRepo := repository.NewTeamModelRepository(db)
	identitySourceRepo := repository.NewIdentitySourceRepository(db)
	identityDepartmentMappingRepo := repository.NewIdentityDepartmentMappingRepository(db)
	directorySourceRepo := repository.NewDirectorySourceRepository(db)
	pauseLogRepo := repository.NewPauseLogRepository(db)
	snapshotReader := budget.NewSnapshotReader(redisClient)
	orgService := org.NewService(teamRepo, teamMemberRepo, quotaPolicyRepo)
	oidcTester := identity.NewOIDCTester()
	identityRuntime, identityRuntimeConfig, identityRuntimeErr := loadIdentityRuntime(os.Getenv)
	if identityRuntimeErr != nil {
		log.Printf("[WARN] enterprise SSO publication is disabled: identity runtime configuration unavailable")
	} else {
		log.Printf("enterprise SSO publication runtime initialized")
	}
	directoryRuntime, directoryRuntimeErr := loadDirectoryRuntime(os.Getenv)
	if directoryRuntimeErr != nil {
		log.Printf("[WARN] directory synchronization runtime is disabled: configuration unavailable")
	} else {
		log.Printf("directory synchronization runtime initialized")
	}
	localIdentityClient, localIdentityIssuer, localIdentityErr := loadLocalIdentityClient(os.Getenv)
	var localIdentityProvisioner localidentity.Provisioner
	if localIdentityErr != nil {
		if !localIdentityRuntimeConfigured(os.Getenv) {
			localIdentityProvisioner, localIdentityErr = localidentity.NewStandaloneProvisioner(db)
			if localIdentityErr != nil {
				log.Fatalf("initialize standalone local account provisioner: %v", localIdentityErr)
			}
			log.Printf("local accounts use control-plane credentials; identity runtime is not configured")
		} else {
			log.Printf("[WARN] local identity management is disabled: identity runtime configuration unavailable")
		}
	} else {
		localIdentityProvisioner, localIdentityErr = localidentity.NewProvisioner(db, localIdentityIssuer)
		if localIdentityErr != nil {
			localIdentityClient = nil
			log.Printf("[WARN] local identity management is disabled: provisioner configuration unavailable")
		} else {
			log.Printf("local identity management runtime initialized")
		}
	}

	nativeServiceProvisioner, err := localidentity.NewNativeServiceProvisioner(db)
	if err != nil {
		log.Fatalf("initialize native service provisioner: %v", err)
	}

	fxRepo := fx.NewRepository(db)
	fxSvc := fx.NewService(fxRepo)

	// Audit chain WORM (P10) - ENV fail-loud
	auditKey := os.Getenv("UAG_AUDIT_HMAC_KEY")
	{
		var chainLen int64
		_ = db.QueryRow(context.Background(), `SELECT count(*) FROM audit_chain`).Scan(&chainLen)
		if auditKey == "" && chainLen > 0 {
			log.Fatal("UAG_AUDIT_HMAC_KEY required: audit_chain has data but no key configured")
		}
	}
	auditKeyIsDefault := auditKey == ""
	if auditKeyIsDefault {
		auditKey = "dev-insecure-key"
		log.Printf("[WARN] UAG_AUDIT_HMAC_KEY not set, using insecure dev key (dev only)")
	}
	chainRepo := repository.NewAuditChainRepository(db, []byte(auditKey))
	auditAppender := audit_chain.NewAppender(chainRepo, os.Getenv("UAG_AUDIT_CHAIN_DISABLED") == "true")

	// 计费/审计链运维告警：进告警组、留消息中心、新告警走告警渠道外发。
	opsAlerts := opsalert.NewEmitter(
		repository.NewAlertGroupRepository(db),
		alert.NewInboxService(repository.NewAlertInboxRepository(db)),
		notify.NewDispatcher(repository.NewNotifyChannelsRepository(db)),
	)

	// Initialize handler dependencies
	var retentionBlobStore retentionstore.Store
	if rcfg, rerr := retentionstore.LoadConfig(ctx, db, os.Getenv("RETENTION_STORE_PATH")); rerr == nil {
		if store, serr := retentionstore.NewStore(rcfg); serr == nil {
			retentionBlobStore = store
			log.Printf("retention blob store initialized backend=%s", rcfg.Backend)
		} else {
			log.Printf("retention blob store init failed: %v", serr)
		}
	} else {
		log.Printf("retention blob config load failed: %v", rerr)
	}

	var billingStore *billing.Store
	walletBillingEnabled := cfg.BillingEnabled && (cfg.BillingMode == config.BillingModePrepaid || cfg.BillingMode == config.BillingModeMetering)
	billingCompensationMonitor := billing.NewReconciliationMonitor(walletBillingEnabled)
	if cfg.BillingEnabled {
		billingStore = billing.NewStore(db)
		// 关键计费审计（切换币种、作废其他币种价格）与业务变更同一事务写入审计链；审计链被显式关闭时不接入。
		if os.Getenv("UAG_AUDIT_CHAIN_DISABLED") != "true" {
			billingStore.SetAuditChain(chainRepo)
		}
		log.Printf("customer billing enabled mode=%s", cfg.BillingMode)
		// Retain cleanup of holds admitted before the wallet funding migration.
		startEmployeeReservationPrune(ctx, billingStore, opsAlerts.ReportReservationLeak)
		if walletBillingEnabled {
			startMonthlyWalletGrants(ctx, billingStore.GrantMonthlyWallets)
			startBillingReconciliation(ctx, billingStore, billingCompensationMonitor, cfg.BillingMode == config.BillingModeMetering)
			startBillingRequestLeaseCleanup(ctx, billingStore)
		}
	}
	onboardingService := onboarding.NewService(db)
	// 运维诊断机器人：只读执行器使用独立连接池；失败时禁用诊断，接口统一返回 503。
	var diagEngine *diagnostics.Engine
	if diagExec, derr := diagnostics.NewExec(cfg.DatabaseURL); derr != nil {
		log.Printf("[diagnostics] 初始化只读执行器失败，诊断功能已禁用: %v", derr)
	} else {
		defer diagExec.Close()
		diagEngine = diagnostics.NewEngine(db, diagExec, diagnostics.NewAgentClientFromEnv())
		diagEngine.StartMaintenance(ctx)
	}
	// MCP 内置红线处置配置仓库（经构造参数注入，不改共享的 Dependencies）。
	mcpRedlineSettingsStore := repository.NewMCPRedlineSettingsRepository(db)
	deps := &handler.Dependencies{
		IntegrationRepo:              repository.NewIntegrationRepository(db),
		IntegrationGatewayURL:        cfg.GatewayCoreURL,
		BillingStore:                 billingStore,
		BillingMode:                  cfg.BillingMode,
		FirstAdminInitializer:        onboardingService,
		ChatDefaultsEnsurer:          onboardingService,
		SessionRepo:                  sessionRepo,
		UserRepo:                     userRepo,
		DepartmentStore:              teamRepo,
		LocalIdentityClient:          localIdentityClient,
		LocalIdentityProvisioner:     localIdentityProvisioner,
		LocalIdentityCleanupQ:        localidentity.NewPostgresCleanupQueue(db),
		NativeServiceProvisioner:     nativeServiceProvisioner,
		TenantRepo:                   tenantRepo,
		ProjectRepo:                  projectRepo,
		ProjectUserRepo:              projectUserRepo,
		UserIdentityLinkLookup:       repository.NewUserIdentityLinkRepository(db),
		KeyRepo:                      keyRepo,
		QuotaKeyLookup:               keyRepo,
		QuotaDepartmentScopeLookup:   teamMemberRepo,
		QuotaProjectMembershipLookup: projectUserRepo,
		QuotaUserLookup:              userRepo,
		ProviderRepo:                 providerRepo,
		ModelRepo:                    modelRepo,
		ModelPolicyRepo:              modelPolicyRepo,
		GroupMappingRuleRepo:         groupMappingRuleRepo,
		QuotaPolicyRepo:              quotaPolicyRepo,
		RequestLogRepo:               requestLogRepo,
		PortalCallRecordReader:       requestLogRepo,
		ModelEvalStatusRepo:          requestLogRepo,
		SecurityEventRepo:            securityEventRepo,
		AlertOccurrenceRepo:          alertOccurrenceRepo,
		PortalUploadEventRepo:        portalUploadEventRepo,
		ChatLoginTickets:             chatLoginTickets,
		EmployeeKeyRepo:              repository.NewEmployeeAPIKeyRepository(db),
		// 智能检测控制台 overview 读源：拉窗内 semantic_attack 命中事件聚合 cascade/hits。
		// 不接线 → deps.SemanticEventReader==nil → 生产 cascade/hits 恒 0（GetSmartDetectionOverview
		// 按空聚合）。securityEventRepo 经 ListSemanticSince 满足 SemanticEventReader（编译期已断言）。
		SemanticEventReader: securityEventRepo,
		// fp_suppressed 跨桶计数源（SFIX-1(c)）：误报压制落在 security_check 桶而非 semantic_attack，
		// 故独立于 SemanticEventReader。securityEventRepo 经 CountTriageSuppressedSince 满足。
		TriageSuppressedReader:     securityEventRepo,
		AuditDispositionRepo:       auditDispositionRepo,
		ForwardProxyAccessRepo:     requestLogRepo,
		EvidenceRunRepo:            requestLogRepo,
		EvidenceTimelineRepo:       requestLogRepo,
		AccessRollupRepo:           rollupReadRepo,
		RetentionStore:             retentionBlobStore,
		UsageDailyRepo:             usageDailyRepo,
		UsageSummaryRepo:           usageDailyRepo,
		UsageRollupRepo:            rollupReadRepo,
		RuleSetRepo:                ruleSetRepo,
		RuleRepo:                   ruleRepo,
		ContentExceptionKeyLookup:  keyRepo,
		ContentExceptionTeamLookup: teamRepo,
		AgentSessionRepo:           agentSessionRepo,
		ContentLogRepo:             contentLogRepo,
		ContentAuditSelector:       handler.ContentAuditSelectorDependencies{Users: userRepo, Departments: teamMemberRepo},
		RetainedArtifactRepo:       requestLogRepo,
		ContentLogReader:           contentLogRepo,
		ToolCallLogRepo:            toolCallLogRepo,
		AgentOperationRepo:         agentOperationRepo,
		ProtectionSettingsStore:    repository.NewProtectionSettingsRepository(db),
		ToolRiskConfigRepo:         toolRiskConfigRepo,
		AgentEndpointBundleRepo:    agentEndpointRepo,
		AgentGuardPolicyRepo:       agentGuardPolicyRepo,
		AgentGuardBehaviorRepo:     agentGuardPolicyRepo,
		PolicyCenterBehaviorRepo:   repository.NewPolicyCenterAgentBehaviorRepository(db),
		SkillAssetsRepo:            repository.NewSkillAssetsRepository(db),
		SkillArchiveScanner:        skillscan.NewScanner(skillscan.Limits{}),
		ConfirmationReplayer:       handler.NewConfirmationReplayer(toolCallLogRepo),
		MCPConfirmationExecutor:    handler.NewGatewayMCPConfirmationExecutor(cfg.GatewayCoreURL, cfg.InternalAPISecret),
		MCPConfirmationScopeSecret: cfg.MCPConfirmationScopeSecret,
		DispositionEnforcer:        handler.NewDispositionEnforcer(keyRepo, userRepo, sessionRepo, pauseLogRepo, redisClient),
		SystemRepo:                 systemRepo,
		ProxyWhitelistRepo:         proxyWhitelistRepo,
		ReverseProxyRouteRepo:      reverseProxyRouteRepo,
		CACertificatesRepo:         caCertificatesRepo,
		// Org module (T17)
		TeamRepo:       teamRepo,
		TeamMemberRepo: teamMemberRepo,
		OrgService:     orgService,
		// IAM enterprise
		TeamModelRepo:        teamModelRepo,
		UserModelRepo:        repository.NewUserModelRepository(db),
		UserAccountMergeRepo: repository.NewUserAccountMergeRepository(db),
		// Budget module (T22)
		PauseLogRepo:                pauseLogRepo,
		BudgetSnapshot:              snapshotReader,
		RedisClient:                 redisClient,
		SecurityEngineURL:           cfg.SecurityEngineURL,
		SecurityEngineInternalToken: cfg.InternalAPISecret,
		CatalogFactory:              catalog.NewFactory(),
		ModelProber:                 catalog.NewHTTPModelProber(),
		ModelSyncProofSecret:        cfg.InternalAPISecret,
		ModelSyncVerifyGate:         handler.NewModelSyncVerifyGate(),
		// FX module (T33)
		FxService: fxSvc,
		// Saving module (T37)
		SavingDB: db,
		DB:       db,
		// Alert inbox + notify channels (T42)
		AlertInboxRepo:     repository.NewAlertInboxRepository(db),
		AlertService:       alert.NewInboxService(repository.NewAlertInboxRepository(db)),
		NotifyChannelsRepo: repository.NewNotifyChannelsRepository(db),
		NotifyDispatcher:   notify.NewDispatcher(repository.NewNotifyChannelsRepository(db)),
		AlertGroupRepo:     repository.NewAlertGroupRepository(db),
		// Proxy access keys (P1-10, task 1.7)
		ProxyAccessKeyRepo: repository.NewProxyAccessKeysRepository(db),
		// MCP servers (P1-22, task 1.8)
		MCPServerRepo: repository.NewMCPServersRepository(db),
		// MCP 安全网关（能力识别 + 权限管控）
		MCPToolRepo:        repository.NewMCPToolsRepository(db),
		MCPPolicyRepo:      repository.NewMCPPoliciesRepository(db),
		MCPSupplyChainRepo: repository.NewMCPToolsRepository(db),
		// Provider price snapshots (P2-2, task 1.9)
		ProviderPriceSnapshotRepo: repository.NewProviderPriceSnapshotRepository(db),
		// Audit chain WORM (P10)
		AuditChainRepo: chainRepo,
		AuditAppender:  auditAppender,
		AuditIntegrity: handler.NewAuditIntegrityStatus(auditKeyIsDefault),
		OpsAlerts:      opsAlerts,
		// Savings config (P15)
		SavingsConfigRepo: repository.NewCostGovernanceConfigRepository(db),
		// Anomaly detection (P18)
		AnomalyEventRepo: repository.NewAnomalyEventRepository(db),

		// 组织称谓设置 (org-units Phase B)
		AppSettingsRepo: repository.NewAppSettingsRepository(db),
		// 身份与访问 — 登录与单点登录 (identity-access-frontdoor)
		IdentitySourceRepo:            identitySourceRepo,
		IdentitySourceLookup:          identitySourceRepo,
		IdentityDepartmentMappingRepo: identityDepartmentMappingRepo,
		DirectorySourceRepo:           directorySourceRepo,
		DirectorySyncPreviewRepo:      repository.NewDirectorySyncPreviewRepository(db),
		OIDCTester:                    oidcTester,
		DirectoryTester:               directoryldap.Client{Policy: directoryTargetPolicy},
		DirectoryTargetPolicy:         directoryTargetPolicy,
		DirectoryRuntime:              directoryRuntime,
		IdentityRuntime:               identityRuntime,
		IdentityRuntimeConfig:         identityRuntimeConfig,
		RulePackAttestationTokens:     rulePackAttestationTokens,
		SemanticGatewayAttestationKey: cfg.SemanticGatewayAttestationKey,
	}
	// 2.9.22：身份源与 LDAP 出站设置改为控制台可配（库里没有键时部署环境变量作初值）。
	identity.SetEgressSettingsSource(handler.IdentityEgressSettingsSource(deps))
	// 平台自身出站被防跳板拒绝时记安全事件（设计 5.2）。
	platformEgressEvents := repository.NewPlatformEgressEventRecorder(db, repository.PlatformEgressEventWindow)
	recordPlatformEgress := func(ctx context.Context, tenantID, kind, target string) {
		writeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
		defer cancel()
		if _, err := platformEgressEvents.Record(writeCtx, tenantID, cfg.EnvironmentScope, kind, target); err != nil {
			log.Printf("platform egress denial event not recorded (kind=%s): %v", kind, err)
		}
	}
	notify.EgressDeniedRecorder = recordPlatformEgress
	identity.EgressDeniedRecorder = func(host string) {
		recordPlatformEgress(context.Background(), handler.PlatformTenantID, "identity_provider", host)
	}
	directoryldap.EgressDeniedRecorder = func(ctx context.Context, host string) {
		recordPlatformEgress(ctx, handler.PlatformTenantID, "ldap", host)
	}
	deps.DirectoryTester = directoryldap.Client{Policy: directoryTargetPolicy, PolicySource: func(ctx context.Context) directoryldap.TargetPolicy {
		return handler.DirectoryTargetPolicyFor(ctx, deps)
	}}
	// 有效策略下发防护项设置，缺仓库会让网关把“没有设置”当成全默认，所以启动时必须有。
	if deps.ProtectionSettingsStore == nil {
		log.Fatal("protection settings store is not configured")
	}
	agentAdminAPI := handler.NewAgentAdminAPI(agentAdminRepo, deps)
	agentUnifiedAssetAPI := handler.NewAgentUnifiedAssetAPI(repository.NewAgentUnifiedAssetRepository(db), deps)
	agentDestinationApprovalAPI := handler.NewAgentDestinationApprovalAPI(repository.NewAgentDestinationApprovalRepository(db), deps)
	nativeEventAPI := handler.NewNativeEventAPI(repository.NewNativeEventLedger(db))
	agentAuthorizationAPI := handler.NewAgentAuthorizationAPI(agentAuthorizationRepo, deps)
	agentAuthorizationApprovalAPI := handler.NewAgentAuthorizationApprovalAPI(agentAuthorizationRepo, deps)
	agentDelegationAPI := handler.NewAgentDelegationAPI(agentAuthorizationRepo, agentDelegationRepo)
	agentDelegationInvestigationAPI := handler.NewAgentDelegationInvestigationAPI(agentDelegationRepo)
	agentEndpointAPI.Deps = deps
	agentEndpointAPI.AuthorizationRepo = agentAuthorizationRepo

	// FX seed (T34)
	{
		fxSeedPath := os.Getenv("UAG_FX_SEED_PATH")
		if fxSeedPath == "" {
			fxSeedPath = "/etc/uag/seeds/fx/latest.json"
		}
		fxSeeds, err := fx.LoadSeed(fxSeedPath)
		if err == nil {
			_ = fx.ApplySeedIfEmpty(ctx, fxSvc, fxSeeds)
		}
	}

	handler.StartCatalogSyncScheduler(ctx, db, deps)
	modelOperations := modelops.NewService(modelops.NewPostgresStore(db), handler.NewModelOperationsExecutor(deps))
	modelOperationsHTTP := handler.NewModelOperationsHandler(deps, modelOperations)
	modelOperationsJobsHTTP := handler.NewModelOperationsJobsHandler(deps, modelOperations, handler.NewPostgresModelOperationsJobStore(db), ctx)
	// 训练语料扫描：后台逐个执行排队任务，每小时清理过期报告与副本（规格第 5 节）。
	corpusScanHTTP := handler.NewCorpusScanHandler(deps, handler.NewPostgresCorpusScanStore(db), ctx)
	modelOperationsDone := make(chan struct{})
	go func() {
		defer close(modelOperationsDone)
		if err := modelOperations.Run(ctx, "control-plane-"+strconv.Itoa(os.Getpid())); err != nil && ctx.Err() == nil {
			log.Printf("model operations scheduler stopped: %v", err)
		}
	}()
	startAccessContentRetentionCron(ctx, requestLogRepo)
	// 本地身份（Keycloak）孤儿清理：删除用户后删除 Keycloak 用户失败的，在持久化队列里指数退避重试；
	// 达到最大次数仍失败则告警并写审计。账号在入队前已被禁用，无法登录。
	if localIdentityClient != nil {
		cleanupQueue := localidentity.NewPostgresCleanupQueue(db)
		go (&localidentity.CleanupWorker{
			Queue: cleanupQueue, Client: localIdentityClient,
			OnExhausted: func(c context.Context, it localidentity.CleanupItem) {
				_ = cleanupQueue.RecordCleanupExhausted(c, it)
				_, _ = opsAlerts.Emit(c, opsalert.Event{TenantID: it.TenantID, Type: opsalert.TypeLocalIdentityCleanupExhausted,
					ScopeKey: "fp:" + it.Fingerprint, ScopeLabel: "指纹 " + it.Fingerprint[:12], Count: 1,
					Detail: map[string]any{"user_id": it.UserID, "subject_fingerprint": it.Fingerprint, "attempts": it.Attempts + 1}})
			},
		}).Run(ctx, 30*time.Second)
	}
	// 计费类告警进告警组：每分钟扫描预算拒绝、未定价拒绝、结算失败与钱包透支。
	go runBillingOpsAlertScanner(ctx, opsalert.NewBillingScanner(db, opsAlerts), time.Minute)
	// 预算 80% / 100% 预警：员工、部门、组织每个周期每个阈值各通知一次（持久化去重），只发通知不参与断流。
	if billingStore != nil {
		go runBillingOpsAlertScanner(ctx, opsalert.NewBudgetThresholdScanner(db, billingStore, snapshotReader, opsAlerts), 5*time.Minute)
	}
	// 审计链守护：启动报告默认密钥、每天完整校验一次、每分钟上报丢失的非关键审计记录。
	go (&handler.AuditChainHealth{
		Verifier: chainRepo, Status: deps.AuditIntegrity, Alerts: opsAlerts, Dropped: auditAppender.TakeDropped,
	}).Run(ctx, 24*time.Hour, time.Minute)
	startLogRetentionCron(ctx, db, contentLogRepo, toolCallLogRepo, requestLogRepo)
	// 执行模式（生效值或配置值）一变化就写高危告警到收件箱，含无身份的直接写库。
	handler.StartExecutionModeWatch(ctx, deps, repository.NewAlertGroupRepository(db))
	startAgentRetentionCron(ctx, agentEndpointRepo, resolveAgentEventRetentionDays(os.Getenv("AGENT_EVENT_RETENTION_DAYS")))
	startAgentAuthorizationRetentionCron(ctx, agentAuthorizationRepo)

	// Saving Calculator cron (T36) - aggregates savings every 5 minutes.
	savingCalc := saving.NewCalculator(db, fxSvc, budget.NewWatermark(db))
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		if n, err := savingCalc.RunOnce(ctx); err != nil {
			log.Printf("[saving] startup run failed: %v", err)
		} else if n > 0 {
			log.Printf("[saving] startup aggregated %d new rows", n)
		}
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if n, err := savingCalc.RunOnce(ctx); err != nil {
					log.Printf("[saving] cron failed: %v", err)
				} else if n > 0 {
					log.Printf("[saving] aggregated %d new rows", n)
				}
			}
		}
	}()

	// saving_v2 crons (P15): snapshot/negotiator/breaker/labor
	snapshotCron := saving_v2.NewSnapshotCron(db)
	go func() {
		if n, err := snapshotCron.RunOnce(ctx); err != nil {
			log.Printf("[snapshot_cron] startup failed: %v", err)
		} else if n > 0 {
			log.Printf("[snapshot_cron] startup: %d snapshots written", n)
		}
		ticker := time.NewTicker(24 * time.Hour)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if n, err := snapshotCron.RunOnce(ctx); err != nil {
					log.Printf("[snapshot_cron] failed: %v", err)
				} else if n > 0 {
					log.Printf("[snapshot_cron] %d snapshots", n)
				}
			}
		}
	}()

	negotiatorCron := saving_v2.NewNegotiator(db, fxSvc, budget.NewWatermark(db))
	go func() {
		if n, err := negotiatorCron.RunOnce(ctx); err != nil {
			log.Printf("[negotiator] startup failed: %v", err)
		} else if n > 0 {
			log.Printf("[negotiator] startup: %d rows", n)
		}
		ticker := time.NewTicker(24 * time.Hour)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if n, err := negotiatorCron.RunOnce(ctx); err != nil {
					log.Printf("[negotiator] failed: %v", err)
				} else if n > 0 {
					log.Printf("[negotiator] %d rows", n)
				}
			}
		}
	}()

	// 持续消费待判定队列，失败或锁竞争后重试；不因启动时暂时无数据而停止。
	go func() {
		for ctx.Err() == nil {
			n, err := requestLogRepo.BackfillInternalTitleRequests(ctx, 500)
			delay := 500 * time.Millisecond
			if err != nil {
				log.Printf("[internal-title] 回填失败: %v", err)
				delay = 10 * time.Second
			} else if n == 0 {
				delay = 5 * time.Second
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(delay):
			}
		}
	}()

	// 告警排查问题（案件）物化：后台回填历史、消化待重算队列（迁移 1002/1003）。读接口在读之前也会先消化
	// 本租户的队列；回填完成前读接口照旧实时查询。JJD_ALERT_CASE_STORE=off 时读接口不用物化表，维护照常。
	go func() {
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for {
			if n, err := alertOccurrenceRepo.MaintainAlertCases(ctx, 3*time.Second); err != nil {
				log.Printf("[alert-cases] maintenance failed: %v", err)
			} else if n >= 100 {
				log.Printf("[alert-cases] maintained %d batches/items", n)
			}
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()

	// 维护 request_logs 预计算列 risk_state / has_retained_content：启动批量回填历史，
	// 之后每 2 分钟增量刷新最近 15 分钟窗口（吸收延迟到达的 security_events 与留存内容）。
	// 读路径据此走 partial 索引，避免对 43 万+ 行做全表实时 jsonb 风险/内容计算。
	go func() {
		for {
			n, err := requestLogRepo.BackfillRiskColumns(ctx, 5000)
			if err != nil {
				log.Printf("[risk-columns] backfill failed: %v", err)
				break
			}
			if n == 0 {
				break
			}
			log.Printf("[risk-columns] backfilled %d rows", n)
			select {
			case <-ctx.Done():
				return
			case <-time.After(500 * time.Millisecond):
			}
		}
		ticker := time.NewTicker(2 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if _, err := requestLogRepo.RefreshRecentRiskColumns(ctx, 15*time.Minute); err != nil {
					log.Printf("[risk-columns] refresh failed: %v", err)
				}
				// 正文清理、留存正文变化、超出刷新窗口才到的安全事件会让触发器（迁移 1006）把预算列置空，
				// 读路径期间回退原表达式；这里按部分索引（迁移 1007）把置空的行重新算出，每轮最多 10 批。
				for batch := 0; batch < 10; batch++ {
					n, err := requestLogRepo.BackfillRiskColumns(ctx, 5000)
					if err != nil {
						log.Printf("[risk-columns] recompute cleared rows failed: %v", err)
						break
					}
					if n < 5000 {
						break
					}
				}
			}
		}
	}()

	breakerCron := saving_v2.NewBreaker(db, fxSvc, budget.NewWatermark(db))
	go func() {
		if n, err := breakerCron.RunOnce(ctx); err != nil {
			log.Printf("[breaker] startup failed: %v", err)
		} else if n > 0 {
			log.Printf("[breaker] startup: %d rows", n)
		}
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if n, err := breakerCron.RunOnce(ctx); err != nil {
					log.Printf("[breaker] failed: %v", err)
				} else if n > 0 {
					log.Printf("[breaker] %d rows", n)
				}
			}
		}
	}()

	cgcRepo := repository.NewCostGovernanceConfigRepository(db)
	laborCron := saving_v2.NewLabor(db, fxSvc, budget.NewWatermark(db), cgcRepo)
	go func() {
		if n, err := laborCron.RunOnce(ctx); err != nil {
			log.Printf("[labor] startup failed: %v", err)
		} else if n > 0 {
			log.Printf("[labor] startup: %d rows", n)
		}
		ticker := time.NewTicker(1 * time.Hour)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if n, err := laborCron.RunOnce(ctx); err != nil {
					log.Printf("[labor] failed: %v", err)
				} else if n > 0 {
					log.Printf("[labor] %d rows", n)
				}
			}
		}
	}()

	// Anomaly scanner cron (P18) - run on startup then every hour
	anomalyEventRepo := repository.NewAnomalyEventRepository(db)
	anomalyInbox := alert.NewInboxService(repository.NewAlertInboxRepository(db))
	anomalyScanner := anomaly.NewScanner(db, anomalyEventRepo, anomalyInbox)
	deps.AnomalyScanner = anomalyScanner
	go func() {
		if n, err := anomalyScanner.RunOnce(ctx); err != nil {
			log.Printf("[anomaly] startup failed: %v", err)
		} else {
			log.Printf("[anomaly] startup: %d new events", n)
		}
		ticker := time.NewTicker(1 * time.Hour)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if n, err := anomalyScanner.RunOnce(ctx); err != nil {
					log.Printf("[anomaly] failed: %v", err)
				} else if n > 0 {
					log.Printf("[anomaly] %d new events", n)
				}
			}
		}
	}()

	// Security event → alert inbox bridge cron (P0-2) - bridges high/critical security_events to inbox + notify
	// P1/P2 误报治理:同一个 alert_groups 仓库同时供组折叠与误报处置静默;
	// securityEventRepo 兼任规则日计数来源;secret 首见登记表见迁移 098。
	secEventAlertGroupRepo := repository.NewAlertGroupRepository(db)
	secEventBridge := alert.NewSecEventBridge(
		securityEventRepo,
		alert.NewInboxService(repository.NewAlertInboxRepository(db)),
		notify.NewDispatcher(repository.NewNotifyChannelsRepository(db)),
	).WithAlertGroups(secEventAlertGroupRepo).
		WithGroupCounters(secEventAlertGroupRepo).
		WithFPDispositions(secEventAlertGroupRepo).
		WithRuleDailyCounts(securityEventRepo).
		WithSecretNovelty(repository.NewSecretFlowFirstSeenRepository(db))
	deps.SecEventBridge = secEventBridge
	go secEventBridge.RunPeriodic(ctx, secEventBridgeBatchCount(), func(n int, err error) {
		if err != nil {
			log.Printf("[secevent_bridge] failed: %v", err)
		} else if n > 0 {
			log.Printf("[secevent_bridge] %d events bridged", n)
		}
	})

	// P1-D 存量回算：给历史 security_events 回填 alert_group_id 并重算组主指标。
	// 一次性任务（done 标记存 system_settings），分批限速、断点续跑，不阻塞启动。
	groupBackfill := alert.NewGroupBackfill(db, secEventAlertGroupRepo, repository.NewSystemRepository(db))
	go func() {
		if err := groupBackfill.Run(ctx); err != nil && ctx.Err() == nil {
			log.Printf("[group_backfill] aborted: %v (断点已存，下次启动续跑)", err)
		}
	}()

	// Alert group TTL auto-close cron (P0-A) — resolves stale zombie groups so the
	// inbox reflects the active surface, not a never-dispositioned backlog.
	// The switch is read on EVERY hourly tick: system_settings alert_ttl_enabled /
	// alert_group_ttl_days first (toggled from 系统设置), env ALERT_TTL_ENABLED /
	// ALERT_GROUP_TTL_DAYS as fallback; with neither set nothing is closed (same as
	// before). AutoCloseStale is fail-closed (only stage='input', non-canary groups
	// without high-value findings, plus quiet runtime-fault groups), and an
	// unreadable settings table skips the tick. No startup run — the first sweep
	// waits one tick, giving a freshly deployed process room.
	alertTTLSettings := repository.NewSystemRepository(db)
	go func() {
		ticker := time.NewTicker(1 * time.Hour)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				n, cfg, err := alert.RunAlertTTLTick(ctx, alertTTLSettings, secEventAlertGroupRepo, os.Getenv, time.Now().UTC())
				if err != nil {
					log.Printf("[alert_ttl] tick skipped/failed (source=%s): %v", cfg.EnabledSource, err)
				} else if n > 0 {
					log.Printf("[alert_ttl] auto-closed %d stale alert groups (ttl=%dd, source=%s)", n, cfg.TTLDays, cfg.EnabledSource)
				}
			}
		}
	}()
	if cfg, err := alert.LoadAlertTTLConfig(ctx, alertTTLSettings, os.Getenv); err == nil {
		log.Printf("[alert_ttl] hourly check started (enabled=%v ttl=%dd source=%s; 可在系统设置中开关)", cfg.Enabled, cfg.TTLDays, cfg.EnabledSource)
	}

	// Forecast worker cron (P21) - processes pending forecast jobs every 10 seconds
	forecastJobRepo := repository.NewForecastJobRepository(db)
	forecastInbox := alert.NewInboxService(repository.NewAlertInboxRepository(db))
	forecastWorker := forecast.NewWorker(forecastJobRepo, db, forecastInbox)
	deps.ForecastJobRepo = forecastJobRepo
	deps.ForecastWorker = forecastWorker

	// R15: routing policies
	deps.RoutingPolicyRepo = repository.NewRoutingPolicyRepository(db)
	deps.ModelRoutingRepo = repository.NewModelRoutingRepository(db)

	// RBAC (UAG-spec-rbac)
	permGrantRepo := repository.NewPermissionGrantRepository(db)
	loginHistoryRepo := repository.NewUserLoginHistoryRepository(db)
	systemRolesRepo := repository.NewSystemRolesRepository(db)
	permCache := permission.NewGrantsCache()
	permChecker := permission.NewChecker(db, permCache)
	dryRun := !permission.RBACEnforceEnabled()
	deps.PermissionGrantRepo = permGrantRepo
	deps.LoginHistoryRepo = loginHistoryRepo
	deps.ConsoleSecurity = repository.NewConsoleUserSecurityRepository(db)
	if runtimeURL := os.Getenv("JJD_IDENTITY_RUNTIME_URL"); runtimeURL != "" {
		deps.PortalBaselineFetcher = &portalbaseline.HTTPFetcher{
			BaseURL: runtimeURL, Realm: identityruntime.RealmName,
			ClientID: os.Getenv("JJD_IDENTITY_RUNTIME_CLIENT_ID"), ClientSecret: os.Getenv("JJD_IDENTITY_RUNTIME_CLIENT_SECRET"),
		}
	}
	deps.SystemRolesRepo = systemRolesRepo
	deps.PermissionChecker = permChecker
	identityBinding := newIdentityBindingRuntime(db, permChecker)
	deps.IdentityBindingService = identityBinding.Service
	deps.IdentityCacheInvalidationReconciler = identityBinding.Reconciler
	go func() {
		if err := identityBinding.Reconciler.Run(ctx, identityBinding.WorkerConfig); err != nil {
			log.Printf("[identity_binding] cache invalidation worker stopped: %v", err)
		}
	}()
	log.Printf("[identity_binding] service and cache invalidation worker initialized")
	go func() {
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if n, err := forecastWorker.RunPending(ctx); err != nil {
					log.Printf("[forecast] worker error: %v", err)
				} else if n > 0 {
					log.Printf("[forecast] processed %d job(s)", n)
				}
			}
		}
	}()

	if err := bootstrap.ApplyAdminConfig(ctx, userRepo, systemRepo, bootstrap.AdminConfig{
		Username: cfg.BootstrapAdminUsername,
		Email:    cfg.BootstrapAdminEmail,
		Password: cfg.BootstrapAdminPassword,
		Sessions: sessionRepo,
	}); err != nil {
		log.Fatalf("Failed to apply bootstrap admin config: %v", err)
	}
	log.Printf("Bootstrap admin prepared for username %q", cfg.BootstrapAdminUsername)
	if localIdentityClient != nil {
		adminIdentityStore := repository.NewUserIdentityLinkRepository(db)
		adminConfig := bootstrap.AdminConfig{
			Username: cfg.BootstrapAdminUsername,
			Email:    cfg.BootstrapAdminEmail,
			Password: cfg.BootstrapAdminPassword,
		}
		go bootstrap.EnsureAdminLoginIdentityUntilReady(
			ctx,
			5*time.Second,
			func(attemptCtx context.Context) error {
				return bootstrap.EnsureAdminLoginIdentity(
					attemptCtx, localIdentityClient, adminIdentityStore, localIdentityIssuer, adminConfig,
				)
			},
			func(error) {
				log.Printf("bootstrap admin Chat identity not ready; retrying")
			},
			func() {
				log.Printf("Bootstrap admin Chat identity prepared for username %q", cfg.BootstrapAdminUsername)
			},
		)
	}

	if err := bootstrap.EnsurePlatformDefaults(ctx, ruleSetRepo, ruleRepo); err != nil {
		log.Fatalf("Failed to ensure platform defaults: %v", err)
	}
	log.Printf("Platform defaults prepared for tenant %q", "tenant_default")
	if err := bootstrap.EnsureAllTenantPolicyDefaults(ctx, tenantRepo, ruleSetRepo, ruleRepo); err != nil {
		log.Fatalf("Failed to backfill tenant security policies: %v", err)
	}
	log.Printf("Tenant security policy catalogs prepared")

	if err := bootstrap.EnsureLicenseInstallAnchor(ctx, systemRepo, time.Now().UTC()); err != nil {
		log.Printf("warning: failed to ensure license install anchor: %v", err)
	}

	// RBAC: seed builtin roles + ensure admin grant
	if err := permission.SeedBuiltinRoles(ctx, db); err != nil {
		log.Printf("[rbac] seed builtin roles failed (non-fatal): %v", err)
	}
	if err := permGrantRepo.EnsureAdminGrant(ctx, "user_admin", "tenant_default"); err != nil {
		log.Printf("[rbac] ensure admin grant failed (non-fatal): %v", err)
	}
	log.Printf("[rbac] RBAC seeded, dryRun=%v", dryRun)
	// Create router

	go func() {
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			sweepCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
			err := deps.UserModelRepo.ExpireExtraGrants(handler.OperationAuditContext(sweepCtx, deps, ""))
			cancel()
			if err != nil {
				log.Printf("personal model grant expiry audit unavailable")
			}
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(handler.CaptureLoginTransportPeer)
	r.Use(middleware.RealIP)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(controlPlaneTimeoutMiddleware)

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
		health := map[string]string{
			"status":   map[bool]string{true: "healthy", false: "degraded"}[status == http.StatusOK],
			"service":  "control-plane",
			"database": dbStatus,
			"redis":    redisStatus,
		}
		if billingStore != nil {
			stats := billingStore.RequestLeaseCleanupStats()
			health["billing_request_lease_cleanup_backlog"] = strconv.FormatBool(stats.Backlog)
			health["billing_request_lease_cleanup_deleted_total"] = strconv.FormatInt(stats.DeletedTotal, 10)
			health["billing_request_lease_cleanup_last_run_unix"] = strconv.FormatInt(stats.LastRunUnix, 10)
		}
		_ = json.NewEncoder(w).Encode(health)
	})

	// Public routes (no auth required)
	r.Get("/admin/v1/captcha", handler.Captcha(deps))
	r.Post("/admin/v1/login", handler.Login(deps))
	r.Post("/admin/v1/employee-login", handler.EmployeeLogin(deps))
	r.Post("/admin/v1/service-login", handler.ServiceLogin(deps))

	// Agent endpoint internal ledger routes (feature-flagged, default off).
	if cfg.AgentEndpointEnabled {
		r.Group(func(r chi.Router) {
			r.Use(handler.InternalAPIMiddleware(cfg.InternalAPISecret, deps))
			r.Post("/admin/v1/internal/agent/endpoints/resolve", agentEndpointAPI.Resolve)
			r.Get("/admin/v1/internal/agent/license-status", agentEndpointAPI.LicenseStatus)
			r.Post("/admin/v1/internal/agent/endpoints/register", agentEndpointAPI.Register)
		})
		r.Group(func(r chi.Router) {
			r.Use(handler.InternalAPIMiddleware(cfg.InternalAPISecret, deps))
			r.Use(handler.EndpointAuth(agentEndpointRepo, deps))
			r.Post("/admin/v1/internal/agent/endpoints/heartbeat", agentEndpointAPI.Heartbeat)
			r.Post("/admin/v1/internal/agent/events", agentEndpointAPI.Events)
			r.Post("/admin/v1/internal/agent/probe-reports", agentEndpointAPI.ProbeReports)
			r.Post("/admin/v1/internal/agent/identity-events", nativeEventAPI.Ingest)
			r.Post("/admin/v1/internal/agent/kubernetes/snapshot-runs", kubernetesSnapshotAPI.BeginSnapshotRun)
			r.Post("/admin/v1/internal/agent/kubernetes/snapshots", kubernetesSnapshotAPI.IngestSnapshot)
			r.Post("/admin/v1/internal/agent/intent-authorizations/resolve", agentEndpointAPI.ResolveIntentAuthorizations)
			r.Get("/admin/v1/internal/agent/policy-bundle", agentEndpointAPI.Policy)
		})
		r.Group(func(r chi.Router) {
			r.Use(agentAuthorizationAPI.Authenticate)
			r.Post("/admin/v1/agent/authorize", agentAuthorizationAPI.Authorize)
			r.Post("/admin/v1/agent/approval-requests", agentAuthorizationApprovalAPI.RequestApproval)
			r.Post("/admin/v1/agent/approval-claims", agentAuthorizationApprovalAPI.ClaimApproval)
			r.Post("/admin/v1/agent/delegations", agentDelegationAPI.Create)
			r.Post("/admin/v1/agent/delegations/{id}/revoke", agentDelegationAPI.Revoke)
			r.Get("/admin/v1/agent/delegations/{id}/calls", agentDelegationAPI.ListCalls)
		})
	}

	// Internal service routes (shared-secret auth for gateway-core)
	r.Group(func(r chi.Router) {
		r.Use(handler.InternalAPIMiddleware(cfg.InternalAPISecret, deps))
		r.Post("/internal/v1/header-contract-conflicts", handler.CreateHeaderContractConflictIngest(deps))
		// Billing: gateway-only, fail-closed admission and
		// immutable price-quoted settlement. Never exposed to a browser.
		r.Post("/internal/v1/billing/reservations", handler.ReserveGatewayBilling(deps))
		r.Post("/internal/v1/billing/quotes", handler.QuoteGatewayBilling(deps))
		r.Post("/internal/v1/billing/settlements", handler.FinalizeGatewayBilling(deps))
		r.Post("/internal/v1/billing/releases", handler.ReleaseGatewayBilling(deps))
		r.Post("/internal/v1/billing/measurements", handler.RecordGatewayMeasurement(deps))
		// 预算断流状态：供正向代理按用户查询（开关关闭时恒为未断流）。
		r.Get("/internal/v1/billing/cutoff-status", handler.GetBillingCutoffStatus(deps))
		r.Get("/admin/v1/internal/tools/config", handler.GetToolRiskConfigs(deps))
		r.Post("/admin/v1/internal/tools/logs", handler.CreateToolCallLogInternal(deps))
		r.Get("/admin/v1/internal/system/settings", handler.GetInternalSystemSettings(deps))
		r.Get("/admin/v1/internal/agentguard/effective-policy", handler.GetInternalAgentGuardEffectivePolicy(deps))
		r.Post("/admin/v1/internal/agentguard/confirmations", handler.CreateAgentGuardConfirmationInternal(deps))
		r.Post("/admin/v1/internal/agentguard/confirmations/consume", handler.ConsumeAgentGuardConfirmationInternal(deps)) // W5 5.2
		// MCP 安全网关：gateway-core 按六元组拉生效策略；tools/call 审计回写复用上面的 internal/tools/logs（tool_type='mcp'），不新建
		r.Get("/admin/v1/internal/mcp/effective-policy", handler.GetInternalMCPEffectivePolicy(deps))
		// MCP 测-堵-验闭环：LSE 用内部密钥拉逐 server 机器可读策略契约（期望裁决 + 静态风险标注
		// + 运行时红线类目 + audit-only 天花板 + 证据核对位置），驱动样本生成与归因断言。
		r.Get("/admin/v1/internal/mcp/policy-contract", handler.GetInternalMCPPolicyContract(deps))
		// 内置红线处置配置：gateway-core 命中红线时按租户拉取（X-Tenant-ID）。此前漏接线（W1 1.11 备忘“需集成人接线”未落实），
		// 网关拉取 404，红线只能降级为仅告警。
		r.Get("/admin/v1/internal/mcp/redline-settings", handler.GetInternalMCPRedlineSettings(mcpRedlineSettingsStore))
		r.Post("/admin/v1/internal/security/skills/definitions", handler.ObserveSkillDefinition(deps))
		r.Get("/admin/v1/internal/security/skills/admission", handler.ResolveSkillAdmission(deps))
		r.Post("/admin/v1/internal/security/skills/invocations", handler.RecordSkillInvocation(deps))
		r.Post("/admin/v1/internal/security/skills/results", handler.LinkSkillResult(deps))
		r.Get("/admin/v1/internal/rules/pack", handler.GetInternalRulePack(deps))
		r.Get("/admin/v1/internal/security/semantic-config", handler.LegacySemanticConfigGone())
		r.Post("/admin/v1/internal/security/semantic-runtime-report", handler.LegacySemanticConfigGone())
		r.Get("/admin/v1/internal/security/semantic-config/gateway", handler.GetInternalSemanticGatewayConfig(deps))
		r.Get("/admin/v1/internal/security/semantic-config/engine", handler.GetInternalSemanticEngineConfig(deps))
		r.Post("/admin/v1/internal/security/semantic-runtime-report/gateway", handler.ReportSemanticRuntimeComponent(deps, "gateway-core"))
		r.Post("/admin/v1/internal/security/semantic-runtime-report/engine", handler.ReportSemanticRuntimeComponent(deps, "security-engine"))
	})

	// Eval integration routes (shared-secret auth for LSE clients)
	r.Group(func(r chi.Router) {
		r.Use(handler.EvalIntegrationAPIMiddleware(cfg.InternalAPISecret, deps))
		r.Get("/admin/v1/eval-integration/health", handler.GetEvalIntegrationHealth(deps))
		r.Post("/admin/v1/eval-integration/policy-suggestions", handler.CreateEvalIntegrationPolicySuggestion(deps))
		r.Get("/admin/v1/eval-integration/policy-suggestions/{id}", handler.GetEvalIntegrationPolicySuggestion(deps))
		r.Get("/admin/v1/eval-integration/verify-reciprocal", handler.VerifyReciprocal(deps))
		r.Get("/admin/v1/eval-integration/audit-events", handler.ListEvalIntegrationAuditEvents(deps))
		r.Get("/admin/v1/eval-integration/assurance-contract", handler.GetEvalIntegrationAssuranceContract(deps))
		r.Get("/admin/v1/eval-integration/assurance-evidence", handler.GetEvalIntegrationAssuranceEvidence(deps))
		r.Get("/admin/v1/eval-integration/audit-events/{id}", handler.GetEvalIntegrationAuditEvent(deps))
		r.Post("/admin/v1/eval-integration/findings", handler.CreateEvalIntegrationFindings(deps))
	})

	// Portal integration routes (shared-secret auth for chat-portal backend)
	r.Group(func(r chi.Router) {
		r.Use(handler.PortalIntegrationAPIMiddleware(cfg.PortalAPISecret, deps))
		r.Get("/admin/v1/portal-integration/health", handler.GetPortalIntegrationHealth(deps))
		// Customer self-service read model. The BFF supplies its authenticated
		// session user_id; its shared secret is never available in the browser.
		r.Get("/admin/v1/portal-integration/customer-billing", handler.GetPortalCustomerBilling(deps))
		r.Get("/admin/v1/portal-integration/model-prices", handler.GetPortalModelPrices(deps))
		r.Get("/admin/v1/portal-integration/model-performance", handler.GetPortalModelPerformance(modelOperations))
		r.Post("/admin/v1/portal-integration/upload-events/legacy-index", handler.GetPortalLegacyUploadIndex(deps))
		r.Get("/admin/v1/portal-integration/client-config", handler.GetPortalClientConfig(deps))
		r.Get("/admin/v1/portal-integration/customer-keys", handler.ListPortalCustomerKeys(deps))
		r.Patch("/admin/v1/portal-integration/customer-keys/{id}", handler.UpdatePortalCustomerKey(deps))
		r.Delete("/admin/v1/portal-integration/customer-keys/{id}", handler.DeletePortalCustomerKey(deps))
		r.Post("/admin/v1/portal-integration/customer-keys/{id}/reset", handler.ResetPortalCustomerKey(deps))
		r.Post("/admin/v1/portal-integration/customer-keys/{id}/reveal", handler.RevealPortalCustomerKey(deps))
		r.Put("/admin/v1/portal-integration/customer-billing/limits", handler.UpdatePortalCustomerBillingLimits(deps))
		r.Post("/admin/v1/portal-integration/customer-billing/redemptions", handler.RedeemPortalCustomerBillingCode(deps))
		r.Post("/admin/v1/portal-integration/keys", handler.CreatePortalKey(deps))
		r.Get("/admin/v1/portal-integration/keys", handler.ListPortalKeys(deps))
		r.Post("/admin/v1/portal-integration/keys/{id}/revoke", handler.RevokePortalKey(deps))
		r.Get("/admin/v1/portal-integration/usage/by-key", handler.GetPortalUsageByKey(deps))
		r.Get("/admin/v1/portal-integration/usage/trend", handler.GetPortalUsageTrend(deps))
		r.Get("/admin/v1/portal-integration/usage/by-model", handler.GetPortalUsageByModel(deps))
		r.Get("/admin/v1/portal-integration/usage/summary", handler.GetPortalUsageSummary(deps))
		r.Get("/admin/v1/portal-integration/teams/{id}/models", handler.GetPortalTeamModels(deps))
		r.Get("/admin/v1/portal-integration/teams/{id}/effective", handler.GetPortalTeamEffective(deps))
		r.Get("/admin/v1/portal-integration/policies/model", handler.GetPortalModelPolicy(deps))
		r.Put("/admin/v1/portal-integration/policies/model", handler.SetPortalModelPolicy(deps))
		r.Get("/admin/v1/portal-integration/group-mapping-rules", handler.GetPortalGroupMappingRules(deps))
		r.Get("/admin/v1/portal-integration/models", handler.ListPortalModels(deps))
		r.Get("/admin/v1/portal-integration/projects", handler.ListPortalProjects(deps))
		r.Post("/admin/v1/portal-integration/projects", handler.CreatePortalProject(deps))
		r.Get("/admin/v1/portal-integration/teams", handler.ListPortalTeams(deps))
		r.Post("/admin/v1/portal-integration/teams", handler.CreatePortalTeam(deps))
		// Phase4：门户员工↔网关 user/team 打通（惰性、幂等、可开可关）
		r.Post("/admin/v1/portal-integration/users", handler.EnsurePortalUser(deps))
		r.Post("/admin/v1/portal-integration/chat-login/redeem", handler.RedeemChatLoginTicket(deps))
		r.Get("/admin/v1/portal-integration/employee-key", handler.EmployeeKeyEndpoint(deps, "metadata"))
		r.Post("/admin/v1/portal-integration/employee-key/ensure", handler.EmployeeKeyEndpoint(deps, "ensure"))
		r.Post("/admin/v1/portal-integration/employee-key/claim", handler.EmployeeKeyEndpoint(deps, "claim"))
		r.Post("/admin/v1/portal-integration/employee-key/reset", handler.EmployeeKeyEndpoint(deps, "reset"))
		r.Get("/admin/v1/portal-integration/employee-key/credential", handler.EmployeeKeyEndpoint(deps, "credential"))
		r.Get("/admin/v1/portal-integration/users/{id}/authorization-context", handler.GetPortalUserAuthorizationContext(deps))
		r.Get("/admin/v1/portal-integration/users/{id}/call-records", handler.ListPortalUserCallRecords(deps))
		r.Post("/admin/v1/portal-integration/teams/{id}/members", handler.EnsureTeamMember(deps))
		r.Get("/admin/v1/portal-integration/audit-events", handler.ListPortalAuditEvents(deps))
		// Chat/SSO 门户暴露开关只读状态（供 portal-proxy 门控）
		r.Get("/admin/v1/portal-integration/system/chat-portal-status", handler.GetPortalChatPortalStatus(deps))
		// M3-B Phase-2：文件上传 ingest + file-policy 读（门户机器通道）
		r.Get("/admin/v1/portal-integration/policies/file", handler.GetPortalFilePolicy(deps))
		r.Post("/admin/v1/portal-integration/upload-ingest", handler.PortalUploadIngest(deps))
		// M3-B Phase-3：员工可见上传留痕读端点（user_id 强制过滤）
		r.Get("/admin/v1/portal-integration/upload-events", handler.ListPortalUploadEvents(deps))
		// 员工诊断助手（门户代调，调用身份固定为非管理员，只能查本人）
		r.Post("/admin/v1/portal-integration/diagnostics/sessions", handler.CreatePortalDiagnosticsSession(deps, diagEngine))
		r.Get("/admin/v1/portal-integration/diagnostics/sessions", handler.ListPortalDiagnosticsSessions(deps, diagEngine))
		r.Get("/admin/v1/portal-integration/diagnostics/sessions/{id}", handler.GetPortalDiagnosticsSession(deps, diagEngine))
		r.Post("/admin/v1/portal-integration/diagnostics/sessions/{id}/messages", handler.AddPortalDiagnosticsMessage(deps, diagEngine))
	})

	// Chat handoff is an authenticated self-service route with no management capability.
	r.With(auth.Middleware(sessionRepo, userRepo)).Post("/admin/v1/me/chat-login", handler.CreateChatLoginTicket(deps))

	// Protected routes (auth required)
	r.Group(func(r chi.Router) {
		r.Use(auth.Middleware(sessionRepo, userRepo))
		// W4: three-officer separation of duties, always enforcing (ignores RBAC dry-run).
		r.Use(permission.SoDGuard(db))
		r.Use(permission.Middleware(permChecker, db, dryRun))
		r.Use(handler.LicenseGuard(deps))

		// Auth
		r.Post("/admin/v1/logout", handler.Logout(deps))
		r.Get("/admin/v1/me", handler.GetCurrentUser(deps))
		r.Post("/admin/v1/me/change-password", handler.ChangeCurrentPassword(deps))
		// W3 控制台双因素自助
		r.Get("/admin/v1/me/totp", handler.GetMyTOTPStatus(deps))
		r.Post("/admin/v1/me/totp/setup", handler.SetupMyTOTP(deps))
		r.Post("/admin/v1/me/totp/enable", handler.EnableMyTOTP(deps))

		if cfg.AgentEndpointEnabled {
			r.Get("/admin/v1/agent/overview", agentAdminAPI.Overview)
			r.Get("/admin/v1/agent/endpoints", agentAdminAPI.ListEndpoints)
			r.Get("/admin/v1/agent/endpoints/{id}", agentAdminAPI.GetEndpoint)
			r.Put("/admin/v1/agent/endpoints/{id}/mode", agentAdminAPI.UpdateEndpointMode)
			r.Post("/admin/v1/agent/endpoints/{id}/revoke", agentAdminAPI.RevokeEndpoint)
			r.Post("/admin/v1/agent/endpoints/{id}/rotate-token", agentAdminAPI.RotateEndpointToken)
			r.Get("/admin/v1/agent/enrollment-tokens", agentAdminAPI.ListEnrollmentTokens)
			r.Post("/admin/v1/agent/enrollment-tokens", agentAdminAPI.CreateEnrollmentToken)
			r.Post("/admin/v1/agent/enrollment-tokens/{id}/revoke", agentAdminAPI.RevokeEnrollmentToken)
			r.Get("/admin/v1/agent/principals", agentAuthorizationAPI.ListPrincipals)
			r.Post("/admin/v1/agent/principals", agentAuthorizationAPI.RegisterPrincipal)
			r.Post("/admin/v1/agent/principals/{id}/revoke", agentAuthorizationAPI.RevokePrincipal)
			r.Post("/admin/v1/agent/principals/{id}/rotate-token", agentAuthorizationAPI.RotatePrincipalCredential)
			r.Get("/admin/v1/agent/intent-tasks/{id}", agentAuthorizationAPI.GetIntentTask)
			r.Post("/admin/v1/agent/intent-tasks", agentAuthorizationAPI.CreateIntentTask)
			r.Post("/admin/v1/agent/intent-tasks/{id}/revoke", agentAuthorizationAPI.RevokeIntentTask)
			r.Get("/admin/v1/agent/principals/{id}/delegation-tree", agentDelegationInvestigationAPI.Tree)
			r.Get("/admin/v1/agent/sessions", agentAdminAPI.ListSessions)
			r.Get("/admin/v1/agent/sessions/{id}", agentAdminAPI.GetSession)
			r.Get("/admin/v1/agent/events", agentAdminAPI.ListEvents)
			r.Get("/admin/v1/agent/native-events", nativeEventAPI.List)
			r.Get("/admin/v1/agent/assets", agentAdminAPI.ListAssets)
			r.Get("/admin/v1/agent/kubernetes/clusters", kubernetesSnapshotAPI.ListClusters)
			r.Post("/admin/v1/agent/kubernetes/clusters", kubernetesSnapshotAPI.CreateCluster)
			r.Post("/admin/v1/agent/kubernetes/clusters/{cluster_id}/namespaces", kubernetesSnapshotAPI.RegisterNamespace)
			r.Post("/admin/v1/agent/kubernetes/namespaces/{registration_id}/revoke", kubernetesSnapshotAPI.RevokeNamespace)
			r.Get("/admin/v1/agent/kubernetes/clusters/{cluster_id}/coverage", kubernetesSnapshotAPI.Coverage)
			r.Get("/admin/v1/agent/unified-assets", agentUnifiedAssetAPI.List)
			r.Get("/admin/v1/agent/unified-assets/native-reference-link", agentUnifiedAssetAPI.FindNativeReferenceAsset)
			r.Get("/admin/v1/agent/unified-assets/{id}/history", agentUnifiedAssetAPI.ListHistory)
			r.Put("/admin/v1/agent/unified-assets/{id}/ownership", agentUnifiedAssetAPI.UpdateOwnership)
			r.Put("/admin/v1/agent/unified-assets/{id}/catalog", agentUnifiedAssetAPI.UpdateCatalog)
			r.Put("/admin/v1/agent/unified-assets/{id}/sources", agentUnifiedAssetAPI.LinkSource)
			r.Post("/admin/v1/agent/unified-assets/{id}/merge", agentUnifiedAssetAPI.Merge)
			r.Get("/admin/v1/agent/approval-rules", agentDestinationApprovalAPI.List)
			r.Post("/admin/v1/agent/approval-rules", agentDestinationApprovalAPI.Create)
			r.Post("/admin/v1/agent/approval-rules/{id}/deactivate", agentDestinationApprovalAPI.Deactivate)
			r.Get("/admin/v1/agent/policy-bundles", agentAdminAPI.ListPolicyBundles)
			r.Get("/admin/v1/agent/policy-bundles/current", agentAdminAPI.CurrentPolicyBundle)
		}

		// Org labels (org-units Phase B)
		r.Get("/admin/v1/settings/org-labels", handler.GetOrgLabels(deps))
		r.Put("/admin/v1/settings/org-labels", handler.PutOrgLabels(deps))

		// Tenants
		r.Get("/admin/v1/tenants", handler.ListTenants(deps))
		r.Post("/admin/v1/tenants", handler.CreateTenant(deps))
		r.Get("/admin/v1/tenants/{id}", handler.GetTenant(deps))
		r.Patch("/admin/v1/tenants/{id}", handler.UpdateTenant(deps))
		// 跨租户只读接口（platform_admin）
		r.Get("/admin/v1/tenants/{id}/teams", handler.ListTenantTeams(deps))
		r.Get("/admin/v1/tenants/{id}/users", handler.ListTenantUsers(deps))
		r.Get("/admin/v1/tenants/{id}/projects", handler.ListTenantProjects(deps))
		r.Delete("/admin/v1/tenants/{id}/projects/{projectId}", handler.DeleteTenantProject(deps))
		r.Get("/admin/v1/tenants/{id}/keys", handler.ListTenantKeys(deps))
		r.Delete("/admin/v1/tenants/{id}", handler.DeleteTenant(deps))

		// Projects
		r.Get("/admin/v1/projects", handler.ListProjects(deps))
		r.Post("/admin/v1/projects", handler.CreateProject(deps))
		r.Get("/admin/v1/projects/{id}", handler.GetProject(deps))
		r.Patch("/admin/v1/projects/{id}", handler.UpdateProject(deps))
		r.Delete("/admin/v1/projects/{id}", handler.DeleteProject(deps))

		// Project-User bindings (private deployment)
		r.Get("/admin/v1/projects/{id}/users", handler.ListAppUsers(deps))
		r.Post("/admin/v1/projects/{id}/users", handler.BindAppUser(deps))
		r.Delete("/admin/v1/projects/{id}/users/{userId}", handler.UnbindAppUser(deps))
		r.Patch("/admin/v1/projects/{id}/model-config", handler.UpdateAppModelConfig(deps))

		// Keys
		r.Get("/admin/v1/keys", handler.ListKeys(deps))
		r.Post("/admin/v1/keys", handler.CreateKey(deps))
		r.Patch("/admin/v1/keys/{id}", handler.UpdateKey(deps))
		r.Put("/admin/v1/keys/{id}/traffic-class", handler.SetKeyTrafficClass(deps.KeyRepo))
		r.Post("/admin/v1/keys/{id}/revoke", handler.RevokeKey(deps))
		r.Get("/admin/v1/keys/{id}/reveal", handler.RevealKey(deps))
		r.Delete("/admin/v1/keys/{id}", handler.DeleteKey(deps))

		// Providers
		r.Get("/admin/v1/providers", handler.ListProviders(deps))
		r.Get("/admin/v1/providers/metrics", handler.GetProvidersMetrics(deps))
		r.Get("/admin/v1/providers/deleted", handler.ListDeletedProviders(deps))
		r.Post("/admin/v1/providers", handler.CreateProvider(deps))
		r.Patch("/admin/v1/providers/{id}", handler.UpdateProvider(deps))
		r.Get("/admin/v1/providers/{id}/credentials/history", handler.GetProviderCredentialHistory(deps))
		r.Post("/admin/v1/providers/{id}/restore", handler.RestoreProvider(deps))
		r.Delete("/admin/v1/providers/{id}", handler.DeleteProvider(deps))

		// Models
		r.Get("/admin/v1/model-operations/overview", modelOperationsHTTP.GetOverview)
		r.Get("/admin/v1/model-operations/sla", modelOperationsHTTP.RequireReadQuery(handler.GetModelOperationsSLA(db), "month", "timezone", "provider_id", "model_id"))
		r.Get("/admin/v1/model-operations/sla/export", modelOperationsHTTP.RequireReadQuery(handler.ExportModelOperationsSLA(db), "month", "timezone", "provider_id", "model_id"))
		r.Get("/admin/v1/model-operations/targets", modelOperationsHTTP.GetTargets)
		r.Get("/admin/v1/model-operations/history", modelOperationsHTTP.GetHistory)
		r.Get("/admin/v1/model-operations/quality", modelOperationsHTTP.GetQuality)
		r.Get("/admin/v1/model-operations/providers", modelOperationsHTTP.GetProviders)
		r.Get("/admin/v1/model-operations/alerts", modelOperationsHTTP.GetAlerts)
		r.Get("/admin/v1/model-operations/config", modelOperationsHTTP.GetConfig)
		r.Put("/admin/v1/model-operations/config", modelOperationsHTTP.PutConfig)
		r.Post("/admin/v1/model-operations/test", modelOperationsJobsHTTP.Submit)
		r.Get("/admin/v1/model-operations/jobs/{id}", modelOperationsJobsHTTP.Get)
		r.Post("/admin/v1/model-operations/jobs/{id}/cancel", modelOperationsJobsHTTP.Cancel)
		r.Post("/admin/v1/model-operations/alerts/{id}/ack", modelOperationsHTTP.AcknowledgeAlert)
		r.Get("/admin/v1/models", handler.ListModels(deps))
		r.Post("/admin/v1/models", handler.CreateModel(deps))
		r.Get("/admin/v1/models/eval-status", handler.ListModelsEvalStatus(deps))
		r.Post("/admin/v1/models/sync", handler.SyncModels(deps))
		r.Get("/admin/v1/models/sync/state", handler.CatalogSyncSettings(deps))
		r.Put("/admin/v1/models/sync/state", handler.CatalogSyncSettings(deps))
		r.Post("/admin/v1/models/sync/candidates", handler.ListModelSyncCandidates(deps))
		r.Post("/admin/v1/models/batch-delete", handler.BatchDeleteModels(deps))
		r.Post("/admin/v1/models/sync/preview", handler.PreviewVerifiedModelSync(deps))
		r.Post("/admin/v1/models/sync/verify", handler.VerifyModelSyncCandidates(deps))
		r.Post("/admin/v1/models/sync/commit", handler.CommitVerifiedModelSync(deps))
		r.Delete("/admin/v1/models/{id}", handler.DeleteModel(deps))

		r.Patch("/admin/v1/models/{id}/routing", handler.UpdateModelRouting(deps))
		r.Patch("/admin/v1/models/{id}/status", handler.UpdateModelStatus(deps))
		r.Patch("/admin/v1/models/{id}/proxy-config", handler.UpdateModelProxyConfig(deps))
		r.Patch("/admin/v1/models/{id}/capabilities", handler.UpdateModelCapabilities(deps))

		// Policies
		r.Get("/admin/v1/policies/model", handler.GetModelPolicy(deps))
		r.Put("/admin/v1/policies/model", handler.SetModelPolicy(deps))
		r.Get("/admin/v1/group-mapping-rules", handler.ListGroupMappingRules(deps))
		r.Post("/admin/v1/group-mapping-rules", handler.CreateGroupMappingRule(deps))
		r.Patch("/admin/v1/group-mapping-rules/{id}", handler.UpdateGroupMappingRule(deps))
		r.Delete("/admin/v1/group-mapping-rules/{id}", handler.DeleteGroupMappingRule(deps))

		// 身份与访问 — 登录与单点登录 (identity-access-frontdoor)
		r.Get("/admin/v1/identity/sources", handler.GetIdentitySources(deps))
		r.Put("/admin/v1/identity/sources/draft", handler.SaveIdentityDraft(deps))
		r.Get("/admin/v1/directory/sources/draft", handler.GetDirectoryDraft(deps))
		r.Put("/admin/v1/directory/sources/draft", handler.SaveDirectoryDraft(deps))
		r.Post("/admin/v1/directory/sources/test", handler.TestDirectoryConnection(deps))
		r.Post("/admin/v1/directory/sources/activate", handler.ActivateDirectorySource(deps))
		r.Post("/admin/v1/directory/sources/disable", handler.DisableDirectorySource(deps))
		r.Post("/admin/v1/directory/sources/preview", handler.PreviewDirectorySource(deps))
		r.Get("/admin/v1/directory/sources/previews/{id}", handler.GetDirectoryPreview(deps))
		r.Post("/admin/v1/directory/sources/previews/{id}/activate", handler.ActivateDirectoryPreview(deps))
		r.Get("/admin/v1/directory/sync-runs", handler.ListDirectorySyncRuns(deps))
		r.Get("/admin/v1/directory/sync-runs/{id}", handler.GetDirectorySyncRun(deps))
		r.Post("/admin/v1/identity/sources/test", handler.TestIdentityConnection(deps))
		r.Post("/admin/v1/identity/sources/activate", handler.ActivateIdentitySource(deps))
		r.Post("/admin/v1/identity/sources/disable", handler.DisableIdentitySource(deps))
		r.Post("/admin/v1/identity/sources/reconcile", handler.ReconcileIdentitySource(deps))
		r.Post("/admin/v1/identity/sources/adopt-runtime", handler.AdoptIdentityRuntime(deps))
		r.Get("/admin/v1/identity/dept-mappings", handler.ListIdentityDeptMappings(deps))
		r.Post("/admin/v1/identity/dept-mappings", handler.CreateIdentityDeptMapping(deps))
		r.Patch("/admin/v1/identity/dept-mappings/{id}", handler.UpdateIdentityDeptMapping(deps))
		r.Delete("/admin/v1/identity/dept-mappings/{id}", handler.DeleteIdentityDeptMapping(deps))
		// 身份与访问 — 统一部门映射 (enterprise-identity-department-mapping)
		r.Get("/admin/v1/identity/department-mappings", handler.ListIdentityDepartmentMappings(deps))
		r.Post("/admin/v1/identity/department-mappings", handler.CreateIdentityDepartmentMapping(deps))
		r.Patch("/admin/v1/identity/department-mappings/{id}", handler.UpdateIdentityDepartmentMapping(deps))
		r.Delete("/admin/v1/identity/department-mappings/{id}", handler.DeleteIdentityDepartmentMapping(deps))
		r.Post("/admin/v1/identity/department-mappings/preview", handler.PreviewIdentityDepartmentMappings(deps))
		r.Get("/admin/v1/identity/status", handler.GetIdentityStatus(deps))
		r.Get("/admin/v1/identity/overview", handler.GetIdentityOverview(deps))
		r.Get("/admin/v1/policies/quota", handler.GetQuotaPolicy(deps))
		r.Put("/admin/v1/policies/quota", handler.SetQuotaPolicy(deps))

		// Security
		r.Get("/admin/v1/rule-sets", handler.ListRuleSets(deps))
		r.Post("/admin/v1/rule-sets", handler.CreateRuleSet(deps))
		r.Post("/admin/v1/rule-sets/{id}/publish", handler.PublishRuleSet(deps))
		r.Post("/admin/v1/security/test", handler.TestSecurity(deps))
		r.Post("/admin/v1/security/semantic/test-judge", handler.TestSemanticJudge(deps))
		r.Get("/admin/v1/security/semantic/settings", handler.GetSemanticSettings(deps))
		r.Put("/admin/v1/security/semantic/settings", handler.UpdateSemanticSettings(deps))
		r.Put("/admin/v1/security/system-settings", handler.UpdateSecuritySystemSettings(deps))
		r.Get("/admin/v1/security/smart-detection/overview", handler.GetSmartDetectionOverview(deps))
		r.Put("/admin/v1/security/smart-detection/config", handler.UpdateSmartDetectionConfig(deps))
		r.Get("/admin/v1/content-security/rules", handler.ListContentSecurityRules(deps))
		r.Post("/admin/v1/content-security/rules", handler.CreateContentSensitiveRule(deps))
		r.Get("/admin/v1/policy-suggestions", handler.ListPolicySuggestions(deps))
		r.Post("/admin/v1/policy-suggestions/{id}/approve", handler.ReviewPolicySuggestion(deps, true))
		r.Post("/admin/v1/policy-suggestions/{id}/reject", handler.ReviewPolicySuggestion(deps, false))
		r.Get("/admin/v1/content-security/exceptions", handler.ListContentAuditExceptions(deps))
		r.Post("/admin/v1/content-security/exceptions", handler.CreateContentAuditException(deps))
		r.Delete("/admin/v1/content-security/exceptions/{id}", handler.DeleteContentAuditException(deps))
		r.Get("/admin/v1/content-security/file-policy", handler.GetContentFilePolicy(deps))
		r.Put("/admin/v1/content-security/file-policy", handler.UpdateContentFilePolicy(deps))
		r.Get("/admin/v1/content-security/industry", handler.GetContentSecurityIndustry(deps))
		r.Put("/admin/v1/content-security/industry", handler.UpdateContentSecurityIndustry(deps))

		// Rules
		r.Get("/admin/v1/security/policies", handler.ListSecurityPolicies(deps))
		r.Post("/admin/v1/security/policies", handler.CreateSecurityPolicy(deps))
		r.Get("/admin/v1/security/policies/capabilities", handler.ListSecurityPolicyCapabilities(deps))
		r.Post("/admin/v1/security/policies/preview", handler.PreviewSecurityPolicies(deps))
		r.Post("/admin/v1/security/policies/quick-create/generate", handler.GenerateQuickSecurityPolicy(deps))
		r.Post("/admin/v1/security/policies/quick-create/preview", handler.PreviewQuickSecurityPolicy(deps))
		r.Post("/admin/v1/security/policies/batch", handler.BatchUpdateSecurityPolicies(deps))
		r.Patch("/admin/v1/security/policies/{id}", handler.UpdateSecurityPolicy(deps))
		r.Delete("/admin/v1/security/policies/{id}", handler.DeleteSecurityPolicy(deps))
		r.Get("/admin/v1/security/policy-assets", handler.ListPolicyAssets(deps))
		r.Put("/admin/v1/security/policy-assets/{id}", handler.UpdatePolicyAsset(deps))
		r.Get("/admin/v1/rules", handler.ListRules(deps))
		r.Post("/admin/v1/rules", handler.CreateRule(deps))
		r.Patch("/admin/v1/rules/{id}", handler.UpdateRule(deps))
		r.Delete("/admin/v1/rules/{id}", handler.DeleteRule(deps))
		r.Post("/admin/v1/rules/{id}/toggle", handler.ToggleRule(deps))
		r.Post("/admin/v1/detectors/batch-update", handler.BatchUpdateDetector(deps))
		r.Post("/admin/v1/detectors/init", handler.InitDetectors(deps))
		// Audit & Usage
		r.With(handler.RequireFullTenantContentEvidence).Get("/admin/v1/audit/requests", handler.ListAuditRequests(deps))
		r.With(handler.RequireFullTenantContentEvidence).Get("/admin/v1/audit/requests/{request_id}", handler.GetAuditRequestDetail(deps))
		r.Get("/admin/v1/audit/events", handler.ListSecurityEvents(deps))
		r.Get("/admin/v1/integration/capabilities", handler.IntegrationCapabilities(deps))
		r.Post("/admin/v1/integration/agent-credentials", handler.IssueAgentCredential(deps))
		r.Get("/admin/v1/integration/agent-credentials", handler.ListAgentCredentials(deps))
		r.Get("/admin/v1/integration/agent-credentials/{id}", handler.GetAgentCredential(deps))
		r.Patch("/admin/v1/integration/agent-credentials/{id}", handler.UpdateAgentCredential(deps))
		r.Get("/admin/v1/integration/dlp-status", handler.GetIntegrationDLPStatus(deps))
		r.Get("/admin/v1/integration/credential-hits", handler.ListIntegrationCredentialHits(deps))
		r.Get("/admin/v1/integration/retention-status", handler.GetIntegrationRetentionStatus(deps))
		r.Post("/admin/v1/integration/agent-credentials/{id}/rotate", handler.RotateAgentCredential(deps))
		r.Post("/admin/v1/integration/agent-credentials/{id}/revoke", handler.RevokeAgentCredential(deps))
		r.Post("/admin/v1/integration/agent-policies", handler.WriteAgentPolicy(deps))
		r.Put("/admin/v1/integration/agent-policies/{id}", handler.WriteAgentPolicy(deps))
		r.Get("/admin/v1/integration/agent-policies", handler.ListAgentPolicies(deps))
		r.Get("/admin/v1/integration/enforcement-status", handler.GetIntegrationEnforcementStatus(deps))
		r.Get("/admin/v1/integration/audit-events", handler.ListIntegrationAuditEvents(deps))
		r.Get("/admin/v1/integration/upstreams", handler.ListIntegrationUpstreams(deps))
		r.Get("/admin/v1/integration/projects", handler.ListIntegrationProjects(deps))
		// 阻断记录：所有真实阻断的请求，含命中规则、明细与阻断/操作编号检索。
		r.Get("/admin/v1/security/block-records", handler.ListSecurityBlockRecords(deps))
		r.Get("/admin/v1/security/block-records/export", handler.ExportSecurityBlockRecords(deps))
		r.Get("/admin/v1/security/block-records/{block_id}", handler.GetSecurityBlockRecord(deps))
		r.Get("/admin/v1/security/block-records/{block_id}/trace", handler.GetSecurityBlockTrace(deps))
		// 训练语料扫描：分片上传、后台扫描、报告与脱敏副本下载。
		r.Post("/admin/v1/security/corpus-scans", corpusScanHTTP.Create)
		r.Get("/admin/v1/security/corpus-scans", corpusScanHTTP.List)
		r.Get("/admin/v1/security/corpus-scans/{id}", corpusScanHTTP.Get)
		r.Delete("/admin/v1/security/corpus-scans/{id}", corpusScanHTTP.Delete)
		r.Put("/admin/v1/security/corpus-scans/{id}/chunks/{n}", corpusScanHTTP.UploadChunk)
		r.Post("/admin/v1/security/corpus-scans/{id}/start", corpusScanHTTP.Start)
		r.Post("/admin/v1/security/corpus-scans/{id}/cancel", corpusScanHTTP.Cancel)
		r.Get("/admin/v1/security/corpus-scans/{id}/report", corpusScanHTTP.DownloadReport)
		r.Get("/admin/v1/security/corpus-scans/{id}/masked", corpusScanHTTP.DownloadMasked)
		r.Get("/admin/v1/security/alert-occurrences", handler.ListAlertOccurrences(deps))
		r.Get("/admin/v1/security/alert-occurrences/summary", handler.SummarizeAlertCases(deps))
		r.Get("/admin/v1/security/alert-occurrences/operational", handler.ListAlertOperationalEvents(deps))
		r.Get("/admin/v1/security/alert-occurrences/operational/summary", handler.SummarizeAlertOperationalEvents(deps))
		// 告警案件物化诊断（平台管理员）：读接口为什么在走实时查询。
		r.Get("/admin/v1/security/alert-occurrences/store-status", handler.GetAlertCaseStoreStatus(deps))
		r.With(handler.RequireFullTenantContentEvidence).Get("/admin/v1/audit/dispositions", handler.ListAuditDispositions(deps))
		r.Put("/admin/v1/audit/dispositions", handler.UpsertAuditDisposition(deps))
		r.Get("/admin/v1/audit/export", handler.ExportAuditLogs(deps))
		r.Get("/admin/v1/audit/raw-evidence", handler.ListRawEvidence(deps))
		r.Get("/admin/v1/audit/raw-evidence/settings", handler.GetRawEvidenceSettings(deps))
		r.Put("/admin/v1/audit/raw-evidence/settings", handler.UpdateRawEvidenceSettings(deps))
		r.Post("/admin/v1/audit/raw-evidence/{id}/reveal", handler.RevealRawEvidence(deps))
		r.Get("/admin/v1/audit/content", handler.ListContentAudit(deps))
		r.Get("/admin/v1/audit/content/security-overview", handler.GetContentSecurityOverview(deps))
		r.Get("/admin/v1/audit/content/users", handler.ListContentAuditUsers(deps))
		r.With(handler.RequireFullTenantContentEvidence).Get("/admin/v1/audit/content/{session_id}", handler.GetSessionContent(deps))
		r.With(handler.RequireFullTenantContentEvidence).Get("/admin/v1/audit/content/{session_id}/events", handler.GetSessionSecurityEvents(deps))
		r.With(handler.RequireFullTenantContentEvidence).Get("/admin/v1/audit/content/{session_id}/export", handler.ExportSessionContent(deps))
		r.Get("/admin/v1/usage/summary", handler.GetUsageSummary(deps))
		r.Get("/admin/v1/usage/by-project", handler.GetUsageByProject(deps))
		r.Get("/admin/v1/usage/cost-coverage", handler.GetUsageCostCoverage(deps))
		r.Get("/admin/v1/usage/by-model", handler.GetUsageByModel(deps))
		r.Get("/admin/v1/usage/trend", handler.GetUsageTrend(deps))
		r.Get("/admin/v1/usage/by-user", handler.GetUsageByUser(deps))
		r.Get("/admin/v1/usage/by-key", handler.GetUsageByKey(deps))
		r.Get("/admin/v1/usage/by-provider", handler.GetUsageByProvider(deps))
		r.Get("/admin/v1/usage/records", handler.GetUsageRecords(deps))
		r.Get("/admin/v1/usage/records/summary", handler.GetUsageRecordsSummary(deps))
		r.Get("/admin/v1/usage/recommendations", handler.GetUsageRecommendations(deps))
		r.Get("/admin/v1/billing/analytics/summary", handler.GetBillingAnalyticsSummary(deps))
		r.Get("/admin/v1/billing/analytics/breakdown", handler.GetBillingAnalyticsBreakdown(deps))
		r.Get("/admin/v1/billing/analytics/series", handler.GetBillingAnalyticsSeries(deps))
		r.Get("/admin/v1/billing/analytics/time-profile", handler.GetBillingAnalyticsTimeProfile(deps))
		r.Get("/admin/v1/billing/analytics/department-provider-matrix", handler.GetBillingAnalyticsDepartmentProviderMatrix(deps))
		r.Get("/admin/v1/billing/analytics/report", handler.GetBillingReport(deps))
		r.Get("/admin/v1/system/initialization", handler.GetFirstAdminInitializationStatus(deps))
		r.Post("/admin/v1/system/initialization/retry", handler.RetryFirstAdminInitialization(deps))

		// Personal usage dashboard (admin drill-down into a single user)
		r.Get("/admin/v1/users/{user_id}/usage/summary", handler.GetUserUsageSummary(deps))
		r.Get("/admin/v1/users/{user_id}/usage/trend", handler.GetUserUsageTrend(deps))
		r.Get("/admin/v1/users/{user_id}/usage/by-model", handler.GetUserUsageByModel(deps))
		r.Get("/admin/v1/users/{user_id}/usage/records", handler.GetUserUsageRecords(deps))

		r.Get("/admin/v1/agent-identities", handler.AgentIdentityManagement(deps))
		r.Post("/admin/v1/agent-identities", handler.AgentIdentityManagement(deps))

		// Agent Sessions (Phase 5)
		r.Get("/admin/v1/agent-sessions", handler.ListAgentSessions(deps))
		r.Get("/admin/v1/agent-sessions/stats", handler.GetAgentStats(deps))
		r.Get("/admin/v1/agent-sessions/distribution", handler.GetAgentTypeDistribution(deps))
		r.Get("/admin/v1/agent-sessions/by-type", handler.ListAgentSessionsByType(deps))
		r.Get("/admin/v1/agent-sessions/{session_id}", handler.GetAgentSession(deps))

		// Statistics Dashboard (Phase 6)
		r.Get("/admin/v1/stats/overview", handler.GetStatsOverview(deps))
		r.Get("/admin/v1/stats/org", handler.GetOrgStats(deps))
		r.Get("/admin/v1/stats/users", handler.GetUserStats(deps))
		r.Get("/admin/v1/stats/apps", handler.GetAppStats(deps))
		r.Get("/admin/v1/stats/models", handler.GetModelStats(deps))
		r.Get("/admin/v1/stats/agents", handler.GetAgentStats(deps))
		r.Get("/admin/v1/stats/agents/distribution", handler.GetAgentTypeDistribution(deps))

		// Agent Statistics (extended)
		r.Get("/admin/v1/audit/agents/user/{user_id}", handler.GetUserAgentDetail(deps))
		r.Get("/admin/v1/audit/agents/sessions", handler.ListAgentSessionsByType(deps))

		// Tool Call Audit (Skills/MCP Risk Audit)
		r.Get("/admin/v1/audit/tools/stats", handler.GetToolCallStats(deps))
		r.Get("/admin/v1/audit/tools/high-risk", handler.ListHighRiskToolCalls(deps))
		r.Get("/admin/v1/audit/tools/session/{session_id}", handler.ListSessionToolCalls(deps))
		r.Get("/admin/v1/audit/tools/user/{user_id}", handler.GetUserToolCalls(deps))
		r.Get("/admin/v1/audit/tools/trend", handler.GetRiskTrend(deps))

		// Tool Risk Config (Skills/MCP Risk Management)
		r.Get("/admin/v1/tools/config", handler.GetToolRiskConfigs(deps))
		r.Post("/admin/v1/tools/config", handler.CreateToolRiskConfig(deps))
		r.Put("/admin/v1/tools/config/{id}", handler.UpdateToolRiskConfig(deps))
		r.Delete("/admin/v1/tools/config/{id}", handler.DeleteToolRiskConfig(deps))
		r.Post("/admin/v1/tools/config/batch", handler.BatchUpsertToolRiskConfigs(deps))

		// Skill supply-chain facts visible at the gateway or submitted as an archive.
		r.Get("/admin/v1/skills/assets", handler.ListSkillAssets(deps))
		r.Get("/admin/v1/skills/assets/{id}/versions", handler.ListSkillAssetVersions(deps))
		r.Get("/admin/v1/skills/invocations", handler.ListSkillInvocations(deps))
		r.Post("/admin/v1/skills/scan", handler.ScanSkillArchive(deps))
		r.Post("/admin/v1/skills/versions/{id}/admission", handler.SetSkillVersionAdmission(deps))
		// AgentGuard policy governance
		r.Get("/admin/v1/agentguard/policies", handler.ListAgentGuardPolicies(deps))
		r.Post("/admin/v1/agentguard/policies", handler.CreateAgentGuardPolicy(deps))
		r.Put("/admin/v1/agentguard/policies/{id}", handler.UpdateAgentGuardPolicy(deps))
		r.Get("/admin/v1/agentguard/templates", handler.ListAgentGuardTemplates(deps))
		r.Get("/admin/v1/agentguard/governance/stats", handler.GetAgentGuardFalsePositiveStats(deps))
		r.Get("/admin/v1/agentguard/risk-overview", handler.GetAgentRiskOverview(deps))
		r.Post("/admin/v1/agentguard/policies/simulate", handler.SimulateAgentGuardPolicy(deps))
		r.Get("/admin/v1/agentguard/policies/{id}/versions", handler.ListAgentGuardPolicyVersions(deps))
		r.Post("/admin/v1/agentguard/policies/{id}/rollback", handler.RollbackAgentGuardPolicy(deps))
		r.Get("/admin/v1/agentguard/exceptions", handler.ListAgentGuardExceptions(deps))
		r.Post("/admin/v1/agentguard/exceptions", handler.CreateAgentGuardException(deps))
		r.Delete("/admin/v1/agentguard/exceptions/{id}", handler.DeleteAgentGuardException(deps))
		r.Post("/admin/v1/agentguard/exceptions/suggest", handler.SuggestAgentGuardException(deps))
		r.Get("/admin/v1/agentguard/confirmations", handler.ListAgentGuardConfirmations(deps))
		r.Post("/admin/v1/agentguard/confirmations/{id}/resolve", handler.ResolveAgentGuardConfirmation(deps))
		if cfg.AgentEndpointEnabled {
			r.Get("/admin/v1/agent/approvals", agentAuthorizationApprovalAPI.ListApprovals)
			r.Post("/admin/v1/agent/approvals/{id}/resolve", agentAuthorizationApprovalAPI.ResolveApproval)
			r.Post("/admin/v1/agent/approvals/{id}/revoke", agentAuthorizationApprovalAPI.RevokeApproval)
			r.Get("/admin/v1/agent/approval-exceptions", agentAuthorizationApprovalAPI.ListExceptions)
			r.Post("/admin/v1/agent/approval-exceptions", agentAuthorizationApprovalAPI.CreateException)
			r.Delete("/admin/v1/agent/approval-exceptions/{id}", agentAuthorizationApprovalAPI.RevokeException)
		}
		r.Get("/admin/v1/agentguard/behavior/baseline", handler.GetAgentGuardBehaviorBaseline(deps))
		r.Get("/admin/v1/agentguard/rollouts", handler.ListAgentGuardRollouts(deps))
		r.Post("/admin/v1/agentguard/rollouts", handler.CreateAgentGuardRollout(deps))
		// Policy center agent behavior projection; advanced editors remain separate.
		r.Get("/admin/v1/policy-center/agent-behaviors", handler.GetPolicyCenterAgentBehaviors(deps))
		r.Put("/admin/v1/policy-center/agent-behaviors/{key}", handler.PutPolicyCenterAgentBehavior(deps))

		r.With(handler.RequireFullTenantContentEvidence).Get("/admin/v1/proxy/forward-access", handler.ListForwardProxyAccess(deps))
		r.With(handler.RequireFullTenantContentEvidence).Get("/admin/v1/audit/access-retention", handler.ListForwardProxyAccess(deps))
		r.With(handler.RequireFullTenantContentEvidence).Get("/admin/v1/audit/access-retention/runs", handler.ListEvidenceRuns(deps))
		r.With(handler.RequireFullTenantContentEvidence).Post("/admin/v1/audit/leak-trace", handler.LeakTrace(deps))
		r.With(handler.RequireFullTenantContentEvidence).Get("/admin/v1/audit/access-retention/{request_id}/timeline", handler.GetEvidenceTimeline(deps))
		r.With(handler.RequireFullTenantContentEvidence).Post("/admin/v1/audit/access-retention/{request_id}/timeline", handler.GetEvidenceTimeline(deps))
		r.With(handler.RequireFullTenantContentEvidence).Get("/admin/v1/audit/access-retention/export", handler.ExportForwardProxyAccess(deps))
		r.With(handler.RequireFullTenantContentEvidence).Get("/admin/v1/audit/access-retention/{request_id}/content", handler.GetAccessRetentionContent(deps))
		r.With(handler.RequireFullTenantContentEvidence).Post("/admin/v1/audit/access-retention/{request_id}/content", handler.GetAccessRetentionContent(deps))
		r.With(handler.RequireFullTenantContentEvidence).Get("/admin/v1/audit/access-retention/{request_id}/image-proxy", handler.GetAccessRetentionImageProxy(deps))
		r.With(handler.RequireFullTenantContentEvidence).Get("/admin/v1/audit/access-retention/{request_id}/artifacts/{artifact_id}/preview", handler.GetAccessRetentionArtifact(true, deps))
		r.With(handler.RequireFullTenantContentEvidence).Get("/admin/v1/audit/access-retention/{request_id}/artifacts/{artifact_id}/original", handler.GetAccessRetentionArtifact(false, deps))
		r.With(handler.RequireFullTenantContentEvidence).Get("/admin/v1/audit/access-retention/{request_id}/blob", handler.GetAccessRetentionBlob(deps))
		r.Get("/admin/v1/llm-provider-catalog", handler.ListLLMProviderCatalog())
		r.Post("/admin/v1/llm-provider-catalog/test-match", handler.MatchLLMProviderCatalog())

		// Proxy whitelist
		r.Get("/admin/v1/proxy/whitelist", handler.GetProxyWhitelist(deps))
		r.Post("/admin/v1/proxy/whitelist", handler.CreateProxyWhitelist(deps))
		r.Put("/admin/v1/proxy/whitelist/{id}", handler.UpdateProxyWhitelist(deps))
		r.Delete("/admin/v1/proxy/whitelist/{id}", handler.DeleteProxyWhitelist(deps))

		// Reverse proxy routes
		r.Get("/admin/v1/reverse-proxy/routes", handler.ListReverseProxyRoutes(deps))
		r.Post("/admin/v1/reverse-proxy/routes", handler.CreateReverseProxyRoute(deps))
		r.Put("/admin/v1/reverse-proxy/routes/{id}", handler.UpdateReverseProxyRoute(deps))
		r.Delete("/admin/v1/reverse-proxy/routes/{id}", handler.DeleteReverseProxyRoute(deps))

		// CA management
		r.Post("/admin/v1/ca/generate", handler.GenerateCA(deps))
		r.Get("/admin/v1/ca/certificate", handler.GetCACertificate(deps))
		r.Get("/admin/v1/ca/download", handler.DownloadCACertificate(deps))
		r.Get("/admin/v1/ca/{id}/download", handler.DownloadCACertificate(deps))
		r.Get("/admin/v1/ca/list", handler.ListCACertificates(deps))
		r.Post("/admin/v1/ca/{id}/activate", handler.ActivateCACertificate(deps))
		r.Delete("/admin/v1/ca/{id}", handler.DeleteCACertificate(deps))

		// 内容留存存储后端配置(本地/挂载目录 | S3 兼容)
		r.Get("/admin/v1/retention/storage-config", handler.GetRetentionStorageConfig(deps))
		r.Put("/admin/v1/retention/storage-config", handler.UpdateRetentionStorageConfig(deps))
		r.Post("/admin/v1/retention/storage-config/test", handler.TestRetentionStorageConfig(deps))

		// Users (private deployment)
		r.Get("/admin/v1/users", handler.ListUsers(deps))
		r.Post("/admin/v1/users", handler.CreateUser(deps))
		r.Patch("/admin/v1/users/{id}", handler.UpdateUser(deps))
		r.Delete("/admin/v1/users/{id}", handler.DeleteUser(deps))
		r.Post("/admin/v1/users/{id}/reset-password", handler.ResetPassword(deps))
		// W3 控制台登录安全
		r.Post("/admin/v1/users/{id}/unlock-login", handler.UnlockUserLogin(deps))
		r.Post("/admin/v1/users/{id}/reset-totp", handler.ResetUserTOTP(deps))
		r.Get("/admin/v1/system/login-security", handler.GetConsoleLoginSecurity(deps))
		r.Put("/admin/v1/system/login-security", handler.UpdateConsoleLoginSecurity(deps))
		r.Get("/admin/v1/system/portal-login-baseline", handler.GetPortalLoginBaseline(deps))
		r.Patch("/admin/v1/users/{id}/status", handler.ToggleUserStatus(deps))
		r.Post("/admin/v1/users/{id}/department/automatic", handler.SetUserDepartmentAutomatic(deps))
		r.Get("/admin/v1/users/{id}/grants", handler.ListUserGrants(deps))
		r.Get("/admin/v1/users/{id}/keys", handler.GetUserKeys(deps))
		r.Post("/admin/v1/users/{id}/grants", handler.CreateUserGrant(deps))
		r.Delete("/admin/v1/users/{id}/grants/{grant_id}", handler.DeleteUserGrant(deps))
		r.Get("/admin/v1/users/{id}/login-history", handler.GetUserLoginHistory(deps))
		// W4: tenant-wide login history for the auditor
		r.Get("/admin/v1/audit/login-history", handler.ListLoginHistoryAudit(deps))
		r.Get("/admin/v1/users/{id}/detail", handler.GetUserDetail(deps))
		r.Post("/admin/v1/users/{id}/merge/preview", handler.AccountMerge(deps, true))
		r.Post("/admin/v1/users/{id}/merge", handler.AccountMerge(deps, false))
		r.Post("/admin/v1/users/{id}/identity-links/{link_id}/rebind", handler.RebindUserIdentity(deps))
		r.Get("/admin/v1/users/{id}/model-access", handler.GetUserModelAccess(deps))
		r.Put("/admin/v1/users/{id}/model-access", handler.SetUserModelAccess(deps))
		r.Get("/admin/v1/users/{id}/model-access/extra-grants", handler.GetUserModelAccess(deps))
		r.Post("/admin/v1/users/{id}/model-access/extra-grants", handler.CreateUserModelExtraGrant(deps))
		r.Post("/admin/v1/users/{id}/model-access/extra-grants/{grant_id}/revoke", handler.RevokeUserModelExtraGrant(deps))

		// System settings (private deployment)
		r.Get("/admin/v1/system/settings", handler.GetSystemSettings(deps))
		r.Put("/admin/v1/system/settings", handler.UpdateSystemSettings(deps))
		r.Get("/admin/v1/security/reply-policy", handler.GetSecurityReplyPolicy(deps))
		r.Put("/admin/v1/security/reply-policy", handler.PutSecurityReplyPolicy(deps))
		r.Get("/admin/v1/security/semantic/runtime-status", handler.GetSemanticRuntimeStatus(deps))
		r.Get("/admin/v1/security/posture", handler.GetSecurityPosture(deps))
		r.Get("/api/security/posture", handler.GetSecurityPosture(deps))
		r.Post("/admin/v1/system/lse/test", handler.TestLSEConnection(deps))
		r.Get("/admin/v1/system/license", handler.GetLicenseStatus(deps))
		r.Post("/admin/v1/system/license/import", handler.ImportLicense(deps))
		r.Get("/admin/v1/system/license/host-info", handler.GetLicenseHostInfo(deps))
		r.Get("/admin/v1/system/audit-operations", handler.ListAuditOperationsW8(deps))
		r.Get("/admin/v1/system/audit-operations/export", handler.ExportAuditOperations(deps))

		// Upgrade & Version (private deployment)
		r.Get("/admin/v1/system/product", handler.GetProductInfo(deps))
		r.Get("/admin/v1/system/version", handler.GetVersionInfo(deps))
		r.Post("/admin/v1/system/upgrade/check", handler.CheckUpgrade(deps))
		r.Post("/admin/v1/system/upgrade/upload", handler.UploadUpgradePackage(deps))
		r.Post("/admin/v1/system/upgrade/execute", handler.ExecuteUpgrade(deps))
		r.Post("/admin/v1/system/upgrade/rollback", handler.RollbackUpgrade(deps))
		r.Get("/admin/v1/system/upgrade/history", handler.GetUpgradeHistory(deps))
		r.Post("/admin/v1/system/ruleset/sync", handler.SyncRuleSet(deps))

		// Org / Teams (T17)
		r.With(handler.OrgWriterGuard).Post("/admin/v1/teams", handler.CreateTeam(deps))
		r.Get("/admin/v1/teams", handler.ListTeams(deps))
		r.With(handler.OrgWriterGuard).Delete("/admin/v1/teams/{id}", handler.DeleteTeam(deps))
		r.With(handler.OrgWriterGuard).Post("/admin/v1/teams/{id}/members", handler.AddTeamMember(deps))
		r.With(handler.OrgWriterGuard).Delete("/admin/v1/teams/{id}/members/{user_id}", handler.RemoveTeamMember(deps))
		// IAM enterprise (B3-B5)
		r.Get("/admin/v1/teams/{id}/members", handler.ListTeamMembers(deps))
		r.With(handler.OrgWriterGuard).Post("/admin/v1/teams/{id}/members/batch", handler.BatchAddTeamMembers(deps))
		r.With(handler.OrgWriterGuard).Put("/admin/v1/teams/{id}/budget", handler.UpdateTeamBudget(deps))
		r.Get("/admin/v1/teams/{id}/models", handler.GetTeamModels(deps))
		r.With(handler.OrgWriterGuard).Put("/admin/v1/teams/{id}/models", handler.PutTeamModels(deps))
		r.With(handler.OrgWriterGuard).Delete("/admin/v1/teams/{id}/models/{model_id}", handler.DeleteTeamModel(deps))
		r.Get("/admin/v1/teams/{id}/effective", handler.GetTeamEffective(deps))
		r.Get("/admin/v1/teams/{id}/projects", handler.GetTeamProjects(deps))
		r.Get("/admin/v1/teams/{id}/usage", handler.GetTeamUsage(deps))
		r.Patch("/admin/v1/projects/{id}/team", handler.PatchProjectTeam(deps))
		r.Patch("/admin/v1/users/{id}/personal-budget", handler.PatchUserPersonalBudget(deps))
		// Budget module (T22)
		r.Get("/admin/v1/budgets/snapshot", handler.GetBudgetSnapshot(deps))
		r.Post("/admin/v1/budgets/keys/{key_prefix}/pause", handler.PauseKey(deps))
		r.Post("/admin/v1/budgets/keys/{key_prefix}/unpause", handler.UnpauseKey(deps))
		r.Get("/admin/v1/budgets/pause-log", handler.ListPauseLog(deps))
		// Billing/health real read models (feat/billing-readmodels-20261002).
		// ReadModelDeps is intentionally separate from Dependencies: every
		// field maps to a variable that already exists above, and the read
		// models never touch the billing core write paths.
		readModelDeps := handler.ReadModelDeps{
			DB:                         db,
			KeyRepo:                    keyRepo,
			BillingStore:               billingStore,
			BudgetSnapshot:             snapshotReader,
			OrgService:                 orgService,
			RedisClient:                redisClient,
			GatewayCoreURL:             cfg.GatewayCoreURL,
			SecurityEngineURL:          cfg.SecurityEngineURL,
			BillingCompensationMonitor: billingCompensationMonitor,
			SemanticDeps:               deps,
		}
		r.Get("/admin/v1/budgets/keys/{key_id}/readmodel", handler.GetBudgetKeyReadModel(readModelDeps))
		r.Get("/admin/v1/service-health/readmodel", handler.GetServiceHealthReadModel(readModelDeps))

		// 运维诊断机器人（员工可用的接口为 SoDCommon；诊断包与设置修改仅管理员）
		r.Post("/admin/v1/diagnostics/sessions", handler.CreateDiagnosticsSession(diagEngine))
		r.Get("/admin/v1/diagnostics/sessions", handler.ListDiagnosticsSessions(diagEngine))
		r.Get("/admin/v1/diagnostics/sessions/{id}", handler.GetDiagnosticsSession(diagEngine))
		r.Post("/admin/v1/diagnostics/sessions/{id}/messages", handler.AddDiagnosticsMessage(diagEngine))
		r.Get("/admin/v1/diagnostics/sessions/{id}/bundle", handler.DownloadDiagnosticsBundle(diagEngine))
		r.Get("/admin/v1/diagnostics/settings", handler.GetDiagnosticsSettings(diagEngine))
		r.Put("/admin/v1/diagnostics/settings", handler.PutDiagnosticsSettings(diagEngine))
		r.Get("/admin/v1/diagnostics/badge", handler.GetDiagnosticsBadge(diagEngine))
		// Billing operations (platform_admin only).
		r.Get("/admin/v1/billing/runtime", handler.GetBillingRuntime(deps))
		r.Get("/admin/v1/billing/customers", handler.ListBillingCustomers(deps))
		r.Get("/admin/v1/billing/models", handler.ListBillingModels(deps))
		r.Get("/admin/v1/billing/pricing-capabilities", handler.GetBillingPricingCapabilities(deps))
		r.Get("/admin/v1/billing/employee-settings", handler.GetEmployeeBillingSettings(deps))
		r.Put("/admin/v1/billing/employee-settings", handler.PutEmployeeBillingSettings(deps))
		r.Post("/admin/v1/billing/currency-switch", handler.SwitchBillingCurrency(deps))
		r.Get("/admin/v1/billing/employee-allowances", handler.ListEmployeeMonthlyAllowances(deps))
		r.Get("/admin/v1/billing/budget-tree", handler.GetBillingBudgetTree(deps))
		r.Get("/admin/v1/billing/statements/monthly", handler.GetBillingMonthlyStatement(deps))
		r.Put("/admin/v1/billing/employee-allowances", handler.PutEmployeeMonthlyAllowances(deps))
		r.Get("/admin/v1/billing/upstream-models", handler.ListBillingUpstreamModels(deps))
		r.Get("/admin/v1/billing/upstream-rates", handler.ListBillingUpstreamRates(deps))
		r.Put("/admin/v1/billing/upstream-rates", handler.PutBillingUpstreamRate(deps))
		r.Delete("/admin/v1/billing/upstream-rates", handler.DeleteBillingUpstreamRate(deps))
		r.Get("/admin/v1/billing/channel-fixed-costs", handler.ListBillingChannelFixedCosts(deps))
		r.Put("/admin/v1/billing/channel-fixed-costs", handler.PutBillingChannelFixedCost(deps))
		r.Delete("/admin/v1/billing/channel-fixed-costs", handler.DeleteBillingChannelFixedCost(deps))
		r.Put("/admin/v1/billing/customers/{id}/group", handler.AssignBillingCustomerGroup(deps))
		r.Get("/admin/v1/billing/customer-groups", handler.ListBillingCustomerGroups(deps))
		r.Post("/admin/v1/billing/customer-groups", handler.CreateBillingCustomerGroup(deps))
		r.Patch("/admin/v1/billing/customer-groups/{id}", handler.UpdateBillingCustomerGroup(deps))
		r.Post("/admin/v1/billing/wallets/credit", handler.CreditCustomerWallet(deps))
		r.Post("/admin/v1/billing/wallets/adjustments", handler.AdjustCustomerWallet(deps))
		r.Get("/admin/v1/billing/ledger", handler.ListBillingLedger(deps))
		r.Get("/admin/v1/billing/prices", handler.ListBillingPrices(deps))
		r.Post("/admin/v1/billing/prices", handler.CreateBillingPrice(deps))
		r.Post("/admin/v1/billing/prices/newapi-ratio", handler.CreateBillingRatioPrice(deps))
		r.Get("/admin/v1/billing/tariffs", handler.ListBillingTariffPlans(deps))
		r.Post("/admin/v1/billing/tariffs", handler.CreateBillingTariffPlan(deps))
		r.Put("/admin/v1/billing/tariffs/{id}", handler.UpdateBillingTariffPlan(deps))
		r.Delete("/admin/v1/billing/tariffs/{id}", handler.DeleteBillingTariffPlan(deps))
		r.Post("/admin/v1/billing/tariffs/{id}/publish", handler.PublishBillingTariffPlan(deps))
		r.Post("/admin/v1/billing/tariffs/{id}/retire", handler.RetireBillingTariffPlan(deps))
		r.Get("/admin/v1/billing/tariffs/preview", handler.PreviewBillingTariff(deps))
		r.Get("/admin/v1/billing/redemptions", handler.ListBillingRedemptions(deps))
		r.Get("/admin/v1/billing/redemptions/export", handler.ExportBillingRedemptionHints(deps))
		r.Get("/admin/v1/billing/redemptions/{id}", handler.GetBillingRedemptionDetail(deps))
		r.Post("/admin/v1/billing/redemptions/{id}/reveal", handler.RevealBillingRedemption(deps))
		r.Post("/admin/v1/billing/redemptions/batch-disable", handler.BatchUpdateBillingRedemptions(deps))
		r.Post("/admin/v1/billing/redemptions", handler.CreateBillingRedemptions(deps))
		r.Patch("/admin/v1/billing/redemptions/{id}", handler.UpdateBillingRedemption(deps))
		r.Delete("/admin/v1/billing/redemptions/{id}", handler.DeleteBillingRedemption(deps))
		// 规则包按节点拉取/收敛观测（方案A 下发可见性）
		r.Get("/admin/v1/rules/pull-status", handler.GetRulePackPullStatus(deps))
		// FX rates (T33)
		r.Get("/admin/v1/fx/current", handler.GetCurrentFxRate(deps))
		r.Put("/admin/v1/fx", handler.SetFxRate(deps))
		r.Get("/admin/v1/fx/history", handler.GetFxHistory(deps))
		// Savings API (T37)
		r.Get("/admin/v1/savings/summary", handler.GetSavingsSummary(deps))
		r.Get("/admin/v1/savings/trend", handler.GetSavingsTrend(deps))
		// Savings config (P15)
		r.Get("/admin/v1/savings/config", handler.GetSavingsConfig(deps))
		r.Put("/admin/v1/savings/config", handler.UpdateSavingsConfig(deps))
		r.Get("/admin/v1/agent-operation-protection", handler.GetAgentOperationProtection(deps))
		r.Put("/admin/v1/agent-operation-protection", handler.PutAgentOperationProtection(deps))
		r.Get("/admin/v1/agent-operation-events", handler.ListAgentOperationEvents(deps))
		r.Get("/admin/v1/agent-operation-events/{public_event_id}", handler.GetAgentOperationEvent(deps))
		// Alert inbox (T42)
		r.Get("/admin/v1/alerts/inbox", handler.ListAlertInboxW8(deps))
		r.Get("/admin/v1/alerts/inbox/export", handler.ExportAlertInbox(deps))
		r.Get("/admin/v1/alerts/inbox/folded", handler.ListAlertInboxFolded(deps))
		r.Get("/admin/v1/alerts/inbox/folded/items", handler.ListAlertInboxFoldedItems(deps))
		r.Get("/admin/v1/alerts/inbox/type-summary", handler.AlertInboxTypeSummary(deps))
		r.Get("/admin/v1/alerts/inbox/bulk-read/preview", handler.PreviewBulkReadAlertInbox(deps))
		r.Post("/admin/v1/alerts/inbox/bulk-read", handler.BulkReadAlertInbox(deps))
		r.Post("/admin/v1/alerts/{id}/read", handler.MarkAlertRead(deps))
		r.Get("/admin/v1/alert-groups", handler.ListAlertGroups(deps))
		r.Post("/admin/v1/alert-groups/batch-status", handler.BatchUpdateAlertGroupStatus(deps))
		r.Get("/admin/v1/alert-groups/{id}", handler.GetAlertGroup(deps))
		r.Get("/admin/v1/alert-groups/{id}/events", handler.ListAlertGroupEvents(deps))
		r.Patch("/admin/v1/alert-groups/{id}", handler.UpdateAlertGroupStatus(deps))
		// Notify channels (T42)
		r.Get("/admin/v1/notify-channels", handler.ListNotifyChannels(deps))
		r.Post("/admin/v1/notify-channels", handler.CreateNotifyChannel(deps))
		r.Put("/admin/v1/notify-channels/{id}", handler.UpdateNotifyChannel(deps))
		r.Delete("/admin/v1/notify-channels/{id}", handler.DeleteNotifyChannel(deps))
		r.Post("/admin/v1/notify-channels/{id}/test", handler.TestNotifyChannel(deps))
		// Proxy access keys (P1-10, task 1.7)
		r.Get("/admin/v1/proxy-access-keys", handler.ListProxyAccessKeys(deps))
		r.Post("/admin/v1/proxy-access-keys", handler.CreateProxyAccessKey(deps))
		r.Put("/admin/v1/proxy-access-keys/{id}", handler.UpdateProxyAccessKey(deps))
		r.Delete("/admin/v1/proxy-access-keys/{id}", handler.DeleteProxyAccessKey(deps))
		r.Post("/admin/v1/proxy-access-keys/{id}/rotate", handler.RotateProxyAccessKey(deps))
		// MCP servers (P1-22, task 1.8)
		r.Get("/admin/v1/mcp-servers", handler.ListMCPServers(deps))
		r.Post("/admin/v1/mcp-servers", handler.CreateMCPServer(deps))
		r.Put("/admin/v1/mcp-servers/{id}", handler.UpdateMCPServer(deps))
		r.Delete("/admin/v1/mcp-servers/{id}", handler.DeleteMCPServer(deps))
		// MCP 安全网关：能力同步 + 工具清单 + 权限策略（新路由必须双注册 permission/resolver.go + seed.go）
		r.Post("/admin/v1/mcp-servers/{id}/sync", handler.SyncMCPServer(deps))
		r.Post("/admin/v1/mcp-servers/{id}/test-connection", handler.TestMCPServer(deps))
		r.Get("/admin/v1/mcp-servers/{id}/tools", handler.ListMCPServerTools(deps))
		r.Post("/admin/v1/mcp-servers/{id}/admission", handler.SetMCPServerAdmission(deps))
		r.Post("/admin/v1/mcp-tools/{id}/admission", handler.SetMCPToolAdmission(deps))
		r.Get("/admin/v1/mcp-tools/shadow-check", handler.MCPToolShadowCheck(deps))
		r.Get("/admin/v1/mcp-policies", handler.ListMCPPolicies(deps))
		r.Post("/admin/v1/mcp-policies", handler.CreateMCPPolicy(deps))
		// 预演/遮蔽检测（零 DB 副作用）：静态段路由，须先于 /{id} 注册避免被当成 id。
		r.Post("/admin/v1/mcp-policies/simulate", handler.SimulateMCPPolicy(deps))
		r.Get("/admin/v1/mcp-policies/shadow-check", handler.MCPPolicyShadowCheck(deps))
		r.Post("/admin/v1/mcp-policies/shadow-check", handler.MCPPolicyShadowCheck(deps))
		r.Put("/admin/v1/mcp-policies/{id}", handler.UpdateMCPPolicy(deps))
		r.Delete("/admin/v1/mcp-policies/{id}", handler.DeleteMCPPolicy(deps))
		// 内置安全红线处置配置（W1 1.11）：GET 任意有 mcp_policies 读权限的成员，PUT 仅管理员（handler 内再校验角色）
		r.Get("/admin/v1/mcp-redline-settings", handler.GetMCPRedlineSettings(deps, mcpRedlineSettingsStore))
		r.Put("/admin/v1/mcp-redline-settings", handler.UpdateMCPRedlineSettings(deps, mcpRedlineSettingsStore))
		// 防护项设置（2.9.22）：权限与三员分立在 permission 包登记（读：安全配置读，写：安全配置写），PUT 另在 handler 内校验 CanManageSecurityPolicy
		r.Get("/admin/v1/protection-settings", handler.GetProtectionSettings(deps))
		r.Put("/admin/v1/protection-settings", handler.UpdateProtectionSettings(deps))
		// 可选“只允许勾选的工具”模板（W1 1.6）与 MCP 调用审计全量导出（W1 1.13）：同样此前漏接线
		r.Get("/admin/v1/mcp-servers/{id}/allowlist-template", handler.GetMCPAllowlistTemplate(deps))
		r.Post("/admin/v1/mcp-servers/{id}/allowlist-template", handler.ApplyMCPAllowlistTemplate(deps))
		r.Delete("/admin/v1/mcp-servers/{id}/allowlist-template", handler.RemoveMCPAllowlistTemplate(deps))
		r.Get("/admin/v1/mcp-audit/export", handler.ExportMCPAuditLogs(deps))
		// Provider price snapshots (P2-2, task 1.9) — read-only history
		r.Get("/admin/v1/provider-price-snapshots", handler.ListProviderPriceSnapshots(deps))
		// Audit chain WORM (P10)
		r.Post("/admin/v1/audit-chain/verify", handler.VerifyAuditChain(deps))
		r.Get("/admin/v1/audit-chain/stats", handler.GetAuditChainStats(deps))
		r.Get("/admin/v1/audit-chain/integrity", handler.GetAuditChainIntegrity(deps))
		r.Get("/admin/v1/audit-chain/export", handler.ExportAuditChain(deps))
		// Anomaly detection (P18)
		r.Get("/admin/v1/anomalies", handler.ListAnomalies(deps))
		r.Post("/admin/v1/anomalies/{id}/ack", handler.AckAnomaly(deps))

		// Forecast dry-run (P21)
		r.Post("/admin/v1/forecast/jobs", handler.CreateForecastJob(deps))
		r.Get("/admin/v1/forecast/jobs", handler.ListForecastJobs(deps))
		r.Get("/admin/v1/forecast/jobs/{id}", handler.GetForecastJob(deps))

		// R15: routing policies CRUD
		// Model routing v2: keep static routes before parameter and wildcard routes.
		r.Get("/admin/v1/model-routing", handler.GetModelRouting(deps))
		r.Get("/admin/v1/model-routing/status", handler.GetModelRoutingStatus(deps))
		r.Get("/admin/v1/model-routing/routes", handler.ListModelRoutingRoutes(deps))
		r.Get("/admin/v1/model-routing/models", handler.SearchModelRoutingModels(deps))
		r.Put("/admin/v1/model-routing/default", handler.PutModelRoutingDefault(deps))
		r.Delete("/admin/v1/model-routing/default", handler.DeleteModelRoutingDefault(deps))
		r.Post("/admin/v1/model-routing/validate", handler.ValidateModelRouting(deps))
		r.Put("/admin/v1/model-routing/models/{model_name}", handler.PutModelRoutingOverride(deps))
		r.Delete("/admin/v1/model-routing/models/{model_name}", handler.DeleteModelRoutingOverride(deps))
		r.Put("/admin/v1/model-routing/models/*", handler.PutModelRoutingOverride(deps))
		r.Delete("/admin/v1/model-routing/models/*", handler.DeleteModelRoutingOverride(deps))

		r.Get("/admin/v1/routing-policies", handler.ListRoutingPolicies(deps))
		r.Put("/admin/v1/routing-policies", handler.UpsertRoutingPolicy(deps))
		r.Delete("/admin/v1/routing-policies/{id}", handler.DeleteRoutingPolicy(deps))
		// R16: dry-run test endpoint
		r.Post("/admin/v1/routing-policies/test", handler.TestRoutingPolicy(deps))

		// R16b: routing decisions (observability) — exposes request_logs.routing_decision_json
		r.Get("/admin/v1/routing-decisions", handler.ListRoutingDecisions(deps))
		r.Get("/admin/v1/routing-decisions/{request_id}", handler.GetRoutingDecision(deps))
		// RBAC: roles + permissions metadata
		r.Get("/admin/v1/roles", handler.ListRoles(deps))
		r.Get("/admin/v1/roles/{name}/permissions", handler.GetRolePermissions(deps))
		r.Get("/admin/v1/permissions/resources", handler.ListPermissionResources(deps))
		r.Get("/admin/v1/permissions/actions", handler.ListPermissionActions(deps))
		// RBAC: me/permissions
		r.Get("/admin/v1/me/permissions", handler.GetMyPermissions(deps))
	})
	server := newControlPlaneHTTPServer(cfg.ListenAddr, r)

	go func() {
		log.Printf("control-plane starting on %s version=%s", cfg.ListenAddr, version.Version)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Server error: %v", err)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	stopWorkers()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	server.Shutdown(shutdownCtx)
	modelOperationsJobsHTTP.Wait(shutdownCtx)
	corpusScanHTTP.Wait(shutdownCtx)
	select {
	case <-modelOperationsDone:
	case <-shutdownCtx.Done():
		log.Printf("model operations scheduler shutdown timed out")
	}
	db.Close()
	redisClient.Close()
	log.Println("control-plane stopped")
}

func startBillingReconciliation(ctx context.Context, store *billing.Store, monitor *billing.ReconciliationMonitor, metering bool) {
	if store == nil {
		return
	}
	reconcile := store.ReconcileStaleReservations
	if metering {
		reconcile = store.ReconcileStaleMeteringReservations
	}
	startBillingReconciliationWorker(ctx, reconcile, monitor)
}

type billingReconcileFunc func(context.Context, time.Duration, int) (billing.ReconciliationResult, error)

func runBillingReconciliation(ctx context.Context, label string, reconcile billingReconcileFunc, monitor *billing.ReconciliationMonitor) {
	runCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	monitor.Start(time.Now().UTC())
	result, err := reconcile(runCtx, 15*time.Minute, 100)
	monitor.Complete(time.Now().UTC(), result, err)
	if err != nil {
		log.Printf("[billing_reconcile] %s failed: %v", label, err)
		return
	}
	if result.Released > 0 || result.Settled > 0 || result.Pending > 0 {
		log.Printf("[billing_reconcile] %s settled=%d released=%d pending=%d", label, result.Settled, result.Released, result.Pending)
	}
}

func startBillingReconciliationWorker(ctx context.Context, reconcile billingReconcileFunc, monitor *billing.ReconciliationMonitor) <-chan struct{} {
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer monitor.Stop()
		runBillingReconciliation(ctx, "startup", reconcile, monitor)
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				runBillingReconciliation(ctx, "scheduled", reconcile, monitor)
			}
		}
	}()
	return done
}

func startBillingRequestLeaseCleanup(ctx context.Context, store *billing.Store) {
	if store == nil {
		return
	}
	run := func(label string) {
		runCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
		defer cancel()
		result, err := store.PruneRequestLeases(runCtx, time.Now().UTC())
		if err != nil {
			log.Printf("[billing_request_leases] %s cleanup paused deleted=%d batches=%d backlog=%v: %v",
				label, result.Deleted, result.Batches, result.Backlog, err)
			return
		}
		if result.Backlog {
			log.Printf("[billing_request_leases] %s cleanup backlog remains deleted=%d batches=%d",
				label, result.Deleted, result.Batches)
		} else if result.Deleted > 0 {
			log.Printf("[billing_request_leases] %s cleanup drained deleted=%d batches=%d",
				label, result.Deleted, result.Batches)
		}
	}
	go func() {
		run("startup")
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				run("scheduled")
			}
		}
	}()
}

func newControlPlaneHTTPServer(addr string, handler http.Handler) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      modelSyncControlPlaneRequestTimeout + 30*time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    32 << 10,
	}
}

type accessContentRetentionRepo interface {
	DeleteExpiredAccessContentLogs(context.Context) (int64, error)
}

func startAccessContentRetentionCron(ctx context.Context, repo accessContentRetentionRepo) {
	if repo == nil {
		return
	}
	run := func(label string) {
		deleted, err := repo.DeleteExpiredAccessContentLogs(ctx)
		if err != nil {
			log.Printf("[access_retention] %s cleanup failed: %v", label, err)
			return
		}
		if deleted > 0 {
			log.Printf("[access_retention] %s deleted %d expired content rows", label, deleted)
		}
	}
	go func() {
		run("startup")
		ticker := time.NewTicker(24 * time.Hour)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				run("daily")
			}
		}
	}()
}

// logRetentionHardFloorDays 是删除保护下限:无论 log_retention_days 配多小,
// content_logs/tool_call_logs 至少保留这么多天,防误配把保留期内的留证清掉。
// 与 proxy-server/gateway-core 写 retention_until 共用 shared-go/logretention 口径。
const logRetentionHardFloorDays = logretention.MinDays

type olderThanDeleter interface {
	DeleteOlderThan(ctx context.Context, retentionDays int) (int64, error)
}

type requestLogPruner interface {
	DeleteRequestLogsOlderThan(ctx context.Context, retentionDays int) (int64, error)
}

// resolveLogRetentionDays 读 system_settings.log_retention_days(默认90),并夹到硬下限之上。
func resolveLogRetentionDays(ctx context.Context, db *pgxpool.Pool) int {
	var raw string
	if err := db.QueryRow(ctx, `SELECT value FROM system_settings WHERE key = 'log_retention_days'`).Scan(&raw); err != nil {
		return logretention.DefaultDays
	}
	return logretention.Resolve(raw)
}

// startLogRetentionCron 每24h按 log_retention_days(夹硬下限)清 content_logs/tool_call_logs
// 及 request_logs 原始明细超期行,止住无界增长。WORM 红线:只删超过保留期的行;request_logs
// 只删无 security_events(安全事件=审计留存)且无 tool_events(RESTRICT 外键)引用的记录,
// 安全事件相关明细与 audit_chain、法定留存期内数据绝不受影响。
const (
	agentEventRetentionDefaultDays = 90
	agentEventRetentionMinDays     = 30
)

func resolveAgentEventRetentionDays(raw string) int {
	days := agentEventRetentionDefaultDays
	if n, err := strconv.Atoi(strings.TrimSpace(raw)); err == nil && n > 0 {
		days = n
	}
	if days < agentEventRetentionMinDays {
		days = agentEventRetentionMinDays
	}
	return days
}

type agentRetentionRepo interface {
	DeleteRetainedData(context.Context, int) (repository.AgentRetentionResult, error)
}

func startAgentRetentionCron(ctx context.Context, repo agentRetentionRepo, retentionDays int) {
	if repo == nil {
		return
	}
	run := func(label string) {
		runCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
		defer cancel()
		result, err := repo.DeleteRetainedData(runCtx, retentionDays)
		if err != nil {
			log.Printf("[agent_retention] %s cleanup failed: %v", label, err)
			return
		}
		if result.Events+result.Turns+result.Sessions+result.Assets > 0 {
			log.Printf("[agent_retention] %s deleted events=%d turns=%d sessions=%d assets=%d older than %d days", label, result.Events, result.Turns, result.Sessions, result.Assets, retentionDays)
		}
	}
	go func() {
		run("startup")
		ticker := time.NewTicker(24 * time.Hour)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				run("daily")
			}
		}
	}()
}

type agentAuthorizationRetentionRepo interface {
	PruneExpiredData(context.Context) (repository.AgentAuthorizationCleanupResult, error)
}
type agentIntentTaskRetentionRepo interface {
	DeleteExpiredIntentTasks(context.Context) (int64, error)
}

func startAgentAuthorizationRetentionCron(ctx context.Context, repo agentAuthorizationRetentionRepo) {
	if repo == nil {
		return
	}
	run := func(label string) {
		runCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
		defer cancel()
		result, err := repo.PruneExpiredData(runCtx)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			log.Printf("[agent_authorization_retention] %s cleanup paused deleted_requests=%d deleted_usage=%d batches=%d backlog=%t: %v",
				label, result.DeletedRequests, result.DeletedUsage, result.Batches, result.Backlog, err)
			return
		}
		if result.Backlog || result.DeletedRequests > 0 || result.DeletedUsage > 0 {
			log.Printf("[agent_authorization_retention] %s deleted_requests=%d deleted_usage=%d batches=%d backlog=%t",
				label, result.DeletedRequests, result.DeletedUsage, result.Batches, result.Backlog)
		}
		if tasks, ok := repo.(agentIntentTaskRetentionRepo); ok {
			deleted, cleanupErr := tasks.DeleteExpiredIntentTasks(runCtx)
			if cleanupErr != nil {
				if ctx.Err() == nil {
					log.Printf("[agent_intent_task_retention] %s cleanup failed: %v", label, cleanupErr)
				}
			} else if deleted > 0 {
				log.Printf("[agent_intent_task_retention] %s deleted=%d expired approved-task records", label, deleted)
			}
		}
	}
	go func() {
		run("startup")
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				run("scheduled")
			}
		}
	}()
}

func startLogRetentionCron(ctx context.Context, db *pgxpool.Pool, contentRepo, toolRepo olderThanDeleter, requestRepo requestLogPruner) {
	if db == nil || contentRepo == nil || toolRepo == nil || requestRepo == nil {
		return
	}
	run := func(label string) {
		days := resolveLogRetentionDays(ctx, db)
		if n, err := contentRepo.DeleteOlderThan(ctx, days); err != nil {
			log.Printf("[log_retention] %s content_logs cleanup failed: %v", label, err)
		} else if n > 0 {
			log.Printf("[log_retention] %s deleted %d content_logs rows older than %d days", label, n, days)
		}
		if n, err := toolRepo.DeleteOlderThan(ctx, days); err != nil {
			log.Printf("[log_retention] %s tool_call_logs cleanup failed: %v", label, err)
		} else if n > 0 {
			log.Printf("[log_retention] %s deleted %d tool_call_logs rows older than %d days", label, n, days)
		}
		if n, err := requestRepo.DeleteRequestLogsOlderThan(ctx, days); err != nil {
			log.Printf("[log_retention] %s request_logs cleanup failed: %v", label, err)
		} else if n > 0 {
			log.Printf("[log_retention] %s deleted %d request_logs rows older than %d days (CASCADE content)", label, n, days)
		}
	}
	go func() {
		run("startup")
		ticker := time.NewTicker(24 * time.Hour)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				run("daily")
			}
		}
	}()
}
