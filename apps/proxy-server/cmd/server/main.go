package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/yangjiyj/aiguard/apps/proxy-server/internal/config"
	"github.com/yangjiyj/aiguard/apps/proxy-server/internal/handler"
	"github.com/yangjiyj/aiguard/apps/proxy-server/internal/httpmw"

	"github.com/yangjiyj/aiguard/packages/shared-go/buildinfo"
	sharedDB "github.com/yangjiyj/aiguard/packages/shared-go/dbhelpers"
	"github.com/yangjiyj/aiguard/packages/shared-go/headeraudit"
	"github.com/yangjiyj/aiguard/packages/shared-go/inspectionscope"
	"github.com/yangjiyj/aiguard/packages/shared-go/retentionstore"
	"github.com/yangjiyj/aiguard/packages/shared-go/scanfp"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}
	version := buildinfo.Current()
	log.Printf("proxy-server version=%s commit=%s built_at=%s", version.Version, version.Commit, version.BuiltAt)

	// Initialize PostgreSQL connection pool
	ctx, stopWorkers := context.WithCancel(context.Background())
	defer stopWorkers()
	db, err := sharedDB.NewPoolForService(ctx, sharedDB.ServiceProxy, cfg.DatabaseURL)
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	defer db.Close()
	log.Println("Connected to PostgreSQL")

	// Initialize whitelist checker
	whitelistChecker := handler.NewWhitelistCheckerWithPolicy(db, cfg.ControlPlaneURL, cfg.ProxyDefaultTenantID, cfg.ProxyWhitelistFailMode)

	// Initialize CA manager
	caManager := handler.NewCAManager(db, cfg.ControlPlaneURL)

	// Initialize security client
	securityClient := handler.NewSecurityClientWithSecret(cfg.SecurityEngineURL, cfg.InternalAPISecret)
	inspectionSettings := inspectionscope.NewGatewayReader(cfg.ControlPlaneURL, cfg.InternalAPISecret, os.Getenv("JJD_SEMANTIC_GATEWAY_ATTESTATION_KEY"))
	inspectionSettings.Start(ctx)
	securityClient.WithInspectionScope(inspectionSettings)
	securityClient.WithFileDLPSettingReader(handler.NewDBFileDLPSettingReaderFromPool(db))
	securityClient.WithSecurityAuditOnlySettingReader(handler.NewDBSecurityAuditOnlySettingReaderFromPool(db))
	// 只带文件 id 的附件按租户文件策略处置（与网关同口径，2.9.22）。
	securityClient.WithFileReferencePolicyReader(handler.NewDBFileReferencePolicyReaderFromPool(db))
	// 检测服务不可用读控制台 guardrail_fail_closed_enabled，库里没有时 PROXY_DETECTION_FAIL_MODE 作初值。
	securityClient.WithDetectionFailClosedSettingReader(handler.NewDBDetectionFailClosedSettingReaderFromPool(db))

	// Initialize audit writer
	auditWriter := handler.NewAuditWriter(db).WithEnvironmentScope(cfg.EnvironmentScope)

	// P1-B 已检指纹缓存（模块 2a）：代码默认关，compose 交付显式置 true。
	if os.Getenv("SECURITY_SCAN_FP_ENABLED") == "true" {
		securityClient.WithFingerprintStore(scanfp.NewStore(db, 4096))
		log.Println("Scan fingerprint cache enabled (SECURITY_SCAN_FP_ENABLED=true)")
	}
	inspectionQueue, queueErr := handler.NewInspectionQueue(db, securityClient, cfg.InternalAPISecret, cfg.EnvironmentScope)
	if queueErr != nil {
		log.Fatalf("Durable inspection initialization failed: %v", queueErr)
	}
	inspectionQueue.Start(ctx)

	// 留存后端从 DB 配置实例化(默认 local,可配 S3),启动 + 60s 热刷新,改了不用重启。
	if rcfg, rerr := retentionstore.LoadConfig(ctx, db, cfg.RetentionStorePath); rerr == nil {
		if store, serr := retentionstore.NewStore(rcfg); serr == nil {
			auditWriter.WithRetentionStore(store)
			log.Printf("Retention store initialized backend=%s", rcfg.Backend)
		} else {
			log.Printf("retention store init failed (backend=%s): %v", rcfg.Backend, serr)
		}
	} else {
		log.Printf("load retention storage config failed: %v", rerr)
	}
	startRetentionBlobReaper(ctx, auditWriter.RetentionStore)
	startRetentionConfigReloader(ctx, db, cfg.RetentionStorePath, auditWriter)

	// One critical-audit client is shared by HTTP and MITM boundaries.
	headerAuditClient := headeraudit.NewClient(cfg.ControlPlaneURL, cfg.InternalAPISecret)

	// Create proxy handler
	proxyHandler := handler.NewProxyHandler(whitelistChecker, caManager, securityClient, auditWriter, headerAuditClient).
		WithEgressSettings(handler.NewEgressSettingsReaderFromPool(db))
	// 受限文件模式：正向代理侧策略读取器（内部 API + TTL 缓存 + 失败回退）。
	// 无内部密钥时 reader 永远返回空策略（功能关闭）并在启动日志提示一次。
	proxyHandler = proxyHandler.WithRestrictedFilePolicyReader(
		handler.NewHTTPRestrictedFilePolicyReader(cfg.ControlPlaneURL, cfg.InternalAPISecret))

	// 双层代理：客户 PC -> 本代理 -> 客户出网代理 -> 互联网。默认不启用。
	// 配置非法直接启动失败：若降级为警告继续跑，客户会以为流量经他的
	// 出网代理而实际是直连出网，那是合规事故，不是可用性问题。
	upstreamProxy, upstreamErr := handler.ParseUpstreamProxy(cfg.UpstreamEgressProxy)
	if upstreamErr != nil {
		log.Fatalf("UPSTREAM_EGRESS_PROXY 配置无效：%v", upstreamErr)
	}
	if upstreamProxy != nil {
		proxyHandler.SetUpstreamEgressProxy(upstreamProxy)
		log.Printf("upstream egress proxy enabled host=%s", upstreamProxy.Host)
	}

	// Create router
	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	// 注意：不再使用 chi middleware.RealIP（无条件信任 XFF/X-Real-IP，裸暴露下可被伪造）。
	// 改用基于 TRUSTED_PROXY_CIDRS 的可信代理中间件：默认不改写 RemoteAddr。
	r.Use(httpmw.TrustedRealIP)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Timeout(60 * time.Second))
	r.Get(handler.InspectionRuntimeStatusPath, handler.InspectionRuntimeStatusHandler(handler.WithProxySecurityPosture(inspectionSettings, proxyHandler), cfg.InternalAPISecret, proxyHandler.Handle))

	// Proxy endpoint - handles all HTTP requests
	r.HandleFunc("/", proxyHandler.Handle)
	r.HandleFunc("/*", proxyHandler.Handle)

	server := &http.Server{
		Addr:         cfg.ListenAddr,
		Handler:      r,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 60 * time.Second,
	}

	go func() {
		log.Printf("proxy-server starting on %s version=%s", cfg.ListenAddr, version.Version)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Server error: %v", err)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	stopWorkers()
	server.Shutdown(shutdownCtx)
	db.Close()
	log.Println("proxy-server stopped")
}

// startRetentionBlobReaper 每 24h 清理 retention_until 已过期的明文附件 blob(对当前后端)。
// 只删超期对象(WORM 安全)。getStore 每轮取当前后端,故配置热切换后 reap 的是新后端。
func startRetentionBlobReaper(ctx context.Context, getStore func() retentionstore.Store) {
	run := func(label string) {
		store := getStore()
		if store == nil {
			return
		}
		n, err := store.ReapExpired(ctx, time.Now())
		if err != nil {
			log.Printf("[blob_reaper] %s failed: %v", label, err)
			return
		}
		if n > 0 {
			log.Printf("[blob_reaper] %s reaped %d expired retention blobs", label, n)
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

// startRetentionConfigReloader 每 60s 看 retention_storage_config 是否变更(按 updated_at),
// 变了就重建后端并热替换到 auditWriter(改了不用重启)。重建失败保留旧后端,不断留存。
func startRetentionConfigReloader(ctx context.Context, db *pgxpool.Pool, localRoot string, aw *handler.AuditWriter) {
	if db == nil || aw == nil {
		return
	}
	go func() {
		last := time.Time{}
		if s, err := retentionstore.ReadSettings(ctx, db); err == nil {
			last = s.UpdatedAt // 与启动配置对齐,避免首个 tick 无谓重建
		}
		ticker := time.NewTicker(60 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
			s, err := retentionstore.ReadSettings(ctx, db)
			if err != nil {
				continue
			}
			if s.UpdatedAt.Equal(last) {
				continue
			}
			cfg, lerr := retentionstore.LoadConfig(ctx, db, localRoot)
			if lerr != nil {
				log.Printf("[retention_reload] load failed: %v", lerr)
				continue
			}
			store, serr := retentionstore.NewStore(cfg)
			if serr != nil {
				log.Printf("[retention_reload] rebuild failed (backend=%s): %v", cfg.Backend, serr)
				continue
			}
			aw.WithRetentionStore(store)
			last = s.UpdatedAt
			log.Printf("[retention_reload] switched retention backend=%s", cfg.Backend)
		}
	}()
}
