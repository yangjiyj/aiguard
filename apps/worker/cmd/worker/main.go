package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/yangjiyj/aiguard/apps/control-plane/pkg/notifydispatch"
	"github.com/yangjiyj/aiguard/apps/control-plane/pkg/rolluprefresh"
	"github.com/yangjiyj/aiguard/apps/worker/internal/auditpipe"
	"github.com/yangjiyj/aiguard/apps/worker/internal/backfill"
	"github.com/yangjiyj/aiguard/apps/worker/internal/config"
	"github.com/yangjiyj/aiguard/apps/worker/internal/fpclean"
	"github.com/yangjiyj/aiguard/apps/worker/internal/nasexport"
	"github.com/yangjiyj/aiguard/apps/worker/internal/notifyagent"
	"github.com/yangjiyj/aiguard/apps/worker/internal/rollup"
	"github.com/yangjiyj/aiguard/packages/shared-go/dbhelpers"
	"github.com/yangjiyj/aiguard/packages/shared-go/outbox"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)

	cfg, err := config.LoadFromEnv()
	if err != nil {
		logger.Error("failed to load worker config", "error", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	db, err := dbhelpers.NewPoolForService(ctx, dbhelpers.ServiceWorker, cfg.DatabaseURL)
	if err != nil {
		logger.Error("failed to connect database", "error", err)
		os.Exit(1)
	}
	defer db.Close()

	if len(os.Args) > 1 {
		if len(os.Args) != 2 || os.Args[1] != "backfill-once" {
			logger.Error("unknown worker command")
			os.Exit(64)
		}
		runner := backfill.NewRunner(backfill.NewPostgresStore(db), backfill.Config{
			Owner: cfg.ConsumerName + "-manual", PollInterval: cfg.MigrationBackfillPollInterval,
			Lease: cfg.MigrationBackfillLease, Logger: logger,
		})
		didWork, runErr := runner.RunOnce(ctx)
		if runErr != nil {
			logger.Error("manual migration backfill batch failed", "error", runErr)
			os.Exit(1)
		}
		logger.Info("manual migration backfill batch finished", "did_work", didWork)
		return
	}

	if cfg.MigrationBackfillEnabled {
		backfillRunner := backfill.NewRunner(backfill.NewPostgresStore(db), backfill.Config{
			Owner: cfg.ConsumerName, PollInterval: cfg.MigrationBackfillPollInterval,
			Lease: cfg.MigrationBackfillLease, Logger: logger,
		})
		go backfillRunner.Run(ctx)
	}

	rollupStore := rolluprefresh.NewStore(db)
	rollupRunner := rollup.NewRunner(rollupStore, rollupStore, rollup.Config{
		Interval: cfg.RollupRefreshInterval,
		Lookback: cfg.RollupLookback,
		Logger:   logger,
	})
	go rollupRunner.Run(ctx)

	fpCleaner := fpclean.NewRunner(db, fpclean.Config{
		Interval:  cfg.ScanFPCleanInterval,
		Retention: cfg.ScanFPRetention,
		Logger:    logger,
	})
	go fpCleaner.Run(ctx)

	if cfg.OutboxEnabled {
		// 安全事件处理器：先写 DB(Sink)；NAS 导出开启时再链式导脱敏事件到挂载目录。
		var processor auditpipe.Processor = auditpipe.NewSink(db, cfg.EnvironmentScope)
		if cfg.NASExportEnabled {
			nasProc, err := nasexport.NewProcessor(cfg.NASExportDir)
			if err != nil {
				logger.Error("NAS export processor init failed, falling back to DB-only", "error", err)
			} else {
				processor = auditpipe.NewChainProcessor(auditpipe.NewSink(db, cfg.EnvironmentScope), nasProc)
				logger.Info("NAS 脱敏事件导出已启用", "dir", cfg.NASExportDir)
			}
		}
		processor = auditpipe.NewChainProcessor(
			processor,
			notifyagent.NewProcessor(notifydispatch.New(db)),
		)
		retryBaseDelay := outbox.DefaultRetryBaseDelay
		trackingStore := notifyagent.NewTrackingStore(db, notifyagent.TrackingConfig{
			MaxAttempts: cfg.OutboxMaxAttempts, RetryBaseDelay: retryBaseDelay,
		})
		auditRunner := auditpipe.NewRunner(trackingStore, processor, auditpipe.Config{
			ConsumerName:   cfg.ConsumerName,
			BatchSize:      cfg.OutboxBatchSize,
			PollInterval:   cfg.OutboxPollInterval,
			MaxAttempts:    cfg.OutboxMaxAttempts,
			RetryBaseDelay: retryBaseDelay,
			Logger:         logger,
		})
		go auditRunner.Run(ctx)
	}

	defer stop()

	logger.Info("worker started",
		"listen_addr", cfg.ListenAddr,
		"event_stream", cfg.EventStream,
		"consumer_group", cfg.ConsumerGroup,
		"consumer_name", cfg.ConsumerName,
		"rollup_refresh_interval", cfg.RollupRefreshInterval.String(),
		"rollup_lookback", cfg.RollupLookback.String(),
		"scan_fp_clean_interval", cfg.ScanFPCleanInterval.String(),
		"outbox_enabled", cfg.OutboxEnabled,
		"outbox_poll_interval", cfg.OutboxPollInterval.String(),
		"outbox_batch_size", cfg.OutboxBatchSize,
		"outbox_max_attempts", cfg.OutboxMaxAttempts,
		"migration_backfill_enabled", cfg.MigrationBackfillEnabled,
	)

	<-ctx.Done()
	logger.Info("worker stopping")
}
