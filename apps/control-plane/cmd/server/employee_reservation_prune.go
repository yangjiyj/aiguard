package main

import (
	"context"
	"log"
	"os"
	"strings"
	"time"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/billing"
)

const (
	// 与 gateway-core 的 GATEWAY_REQUEST_TIMEOUT 默认值一致；预占的最大合理存活时间 = 最大请求时长 + 5 分钟。
	defaultGatewayRequestTimeout        = 30 * time.Minute
	employeeReservationGrace            = 5 * time.Minute
	employeeReservationPruneEvery       = time.Minute
	employeeReservationPruneBatch       = 500
	employeeReservationMaxBatchesPerRun = 20
)

// employeeReservationMaxAge 返回员工额度预占允许的最大存活时间：最大请求时长 + 5 分钟。
// 请求时长取 GATEWAY_REQUEST_TIMEOUT（与网关一致），缺失或非法时用 30 分钟默认值。
func employeeReservationMaxAge() time.Duration {
	timeout := defaultGatewayRequestTimeout
	if raw := strings.TrimSpace(os.Getenv("GATEWAY_REQUEST_TIMEOUT")); raw != "" {
		if parsed, err := time.ParseDuration(raw); err == nil && parsed > 0 {
			timeout = parsed
		}
	}
	return timeout + employeeReservationGrace
}

type employeeReservationPruneFunc func(ctx context.Context, maxAge time.Duration, now time.Time, limit int) (deleted int64, backlog bool, err error)

// employeeReservationLeakReporter 接收每轮各租户释放的预占数（产生“预占泄漏清理”告警）。
type employeeReservationLeakReporter func(ctx context.Context, tenantID string, released int64)

// startEmployeeReservationPrune 在现有对账节奏（每分钟）里清理过期的员工额度预占，释放被永久占住的额度。
// 员工额度在 metering 与 prepaid 两种计费模式下都生效，所以不依赖 prepaid 对账 worker。
func startEmployeeReservationPrune(ctx context.Context, store *billing.Store, report employeeReservationLeakReporter) {
	if store == nil {
		return
	}
	startEmployeeReservationPruneWorker(ctx, employeeReservationPruneEvery, employeeReservationMaxAge(),
		func(runCtx context.Context, maxAge time.Duration, now time.Time, limit int) (int64, bool, error) {
			result, err := store.PruneStaleEmployeeReservations(runCtx, maxAge, now, limit)
			if report != nil {
				for tenantID, released := range result.ByTenant {
					report(context.WithoutCancel(runCtx), tenantID, released)
				}
			}
			return result.Deleted, result.Backlog, err
		})
}

func startEmployeeReservationPruneWorker(ctx context.Context, interval, maxAge time.Duration, prune employeeReservationPruneFunc) <-chan struct{} {
	done := make(chan struct{})
	run := func(label string) {
		runCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		var total int64
		for batch := 0; batch < employeeReservationMaxBatchesPerRun; batch++ {
			deleted, backlog, err := prune(runCtx, maxAge, time.Now().UTC(), employeeReservationPruneBatch)
			total += deleted
			if err != nil {
				log.Printf("[billing_employee_reservations] %s prune failed deleted=%d: %v", label, total, err)
				return
			}
			if !backlog {
				break
			}
		}
		if total > 0 {
			log.Printf("[billing_employee_reservations] %s released %d stale allowance reservation(s)", label, total)
		}
	}
	go func() {
		defer close(done)
		run("startup")
		ticker := time.NewTicker(interval)
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
	return done
}

type billingOpsAlertScanner interface {
	RunOnce(ctx context.Context, now time.Time) (int, error)
}

// runBillingOpsAlertScanner 按间隔扫描计费事件并转成告警组；单轮失败只打日志，下一轮继续。
func runBillingOpsAlertScanner(ctx context.Context, scanner billingOpsAlertScanner, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		runCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		if n, err := scanner.RunOnce(runCtx, time.Now().UTC()); err != nil {
			log.Printf("[billing_ops_alert] scan failed: %v", err)
		} else if n > 0 {
			log.Printf("[billing_ops_alert] %d billing alert group(s) updated", n)
		}
		cancel()
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
