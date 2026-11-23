package repository

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// 告警案件物化：后台维护的调度与一次性准备。

// MaintainAlertCases 是后台维护的一轮：推进各租户的历史回填，消化各租户的待重算队列，直到做完或用完时间预算。
// 返回本轮处理的回填批次数与队列条数之和。
func (r *AlertOccurrenceRepository) MaintainAlertCases(ctx context.Context, budget time.Duration) (int, error) {
	usable, err := alertCaseStoreUsable(ctx, r.db)
	if err != nil || !usable {
		return 0, err
	}
	useMeta, err := r.useReadMetadata(ctx)
	if err != nil {
		return 0, err
	}
	if err := ensureAlertCaseLogicVersion(ctx, r.db, useMeta); err != nil {
		return 0, fmt.Errorf("check alert case logic version: %w", err)
	}
	deadline := time.Now().Add(budget)
	work := 0
	// 某个租户回填或消化出错时记下来、本轮跳过它，别的租户照常处理；整轮结束后一并返回错误。
	var failures []error
	failed := map[string]bool{}
	for time.Now().Before(deadline) {
		var tenants []string
		if err := r.db.QueryRow(ctx, `SELECT COALESCE(array_agg(tenant_id ORDER BY tenant_id),'{}') FROM alert_case_backfill WHERE NOT done`).Scan(&tenants); err != nil {
			return work, err
		}
		progressed := false
		for _, tenant := range tenants {
			if time.Now().After(deadline) {
				return work, errors.Join(failures...)
			}
			if failed[tenant] {
				continue
			}
			if _, err := backfillAlertCases(ctx, r.db, useMeta, tenant, alertCaseBackfillBatch); err != nil {
				failures = append(failures, fmt.Errorf("backfill alert cases for %s: %w", tenant, err))
				failed[tenant] = true
				continue
			}
			work++
			progressed = true
		}
		if err := r.db.QueryRow(ctx, `SELECT COALESCE(array_agg(DISTINCT tenant_id),'{}') FROM alert_case_dirty`).Scan(&tenants); err != nil {
			return work, err
		}
		for _, tenant := range tenants {
			if time.Now().After(deadline) {
				return work, errors.Join(failures...)
			}
			if failed[tenant] {
				continue
			}
			// 每批持锁时间都短（窄条目按条数、告警组和凭据按展开后的事件数切批）；坏条目逐条重试后移进隔离表，
			// 同租户的其他条目照常消化。
			n, err := drainAlertCasesInBatches(ctx, r.db, useMeta, tenant, alertCaseLock{}, true)
			work += n
			progressed = progressed || n > 0
			if errors.Is(err, errAlertCaseQuarantined) {
				failures = append(failures, err)
				continue
			}
			if err != nil {
				failures = append(failures, fmt.Errorf("drain alert cases for %s: %w", tenant, err))
				failed[tenant] = true
			}
		}
		// 隔离超过重试间隔的坏条目再试一次。
		if err := r.db.QueryRow(ctx, `SELECT COALESCE(array_agg(DISTINCT tenant_id),'{}') FROM alert_case_dirty_quarantine
 WHERE last_failed_at <= now() - make_interval(secs => $1)`, alertCaseQuarantineRetryAfter.Seconds()).Scan(&tenants); err != nil {
			return work, err
		}
		for _, tenant := range tenants {
			if failed[tenant] || time.Now().After(deadline) {
				continue
			}
			if _, err := retryAlertCaseQuarantine(ctx, r.db, useMeta, tenant); err != nil {
				failures = append(failures, fmt.Errorf("retry quarantined alert case entries for %s: %w", tenant, err))
				failed[tenant] = true
			}
		}
		if !progressed {
			break
		}
	}
	return work, errors.Join(failures...)
}

// PrepareAlertCases 把一个租户的回填做完、队列清空（测试与运维脚本用；平时由后台维护完成）。
func (r *AlertOccurrenceRepository) PrepareAlertCases(ctx context.Context, tenant string) error {
	exists, err := alertCaseStoreExists(ctx, r.db)
	if err != nil {
		return err
	}
	if !exists {
		return errAlertCaseStoreMissing
	}
	if usable, err := alertCaseStoreUsable(ctx, r.db); err != nil || !usable {
		if err == nil {
			err = errAlertCaseTriggersMissing
		}
		return err
	}
	useMeta, err := r.useReadMetadata(ctx)
	if err != nil {
		return err
	}
	if err := ensureAlertCaseLogicVersion(ctx, r.db, useMeta); err != nil {
		return err
	}
	for {
		finished, err := backfillAlertCases(ctx, r.db, useMeta, tenant, alertCaseBackfillBatch)
		if err != nil {
			return err
		}
		if finished {
			break
		}
	}
	for {
		n, err := drainAlertCasesInBatches(ctx, r.db, useMeta, tenant, alertCaseLock{}, false)
		if err != nil {
			return err
		}
		if n == 0 {
			return nil
		}
	}
}
