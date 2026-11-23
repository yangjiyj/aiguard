package forecast

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/alert"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Worker processes forecast jobs asynchronously.
type Worker struct {
	repo   *repository.ForecastJobRepository
	db     *pgxpool.Pool
	inbox  *alert.InboxService
	fxRate float64
}

// NewWorker creates a new Worker.
func NewWorker(repo *repository.ForecastJobRepository, db *pgxpool.Pool, inbox *alert.InboxService) *Worker {
	return &Worker{repo: repo, db: db, inbox: inbox, fxRate: 7.20}
}

// SetFxRate sets the USD-to-CNY exchange rate for savings calculations.
func (w *Worker) SetFxRate(r float64) {
	if r > 0 {
		w.fxRate = r
	}
}

// RunPending claims one pending forecast job and executes it.
// Returns 0, nil if no pending jobs exist.
// Returns 1, nil on success; 1, err if processing failed (job marked failed in DB).
func (w *Worker) RunPending(ctx context.Context) (int, error) {
	job, err := w.repo.ClaimPending(ctx)
	if err != nil {
		return 0, fmt.Errorf("claim pending forecast job: %w", err)
	}
	if job == nil {
		return 0, nil
	}

	processErr := w.processJob(ctx, job)
	if processErr != nil {
		_ = w.repo.Finish(ctx, job.ID, "failed", nil, processErr.Error())
		return 1, processErr
	}
	return 1, nil
}

// processJob executes the dry-run replay for a claimed job.
func (w *Worker) processJob(ctx context.Context, job *repository.ForecastJob) error {
	// Parse params
	rangeDays := 30
	var quotaParams QuotaParams

	if v, ok := job.ParamsJSON["range_days"]; ok {
		switch val := v.(type) {
		case float64:
			rangeDays = int(val)
		case json.Number:
			if n, err := val.Int64(); err == nil {
				rangeDays = int(n)
			}
		case int:
			rangeDays = val
		case int64:
			rangeDays = int(val)
		}
	}
	// Cap range_days to 90
	if rangeDays > 90 {
		rangeDays = 90
	}
	if rangeDays <= 0 {
		rangeDays = 30
	}

	if qp, ok := job.ParamsJSON["quota_params"]; ok {
		b, err := json.Marshal(qp)
		if err != nil {
			return fmt.Errorf("re-marshal quota_params: %w", err)
		}
		if err := json.Unmarshal(b, &quotaParams); err != nil {
			return fmt.Errorf("parse quota_params: %w", err)
		}
	}

	// Fetch historical request_logs for this tenant
	rows, err := w.fetchRows(ctx, job.TenantID, rangeDays)
	if err != nil {
		return fmt.Errorf("fetch request_logs: %w", err)
	}

	// Run simulation
	sim := NewSimulator(quotaParams)
	sim.SetFxRate(w.fxRate)
	result := sim.Replay(rows)

	// Serialize result
	resultMap := map[string]any{
		"total":          result.Total,
		"intercepted":    result.Intercepted,
		"saved_usd":      result.SavedUSD,
		"saved_cny":      result.SavedCNY,
		"affected_users": result.AffectedUsers,
		"by_action":      result.ByAction,
	}

	if err := w.repo.Finish(ctx, job.ID, "done", resultMap, ""); err != nil {
		return fmt.Errorf("finish job: %w", err)
	}

	// Send inbox notification
	if w.inbox != nil {
		_ = w.inbox.Push(ctx, job.TenantID, "info", "forecast.done",
			"预测分析完成",
			map[string]any{
				"job_id":      job.ID,
				"intercepted": result.Intercepted,
				"saved_usd":   result.SavedUSD,
				"saved_cny":   result.SavedCNY,
			},
			"/forecast/jobs/"+job.ID,
		)
	}

	return nil
}

// forecastReplayRowsSQL 取租户近 rangeDays 天的业务请求；平台自建的请求日志（名单见
// repository.NonBusinessEndpointTypes）不算业务，不进预测回放。
var forecastReplayRowsSQL = `
		SELECT
			COALESCE(total_cost, 0),
			COALESCE(input_tokens, 0) + COALESCE(output_tokens, 0),
			COALESCE(user_id, '')
		FROM request_logs
		WHERE tenant_id = $1
		  AND created_at >= NOW() - ($2::int * INTERVAL '1 day')
		  AND ` + repository.ExcludeNonBusinessEndpointsSQL("request_logs") + `
		ORDER BY created_at
	`

// fetchRows queries request_logs for the tenant over the last rangeDays days.
func (w *Worker) fetchRows(ctx context.Context, tenantID string, rangeDays int) ([]ReplayRow, error) {
	sqlRows, err := w.db.Query(ctx, forecastReplayRowsSQL, tenantID, rangeDays)
	if err != nil {
		return nil, fmt.Errorf("query request_logs: %w", err)
	}
	defer sqlRows.Close()

	var rows []ReplayRow
	for sqlRows.Next() {
		var row ReplayRow
		if err := sqlRows.Scan(&row.Cost, &row.Tokens, &row.UserID); err != nil {
			return nil, fmt.Errorf("scan request_log row: %w", err)
		}
		rows = append(rows, row)
	}
	return rows, sqlRows.Err()
}
