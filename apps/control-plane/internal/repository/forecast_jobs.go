package repository

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ForecastJob represents a row in the forecast_jobs table.
type ForecastJob struct {
	ID         string
	TenantID   string
	Status     string
	ParamsJSON map[string]any
	ResultJSON map[string]any
	Error      string
	CreatedBy  string
	CreatedAt  *time.Time
	FinishedAt *time.Time
}

// ForecastJobRepository handles forecast_jobs database operations.
type ForecastJobRepository struct {
	db *pgxpool.Pool
}

// NewForecastJobRepository creates a new ForecastJobRepository.
func NewForecastJobRepository(db *pgxpool.Pool) *ForecastJobRepository {
	return &ForecastJobRepository{db: db}
}

// Create inserts a new forecast job with status=pending.
func (r *ForecastJobRepository) Create(ctx context.Context, job *ForecastJob) error {
	paramsBytes, err := json.Marshal(job.ParamsJSON)
	if err != nil {
		return fmt.Errorf("marshal params_json: %w", err)
	}
	_, err = r.db.Exec(ctx, `
		INSERT INTO forecast_jobs (id, tenant_id, status, params_json, created_by)
		VALUES ($1, $2, 'pending', $3::jsonb, $4)
	`, job.ID, job.TenantID, string(paramsBytes), job.CreatedBy)
	if err != nil {
		return fmt.Errorf("create forecast_job: %w", err)
	}
	return nil
}

// Get retrieves a forecast job by ID.
func (r *ForecastJobRepository) Get(ctx context.Context, id string) (*ForecastJob, error) {
	row := r.db.QueryRow(ctx, `
		SELECT id, tenant_id, status, params_json, result_json, error, created_by, created_at, finished_at
		FROM forecast_jobs
		WHERE id = $1
	`, id)
	return scanForecastJob(row)
}

// ListByTenant returns jobs for a tenant, most recent first, up to limit.
func (r *ForecastJobRepository) ListByTenant(ctx context.Context, tenantID string, limit int) ([]*ForecastJob, error) {
	rows, err := r.db.Query(ctx, `
		SELECT id, tenant_id, status, params_json, result_json, error, created_by, created_at, finished_at
		FROM forecast_jobs
		WHERE tenant_id = $1
		ORDER BY created_at DESC
		LIMIT $2
	`, tenantID, limit)
	if err != nil {
		return nil, fmt.Errorf("list forecast_jobs: %w", err)
	}
	defer rows.Close()

	var jobs []*ForecastJob
	for rows.Next() {
		job, err := scanForecastJobRow(rows)
		if err != nil {
			return nil, err
		}
		jobs = append(jobs, job)
	}
	return jobs, rows.Err()
}

// ClaimPending atomically picks the oldest pending job and transitions it to running.
// Returns nil, nil if no pending job exists.
func (r *ForecastJobRepository) ClaimPending(ctx context.Context) (*ForecastJob, error) {
	row := r.db.QueryRow(ctx, `
		UPDATE forecast_jobs
		SET status = 'running'
		WHERE id = (
			SELECT id FROM forecast_jobs
			WHERE status = 'pending'
			ORDER BY created_at
			LIMIT 1
			FOR UPDATE SKIP LOCKED
		)
		RETURNING id, tenant_id, status, params_json, result_json, error, created_by, created_at, finished_at
	`)
	job, err := scanForecastJob(row)
	if err != nil {
		return nil, err
	}
	return job, nil
}

// Finish sets the job status (done/failed), result, error message, and finished_at.
func (r *ForecastJobRepository) Finish(ctx context.Context, id, status string, result map[string]any, errMsg string) error {
	var resultBytes []byte
	if result != nil {
		b, err := json.Marshal(result)
		if err != nil {
			return fmt.Errorf("marshal result_json: %w", err)
		}
		resultBytes = b
	}
	_, err := r.db.Exec(ctx, `
		UPDATE forecast_jobs
		SET status = $2,
		    result_json = $3::jsonb,
		    error = $4,
		    finished_at = NOW()
		WHERE id = $1
	`, id, status, nullableJSON(resultBytes), errMsg)
	if err != nil {
		return fmt.Errorf("finish forecast_job: %w", err)
	}
	return nil
}

// nullableJSON returns nil if b is nil, else a string pointer.
func nullableJSON(b []byte) interface{} {
	if b == nil {
		return nil
	}
	s := string(b)
	return s
}

type forecastJobScanner interface {
	Scan(dest ...any) error
}

func scanForecastJob(row forecastJobScanner) (*ForecastJob, error) {
	return scanForecastJobRow(row)
}

func scanForecastJobRow(row forecastJobScanner) (*ForecastJob, error) {
	var job ForecastJob
	var paramsRaw, resultRaw []byte
	var errMsg *string
	var createdBy *string
	err := row.Scan(
		&job.ID,
		&job.TenantID,
		&job.Status,
		&paramsRaw,
		&resultRaw,
		&errMsg,
		&createdBy,
		&job.CreatedAt,
		&job.FinishedAt,
	)
	if errMsg != nil {
		job.Error = *errMsg
	}
	if createdBy != nil {
		job.CreatedBy = *createdBy
	}
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("scan forecast_job: %w", err)
	}
	if paramsRaw != nil {
		if err := json.Unmarshal(paramsRaw, &job.ParamsJSON); err != nil {
			return nil, fmt.Errorf("unmarshal params_json: %w", err)
		}
	}
	if resultRaw != nil {
		if err := json.Unmarshal(resultRaw, &job.ResultJSON); err != nil {
			return nil, fmt.Errorf("unmarshal result_json: %w", err)
		}
	}
	return &job, nil
}
