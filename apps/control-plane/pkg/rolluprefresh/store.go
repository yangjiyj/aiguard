package rolluprefresh

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

type Store struct {
	db   *pgxpool.Pool
	repo *repository.RollupReadModelRepository
}

func NewStore(db *pgxpool.Pool) *Store {
	return &Store{db: db, repo: repository.NewRollupReadModelRepository(db)}
}

func (s *Store) ActiveTenantIDs(ctx context.Context) ([]string, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("rollup refresh db is nil")
	}
	rows, err := s.db.Query(ctx, `
		SELECT id
		FROM tenants
		WHERE status = 'active'
		ORDER BY id
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	ids := []string{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

func (s *Store) Refresh(ctx context.Context, tenantID string, from, to time.Time) error {
	if s == nil || s.repo == nil {
		return errors.New("rollup refresh repository is nil")
	}
	win := repository.RollupRefreshWindow{TenantID: tenantID, From: from, To: to}
	if err := s.repo.RefreshUsageHourly(ctx, win); err != nil {
		return err
	}
	return s.repo.RefreshAccessHourly(ctx, win)
}
