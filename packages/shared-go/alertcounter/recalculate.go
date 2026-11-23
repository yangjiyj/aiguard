package alertcounter

import (
	"context"
	"github.com/jackc/pgx/v5/pgxpool"
)

// RecalculateGroup serializes the snapshot with other group writers. Taking
// the row lock in a separate statement ensures a fresh READ COMMITTED snapshot
// after waiting for a concurrent writer, rather than counting its old facts.
func RecalculateGroup(ctx context.Context, db *pgxpool.Pool, tenant, group string) (int, int, error) {
	return recalculate(ctx, db, tenant, group, false)
}
func RecalculateRepresentative(ctx context.Context, db *pgxpool.Pool, tenant, event string) (int, int, error) {
	return recalculate(ctx, db, tenant, event, true)
}
func recalculate(ctx context.Context, db *pgxpool.Pool, tenant, id string, representative bool) (int, int, error) {
	tx, err := db.Begin(ctx)
	if err != nil {
		return 0, 0, err
	}
	defer tx.Rollback(ctx)
	lock := `SELECT id FROM alert_groups WHERE tenant_id=$1 AND id=$2 FOR UPDATE`
	if representative {
		lock = `SELECT ag.id FROM alert_groups ag JOIN security_events se ON se.tenant_id=ag.tenant_id AND se.alert_group_id=ag.id WHERE se.tenant_id=$1 AND se.id=$2 FOR UPDATE OF ag`
	}
	var group string
	if err = tx.QueryRow(ctx, lock, tenant, id).Scan(&group); err != nil {
		return 0, 0, err
	}
	var occurrences, users int
	if err = tx.QueryRow(ctx, ByGroup, tenant, group).Scan(&occurrences, &users); err != nil {
		return 0, 0, err
	}
	if err = tx.Commit(ctx); err != nil {
		return 0, 0, err
	}
	return occurrences, users, nil
}
