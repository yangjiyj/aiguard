package repository

import (
	"context"
	"fmt"
	"github.com/jackc/pgx/v5/pgxpool"
	"sync"
	"time"
)

// One connection owns the advisory lock and performs every credential write.
// Waiting operations cannot exhaust the pool needed by the lock holder.
type UserPasswordOperation struct {
	conn               *pgxpool.Conn
	tenant, user, lock string
	once               sync.Once
}

func (r *UserRepository) LockPasswordOperation(ctx context.Context, tenant, user string) (*UserPasswordOperation, error) {
	conn, err := r.db.Acquire(ctx)
	if err != nil {
		return nil, err
	}
	key := fmt.Sprintf("password:%d:%s:%d:%s", len(tenant), tenant, len(user), user)
	if _, err = conn.Exec(ctx, "SELECT pg_advisory_lock(hashtextextended($1,0))", key); err != nil {
		conn.Release()
		return nil, err
	}
	return &UserPasswordOperation{conn: conn, tenant: tenant, user: user, lock: key}, nil
}
func (op *UserPasswordOperation) Close() {
	op.once.Do(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		var unlocked bool
		if err := op.conn.QueryRow(ctx, "SELECT pg_advisory_unlock(hashtextextended($1,0))", op.lock).Scan(&unlocked); err != nil || !unlocked {
			_ = op.conn.Conn().Close(ctx)
		}
		op.conn.Release()
	})
}
func (op *UserPasswordOperation) PrepareNative(ctx context.Context, currentHash string, expectedStatus ...string) (bool, error) {
	state := "active"
	if len(expectedStatus) == 1 {
		state = expectedStatus[0]
	}
	if state != "active" && state != "disabled" && state != "reconciliation_required" {
		return false, nil
	}
	tag, err := op.conn.Exec(ctx, `UPDATE users SET status='reconciliation_required',local_credential_version=local_credential_version+1,updated_at=NOW() WHERE tenant_id=$1 AND id=$2 AND status=$4::varchar AND password_hash=$3`, op.tenant, op.user, currentHash, state)
	return tag.RowsAffected() == 1, err
}
func (op *UserPasswordOperation) UpdatePassword(ctx context.Context, hash string, mustChange bool, expectedHash ...string) (bool, error) {
	expected := ""
	if len(expectedHash) == 1 {
		expected = expectedHash[0]
	}
	tag, err := op.conn.Exec(ctx, `UPDATE users SET password_hash=$3,must_change_password=$4,local_credential_version=local_credential_version+1,updated_at=NOW() WHERE tenant_id=$1 AND id=$2 AND ($5='' OR password_hash=$5)`, op.tenant, op.user, hash, mustChange, expected)
	return tag.RowsAffected() == 1, err
}
func (op *UserPasswordOperation) CompleteNative(ctx context.Context, hash string, finalStatus ...string) (bool, error) {
	state := "active"
	if len(finalStatus) == 1 {
		state = finalStatus[0]
	}
	if state != "active" && state != "disabled" {
		return false, nil
	}
	tag, err := op.conn.Exec(ctx, `UPDATE users SET status=$4::varchar,updated_at=NOW() WHERE tenant_id=$1 AND id=$2 AND status='reconciliation_required' AND password_hash=$3`, op.tenant, op.user, hash, state)
	return tag.RowsAffected() == 1, err
}

// Administrative resets read the current hash after acquiring the same lock
// as self-service, so a queued reset cannot apply a stale password snapshot.
func (op *UserPasswordOperation) CurrentPasswordState(ctx context.Context) (string, string, error) {
	var hash, status string
	err := op.conn.QueryRow(ctx, "SELECT COALESCE(password_hash,''),status FROM users WHERE tenant_id=$1 AND id=$2", op.tenant, op.user).Scan(&hash, &status)
	return hash, status, err
}
