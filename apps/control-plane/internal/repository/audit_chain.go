package repository

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/audit_chain"
)

// AuditChainRepository provides WORM-safe append and verification for the audit_chain table.
type AuditChainRepository struct {
	db  *pgxpool.Pool
	key []byte
}

// NewAuditChainRepository creates a new repository with the given signing key.
func NewAuditChainRepository(db *pgxpool.Pool, key []byte) *AuditChainRepository {
	return &AuditChainRepository{db: db, key: key}
}

// reserveAuditChainSequence serializes every chain append, then reserves the
// actual PostgreSQL sequence value used by the row. Sequences are not rolled
// back, so max(seq)+1 is not a safe hash input after an aborted transaction.
func reserveAuditChainSequence(ctx context.Context, tx pgx.Tx) (string, int64, error) {
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended(current_database() || ':' || current_schema() || ':audit_chain', 0))`); err != nil {
		return "", 0, err
	}
	var prevHash string
	var lastSeq int64
	err := tx.QueryRow(ctx, `SELECT chain_hash,seq FROM audit_chain ORDER BY seq DESC LIMIT 1`).Scan(&prevHash, &lastSeq)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return "", 0, err
	}
	var seq int64
	if err := tx.QueryRow(ctx, `SELECT nextval(pg_get_serial_sequence('audit_chain','seq'))`).Scan(&seq); err != nil {
		return "", 0, err
	}
	if seq <= lastSeq {
		var aligned int64
		if err := tx.QueryRow(ctx, `SELECT setval(pg_get_serial_sequence('audit_chain','seq'),$1,true)`, lastSeq).Scan(&aligned); err != nil {
			return "", 0, err
		}
		if err := tx.QueryRow(ctx, `SELECT nextval(pg_get_serial_sequence('audit_chain','seq'))`).Scan(&seq); err != nil {
			return "", 0, err
		}
	}
	return prevHash, seq, nil
}

// VerifyResult is returned by Verify.
type VerifyResult struct {
	OK              bool   `json:"ok"`
	FirstBreakAtSeq int64  `json:"first_break_at_seq,omitempty"`
	Detail          string `json:"detail,omitempty"`
}

// ChainStats holds summary information about the audit chain.
type ChainStats struct {
	Count      int64  `json:"count"`
	MaxSeq     int64  `json:"max_seq"`
	LastSeenAt string `json:"last_seen_at,omitempty"`
}

// Append inserts a new entry while holding the shared transaction-scoped chain lock.
func (r *AuditChainRepository) Append(ctx context.Context, tenantID, eventType, eventID string, payload map[string]any) error {
	frozen, err := audit_chain.CanonicalPayload(payload)
	if err != nil {
		return err
	}
	tx, err := r.db.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	if err := r.appendFrozenTx(ctx, tx, tenantID, eventType, eventID, frozen); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// AppendTx 在调用方已打开的事务里追加一条审计链记录，用于“业务变更与审计链同一事务”的关键操作：
// 事务回滚时审计链记录一并回滚；这里写失败则返回错误，调用方应让整个事务失败。
// 链头锁沿用与 Append 相同的事务级咨询锁，持有到调用方事务结束，所以调用方应尽量把它放在事务末尾。
func (r *AuditChainRepository) AppendTx(ctx context.Context, tx pgx.Tx, tenantID, eventType, eventID string, payload map[string]any) error {
	frozen, err := audit_chain.CanonicalPayload(payload)
	if err != nil {
		return err
	}
	return r.appendFrozenTx(ctx, tx, tenantID, eventType, eventID, frozen)
}

func (r *AuditChainRepository) appendFrozenTx(ctx context.Context, tx pgx.Tx, tenantID, eventType, eventID string, frozen json.RawMessage) error {
	prevHash, seq, err := reserveAuditChainSequence(ctx, tx)
	if err != nil {
		return err
	}
	payloadHash := audit_chain.PayloadHash(frozen)
	chainHash := audit_chain.ChainHash(prevHash, payloadHash, seq)
	sig := audit_chain.Sign(chainHash, r.key)

	// prevHash is NULL for the first row
	var prevHashArg any
	if prevHash != "" {
		prevHashArg = prevHash
	}

	_, err = tx.Exec(ctx,
		`INSERT INTO audit_chain (seq, tenant_id, event_type, event_id, payload_json, prev_hash, payload_hash, chain_hash, signature)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
		seq, tenantID, eventType, eventID, frozen, prevHashArg, payloadHash, chainHash, sig,
	)
	return err
}

// Verify walks the chain from fromSeq to toSeq and checks integrity.
// Pass fromSeq=0, toSeq=0 to verify the entire chain.
func (r *AuditChainRepository) Verify(ctx context.Context, fromSeq, toSeq int64) (*VerifyResult, error) {
	return r.verifyAuditChain(ctx, fromSeq, toSeq, false)
}

// Both entry points read raw JSONB and preserve decimal numbers. The legacy
// entry point intentionally retains SHA-256-only behavior for mixed-alg callers.
func (r *AuditChainRepository) verifyAuditChain(ctx context.Context, fromSeq, toSeq int64, recordedAlgorithm bool) (*VerifyResult, error) {
	query := `SELECT seq, prev_hash, payload_json, payload_hash, chain_hash, signature, event_type, hash_alg FROM audit_chain`
	var args []any
	if fromSeq > 0 && toSeq > 0 {
		query += ` WHERE seq BETWEEN $1 AND $2`
		args = append(args, fromSeq, toSeq)
	}
	query += ` ORDER BY seq ASC`
	rows, err := r.db.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	prevChainHash, first := "", true
	for rows.Next() {
		var seq int64
		var prevHashNullable *string
		var raw []byte
		var payloadHash, chainHash, signature, eventType, algName string
		if err := rows.Scan(&seq, &prevHashNullable, &raw, &payloadHash, &chainHash, &signature, &eventType, &algName); err != nil {
			return &VerifyResult{OK: false, FirstBreakAtSeq: seq, Detail: "scan error: " + err.Error()}, nil
		}
		if !recordedAlgorithm {
			algName = audit_chain.AlgSHA256
		}
		alg, ok := audit_chain.AlgorithmByName(algName)
		if !ok {
			return &VerifyResult{OK: false, FirstBreakAtSeq: seq, Detail: "unknown hash_alg " + algName}, nil
		}
		payload, err := audit_chain.DecodePayload(raw)
		if err != nil {
			return &VerifyResult{OK: false, FirstBreakAtSeq: seq, Detail: "invalid payload JSON"}, nil
		}
		prevHash := ""
		if prevHashNullable != nil {
			prevHash = *prevHashNullable
		}
		if detail := audit_chain.VerifyRecordedRow(alg, r.key, prevChainHash, !first, prevHash, eventType, payload, payloadHash, chainHash, signature, seq); detail != "" {
			return &VerifyResult{OK: false, FirstBreakAtSeq: seq, Detail: detail}, nil
		}
		prevChainHash, first = chainHash, false
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return &VerifyResult{OK: true}, nil
}

// Stats returns total count, max seq, and last created_at of the audit chain.
func (r *AuditChainRepository) Stats(ctx context.Context) (*ChainStats, error) {
	var count int64
	var maxSeq *int64
	var lastSeenAt *time.Time
	err := r.db.QueryRow(ctx,
		`SELECT count(*), max(seq), max(created_at) FROM audit_chain`,
	).Scan(&count, &maxSeq, &lastSeenAt)
	if err != nil {
		return nil, err
	}
	stats := &ChainStats{Count: count}
	if maxSeq != nil {
		stats.MaxSeq = *maxSeq
	}
	if lastSeenAt != nil {
		stats.LastSeenAt = lastSeenAt.UTC().Format(time.RFC3339)
	}
	return stats, nil
}

// ListRange returns rows in [fromSeq, toSeq] ordered by seq ASC.
// Pass fromSeq=0, toSeq=0 to list all rows.
func (r *AuditChainRepository) ListRange(ctx context.Context, fromSeq, toSeq int64) (pgx.Rows, error) {
	query := `SELECT seq, tenant_id, event_type, event_id, payload_json, prev_hash, payload_hash, chain_hash, signature, created_at
	          FROM audit_chain`
	var args []any
	if fromSeq > 0 && toSeq > 0 {
		query += ` WHERE seq BETWEEN $1 AND $2`
		args = append(args, fromSeq, toSeq)
	}
	query += ` ORDER BY seq ASC`
	return r.db.Query(ctx, query, args...)
}

// AppendHeaderContractConflictOnce appends exactly one WORM row per occurrence.
func (r *AuditChainRepository) AppendHeaderContractConflictOnce(ctx context.Context, tenantID, eventID string, payload map[string]any) error {
	frozen, err := audit_chain.CanonicalPayload(payload)
	if err != nil {
		return err
	}
	if ok, err := r.headerConflictMatches(ctx, tenantID, eventID, frozen); err != nil || ok {
		return err
	}
	tx, err := r.db.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	prevHash, seq, err := reserveAuditChainSequence(ctx, tx)
	if err != nil {
		return err
	}
	payloadHash := audit_chain.PayloadHash(frozen)
	chainHash := audit_chain.ChainHash(prevHash, payloadHash, seq)
	sig := audit_chain.Sign(chainHash, r.key)
	var prevHashArg any
	if prevHash != "" {
		prevHashArg = prevHash
	}
	_, err = tx.Exec(ctx, `INSERT INTO audit_chain
		(seq,tenant_id,event_type,event_id,payload_json,prev_hash,payload_hash,chain_hash,signature)
		VALUES ($1,$2,'header_contract_conflict',$3,$4,$5,$6,$7,$8)`, seq, tenantID, eventID, frozen, prevHashArg, payloadHash, chainHash, sig)
	if err != nil {
		_ = tx.Rollback(ctx)
		if ok, matchErr := r.headerConflictMatches(ctx, tenantID, eventID, frozen); ok || matchErr != nil {
			return matchErr
		}
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		if ok, matchErr := r.headerConflictMatches(ctx, tenantID, eventID, frozen); ok || matchErr != nil {
			return matchErr
		}
		return err
	}
	return nil
}

func (r *AuditChainRepository) headerConflictMatches(ctx context.Context, tenantID, eventID string, payload any) (bool, error) {
	want, err := audit_chain.CanonicalPayload(payload)
	if err != nil {
		return false, err
	}
	rows, err := r.db.Query(ctx, `SELECT event_type,tenant_id,payload_json FROM audit_chain WHERE event_id=$1 ORDER BY seq`, eventID)
	if err != nil {
		return false, err
	}
	defer rows.Close()
	found := false
	for rows.Next() {
		var eventType, existingTenant string
		var existing []byte
		if err := rows.Scan(&eventType, &existingTenant, &existing); err != nil {
			return false, err
		}
		if eventType != "header_contract_conflict" || existingTenant != tenantID {
			return false, ErrHeaderContractCollision
		}
		decoded, err := audit_chain.DecodePayload(existing)
		if err != nil {
			return false, ErrHeaderContractCollision
		}
		got, err := audit_chain.CanonicalPayload(decoded)
		if err != nil || !bytes.Equal(got, want) {
			return false, ErrHeaderContractCollision
		}

		found = true
	}
	if err := rows.Err(); err != nil {
		return false, err
	}
	return found, nil
}
