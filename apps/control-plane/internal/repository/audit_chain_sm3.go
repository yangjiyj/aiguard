package repository

// W10: algorithm-aware audit chain access. New file only; the existing
// Append/Verify in audit_chain.go keep writing and checking SHA-256 rows.
// Requires migration 940 (audit_chain.hash_alg).
//
// Integration (for the integrator, not done in this branch):
//   - writer: wrap the repository with NewSM3ChainWriter when
//     UAG_AUDIT_CHAIN_HASH=sm3 and pass it to audit_chain.NewAppender;
//   - verifier: switch VerifyAuditChain to VerifyByRecordedAlgorithm, which
//     accepts mixed SHA-256 -> SM3 chains. The legacy Verify reports the
//     first SM3 row as "payload_hash mismatch".

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/audit_chain"
)

// ErrUnknownChainAlgorithm is returned when asked to append with an
// algorithm this build does not implement.
var ErrUnknownChainAlgorithm = errors.New("unknown audit chain algorithm")

// AppendWithAlgorithm appends one row hashed and signed with alg and records
// alg in hash_alg. It shares the chain lock with Append, so SHA-256 and SM3
// writers can run side by side during a rollout.
func (r *AuditChainRepository) AppendWithAlgorithm(ctx context.Context, algName, tenantID, eventType, eventID string, payload map[string]any) error {
	alg, ok := audit_chain.AlgorithmByName(algName)
	if !ok {
		return ErrUnknownChainAlgorithm
	}
	frozen, err := audit_chain.CanonicalPayload(payload)
	if err != nil {
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
	payloadHash := alg.PayloadHash(frozen)
	chainHash := alg.ChainHash(prevHash, payloadHash, seq)
	sig := alg.Sign(chainHash, r.key)
	var prevHashArg any
	if prevHash != "" {
		prevHashArg = prevHash
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO audit_chain (seq, tenant_id, event_type, event_id, payload_json, prev_hash, payload_hash, chain_hash, signature, hash_alg)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
		seq, tenantID, eventType, eventID, frozen, prevHashArg, payloadHash, chainHash, sig, alg.Name,
	); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// SM3ChainWriter adapts the repository to audit_chain.ChainWriter using SM3.
type SM3ChainWriter struct{ Repo *AuditChainRepository }

// NewSM3ChainWriter returns a ChainWriter that appends SM3/HMAC-SM3 rows.
func NewSM3ChainWriter(repo *AuditChainRepository) *SM3ChainWriter {
	return &SM3ChainWriter{Repo: repo}
}

// Append implements audit_chain.ChainWriter.
func (w *SM3ChainWriter) Append(ctx context.Context, tenantID, eventType, eventID string, payload map[string]any) error {
	return w.Repo.AppendWithAlgorithm(ctx, audit_chain.AlgSM3, tenantID, eventType, eventID, payload)
}

var _ audit_chain.ChainWriter = (*SM3ChainWriter)(nil)

// VerifyByRecordedAlgorithm walks the chain like Verify but checks each row
// with the algorithm recorded in hash_alg. Unknown algorithms fail closed.
func (r *AuditChainRepository) VerifyByRecordedAlgorithm(ctx context.Context, fromSeq, toSeq int64) (*VerifyResult, error) {
	return r.verifyAuditChain(ctx, fromSeq, toSeq, true)
}
