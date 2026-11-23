package compliance

import (
	"archive/zip"
	"context"
	"encoding/json"
	"fmt"
	"io"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

// Exporter generates compliance ZIP archives from the audit chain.
type Exporter struct {
	repo *repository.AuditChainRepository
}

// NewExporter creates a new Exporter backed by the given repository.
func NewExporter(repo *repository.AuditChainRepository) *Exporter {
	return &Exporter{repo: repo}
}

// ExportZip writes a ZIP to w containing:
//   - audit_chain.jsonl: one JSON object per row in [fromSeq, toSeq]
//   - certificate.json: summary + integrity verification result
//
// exportedAt is caller-supplied (string) so the function stays deterministic for testing.
// Pass fromSeq=0, toSeq=0 to export the entire chain.
func (e *Exporter) ExportZip(ctx context.Context, fromSeq, toSeq int64, exportedAt string, w io.Writer) error {
	zw := zip.NewWriter(w)
	defer zw.Close()

	// ---- 1) audit_chain.jsonl ----
	jf, err := zw.Create("audit_chain.jsonl")
	if err != nil {
		return fmt.Errorf("create jsonl entry: %w", err)
	}

	rows, err := e.repo.ListRange(ctx, fromSeq, toSeq)
	if err != nil {
		return fmt.Errorf("list range: %w", err)
	}
	defer rows.Close()

	var count int
	var firstChainHash, lastChainHash string

	for rows.Next() {
		// SELECT order from ListRange:
		// seq, tenant_id, event_type, event_id, payload_json,
		// prev_hash, payload_hash, chain_hash, signature, created_at
		var seq int64
		var tenantID, eventType, eventID string
		// Preserve the stored JSON numbers and structure in the evidence ZIP.
		// Scanning through map[string]any would silently round large integers.
		var payload json.RawMessage
		var prevHash *string
		var payloadHash, chainHash, signature string
		var createdAt interface{}

		if err := rows.Scan(
			&seq, &tenantID, &eventType, &eventID, &payload,
			&prevHash, &payloadHash, &chainHash, &signature, &createdAt,
		); err != nil {
			return fmt.Errorf("scan row %d: %w", count+1, err)
		}

		if count == 0 {
			firstChainHash = chainHash
		}
		lastChainHash = chainHash

		rec := map[string]any{
			"seq":          seq,
			"tenant_id":    tenantID,
			"event_type":   eventType,
			"event_id":     eventID,
			"payload_json": payload,
			"prev_hash":    prevHash,
			"payload_hash": payloadHash,
			"chain_hash":   chainHash,
			"signature":    signature,
			"created_at":   fmt.Sprintf("%v", createdAt),
		}
		line, err := json.Marshal(rec)
		if err != nil {
			return fmt.Errorf("marshal row: %w", err)
		}
		if _, err := jf.Write(append(line, '\n')); err != nil {
			return fmt.Errorf("write jsonl: %w", err)
		}
		count++
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("rows iteration: %w", err)
	}

	// ---- 2) certificate.json ----
	cf, err := zw.Create("certificate.json")
	if err != nil {
		return fmt.Errorf("create certificate entry: %w", err)
	}

	cert := map[string]any{
		"from_seq":         fromSeq,
		"to_seq":           toSeq,
		"record_count":     count,
		"first_chain_hash": firstChainHash,
		"last_chain_hash":  lastChainHash,
		"exported_at":      exportedAt,
		"note":             "审计链证据导出。verify_ok=true 表示导出区间链式签名完整未被篡改。",
	}

	vr, verr := e.repo.Verify(ctx, fromSeq, toSeq)
	if verr != nil {
		cert["verify_ok"] = false
		cert["verify_error"] = verr.Error()
	} else {
		cert["verify_ok"] = vr.OK
		if !vr.OK {
			cert["first_break_at_seq"] = vr.FirstBreakAtSeq
			cert["break_detail"] = vr.Detail
		}
	}

	cbytes, err := json.MarshalIndent(cert, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal certificate: %w", err)
	}
	if _, err := cf.Write(cbytes); err != nil {
		return fmt.Errorf("write certificate: %w", err)
	}

	return nil
}
