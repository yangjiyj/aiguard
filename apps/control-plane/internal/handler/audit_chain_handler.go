package handler

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/compliance"
)

// VerifyAuditChain handles POST /admin/v1/audit-chain/verify
func VerifyAuditChain(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if deps.AuditChainRepo == nil {
			writeError(w, "not_configured", "audit chain repository not configured")
			return
		}

		fromSeq, _ := strconv.ParseInt(r.URL.Query().Get("from_seq"), 10, 64)
		toSeq, _ := strconv.ParseInt(r.URL.Query().Get("to_seq"), 10, 64)

		result, err := deps.AuditChainRepo.Verify(r.Context(), fromSeq, toSeq)
		if err != nil {
			writeError(w, "internal_error", err.Error())
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(result)
	}
}

// GetAuditChainStats handles GET /admin/v1/audit-chain/stats
func GetAuditChainStats(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if deps.AuditChainRepo == nil {
			writeError(w, "not_configured", "audit chain repository not configured")
			return
		}

		stats, err := deps.AuditChainRepo.Stats(r.Context())
		if err != nil {
			writeError(w, "internal_error", err.Error())
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(stats)
	}
}

// ExportAuditChain handles GET /admin/v1/audit-chain/export
// Query params: from (seq, default 1), to (seq, default current max)
// Returns a ZIP containing audit_chain.jsonl + certificate.json
func ExportAuditChain(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if deps.AuditChainRepo == nil {
			writeError(w, "not_configured", "audit chain repository not configured")
			return
		}

		ctx := r.Context()

		// Resolve from/to seq defaults
		fromSeq, _ := strconv.ParseInt(r.URL.Query().Get("from"), 10, 64)
		toSeq, _ := strconv.ParseInt(r.URL.Query().Get("to"), 10, 64)

		if fromSeq <= 0 {
			fromSeq = 1
		}
		if toSeq <= 0 {
			stats, err := deps.AuditChainRepo.Stats(ctx)
			if err != nil {
				writeError(w, "internal_error", "failed to get chain stats: "+err.Error())
				return
			}
			toSeq = stats.MaxSeq
		}

		if toSeq < fromSeq {
			writeError(w, "invalid_range", "to must be greater than or equal to from")
			return
		}

		exportedAt := time.Now().UTC().Format(time.RFC3339)

		// Set ZIP response headers
		w.Header().Set("Content-Type", "application/zip")
		w.Header().Set("Content-Disposition",
			fmt.Sprintf("attachment; filename=\"audit-chain-%d-%d.zip\"", fromSeq, toSeq))

		exp := compliance.NewExporter(deps.AuditChainRepo)
		if err := exp.ExportZip(ctx, fromSeq, toSeq, exportedAt, w); err != nil {
			// Headers already sent; log only
			_ = err
			return
		}

		logAudit(r, deps, "audit_chain.export",
			map[string]interface{}{"from_seq": fromSeq, "to_seq": toSeq},
			"audit_chain", fmt.Sprintf("%d-%d", fromSeq, toSeq))
	}
}
