package handler

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/billing"
)

type billingRedemptionCreateRequest struct {
	TenantID     string `json:"tenant_id"`
	Label        string `json:"label"`
	AmountMicros int64  `json:"amount_micros"`
	Count        int    `json:"count"`
	ExpiresAt    string `json:"expires_at"`
}

func ListBillingRedemptions(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, ok := billingAdmin(w, r); !ok {
			return
		}
		tenantID, ok := billingTenant(w, r)
		if !ok {
			return
		}
		store, ok := billingStore(deps)
		if !ok {
			portalNotConfigured(w, "billing store")
			return
		}
		filter, valid := redemptionFilterRequest(w, r)
		if !valid {
			return
		}
		page, err := store.ListRedemptionCodePage(r.Context(), tenantID, filter)
		if err != nil {
			billingHTTPError(w, err)
			return
		}
		writeJSON(w, map[string]any{"data": page.Items, "meta": map[string]any{"total": page.Total, "page": page.Page, "page_size": page.PageSize}})
	}
}

// CreateBillingRedemptions creates one or more cryptographically-random
// single-use cards. Codes are encrypted at rest and returned only through
// explicit administration actions, never list/export responses or audit logs.
func CreateBillingRedemptions(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		actorID, ok := billingAdmin(w, r)
		if !ok {
			return
		}
		var req billingRedemptionCreateRequest
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 32<<10)).Decode(&req); err != nil {
			writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "invalid JSON format")
			return
		}
		req.TenantID = strings.TrimSpace(req.TenantID)
		req.Label = strings.TrimSpace(req.Label)
		var expiresAt *time.Time
		if strings.TrimSpace(req.ExpiresAt) != "" {
			value, err := time.Parse(time.RFC3339, strings.TrimSpace(req.ExpiresAt))
			if err != nil {
				writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "expires_at must be RFC3339")
				return
			}
			expiresAt = &value
		}
		store, ok := billingStore(deps)
		if !ok {
			portalNotConfigured(w, "billing store")
			return
		}
		codes, err := store.CreateRedemptionCodes(r.Context(), billing.NewRedemptionBatch{
			TenantID: req.TenantID, Label: req.Label, AmountMicros: billing.Micros(req.AmountMicros),
			Count: req.Count, ExpiresAt: expiresAt, CreatedBy: actorID,
		})
		if err != nil {
			billingHTTPError(w, err)
			return
		}
		logAudit(r, deps, "billing.redemption.create", map[string]interface{}{
			"tenant_id": req.TenantID, "label": req.Label, "amount_micros": req.AmountMicros, "count": req.Count,
			"expires_at": req.ExpiresAt,
		}, "billing_redemption_batch", req.TenantID)
		w.Header().Set("Cache-Control", "no-store")
		writeJSON(w, map[string]any{"data": codes})
	}
}

type billingRedemptionStatusRequest struct {
	TenantID string `json:"tenant_id"`
	Status   string `json:"status"`
}

func UpdateBillingRedemption(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, ok := billingAdmin(w, r); !ok {
			return
		}
		id := strings.TrimSpace(chi.URLParam(r, "id"))
		var req billingRedemptionStatusRequest
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&req); err != nil {
			writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "invalid JSON format")
			return
		}
		req.TenantID = strings.TrimSpace(req.TenantID)
		req.Status = strings.TrimSpace(req.Status)
		if id == "" || req.TenantID == "" {
			writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "redemption id and tenant_id are required")
			return
		}
		store, ok := billingStore(deps)
		if !ok {
			portalNotConfigured(w, "billing store")
			return
		}
		if err := store.SetRedemptionCodeStatus(r.Context(), req.TenantID, id, req.Status); err != nil {
			billingHTTPError(w, err)
			return
		}
		logAudit(r, deps, "billing.redemption.status", map[string]interface{}{
			"tenant_id": req.TenantID, "status": req.Status,
		}, "billing_redemption_code", id)
		writeJSON(w, map[string]any{"data": map[string]any{"id": id, "status": req.Status}})
	}
}

func redemptionFilterRequest(w http.ResponseWriter, r *http.Request) (billing.RedemptionFilter, bool) {
	q := r.URL.Query()
	f := billing.RedemptionFilter{Status: strings.TrimSpace(q.Get("status")), Label: strings.TrimSpace(q.Get("batch")), Redeemer: strings.TrimSpace(q.Get("redeemer")), Keyword: strings.TrimSpace(q.Get("keyword"))}
	for _, part := range []struct {
		name   string
		target *int
	}{{"page", &f.Page}, {"page_size", &f.PageSize}} {
		if raw := q.Get(part.name); raw != "" {
			value, err := strconv.Atoi(raw)
			if err != nil || value <= 0 {
				writeErrorWithStatus(w, 400, "invalid_request", "invalid pagination")
				return f, false
			}
			*part.target = value
		}
	}
	for _, part := range []struct {
		name   string
		target **time.Time
	}{{"from", &f.From}, {"to", &f.To}} {
		if raw := q.Get(part.name); raw != "" {
			value, err := time.Parse(time.RFC3339, raw)
			if err != nil {
				writeErrorWithStatus(w, 400, "invalid_request", "time range must be RFC3339")
				return f, false
			}
			*part.target = &value
		}
	}
	return f, true
}
func BatchUpdateBillingRedemptions(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, ok := billingAdmin(w, r); !ok {
			return
		}
		var input struct {
			TenantID string   `json:"tenant_id"`
			IDs      []string `json:"ids"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&input); err != nil {
			writeErrorWithStatus(w, 400, "invalid_request", "invalid batch")
			return
		}
		store, ok := billingStore(deps)
		if !ok {
			portalNotConfigured(w, "billing store")
			return
		}
		changed, err := store.BatchSetRedemptionStatus(r.Context(), strings.TrimSpace(input.TenantID), input.IDs, "disabled")
		if err != nil {
			billingHTTPError(w, err)
			return
		}
		logAudit(r, deps, "billing.redemption.batch_disable", map[string]interface{}{"tenant_id": input.TenantID, "ids": input.IDs, "changed": changed}, "billing_redemption_batch", input.TenantID)
		writeJSON(w, map[string]any{"data": map[string]any{"changed": changed}})
	}
}
func GetBillingRedemptionDetail(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, ok := billingAdmin(w, r); !ok {
			return
		}
		tenant, ok := billingTenant(w, r)
		if !ok {
			return
		}
		store, ok := billingStore(deps)
		if !ok {
			portalNotConfigured(w, "billing store")
			return
		}
		item, err := store.RedemptionDetail(r.Context(), tenant, strings.TrimSpace(chi.URLParam(r, "id")))
		if err != nil {
			billingHTTPError(w, err)
			return
		}
		w.Header().Set("Cache-Control", "private, no-store")
		writeJSON(w, map[string]any{"data": item})
	}
}
func ExportBillingRedemptionHints(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, ok := billingAdmin(w, r); !ok {
			return
		}
		tenant, ok := billingTenant(w, r)
		if !ok {
			return
		}
		store, ok := billingStore(deps)
		if !ok {
			portalNotConfigured(w, "billing store")
			return
		}
		var buffer bytes.Buffer
		writer := csv.NewWriter(&buffer)
		_ = writer.Write([]string{"code_hint", "status"})
		err := store.WalkRedemptionHints(r.Context(), tenant, strings.TrimSpace(r.URL.Query().Get("batch")), func(hint, status string) error {
			if strings.ContainsAny(hint[:min(len(hint), 1)], "=+-@\t\r") {
				hint = "'" + hint
			}
			return writer.Write([]string{hint, status})
		})
		writer.Flush()
		if err != nil {
			billingHTTPError(w, err)
			return
		}
		if writer.Error() != nil {
			billingHTTPError(w, writer.Error())
			return
		}
		w.Header().Set("Cache-Control", "private, no-store")
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", "attachment; filename=redemption-hints.csv")
		_, _ = w.Write(buffer.Bytes())
	}
}

func RevealBillingRedemption(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "private, no-store")
		w.Header().Set("Pragma", "no-cache")
		if _, ok := billingAdmin(w, r); !ok {
			return
		}
		tenant, ok := billingTenant(w, r)
		if !ok {
			return
		}
		store, ok := billingStore(deps)
		if !ok {
			portalNotConfigured(w, "billing store")
			return
		}
		id := strings.TrimSpace(chi.URLParam(r, "id"))
		code, err := store.RevealRedemptionCode(r.Context(), tenant, id)
		if errors.Is(err, billing.ErrRedemptionNotRecoverable) {
			writeErrorWithStatus(w, 409, "created_before_encryption", "historic redemption code is not recoverable")
			return
		}
		if errors.Is(err, billing.ErrRedemptionInvalid) {
			writeErrorWithStatus(w, 404, "not_found", "redemption code not found")
			return
		}
		if err != nil {
			writeErrorWithStatus(w, 503, "redemption_unavailable", "redemption copy unavailable")
			return
		}
		logAudit(r, deps, "billing.redemption.reveal", map[string]interface{}{"tenant_id": tenant}, "billing_redemption_code", id)
		writeJSON(w, map[string]any{"data": map[string]any{"code": code}})
	}
}

// DeleteBillingRedemption archives any state; redeemed money and its ledger are retained.
func DeleteBillingRedemption(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		actor, ok := billingAdmin(w, r)
		if !ok {
			return
		}
		tenant, ok := billingTenant(w, r)
		if !ok {
			return
		}
		store, ok := billingStore(deps)
		if !ok {
			portalNotConfigured(w, "billing store")
			return
		}
		id := strings.TrimSpace(chi.URLParam(r, "id"))
		event, err := store.ArchiveRedemptionCode(r.Context(), tenant, id, actor, requestClientIP(r))
		if errors.Is(err, billing.ErrRedemptionInvalid) {
			writeErrorWithStatus(w, 404, "not_found", "redemption code not found")
			return
		}
		if err != nil {
			billingHTTPError(w, err)
			return
		}
		appendAuditChain(context.WithoutCancel(r.Context()), deps, tenant, "billing.redemption.delete", event.ID, event.Detail)
		w.WriteHeader(http.StatusNoContent)
	}
}
