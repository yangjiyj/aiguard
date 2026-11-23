package handler

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/fx"
)

// GetCurrentFxRate handles GET /fx/current
func GetCurrentFxRate(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ratePPM, err := deps.FxService.CurrentPPM(r.Context())
		if err != nil {
			http.Error(w, "no fx rate available: "+err.Error(), http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"rate":            fx.FormatRatePPM(ratePPM),
			"rate_ppm":        ratePPM,
			"base_currency":   "USD",
			"target_currency": "CNY",
		})
	}
}

// SetFxRate handles PUT /fx. The rate is parsed from its literal JSON text so
// a value the DECIMAL(18,6) column cannot hold exactly is rejected, not rounded.
func SetFxRate(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Rate        json.Number `json:"rate"`
			EffectiveAt string      `json:"effective_at"`
		}
		var body bytes.Buffer
		if _, err := body.ReadFrom(http.MaxBytesReader(w, r.Body, 1<<16)); err != nil {
			http.Error(w, "invalid JSON body", http.StatusBadRequest)
			return
		}
		decoder := json.NewDecoder(&body)
		decoder.UseNumber()
		if err := decoder.Decode(&req); err != nil {
			http.Error(w, "invalid JSON body", http.StatusBadRequest)
			return
		}
		ratePPM, err := fx.ParseRatePPM(req.Rate.String())
		if err != nil {
			http.Error(w, "rate must be positive with at most 6 decimal places", http.StatusBadRequest)
			return
		}

		effAt := time.Now()
		if req.EffectiveAt != "" {
			if t, err := time.Parse(time.RFC3339, req.EffectiveAt); err == nil {
				effAt = t
			}
		}

		actor := "api"
		if err := deps.FxService.SetRate(r.Context(), "USD", "CNY", ratePPM, effAt, actor); err != nil {
			if errors.Is(err, fx.ErrInvalidRate) {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		rate := fx.FormatRatePPM(ratePPM)
		logAudit(r, deps, "fx.update", map[string]interface{}{
			"rate":         rate,
			"rate_ppm":     ratePPM,
			"effective_at": effAt.Format(time.RFC3339),
		}, "fx_rate", "USD_CNY")

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"rate":         rate,
			"rate_ppm":     ratePPM,
			"effective_at": effAt.Format(time.RFC3339),
		})
	}
}

// GetFxHistory handles GET /fx/history
func GetFxHistory(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		limit := 50
		history, err := deps.FxService.History(r.Context(), limit)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if history == nil {
			history = []fx.Rate{}
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"history": history,
		})
	}
}
