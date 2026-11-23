package saving_v2

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

// toFloatSV2 converts an interface{} value to float64.
// Defined here in snapshot_cron.go; other files in the package use toFloat64Any from helpers.go.
func toFloatSV2(v any) float64 {
	return toFloat64Any(v)
}

// SnapshotCron writes a daily snapshot of model pricing from the models table.
type SnapshotCron struct {
	db       *pgxpool.Pool
	snapRepo *repository.ProviderPriceSnapshotRepository
}

// NewSnapshotCron creates a SnapshotCron.
func NewSnapshotCron(db *pgxpool.Pool) *SnapshotCron {
	return &SnapshotCron{
		db:       db,
		snapRepo: repository.NewProviderPriceSnapshotRepository(db),
	}
}

type modelPricingRow struct {
	modelID    string
	providerID string
	pricingJSON []byte
}

// RunOnce scans current model pricing and writes today's snapshot.
// Returns the number of rows upserted.
func (s *SnapshotCron) RunOnce(ctx context.Context) (int, error) {
	today := time.Now().UTC().Format("2006-01-02")

	rows, err := s.db.Query(ctx, `
		SELECT m.id, m.provider_id, COALESCE(m.pricing_json, '{}')
		FROM models m
		WHERE m.pricing_json IS NOT NULL
		  AND m.pricing_json::text != '{}'
		  AND m.status = 'active'
	`)
	if err != nil {
		return 0, fmt.Errorf("snapshot_cron query models: %w", err)
	}
	defer rows.Close()

	var modelRows []modelPricingRow
	for rows.Next() {
		var mr modelPricingRow
		if err := rows.Scan(&mr.modelID, &mr.providerID, &mr.pricingJSON); err != nil {
			log.Printf("[snapshot_cron] scan row: %v", err)
			continue
		}
		modelRows = append(modelRows, mr)
	}
	rows.Close()

	count := 0
	for _, mr := range modelRows {
		var p map[string]any
		if err := json.Unmarshal(mr.pricingJSON, &p); err != nil {
			continue
		}
		inputPrice := toFloatSV2(p["input"])
		outputPrice := toFloatSV2(p["output"])
		currency, _ := p["currency"].(string)
		if currency == "" {
			currency = "USD"
		}

		snap := &repository.ProviderPriceSnapshot{
			SnapshotDate: today,
			ProviderID:   mr.providerID,
			ModelID:      mr.modelID,
			InputPrice:   inputPrice,
			OutputPrice:  outputPrice,
			Currency:     currency,
		}
		if err := s.snapRepo.Upsert(ctx, snap); err != nil {
			log.Printf("[snapshot_cron] upsert failed model=%s: %v", mr.modelID, err)
			continue
		}
		count++
	}
	return count, nil
}

