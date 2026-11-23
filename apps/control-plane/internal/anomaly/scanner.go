package anomaly

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/alert"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Scanner detects cost anomalies by running 5-dimension checks per tenant.
type Scanner struct {
	db     *pgxpool.Pool
	events *repository.AnomalyEventRepository
	inbox  *alert.InboxService
}

// NewScanner creates a new Scanner.
func NewScanner(db *pgxpool.Pool, events *repository.AnomalyEventRepository, inbox *alert.InboxService) *Scanner {
	return &Scanner{db: db, events: events, inbox: inbox}
}

// dailyCost holds total cost for one day.
type dailyCost struct {
	date  string  // YYYY-MM-DD
	total float64 // USD
}

// RunOnce runs anomaly detection for all active tenants.
// Returns the number of new anomaly events created.
func (s *Scanner) RunOnce(ctx context.Context) (int, error) {
	tenants, err := s.activeTenants(ctx)
	if err != nil {
		return 0, fmt.Errorf("list active tenants: %w", err)
	}

	today := time.Now().UTC().Format("2006-01-02")
	total := 0

	for _, tenantID := range tenants {
		n, err := s.scanTenant(ctx, tenantID, today)
		if err != nil {
			log.Printf("[anomaly] tenant %s scan failed: %v", tenantID, err)
			continue
		}
		total += n
	}
	return total, nil
}

// 异常扫描只看业务请求：排除平台自建的请求日志（名单见 repository.NonBusinessEndpointTypes）。
var excludeNonBusiness = repository.ExcludeNonBusinessEndpointsSQL("request_logs")

var activeTenantsSQL = `
		SELECT DISTINCT tenant_id
		FROM request_logs
		WHERE ` + excludeNonBusiness + ` AND created_at >= NOW() - INTERVAL '30 days'
	`

var dailyCostsSQL = `
		SELECT DATE(created_at)::text AS day, COALESCE(SUM(total_cost), 0)
		FROM request_logs
		WHERE ` + excludeNonBusiness + ` AND tenant_id = $1
		  AND created_at >= NOW() - INTERVAL '30 days'
		GROUP BY day
		ORDER BY day ASC
	`

var keySurgeSQL = `
		WITH today_costs AS (
			SELECT
				client_id,
				COALESCE(SUM(total_cost), 0) AS key_cost
			FROM request_logs
			WHERE ` + excludeNonBusiness + ` AND tenant_id = $1
			  AND DATE(created_at) = $2::date
			  AND total_cost IS NOT NULL
			  AND client_id IS NOT NULL
			  AND client_id <> ''
			GROUP BY client_id
		),
		tenant_today_total AS (
			SELECT COALESCE(SUM(total_cost), 0) AS total
			FROM request_logs
			WHERE ` + excludeNonBusiness + ` AND tenant_id = $1
			  AND DATE(created_at) = $2::date
			  AND total_cost IS NOT NULL
		),
		hist_costs AS (
			SELECT
				client_id,
				DATE(created_at) AS day,
				COALESCE(SUM(total_cost), 0) AS key_day_cost
			FROM request_logs
			WHERE ` + excludeNonBusiness + ` AND tenant_id = $1
			  AND DATE(created_at) >= $2::date - INTERVAL '7 days'
			  AND DATE(created_at) < $2::date
			  AND total_cost IS NOT NULL
			  AND client_id IS NOT NULL
			  AND client_id <> ''
			GROUP BY client_id, day
		),
		hist_tenant_daily AS (
			SELECT
				DATE(created_at) AS day,
				COALESCE(SUM(total_cost), 0) AS tenant_day_cost
			FROM request_logs
			WHERE ` + excludeNonBusiness + ` AND tenant_id = $1
			  AND DATE(created_at) >= $2::date - INTERVAL '7 days'
			  AND DATE(created_at) < $2::date
			  AND total_cost IS NOT NULL
			GROUP BY day
		),
		hist_shares AS (
			SELECT
				hc.client_id,
				CASE WHEN htd.tenant_day_cost > 0
					THEN hc.key_day_cost / htd.tenant_day_cost
					ELSE 0
				END AS day_share
			FROM hist_costs hc
			JOIN hist_tenant_daily htd ON hc.day = htd.day
		),
		hist_avg_shares AS (
			SELECT client_id, AVG(day_share) AS avg_share
			FROM hist_shares
			GROUP BY client_id
		)
		SELECT
			tc.client_id,
			CASE WHEN tt.total > 0 THEN tc.key_cost / tt.total ELSE 0 END AS today_share,
			COALESCE(has.avg_share, 0) AS avg_share
		FROM today_costs tc
		CROSS JOIN tenant_today_total tt
		LEFT JOIN hist_avg_shares has ON tc.client_id = has.client_id
		WHERE tt.total > 0
	`

var newModelSQL = `
		WITH today_models AS (
			SELECT model_id, COUNT(*) AS today_reqs
			FROM request_logs
			WHERE ` + excludeNonBusiness + ` AND tenant_id = $1
			  AND DATE(created_at)::text = $2
			  AND model_id IS NOT NULL
			GROUP BY model_id
			HAVING COUNT(*) > 100
		),
		hist_models AS (
			SELECT DISTINCT model_id
			FROM request_logs
			WHERE ` + excludeNonBusiness + ` AND tenant_id = $1
			  AND DATE(created_at)::text < $2
			  AND created_at >= NOW() - INTERVAL '30 days'
			  AND model_id IS NOT NULL
		)
		SELECT tm.model_id, tm.today_reqs
		FROM today_models tm
		WHERE tm.model_id NOT IN (SELECT model_id FROM hist_models)
	`

// activeTenants returns tenant IDs that have request_logs in the last 30 days.
func (s *Scanner) activeTenants(ctx context.Context) ([]string, error) {
	rows, err := s.db.Query(ctx, activeTenantsSQL)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []string
	for rows.Next() {
		var tid string
		if err := rows.Scan(&tid); err != nil {
			return nil, err
		}
		result = append(result, tid)
	}
	return result, rows.Err()
}

// dailyCosts returns the per-day total cost for the tenant over the last 30 days.
// Index 0 = oldest, last = most recent (today).
func (s *Scanner) dailyCosts(ctx context.Context, tenantID string) ([]dailyCost, error) {
	rows, err := s.db.Query(ctx, dailyCostsSQL, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []dailyCost
	for rows.Next() {
		var dc dailyCost
		if err := rows.Scan(&dc.date, &dc.total); err != nil {
			return nil, err
		}
		result = append(result, dc)
	}
	return result, rows.Err()
}

// scanTenant runs all anomaly dimensions for one tenant.
func (s *Scanner) scanTenant(ctx context.Context, tenantID, today string) (int, error) {
	costs, err := s.dailyCosts(ctx, tenantID)
	if err != nil {
		return 0, err
	}

	// Find today's cost and build history excluding today.
	var todayCost float64
	var hist []float64
	var prevDayCost float64 // yesterday
	var weekAgoCost float64 // 7 days ago

	todayIdx := -1
	for i, dc := range costs {
		if dc.date == today {
			todayCost = dc.total
			todayIdx = i
			break
		}
	}

	// Build history: all days before today.
	for _, dc := range costs {
		if dc.date != today {
			hist = append(hist, dc.total)
		}
	}

	// yesterday: the day just before today in the series
	yesterday := time.Now().UTC().AddDate(0, 0, -1).Format("2006-01-02")
	weekAgo := time.Now().UTC().AddDate(0, 0, -7).Format("2006-01-02")
	for _, dc := range costs {
		if dc.date == yesterday {
			prevDayCost = dc.total
		}
		if dc.date == weekAgo {
			weekAgoCost = dc.total
		}
	}

	_ = todayIdx // suppress unused warning

	// Only proceed if today has data.
	if todayCost == 0 {
		return 0, nil
	}

	newCount := 0

	// --- Dimension 1: absolute_spike (MAD-based) ---
	if HasEnoughData(hist) {
		b := Baseline(hist)
		if IsAbsoluteSpike(todayCost, b, 3.0) {
			sev := "high"
			if todayCost > b.Median+5*1.4826*b.MAD {
				sev = "critical"
			}
			n, err := s.emit(ctx, tenantID, today, "absolute_spike", "", "", b.Median, todayCost, sev, map[string]any{
				"median":    b.Median,
				"mad":       b.MAD,
				"threshold": b.Median + 3*1.4826*b.MAD,
				"actual":    todayCost,
			})
			if err != nil {
				log.Printf("[anomaly] emit absolute_spike for %s: %v", tenantID, err)
			}
			newCount += n
		}
	}

	// --- Dimension 2: dod (day-over-day ratio) ---
	if RatioSpike(todayCost, prevDayCost, 2.0) {
		ratio := todayCost / prevDayCost
		sev := "warning"
		if ratio > 3.0 {
			sev = "high"
		}
		n, err := s.emit(ctx, tenantID, today, "dod", "", "", prevDayCost, todayCost, sev, map[string]any{
			"prev_day": prevDayCost,
			"today":    todayCost,
			"ratio":    ratio,
		})
		if err != nil {
			log.Printf("[anomaly] emit dod for %s: %v", tenantID, err)
		}
		newCount += n
	}

	// --- Dimension 3: yoy (week-over-week / same day last week) ---
	if RatioSpike(todayCost, weekAgoCost, 2.0) {
		ratio := todayCost / weekAgoCost
		sev := "warning"
		if ratio > 3.0 {
			sev = "high"
		}
		n, err := s.emit(ctx, tenantID, today, "yoy", "", "", weekAgoCost, todayCost, sev, map[string]any{
			"week_ago": weekAgoCost,
			"today":    todayCost,
			"ratio":    ratio,
		})
		if err != nil {
			log.Printf("[anomaly] emit yoy for %s: %v", tenantID, err)
		}
		newCount += n
	}

	// --- Dimension 4: new_model ---
	newModelCount, err := s.detectNewModel(ctx, tenantID, today)
	if err != nil {
		log.Printf("[anomaly] new_model detection for %s: %v", tenantID, err)
	}
	newCount += newModelCount

	// --- Dimension 5: key_surge ---
	keySurgeCount, err := s.detectKeySurge(ctx, tenantID, today)
	if err != nil {
		log.Printf("[anomaly] key_surge detection for %s: %v", tenantID, err)
	}
	newCount += keySurgeCount

	return newCount, nil
}

// keyCostShare holds today's cost share info for a single client_id (API key proxy).
type keyCostShare struct {
	clientID   string
	todayShare float64 // fraction [0,1] of tenant total today
	avgShare   float64 // 7-day rolling average share
}

// detectKeySurge finds client_ids whose today cost share is >3x their 7-day avg share,
// and whose today share exceeds 5% of tenant total (noise floor).
// client_id is used as the key proxy dimension (client_id ≈ API Key in most deployments).
func (s *Scanner) detectKeySurge(ctx context.Context, tenantID, today string) (int, error) {
	// Single query: compute today share and 7-day avg share per client_id.
	rows, err := s.db.Query(ctx, keySurgeSQL, tenantID, today)
	if err != nil {
		return 0, fmt.Errorf("key_surge query: %w", err)
	}
	defer rows.Close()

	var candidates []keyCostShare
	for rows.Next() {
		var kcs keyCostShare
		if err := rows.Scan(&kcs.clientID, &kcs.todayShare, &kcs.avgShare); err != nil {
			return 0, err
		}
		candidates = append(candidates, kcs)
	}
	if err := rows.Err(); err != nil {
		return 0, err
	}

	count := 0
	for _, kcs := range candidates {
		// Noise floor: today share must be > 5% to avoid small-amount false positives.
		if kcs.todayShare <= 0.05 {
			continue
		}
		// Spike check: today share > 3x 7-day average share.
		if !RatioSpike(kcs.todayShare, kcs.avgShare, 3.0) {
			continue
		}
		sev := "warning"
		if kcs.todayShare > 0.5 {
			sev = "high"
		}
		n, err := s.emit(ctx, tenantID, today, "key_surge", "key", kcs.clientID,
			kcs.avgShare, kcs.todayShare, sev, map[string]any{
				"client_id":    kcs.clientID,
				"today_share":  kcs.todayShare,
				"avg_7d_share": kcs.avgShare,
				"ratio":        kcs.todayShare / kcs.avgShare,
				"description":  "key cost share surged vs 7-day average",
			})
		if err != nil {
			log.Printf("[anomaly] emit key_surge for %s/%s: %v", tenantID, kcs.clientID, err)
		}
		count += n
	}
	return count, nil
}

// detectNewModel finds models that appear today but had 0 requests in the past 30 days
// and today's request count > 100.
func (s *Scanner) detectNewModel(ctx context.Context, tenantID, today string) (int, error) {
	rows, err := s.db.Query(ctx, newModelSQL, tenantID, today)
	if err != nil {
		return 0, err
	}
	defer rows.Close()

	count := 0
	for rows.Next() {
		var modelID string
		var todayReqs int64
		if err := rows.Scan(&modelID, &todayReqs); err != nil {
			return count, err
		}
		n, err := s.emit(ctx, tenantID, today, "new_model", "model", modelID, 0, float64(todayReqs), "warning", map[string]any{
			"model_id":    modelID,
			"today_reqs":  todayReqs,
			"description": "new model appeared with no historical usage",
		})
		if err != nil {
			log.Printf("[anomaly] emit new_model for %s/%s: %v", tenantID, modelID, err)
		}
		count += n
	}
	return count, rows.Err()
}

// emit upserts an anomaly event and pushes an inbox alert if it's new.
func (s *Scanner) emit(ctx context.Context, tenantID, date, dimension, scopeType, scopeID string, baseline, actual float64, severity string, detail map[string]any) (int, error) {
	ev := &repository.AnomalyEvent{
		ID:           fmt.Sprintf("ae_%s", uuid.New().String()[:12]),
		TenantID:     tenantID,
		DetectedDate: date,
		Dimension:    dimension,
		ScopeType:    scopeType,
		ScopeID:      scopeID,
		Baseline:     baseline,
		Actual:       actual,
		Severity:     severity,
		DetailJSON:   detail,
	}

	isNew, err := s.events.UpsertIfNew(ctx, ev)
	if err != nil {
		return 0, err
	}
	if !isNew {
		return 0, nil
	}

	title := fmt.Sprintf("成本异常 [%s]: 租户 %s 于 %s", dimension, tenantID, date)
	if err := s.inbox.Push(ctx, tenantID, severity, "anomaly_"+dimension, title, detail, "/anomalies"); err != nil {
		log.Printf("[anomaly] push inbox for %s/%s: %v", tenantID, dimension, err)
	}
	return 1, nil
}
