package modelrouter

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

const defaultRouteAlertTimeout = 500 * time.Millisecond

type RouteAlertType string

const (
	AlertRouteUnavailable RouteAlertType = "model_route_unavailable"
	AlertRouteDegraded    RouteAlertType = "model_route_degraded"
	AlertRouteFallback    RouteAlertType = "model_route_fallback"
	AlertCircuitOpened    RouteAlertType = "model_route_circuit_opened"
	AlertRouteRecovered   RouteAlertType = "model_route_recovered"
	AlertRouteFlapping    RouteAlertType = "model_route_flapping"
)

type RouteAlert struct {
	TenantID    string
	ModelName   string
	ProviderRef string
	Type        RouteAlertType
	Reason      string
	OccurredAt  time.Time
}

// RouteAlertWriter owns durable, cross-process de-duplication.
type RouteAlertWriter interface {
	WriteRouteAlert(ctx context.Context, alert RouteAlert, dedupeWindow time.Duration) (inserted bool, err error)
}

// AlertSink intentionally hides persistence failures from the request path.
// Failures remain observable through the gateway log.
type AlertSink struct {
	writer    RouteAlertWriter
	window    time.Duration
	queue     chan queuedRouteAlert
	mu        sync.Mutex
	accepting bool
	stop      chan struct{}
	done      chan struct{}
}

type queuedRouteAlert struct {
	alert RouteAlert
	done  chan struct{}
}

func NewAlertSink(writer RouteAlertWriter, dedupeWindow time.Duration) *AlertSink {
	return newAlertSink(writer, dedupeWindow, 256)
}

func newAlertSink(writer RouteAlertWriter, dedupeWindow time.Duration, queueSize int) *AlertSink {
	if dedupeWindow <= 0 {
		dedupeWindow = 5 * time.Minute
	}
	if queueSize <= 0 {
		queueSize = 1
	}
	sink := &AlertSink{writer: writer, window: dedupeWindow, queue: make(chan queuedRouteAlert, queueSize), accepting: true, stop: make(chan struct{}), done: make(chan struct{})}
	go sink.run()
	return sink
}

func NewDBAlertSink(db *pgxpool.Pool) *AlertSink {
	return NewAlertSink(&dbRouteAlertWriter{db: db}, 5*time.Minute)
}

func (s *AlertSink) Emit(_ context.Context, alert RouteAlert) {
	if s == nil || s.writer == nil || !validRouteAlert(alert) {
		return
	}
	if alert.OccurredAt.IsZero() {
		alert.OccurredAt = time.Now()
	}
	alert.Reason = truncateAlertText(strings.TrimSpace(alert.Reason), 512)
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.accepting {
		log.Printf("[modelrouter.alert] sink closed tenant=%s model=%s route=%s type=%s", alert.TenantID, alert.ModelName, alert.ProviderRef, alert.Type)
		return
	}
	select {
	case s.queue <- queuedRouteAlert{alert: alert}:
	default:
		log.Printf("[modelrouter.alert] queue full tenant=%s model=%s route=%s type=%s", alert.TenantID, alert.ModelName, alert.ProviderRef, alert.Type)
	}
}

func (s *AlertSink) run() {
	defer close(s.done)
	for {
		select {
		case queued := <-s.queue:
			s.process(queued)
		case <-s.stop:
			for {
				select {
				case queued := <-s.queue:
					s.process(queued)
				default:
					return
				}
			}
		}
	}
}

func (s *AlertSink) process(queued queuedRouteAlert) {
	if queued.done != nil {
		close(queued.done)
		return
	}
	defer func() {
		if recovered := recover(); recovered != nil {
			log.Printf("[modelrouter.alert] writer panic tenant=%s model=%s route=%s type=%s panic=%v", queued.alert.TenantID, queued.alert.ModelName, queued.alert.ProviderRef, queued.alert.Type, recovered)
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), defaultRouteAlertTimeout)
	defer cancel()
	if _, err := s.writer.WriteRouteAlert(ctx, queued.alert, s.window); err != nil {
		log.Printf("[modelrouter.alert] write failed tenant=%s model=%s route=%s type=%s: %v", queued.alert.TenantID, queued.alert.ModelName, queued.alert.ProviderRef, queued.alert.Type, err)
	}
}

// Close stops accepting alerts, drains every alert already accepted, and waits
// for the worker. It is safe to call concurrently and repeatedly.
func (s *AlertSink) Close(ctx context.Context) error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	if s.accepting {
		s.accepting = false
		close(s.stop)
	}
	done := s.done
	s.mu.Unlock()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// flush waits until alerts already accepted by the queue have been processed.
// It is intentionally test-only surface inside this package.
func (s *AlertSink) flush(ctx context.Context) error {
	if s == nil || s.queue == nil {
		return nil
	}
	done := make(chan struct{})
	s.mu.Lock()
	if !s.accepting {
		workerDone := s.done
		s.mu.Unlock()
		select {
		case <-workerDone:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	select {
	case s.queue <- queuedRouteAlert{done: done}:
		s.mu.Unlock()
	case <-ctx.Done():
		s.mu.Unlock()
		return ctx.Err()
	}
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func validRouteAlert(alert RouteAlert) bool {
	if strings.TrimSpace(alert.TenantID) == "" || strings.TrimSpace(alert.ModelName) == "" || strings.TrimSpace(alert.ProviderRef) == "" {
		return false
	}
	switch alert.Type {
	case AlertRouteUnavailable, AlertRouteDegraded, AlertRouteFallback, AlertCircuitOpened, AlertRouteRecovered, AlertRouteFlapping:
		return true
	default:
		return false
	}
}

type dbRouteAlertWriter struct{ db *pgxpool.Pool }

func (w *dbRouteAlertWriter) WriteRouteAlert(ctx context.Context, alert RouteAlert, window time.Duration) (bool, error) {
	if w == nil || w.db == nil {
		return false, fmt.Errorf("alert database is unavailable")
	}
	tx, err := w.db.Begin(ctx)
	if err != nil {
		return false, err
	}
	defer tx.Rollback(ctx)
	dedupeKey := strings.Join([]string{alert.TenantID, alert.ModelName, alert.ProviderRef, string(alert.Type)}, "\x1f")
	if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, dedupeKey); err != nil {
		return false, err
	}
	body, err := json.Marshal(map[string]any{
		"model_name":   alert.ModelName,
		"provider_ref": alert.ProviderRef,
		"reason":       alert.Reason,
		"occurred_at":  alert.OccurredAt.UTC(),
	})
	if err != nil {
		return false, err
	}
	result, err := tx.Exec(ctx, `
		INSERT INTO alert_inbox (id, tenant_id, severity, type, title, body_json, created_at)
		SELECT $1::varchar, $2::varchar, $3::varchar, $4::varchar, $5::varchar, $6::jsonb, NOW()
		WHERE NOT EXISTS (
			SELECT 1 FROM alert_inbox
			WHERE tenant_id = $2::varchar AND type = $4::varchar
			  AND body_json->>'model_name' = $7::text
			  AND body_json->>'provider_ref' = $8::text
			  AND created_at >= NOW() - make_interval(secs => $9::double precision)
		)`, "alert_"+uuid.NewString(), alert.TenantID, alertSeverity(alert.Type), string(alert.Type), alertTitle(alert), body, alert.ModelName, alert.ProviderRef, window.Seconds())
	if err != nil {
		return false, err
	}
	if err := tx.Commit(ctx); err != nil {
		return false, err
	}
	return result.RowsAffected() == 1, nil
}

func alertSeverity(typ RouteAlertType) string {
	switch typ {
	case AlertRouteUnavailable:
		return "high"
	case AlertCircuitOpened, AlertRouteDegraded, AlertRouteFallback, AlertRouteFlapping:
		return "warning"
	default:
		return "info"
	}
}

func alertTitle(alert RouteAlert) string {
	switch alert.Type {
	case AlertRouteUnavailable:
		return "模型无可用线路"
	case AlertRouteDegraded:
		return "模型仅剩一条健康线路"
	case AlertRouteFallback:
		return "模型请求已切换备用线路"
	case AlertCircuitOpened:
		return "上游线路已熔断"
	case AlertRouteRecovered:
		return "上游线路已恢复"
	default:
		return "模型路由频繁切换"
	}
}

func truncateAlertText(value string, limit int) string {
	runes := []rune(value)
	if len(runes) <= limit {
		return value
	}
	return string(runes[:limit])
}
