package modelrouter

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

type blockingAlertWriter struct {
	started chan struct{}
	release chan struct{}
	once    sync.Once
}

func (w *blockingAlertWriter) WriteRouteAlert(context.Context, RouteAlert, time.Duration) (bool, error) {
	w.once.Do(func() { close(w.started) })
	<-w.release
	return true, nil
}

type failingAlertWriter struct{}

func (failingAlertWriter) WriteRouteAlert(context.Context, RouteAlert, time.Duration) (bool, error) {
	return false, errors.New("database unavailable")
}

type countingAlertWriter struct{ calls atomic.Int64 }

func (w *countingAlertWriter) WriteRouteAlert(context.Context, RouteAlert, time.Duration) (bool, error) {
	w.calls.Add(1)
	return true, nil
}

type panicThenWriteAlertWriter struct{ calls atomic.Int64 }

func (w *panicThenWriteAlertWriter) WriteRouteAlert(context.Context, RouteAlert, time.Duration) (bool, error) {
	if w.calls.Add(1) == 1 {
		panic("writer boom")
	}
	return true, nil
}

type recordingAlertWriter struct {
	alerts []RouteAlert
	seen   map[string]time.Time
}

func TestDBAlertSinkDeduplicatesAcrossConcurrentWriters(t *testing.T) {
	databaseURL := os.Getenv("CONTENT_LOGS_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("CONTENT_LOGS_TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	db, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	tenantID := fmt.Sprintf("tenant_route_alert_%d", time.Now().UnixNano())
	if _, err := db.Exec(ctx, `INSERT INTO tenants (id, name, edition, status) VALUES ($1, $1, 'enterprise', 'active')`, tenantID); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = db.Exec(ctx, `DELETE FROM alert_inbox WHERE tenant_id=$1`, tenantID)
		_, _ = db.Exec(ctx, `DELETE FROM tenants WHERE id=$1`, tenantID)
		db.Close()
	})

	alert := RouteAlert{TenantID: tenantID, ModelName: "logical/model", ProviderRef: "provider-a", Type: AlertCircuitOpened, Reason: "safe reason", OccurredAt: time.Now()}
	const writers = 20
	var wg sync.WaitGroup
	results := make(chan bool, writers)
	errors := make(chan error, writers)
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			inserted, writeErr := (&dbRouteAlertWriter{db: db}).WriteRouteAlert(ctx, alert, 5*time.Minute)
			results <- inserted
			errors <- writeErr
		}()
	}
	wg.Wait()
	close(results)
	close(errors)
	insertedCount := 0
	for inserted := range results {
		if inserted {
			insertedCount++
		}
	}
	for writeErr := range errors {
		if writeErr != nil {
			t.Fatal(writeErr)
		}
	}
	if insertedCount != 1 {
		t.Fatalf("inserted=%d want 1", insertedCount)
	}
	var stored int
	if err := db.QueryRow(ctx, `SELECT count(*) FROM alert_inbox WHERE tenant_id=$1 AND type=$2`, tenantID, AlertCircuitOpened).Scan(&stored); err != nil || stored != 1 {
		t.Fatalf("stored=%d err=%v", stored, err)
	}
	other := alert
	other.ProviderRef = "provider-b"
	if inserted, err := (&dbRouteAlertWriter{db: db}).WriteRouteAlert(ctx, other, 5*time.Minute); err != nil || !inserted {
		t.Fatalf("tenant/model/type with another route must not collide: inserted=%v err=%v", inserted, err)
	}
}

func (w *recordingAlertWriter) WriteRouteAlert(_ context.Context, alert RouteAlert, window time.Duration) (bool, error) {
	if w.seen == nil {
		w.seen = make(map[string]time.Time)
	}
	key := alert.TenantID + "/" + alert.ModelName + "/" + alert.ProviderRef + "/" + string(alert.Type)
	if previous := w.seen[key]; !previous.IsZero() && alert.OccurredAt.Sub(previous) < window {
		return false, nil
	}
	w.seen[key] = alert.OccurredAt
	w.alerts = append(w.alerts, alert)
	return true, nil
}

func TestAlertSinkEmitsUnavailableDegradedOpenedRecoveredAndFlapping(t *testing.T) {
	writer := &recordingAlertWriter{}
	sink := NewAlertSink(writer, 5*time.Minute)
	for _, typ := range []RouteAlertType{AlertRouteUnavailable, AlertRouteDegraded, AlertCircuitOpened, AlertRouteRecovered, AlertRouteFlapping} {
		sink.Emit(context.Background(), RouteAlert{TenantID: "tenant-a", ModelName: "logical/model", ProviderRef: "provider-a", Type: typ, Reason: "safe reason", OccurredAt: time.Now()})
	}
	if err := sink.flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(writer.alerts) != 5 {
		t.Fatalf("alerts=%d want 5", len(writer.alerts))
	}
}

func TestAlertSinkDeduplicatesSameRouteAlertForFiveMinutes(t *testing.T) {
	writer := &recordingAlertWriter{}
	sink := NewAlertSink(writer, 5*time.Minute)
	alert := RouteAlert{TenantID: "tenant-a", ModelName: "logical/model", ProviderRef: "provider-a", Type: AlertCircuitOpened, Reason: "safe reason", OccurredAt: time.Now()}
	sink.Emit(context.Background(), alert)
	sink.Emit(context.Background(), alert)
	if err := sink.flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(writer.alerts) != 1 {
		t.Fatalf("alerts=%d want 1", len(writer.alerts))
	}
}

func TestEngineEmitsUnavailableDegradedOpenedRecoveredAndFlapping(t *testing.T) {
	now := time.Date(2026, 7, 16, 12, 0, 0, 0, time.UTC)
	writer := &recordingAlertWriter{}
	sink := NewAlertSink(writer, 5*time.Minute)
	policy := validSmartLatencyPolicy("p1", "p2")

	unavailable := newModelRouteEngineWithAlertSink(fakeModelRouteSource{}, fakeV2PolicySource{policy: policy}, sink, func() time.Time { return now })
	_, applied, err := unavailable.Plan(context.Background(), RequestEnvelope{TenantID: "tenant-a", Model: "logical/model"})
	if !applied || err == nil {
		t.Fatalf("unavailable plan applied=%v err=%v", applied, err)
	}

	oneRoute := []ModelRecord{{ID: "m1", ModelName: "logical/model", ProviderID: "p1"}}
	degraded := newModelRouteEngineWithAlertSink(fakeModelRouteSource{routes: oneRoute}, fakeV2PolicySource{policy: validPriorityPolicy("p1")}, sink, func() time.Time { return now })
	if _, applied, err := degraded.Plan(context.Background(), RequestEnvelope{TenantID: "tenant-a", Model: "logical/model"}); err != nil || !applied {
		t.Fatalf("single-route plan applied=%v err=%v", applied, err)
	}

	healthEngine := newModelRouteEngineWithAlertSink(fakeModelRouteSource{routes: oneRoute}, fakeV2PolicySource{policy: validPriorityPolicy("p1")}, sink, func() time.Time { return now })
	healthKey := RouteKey{TenantID: "tenant-a", ModelName: "logical/model", ProviderID: "p1"}
	for i := 0; i < 3; i++ {
		healthEngine.RecordAttempt(healthKey, AttemptResult{Retryable: true})
	}
	now = now.Add(circuitOpenPeriod + time.Second)
	if !healthEngine.AllowAttempt(healthKey) {
		t.Fatal("half-open recovery probe was not admitted")
	}
	healthEngine.RecordAttempt(healthKey, AttemptResult{Success: true})

	flapping := newModelRouteEngineWithAlertSink(fakeModelRouteSource{}, fakeV2PolicySource{}, sink, func() time.Time { return now })
	preferenceKey := RoutePreferenceKey{TenantID: "tenant-a", ModelName: "logical/model"}
	flapping.preferences.SetBaseline(preferenceKey, "p1")
	for _, candidate := range []string{"p2", "p1", "p2"} {
		current := flapping.preferences.Current(preferenceKey)
		other := "p1"
		if candidate == "p1" {
			other = "p2"
		}
		selection := routeSelection{Routes: []ModelRecord{{ProviderID: candidate}, {ProviderID: other}}, OrderedRoutes: []ModelRecord{{ProviderID: candidate}, {ProviderID: other}}, Mode: "smart"}
		flapping.stabilizePreference(preferenceKey, current, false, selection, policy.Config)
	}
	if err := sink.flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	want := map[RouteAlertType]bool{AlertRouteUnavailable: true, AlertRouteDegraded: true, AlertCircuitOpened: true, AlertRouteRecovered: true, AlertRouteFlapping: true}
	for _, alert := range writer.alerts {
		delete(want, alert.Type)
	}
	if len(want) != 0 {
		t.Fatalf("missing engine alerts: %v; got=%+v", want, writer.alerts)
	}
}

func TestAlertSinkQueueFullReturnsImmediatelyAndLogs(t *testing.T) {
	var logs bytes.Buffer
	previous := log.Writer()
	log.SetOutput(&logs)
	t.Cleanup(func() { log.SetOutput(previous) })
	writer := &blockingAlertWriter{started: make(chan struct{}), release: make(chan struct{})}
	sink := newAlertSink(writer, 5*time.Minute, 1)
	alert := RouteAlert{TenantID: "tenant-a", ModelName: "logical/model", ProviderRef: "provider-a", Type: AlertCircuitOpened, Reason: "safe", OccurredAt: time.Now()}
	sink.Emit(context.Background(), alert)
	<-writer.started
	sink.Emit(context.Background(), alert)
	started := time.Now()
	sink.Emit(context.Background(), alert)
	if elapsed := time.Since(started); elapsed > 50*time.Millisecond {
		t.Fatalf("full queue blocked Emit for %v", elapsed)
	}
	if !strings.Contains(logs.String(), "queue full") {
		t.Fatalf("queue overflow was not observable: %s", logs.String())
	}
	close(writer.release)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := sink.flush(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestAlertSinkWriteFailureDoesNotAffectCallerAndLogs(t *testing.T) {
	var logs bytes.Buffer
	previous := log.Writer()
	log.SetOutput(&logs)
	t.Cleanup(func() { log.SetOutput(previous) })
	sink := newAlertSink(failingAlertWriter{}, 5*time.Minute, 1)
	alert := RouteAlert{TenantID: "tenant-a", ModelName: "logical/model", ProviderRef: "provider-a", Type: AlertCircuitOpened, Reason: "safe", OccurredAt: time.Now()}
	started := time.Now()
	sink.Emit(context.Background(), alert)
	if elapsed := time.Since(started); elapsed > 50*time.Millisecond {
		t.Fatalf("writer failure blocked Emit for %v", elapsed)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := sink.flush(ctx); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(logs.String(), "write failed") {
		t.Fatalf("write failure was not observable: %s", logs.String())
	}
}

func TestAlertSinkCloseDrainsAcceptedQueueAndRejectsLaterEmits(t *testing.T) {
	var logs bytes.Buffer
	previous := log.Writer()
	log.SetOutput(&logs)
	t.Cleanup(func() { log.SetOutput(previous) })
	writer := &countingAlertWriter{}
	sink := newAlertSink(writer, 5*time.Minute, 64)
	for i := 0; i < 32; i++ {
		sink.Emit(context.Background(), RouteAlert{TenantID: "tenant-a", ModelName: "logical/model", ProviderRef: fmt.Sprintf("provider-%d", i), Type: AlertCircuitOpened})
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := sink.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if writer.calls.Load() != 32 {
		t.Fatalf("drained calls=%d want 32", writer.calls.Load())
	}
	sink.Emit(context.Background(), RouteAlert{TenantID: "tenant-a", ModelName: "logical/model", ProviderRef: "after-close", Type: AlertCircuitOpened})
	if writer.calls.Load() != 32 || !strings.Contains(logs.String(), "sink closed") {
		t.Fatalf("post-close emit was not rejected observably: calls=%d logs=%s", writer.calls.Load(), logs.String())
	}
	select {
	case <-sink.done:
	default:
		t.Fatal("worker goroutine did not exit after Close")
	}
}

func TestAlertSinkConcurrentEmitAndCloseIsSafeAndIdempotent(t *testing.T) {
	previous := log.Writer()
	log.SetOutput(io.Discard)
	t.Cleanup(func() { log.SetOutput(previous) })
	writer := &countingAlertWriter{}
	sink := newAlertSink(writer, 5*time.Minute, 2048)
	var emitters sync.WaitGroup
	for worker := 0; worker < 16; worker++ {
		emitters.Add(1)
		go func(worker int) {
			defer emitters.Done()
			for i := 0; i < 100; i++ {
				sink.Emit(context.Background(), RouteAlert{TenantID: "tenant-a", ModelName: "logical/model", ProviderRef: fmt.Sprintf("provider-%d-%d", worker, i), Type: AlertRouteDegraded})
			}
		}(worker)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := sink.Close(ctx); err != nil {
		t.Fatal(err)
	}
	emitters.Wait()
	if err := sink.Close(ctx); err != nil {
		t.Fatalf("idempotent Close: %v", err)
	}
}

func TestAlertSinkCloseTimeoutCanBeRetried(t *testing.T) {
	writer := &blockingAlertWriter{started: make(chan struct{}), release: make(chan struct{})}
	sink := newAlertSink(writer, 5*time.Minute, 1)
	sink.Emit(context.Background(), RouteAlert{TenantID: "tenant-a", ModelName: "logical/model", ProviderRef: "provider-a", Type: AlertCircuitOpened})
	<-writer.started
	timeoutCtx, timeoutCancel := context.WithTimeout(context.Background(), time.Millisecond)
	defer timeoutCancel()
	if err := sink.Close(timeoutCtx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Close timeout err=%v", err)
	}
	close(writer.release)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := sink.Close(ctx); err != nil {
		t.Fatalf("retry Close: %v", err)
	}
	if err := sink.Close(ctx); err != nil {
		t.Fatalf("third Close: %v", err)
	}
}

func TestAlertSinkRecoversWriterPanicAndContinues(t *testing.T) {
	var logs bytes.Buffer
	previous := log.Writer()
	log.SetOutput(&logs)
	t.Cleanup(func() { log.SetOutput(previous) })
	writer := &panicThenWriteAlertWriter{}
	sink := newAlertSink(writer, 5*time.Minute, 2)
	for _, providerRef := range []string{"panic", "after-panic"} {
		sink.Emit(context.Background(), RouteAlert{TenantID: "tenant-a", ModelName: "logical/model", ProviderRef: providerRef, Type: AlertCircuitOpened})
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := sink.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if writer.calls.Load() != 2 || !strings.Contains(logs.String(), "writer panic") {
		t.Fatalf("worker did not survive panic: calls=%d logs=%s", writer.calls.Load(), logs.String())
	}
}
