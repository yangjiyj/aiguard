package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
)

// poolDBExecutor adapts a real pool to the writer's dbExecutor interface, whose
// Exec returns the package's own execResult. It exists so these tests exercise
// the actual SQL against PostgreSQL rather than a mock.
type poolDBExecutor struct {
	*pgxpool.Pool
}

func (p *poolDBExecutor) Exec(ctx context.Context, query string, args ...interface{}) (execResult, error) {
	tag, err := p.Pool.Exec(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	return pgxCommandTag{tag}, nil
}

type pgxCommandTag struct {
	pgconn.CommandTag
}

func (t pgxCommandTag) RowsAffected() int64 {
	return t.CommandTag.RowsAffected()
}

// Real-PostgreSQL coverage for the billing usage_source marker. The mock-based
// tests elsewhere assert the same derivation, but only a real row proves the
// marker survives the whole INSERT and lands where control-plane
// reconciliation looks for it:
// request_logs.output_audit_result->'response_metadata'->>'usage_source'.
//
// This is the billing-only deployment shape: cfg.BillingEnabled with the quota
// governor disabled, so QuotaAdmissionManaged is never set. Before the fix the
// marker was derived only under that flag, so these rows carried no
// usage_source at all and reconciliation could not settle any of them.
func setupBillingUsageSourceDB(t *testing.T) (*pgxpool.Pool, context.Context, string, string, string) {
	t.Helper()
	dsn := os.Getenv("CONTENT_LOGS_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("CONTENT_LOGS_TEST_DATABASE_URL not set; skipping DB-backed billing usage_source test")
	}
	ctx := context.Background()
	db, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect db: %v", err)
	}
	t.Cleanup(db.Close)
	ns := fmt.Sprintf("bus_%d", time.Now().UnixNano())
	tenantID := "tenant_" + ns
	if _, err := db.Exec(ctx,
		`INSERT INTO tenants (id, name, is_test) VALUES ($1, $2, TRUE)`, tenantID, ns); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	// EnsureRequestLog inserts project_id as a bare value (not NULLIF'd), so the
	// project row must exist or the whole insert fails on its foreign key.
	projectID := "proj_" + ns
	if _, err := db.Exec(ctx,
		`INSERT INTO projects (id, tenant_id, name, status) VALUES ($1, $2, $1, 'active')`,
		projectID, tenantID); err != nil {
		t.Fatalf("seed project: %v", err)
	}
	// request_logs.user_id is a real foreign key, and EnsureRequestLog writes it
	// as NULLIF('\', '') — a non-empty but nonexistent id fails the whole
	// INSERT, and the writer only logs that failure. Seed the user.
	userID := "user_" + ns
	if _, err := db.Exec(ctx,
		`INSERT INTO users (id, tenant_id, username, email, password_hash, role, status)
		 VALUES ($1::varchar, $2::varchar, $1::varchar, $1::varchar || '@test.invalid', 'x', 'developer', 'active')`,
		userID, tenantID); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	return db, ctx, tenantID, projectID, userID
}

// readPersistedUsageSource reads the marker back the way reconciliation does.
func readPersistedUsageSource(t *testing.T, db *pgxpool.Pool, ctx context.Context, tenantID, requestID string) string {
	t.Helper()
	var raw []byte
	if err := db.QueryRow(ctx,
		`SELECT output_audit_result FROM request_logs WHERE tenant_id=$1 AND request_id=$2`,
		tenantID, requestID).Scan(&raw); err != nil {
		t.Fatalf("read request_logs %s: %v", requestID, err)
	}
	var audit struct {
		ResponseMetadata struct {
			UsageSource string `json:"usage_source"`
		} `json:"response_metadata"`
	}
	if err := json.Unmarshal(raw, &audit); err != nil {
		t.Fatalf("decode output_audit_result %s: %v", raw, err)
	}
	return audit.ResponseMetadata.UsageSource
}

// Every settle-family shape a billing-only deployment can produce must persist
// its authoritative source into the real row, and the raw usage the settlement
// carried must agree with it.
func TestBillingOnlyUsageSourceLandsInRequestLogs(t *testing.T) {
	db, ctx, tenantID, projectID, userID := setupBillingUsageSourceDB(t)

	cases := []struct {
		name       string
		mode       string
		status     string
		body       string
		admitted   bool
		wantSource string
	}{
		{"prepaid verified", "prepaid", "success",
			`{"usage":{"prompt_tokens":2,"completion_tokens":3}}`, true, "upstream"},
		{"prepaid total adjusted", "prepaid", "success",
			`{"usage":{"prompt_tokens":2,"completion_tokens":3,"total_tokens":9}}`, true, "upstream_total_adjusted"},
		{"prepaid estimated", "prepaid", "success",
			`{"id":"no-usage"}`, true, "estimated_reservation"},
		{"prepaid estimated cancel", "prepaid", "client_canceled",
			`{"id":"no-usage"}`, true, "estimated_incomplete"},
		{"prepaid invalid usage", "prepaid", "success",
			`{"usage":{"prompt_tokens":-5}}`, true, "estimated_reservation_invalid_usage"},
		{"prepaid invalid cancel", "prepaid", "stream_aborted",
			`{"usage":{"prompt_tokens":-5}}`, true, "estimated_incomplete_invalid_usage"},
		{"unadmitted claims nothing", "prepaid", "success",
			`{"id":"no-usage"}`, false, unknownUsageSource},
		{"metering non settle", "metering", "error",
			`{"id":"no-upstream"}`, true, "estimated_reservation"},
		{"metering success", "metering", "success",
			`{"usage":{"prompt_tokens":1,"completion_tokens":1}}`, true, "upstream"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			settlementRaw := map[string]any{}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/internal/v1/billing/reservations", "/internal/v1/billing/quotes":
					_, _ = w.Write([]byte(`{"reserved":true,"billable_amount_micros":10,"estimated_output_tokens":4}`))
				case "/internal/v1/billing/settlements", "/internal/v1/billing/measurements":
					var payload map[string]any
					if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
						t.Errorf("decode settlement payload: %v", err)
					}
					if raw, ok := payload["raw_usage"]; ok {
						settlementRaw = map[string]any{}
						if encoded, err := json.Marshal(raw); err == nil {
							_ = json.Unmarshal(encoded, &settlementRaw)
						}
					}
					_, _ = w.Write([]byte(`{"amount_micros":10,"billable_amount_micros":10}`))
				default:
					_, _ = w.Write([]byte(`{}`))
				}
			}))
			defer server.Close()

			client := NewBillingClientWithMode(server.URL, "internal-secret", "default", tc.mode)
			requestID := "req-src-" + tenantID + "-" + tc.name
			envelope := &modelrouter.RequestEnvelope{
				TenantID: tenantID, ProjectID: projectID, UserID: userID, RequestID: requestID, Model: "model-a",
				// The billing-only deployment: no quota lease ever ran.
				QuotaAdmissionManaged: false,
			}
			client.reserved.Store(requestID, billingTrackingState{
				Usage: BillingUsage{PromptTokens: 12, OutputTokens: 4}, Admitted: tc.admitted, PriceID: "test-price", AdmittedAt: time.Now().UTC(),
			})

			writer := NewBillingAuditWriter(&RealAuditWriter{db: &poolDBExecutor{Pool: db}}, client)
			writer.EnsureRequestLog(ctx, envelope)
			writer.FinalizeRequestLog(ctx, envelope, []byte(tc.body), tc.status, http.StatusOK, 1, nil)

			got := readPersistedUsageSource(t, db, ctx, tenantID, requestID)
			if got != tc.wantSource {
				t.Fatalf("persisted usage_source=%q want %q", got, tc.wantSource)
			}
			// The settlement's raw_usage must carry the SAME source as the log,
			// or the two records of one request disagree. The unknown sentinel
			// is deliberately outside the enumerated set and is never claimed
			// as verified usage, so it is excluded from this comparison.
			if tc.wantSource != "" && tc.wantSource != unknownUsageSource {
				if settlementSource, _ := settlementRaw["usage_source"].(string); settlementSource != tc.wantSource {
					t.Fatalf("settlement raw_usage source=%q != log source %q",
						settlementSource, tc.wantSource)
				}
			}
		})
	}
}

// The audit body injection must never be mistaken for provider usage. When the
// provider omitted usage, the store injects the admission estimate into the
// logged body; if the derivation read that injected body it would label the
// request "upstream" and claim provider verification that never happened. The
// persisted marker must stay estimated_*.
func TestInjectedAuditUsageIsNeverReportedAsUpstream(t *testing.T) {
	db, ctx, tenantID, projectID, userID := setupBillingUsageSourceDB(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/internal/v1/billing/reservations":
			_, _ = w.Write([]byte(`{"reserved":true,"billable_amount_micros":10,"estimated_output_tokens":4}`))
		default:
			_, _ = w.Write([]byte(`{"amount_micros":10}`))
		}
	}))
	defer server.Close()

	client := NewBillingClient(server.URL, "internal-secret", "default")
	requestID := "req-injected-usage-" + tenantID
	envelope := &modelrouter.RequestEnvelope{
		TenantID: tenantID, ProjectID: projectID, UserID: userID, RequestID: requestID, Model: "model-a",
	}
	client.reserved.Store(requestID, billingTrackingState{
		Usage: BillingUsage{PromptTokens: 12, OutputTokens: 4}, Admitted: true, PriceID: "test-price", AdmittedAt: time.Now().UTC(),
	})
	writer := NewBillingAuditWriter(&RealAuditWriter{db: &poolDBExecutor{Pool: db}}, client)
	writer.EnsureRequestLog(ctx, envelope)
	// The provider body carries NO usage at all.
	writer.FinalizeRequestLog(ctx, envelope, []byte(`{"id":"chatcmpl-no-usage"}`), "success", http.StatusOK, 1, nil)

	source := readPersistedUsageSource(t, db, ctx, tenantID, requestID)
	if source != "estimated_reservation" {
		t.Fatalf("usage_source=%q want estimated_reservation: the audit-injected estimate must not be reported as provider usage", source)
	}
	// The logged token columns come from the admission estimate, which is what
	// the estimate marker is asserting.
	var inputTokens, outputTokens *int
	if err := db.QueryRow(ctx,
		`SELECT input_tokens, output_tokens FROM request_logs WHERE tenant_id=$1 AND request_id=$2`,
		tenantID, requestID).Scan(&inputTokens, &outputTokens); err != nil {
		t.Fatal(err)
	}
	if inputTokens == nil || *inputTokens != 12 {
		t.Fatalf("logged input_tokens=%v want the admission estimate 12", inputTokens)
	}
}

// After a request finalizes as PENDING the wallet stays frozen, and the row is
// only resolvable later if it carries a source. This asserts the durable
// evidence a compensation pass would key on actually exists on the row, and
// that the outcome recorded is pending rather than a silent success.
func TestPendingRequestLeavesReconciliationReadyEvidence(t *testing.T) {
	db, ctx, tenantID, projectID, userID := setupBillingUsageSourceDB(t)
	// A control plane that must not be contacted on a pending decision.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/internal/v1/billing/reservations":
			_, _ = w.Write([]byte(`{"reserved":true,"billable_amount_micros":10,"estimated_output_tokens":4}`))
		case "/internal/v1/billing/settlements", "/internal/v1/billing/releases":
			t.Errorf("pending must not call %s", r.URL.Path)
			w.WriteHeader(http.StatusInternalServerError)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	client := NewBillingClient(server.URL, "internal-secret", "default")
	requestID := "req-pending-evidence-" + tenantID
	envelope := &modelrouter.RequestEnvelope{
		TenantID: tenantID, ProjectID: projectID, UserID: userID, RequestID: requestID, Model: "model-a",
	}
	// Admitted, so an estimate marker is legitimate; the generic status is what
	// makes the decision pending rather than settle or release.
	client.reserved.Store(requestID, billingTrackingState{
		Usage: BillingUsage{PromptTokens: 7, OutputTokens: 3}, Admitted: true, PriceID: "test-price", AdmittedAt: time.Now().UTC(),
	})
	writer := NewBillingAuditWriter(&RealAuditWriter{db: &poolDBExecutor{Pool: db}}, client)
	writer.EnsureRequestLog(ctx, envelope)
	writer.FinalizeRequestLog(ctx, envelope, []byte(`{"id":"no-usage"}`), "provider_result_unknown", http.StatusOK, 1, nil)

	if envelope.BillingOutcome != "pending" {
		t.Fatalf("BillingOutcome=%q want pending", envelope.BillingOutcome)
	}
	// The exact expression reconciliation evaluates.
	source := readPersistedUsageSource(t, db, ctx, tenantID, requestID)
	if source != "estimated_reservation" {
		t.Fatalf("usage_source=%q want estimated_reservation so a later pass can attribute the row", source)
	}
	var billingOutcome string
	if err := db.QueryRow(ctx,
		`SELECT billing_outcome FROM request_logs WHERE tenant_id=$1 AND request_id=$2`,
		tenantID, requestID).Scan(&billingOutcome); err != nil {
		t.Fatal(err)
	}
	if billingOutcome != "pending" {
		t.Fatalf("billing_outcome=%q want pending", billingOutcome)
	}
}

// A definitive non-dispatch keeps its established release contract even on the
// billing-only path: the marker says no upstream work happened, and the wallet
// is refunded rather than frozen.
func TestBillingOnlyDefinitiveFailureStillReleases(t *testing.T) {
	db, ctx, tenantID, projectID, userID := setupBillingUsageSourceDB(t)
	var released bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/internal/v1/billing/reservations":
			_, _ = w.Write([]byte(`{"reserved":true,"billable_amount_micros":10,"estimated_output_tokens":4}`))
		case "/internal/v1/billing/releases":
			released = true
			_, _ = w.Write([]byte(`{}`))
		default:
			_, _ = w.Write([]byte(`{}`))
		}
	}))
	defer server.Close()

	client := NewBillingClient(server.URL, "internal-secret", "default")
	requestID := "req-definitive-fail-" + tenantID
	envelope := &modelrouter.RequestEnvelope{
		TenantID: tenantID, ProjectID: projectID, UserID: userID, RequestID: requestID, Model: "model-a",
	}
	client.reserved.Store(requestID, billingTrackingState{
		Usage: BillingUsage{PromptTokens: 7, OutputTokens: 3}, Admitted: true, PriceID: "test-price", AdmittedAt: time.Now().UTC(),
	})
	writer := NewBillingAuditWriter(&RealAuditWriter{db: &poolDBExecutor{Pool: db}}, client)
	writer.EnsureRequestLog(ctx, envelope)
	writer.FinalizeRequestLog(ctx, envelope, nil, "provider_unavailable", http.StatusBadGateway, 1, nil)

	if !released {
		t.Fatal("a definitive non-dispatch must still release its reservation")
	}
	if envelope.BillingOutcome != "released" {
		t.Fatalf("BillingOutcome=%q want released", envelope.BillingOutcome)
	}
	var billingOutcome string
	if err := db.QueryRow(ctx,
		`SELECT billing_outcome FROM request_logs WHERE tenant_id=$1 AND request_id=$2`,
		tenantID, requestID).Scan(&billingOutcome); err != nil {
		t.Fatal(err)
	}
	if billingOutcome != "released" {
		t.Fatalf("billing_outcome=%q want released", billingOutcome)
	}
}
