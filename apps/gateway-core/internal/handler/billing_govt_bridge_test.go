package handler

import (
	"context"
	"errors"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/config"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/relay"
	"github.com/jackc/pgx/v5/pgxpool"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestGovernmentBillingGatewayBridge(t *testing.T) {
	endpoint := os.Getenv("GOVT_BILLING_ENDPOINT")
	if endpoint == "" {
		t.Skip("GOVT_BILLING_ENDPOINT not set")
	}
	ctx := context.Background()
	db, err := pgxpool.New(ctx, os.Getenv("CONTENT_LOGS_TEST_DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	c := NewBillingClientWithMode(endpoint, "govt-test-secret", "default", "metering")
	c.AllowanceRequired = func(context.Context, string, string) (bool, error) { return true, nil }
	writer := NewBillingAuditWriter(&RealAuditWriter{db: &poolDBExecutor{Pool: db}}, c)
	kind := os.Getenv("GOVT_BILLING_KIND")
	var upstreamHits atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamHits.Add(1)
		if kind == "F-concurrent-upstream-5xx" {
			w.WriteHeader(503)
			_, _ = w.Write([]byte(`{"error":"upstream failure"}`))
			return
		}
		_, _ = w.Write([]byte(`{"usage":{"prompt_tokens":2,"completion_tokens":3}}`))
	}))
	defer upstream.Close()
	run := func(id, model string) error {
		e := &modelrouter.RequestEnvelope{TenantID: os.Getenv("GOVT_BILLING_TENANT"), UserID: os.Getenv("GOVT_BILLING_USER"), ProjectID: os.Getenv("GOVT_BILLING_PROJECT"), ClientID: os.Getenv("GOVT_BILLING_KEY"), RequestID: os.Getenv("GOVT_BILLING_TENANT") + id, Model: model}
		usage := BillingUsage{PromptTokens: 12, OutputTokens: 4}
		if kind == "E-stream-disconnect" {
			usage.PromptTokens = 2
		}
		err := c.ReserveUsage(ctx, e, usage)
		if kind == "B-exhausted" || kind == "I-funded-exhausted" {
			if err == nil {
				return errors.New("exhausted account admitted")
			}
			status, _, _ := billingAdmissionResponse(err)
			if status != 429 {
				return errors.New("exhausted account did not return 429")
			}
			return nil
		}
		if err != nil {
			return err
		}
		writer.EnsureRequestLog(ctx, e)
		if kind == "E-stream-disconnect" {
			events := longStreamEvents(200)
			reader := &liveRelayReader{events: events[:len(events)-1], err: errors.New("stream reset")}
			h := &ChatCompletionsHandler{cfg: &config.Config{UpstreamStreaming: true, OutputSecurityMode: "stream_audit"}, securityClient: &MockSecurityChecker{}, auditWriter: writer, billingPreflight: c}
			attempted, err := h.tryLiveChatStream(ctx, httptest.NewRecorder(), e, &liveRelayCaller{reader: reader}, []byte(`{}`), time.Now(), "", &relay.CommitTracker{})
			if err != nil || !attempted {
				return errors.New("stream relay failed")
			}
			return nil
		}
		resp, err := http.Get(upstream.URL)
		if err != nil {
			return err
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		status := "success"
		if resp.StatusCode >= 500 {
			status = "provider_error"
		}
		writer.FinalizeRequestLog(ctx, e, body, status, resp.StatusCode, 1, nil)
		if e.BillingOutcome == "failed" || e.BillingOutcome == "pending" {
			return errors.New("accounting did not finish")
		}
		return nil
	}
	if kind == "F-concurrent-upstream-5xx" {
		var wg sync.WaitGroup
		errs := make(chan error, 24)
		for i := 0; i < 24; i++ {
			wg.Add(1)
			go func(i int) { defer wg.Done(); errs <- run(string(rune('a'+i)), "govt-paid") }(i)
		}
		wg.Wait()
		close(errs)
		for err := range errs {
			if err != nil {
				t.Fatal(err)
			}
		}
	} else {
		model := "govt-paid"
		if kind == "C-unpriced-exhausted" {
			model = "govt-unpriced"
		}
		if err := run("-one", model); err != nil {
			t.Fatal(err)
		}
		if kind == "D-mixed-key" {
			if err := run("-two", "govt-unpriced"); err != nil {
				t.Fatal(err)
			}
		}
	}
	if (kind == "B-exhausted" || kind == "I-funded-exhausted") && upstreamHits.Load() != 0 {
		t.Fatalf("rejected call reached upstream: %d", upstreamHits.Load())
	}
	if kind == "F-concurrent-upstream-5xx" && upstreamHits.Load() != 24 {
		t.Fatalf("upstream calls=%d", upstreamHits.Load())
	}
}
