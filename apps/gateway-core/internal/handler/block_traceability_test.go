package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/config"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
	"github.com/yangjiyj/aiguard/packages/shared-go/eventbus"
	"net/http"
)

func TestAsyncBlockFallbackKeepsTheAdvertisedEventID(t *testing.T) {
	for _, tc := range []struct {
		name   string
		outbox outboxEnqueuer
	}{
		{"enqueue fails", &fakeOutboxEnqueuer{err: errors.New("outbox unavailable")}},
		{"outbox missing", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db := &mockDBExecutor{}
			writer := NewAsyncAuditWriter(&RealAuditWriter{db: db}, tc.outbox)
			ctx := withBlockLedger(context.Background())
			env := asyncAuditTestEnvelope()
			writer.WriteSecurityEvent(ctx, env, []SecurityFinding{passwordRuleFinding}, "security_blocked", "input blocked")
			if db.execCalls != 1 {
				t.Fatalf("durable fallback writes=%d", db.execCalls)
			}
			block := requestBlockAttribution(ctx)
			if block == nil || block.BlockID != db.args[0][0] || block.RequestID != env.RequestID {
				t.Fatalf("notice cannot find durable event: block=%+v persisted=%v", block, db.args[0][0])
			}
			var persisted struct {
				Block blockAttribution `json:"block"`
			}
			if err := json.Unmarshal(db.args[0][9].([]byte), &persisted); err != nil {
				t.Fatal(err)
			}
			if persisted.Block != *block {
				t.Fatalf("payload block differs from client notice: %+v %+v", persisted.Block, block)
			}
			notice := (&ChatCompletionsHandler{}).securityBlockNotice(ctx, env, "")
			if !strings.Contains(notice.Text, block.BlockID) || !strings.Contains(notice.Text, env.RequestID) {
				t.Fatalf("unsearchable client notice: %s", notice.Text)
			}
			w := httptest.NewRecorder()
			setBlockNoticeHeaders(w, notice)
			if w.Header().Get("X-JJDGuard-Block-ID") != block.BlockID || w.Header().Get("X-JJDGuard-Request-ID") != env.RequestID || w.Header().Get("X-Request-ID") != env.RequestID {
				t.Fatalf("trace headers mismatch: %v", w.Header())
			}
		})
	}
}

func TestAsyncBlockSuccessfulOutboxMatchesClientNotice(t *testing.T) {
	outbox := &fakeOutboxEnqueuer{}
	writer := NewAsyncAuditWriter(&fakeSyncAuditWriter{}, outbox)
	ctx := withBlockLedger(context.Background())
	writer.WriteSecurityEvent(ctx, asyncAuditTestEnvelope(), []SecurityFinding{passwordRuleFinding}, "security_blocked", "blocked")
	if len(outbox.events) != 1 {
		t.Fatalf("event count=%d", len(outbox.events))
	}
	var payload eventbus.AuditSecurityEventPayload
	if err := json.Unmarshal(outbox.events[0].Payload, &payload); err != nil {
		t.Fatal(err)
	}
	block := requestBlockAttribution(ctx)
	if block == nil || block.BlockID != payload.EventID || block.RequestID != payload.RequestLog.RequestID {
		t.Fatalf("queued event cannot be found from notice: block=%+v payload=%+v", block, payload)
	}
}

type cancellationAwareAuditWriter struct {
	fakeSyncAuditWriter
	contextError error
	fixedEventID string
}

func (w *cancellationAwareAuditWriter) WriteSecurityEvent(ctx context.Context, _ *modelrouter.RequestEnvelope, _ []SecurityFinding, _, _ string) {
	w.securityWrites++
	w.contextError = ctx.Err()
	w.fixedEventID = securityEventIDFromContext(ctx)
}

func TestAsyncBlockFallbackOutlivesClientCancellation(t *testing.T) {
	syncWriter := &cancellationAwareAuditWriter{}
	writer := NewAsyncAuditWriter(syncWriter, &fakeOutboxEnqueuer{err: context.Canceled})
	ctx, cancel := context.WithCancel(withBlockLedger(context.Background()))
	cancel()
	writer.WriteSecurityEvent(ctx, asyncAuditTestEnvelope(), []SecurityFinding{passwordRuleFinding}, "security_blocked", "blocked")
	if syncWriter.securityWrites != 1 || syncWriter.contextError != nil || syncWriter.fixedEventID == "" {
		t.Fatalf("client cancellation discarded fallback trace: %+v", syncWriter)
	}
	if block := requestBlockAttribution(ctx); block == nil || block.BlockID != syncWriter.fixedEventID {
		t.Fatalf("fallback event ID differs from client: %+v", block)
	}
}

func TestAsyncMissingOutboxStillPersistsContent(t *testing.T) {
	syncWriter := &fakeSyncAuditWriter{}
	writer := NewAsyncAuditWriter(syncWriter, nil)
	writer.WriteContentLog(context.Background(), asyncAuditTestEnvelope(), "user", "audit trail", 3)
	if syncWriter.contentWrites != 1 {
		t.Fatalf("missing outbox discarded content: %d", syncWriter.contentWrites)
	}
}

func TestFailedBlockPersistenceDoesNotAdvertisePhantomEvent(t *testing.T) {
	ctx := withBlockLedger(context.Background())
	db := &mockDBExecutor{execError: errors.New("database unavailable")}
	writer := &RealAuditWriter{db: db}
	env := asyncAuditTestEnvelope()
	writer.WriteSecurityEvent(ctx, env, []SecurityFinding{passwordRuleFinding}, "security_blocked", "blocked")
	if blockRecorded(ctx) {
		t.Fatal("failed insert must not claim a persisted block")
	}
	notice := (&ChatCompletionsHandler{}).securityBlockNotice(ctx, env, "security policy")
	if notice.Attribution.BlockID != "" || !strings.Contains(notice.Text, env.RequestID) {
		t.Fatalf("failed insert must retain request lookup only: %+v", notice)
	}
}

func TestFinalizedRequestTrailCarriesClientBlockNumber(t *testing.T) {
	ctx := withBlockLedger(context.Background())
	db := &mockDBExecutor{}
	writer := &RealAuditWriter{db: db}
	env := asyncAuditTestEnvelope()
	writer.WriteSecurityEvent(ctx, env, []SecurityFinding{passwordRuleFinding}, "security_blocked", "blocked")
	block := requestBlockAttribution(ctx)
	writer.FinalizeRequestLog(ctx, env, nil, "security_blocked", 403, 1, &AuditResult{
		OutputAction: "block", ResponseMetadata: map[string]interface{}{"retained": true},
	})
	var trail struct {
		Block            blockAttribution       `json:"block"`
		ResponseMetadata map[string]interface{} `json:"response_metadata"`
	}
	if err := json.Unmarshal(db.args[1][20].([]byte), &trail); err != nil {
		t.Fatal(err)
	}
	if trail.Block != *block || trail.ResponseMetadata["retained"] != true {
		t.Fatalf("request audit trail lost block correlation or existing metadata: %+v", trail)
	}
}

func TestCustomBlockNoticeAlwaysIncludesSearchableIDs(t *testing.T) {
	block := blockAttribution{BlockID: "evt_customer", RequestID: "req_customer"}
	for _, tc := range []struct{ template, want string }{
		{"请联系安全组", "请联系安全组\n阻断编号：evt_customer\n请求 ID：req_customer"},
		{"编号 {block_id}", "编号 evt_customer\n请求 ID：req_customer"},
		{"编号 {block_id} 请求 {request_id}", "编号 evt_customer 请求 req_customer"},
		{"evt_customer req_customer", "evt_customer req_customer"},
	} {
		if got := renderBlockNotice(tc.template, block); got != tc.want {
			t.Fatalf("template %q rendered=%q want=%q", tc.template, got, tc.want)
		}
	}
	if strings.Contains(DefaultBlockNoticeTemplate, "安全护栏") || !strings.Contains(DefaultBlockNoticeTemplate, "风险处理 → 阻断记录") {
		t.Fatal("default notice points to wrong menu")
	}
}

func TestDataEndpointBlockNoticesIdentifyPersistedEvent(t *testing.T) {
	t.Setenv("UAG_ROUTING_DISABLED", "true")
	for _, endpoint := range []string{"images", "embeddings"} {
		t.Run(endpoint, func(t *testing.T) {
			audit := &MockAuditWriter{}
			security := &MockSecurityChecker{InputAction: "block", InputFindings: []SecurityFinding{passwordRuleFinding}}
			var handler http.Handler
			var req *http.Request
			switch endpoint {
			case "images":
				handler = NewImagesHandler(&config.Config{}, &MockModelResolver{}, &MockRateLimitChecker{}, security, audit, &MockProviderAdapterFactory{}, nil).Handler()
				req = newImagesTestRequest(`{"model":"gpt-image-2","prompt":"password pass1996"}`)
			case "embeddings":
				handler = NewEmbeddingsHandler(&config.Config{}, &MockModelResolver{}, &MockRateLimitChecker{}, security, audit, &MockProviderAdapterFactory{}).Handler()
				req = httptest.NewRequest(http.MethodPost, "/v1/embeddings", strings.NewReader(`{"model":"text-embedding-ada-002","input":"password pass1996"}`))
				req = req.WithContext(setAuthInfo(req.Context(), "tenant-a", "project-a", "user-a", "key-a", ""))
			}
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			if rec.Code != http.StatusForbidden {
				t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
			}
			var body ErrorResponse
			if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
				t.Fatal(err)
			}
			blockID := blockedEventID(t, audit)
			assertNoticeNamesRule(t, body.Error.Message, blockID)
			if rec.Header().Get("X-JJDGuard-Block-ID") != blockID || rec.Header().Get("X-JJDGuard-Request-ID") == "" || !strings.Contains(body.Error.Message, rec.Header().Get("X-JJDGuard-Request-ID")) {
				t.Fatalf("data endpoint notice cannot be correlated: %v %s", rec.Header(), rec.Body.String())
			}
		})
	}
}

func TestReverseStreamingTerminationCarriesSearchableRequest(t *testing.T) {
	for _, path := range []string{"/v1/chat/completions", "/v1/responses", "/v1/messages"} {
		t.Run(path, func(t *testing.T) {
			h := &ReverseProxyHandler{}
			notice := h.reverseBlockNotice(withBlockLedger(context.Background()), "request-reverse", "output", []SecurityFinding{passwordRuleFinding})
			rec := httptest.NewRecorder()
			if err := writeReverseSecurityTermination(rec, path, "output_security_blocked", notice); err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(rec.Body.String(), "request-reverse") || !strings.Contains(rec.Body.String(), "rule_525f3078") || strings.Contains(rec.Body.String(), "pass1996") || !strings.Contains(rec.Body.String(), `"request_id":"request-reverse"`) {
				t.Fatalf("reverse stream termination lost trace or leaked raw secret: %s", rec.Body.String())
			}
			if strings.Contains(rec.Body.String(), `"block_id"`) {
				t.Fatal("live stream must not advertise a block ID before persistence")
			}
		})
	}
}

func TestRealBlockedNoticeAndRequestTrailDatabase(t *testing.T) {
	db, baseCtx, tenant, project, provider, model := setupAuditWriterNullUserFixture(t)
	ctx := withBlockLedger(baseCtx)
	writer := &RealAuditWriter{db: &realDBExecutor{pool: db}}
	env := &modelrouter.RequestEnvelope{RequestID: "trace_" + tenant, TenantID: tenant, ProjectID: project, ProviderID: provider, ModelID: model, EndpointType: "chat"}
	finding := passwordRuleFinding
	finding.Type = "secret" // Unbound detector IDs are attribution, not policy-rule FKs.
	writer.EnsureRequestLog(ctx, env)
	asyncWriter := NewAsyncAuditWriter(writer, &fakeOutboxEnqueuer{err: errors.New("outbox unavailable")})
	asyncWriter.WriteSecurityEvent(ctx, env, []SecurityFinding{finding}, "security_blocked", "blocked by detector")
	block := requestBlockAttribution(ctx)
	if block == nil {
		t.Fatal("real database fallback left no block trace")
	}
	writer.FinalizeRequestLog(ctx, env, nil, "security_blocked", http.StatusForbidden, 1, nil)
	var eventBlock, logBlock, request, status string
	if err := db.QueryRow(ctx, `SELECT e.matched_summary->'block'->>'block_id', r.output_audit_result->'block'->>'block_id', r.request_id, r.request_status FROM security_events e JOIN request_logs r ON r.request_id=e.request_id AND r.tenant_id=e.tenant_id WHERE e.id=$1 AND e.tenant_id=$2`, block.BlockID, tenant).Scan(&eventBlock, &logBlock, &request, &status); err != nil {
		t.Fatal(err)
	}
	notice := (&ChatCompletionsHandler{}).securityBlockNotice(ctx, env, "")
	if eventBlock != block.BlockID || logBlock != block.BlockID || request != env.RequestID || status != "security_blocked" || !strings.Contains(notice.Text, eventBlock) || !strings.Contains(notice.Text, request) {
		t.Fatalf("customer key fails actual event/request join: event=%s log=%s request=%s status=%s notice=%s", eventBlock, logBlock, request, status, notice.Text)
	}
}

func TestLegacyStockBlockTemplateUpdatesWithoutChangingCustomWording(t *testing.T) {
	for _, value := range []string{legacyDefaultBlockNoticeTemplate, " \n" + legacyDefaultBlockNoticeTemplate + "\n "} {
		if normalized := normalizeBlockNoticeTemplate(value); normalized != DefaultBlockNoticeTemplate {
			t.Fatalf("old stock template not normalized: %q", normalized)
		}
		notice := renderBlockNotice(value, blockAttribution{BlockID: "evt_compat", RequestID: "request_compat"})
		if strings.Contains(notice, "安全护栏") || !strings.Contains(notice, "风险处理 → 阻断记录") || !strings.Contains(notice, "request_compat") {
			t.Fatalf("old saved stock template still points to stale menu: %s", notice)
		}
	}
	custom := legacyDefaultBlockNoticeTemplate + "\n请联系本公司的安全组。"
	if normalized := normalizeBlockNoticeTemplate(custom); normalized != custom {
		t.Fatal("company custom notice must remain intact")
	}
	client := NewToolRiskClient("http://127.0.0.1:1", "synthetic-test-secret")
	client.setBlockNoticeSettings(blockNoticeSettings{Mode: blockResponseModeMessage, Template: legacyDefaultBlockNoticeTemplate})
	if cached := client.BlockNoticeSettings(context.Background()); cached.Template != DefaultBlockNoticeTemplate || cached.Mode != blockResponseModeMessage {
		t.Fatalf("cache compatibility changed response mode or retained old default: %+v", cached)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("compatibility must not write settings; method=%s", r.Method)
		}
		_ = json.NewEncoder(w).Encode(map[string]string{blockResponseModeSettingKey: blockResponseModeMessage, blockNoticeTemplateSettingKey: legacyDefaultBlockNoticeTemplate})
	}))
	defer server.Close()
	fetched, err := NewToolRiskClient(server.URL, "synthetic-test-secret").fetchBlockNoticeSettings(context.Background())
	if err != nil || fetched.Template != DefaultBlockNoticeTemplate || fetched.Mode != blockResponseModeMessage {
		t.Fatalf("fetched legacy stock template=%+v err=%v", fetched, err)
	}
}
