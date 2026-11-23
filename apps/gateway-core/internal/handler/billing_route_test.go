package handler

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
)

type billingRouteOrderWriter struct {
	MockAuditWriter
	events   *[]string
	routeErr error
	canceled bool
}

func (w *billingRouteOrderWriter) PersistBillingRoute(ctx context.Context, e *modelrouter.RequestEnvelope) error {
	*w.events = append(*w.events, "route:"+e.ProviderID+":"+e.ModelID)
	w.canceled = ctx.Err() != nil
	return w.routeErr
}

func (w *billingRouteOrderWriter) FinalizeRequestLog(_ context.Context, _ *modelrouter.RequestEnvelope, _ []byte, _ string, _ int, _ int, _ *AuditResult) {
	*w.events = append(*w.events, "audit")
}

func TestBillingFinalRoutePersistsBeforeSettlementAndAudit(t *testing.T) {
	for _, async := range []bool{false, true} {
		for _, failRoute := range []bool{false, true} {
			t.Run(map[bool]string{false: "sync", true: "async"}[async]+map[bool]string{false: "_ok", true: "_route_failed"}[failRoute], func(t *testing.T) {
				events := []string{}
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					switch r.URL.Path {
					case "/internal/v1/billing/reservations":
						_, _ = w.Write([]byte(`{"reserved":true,"price_id":"test-price","admitted_at":"2026-10-03T01:00:00Z"}`))
					case "/internal/v1/billing/settlements":
						events = append(events, "settle")
						_, _ = w.Write([]byte(`{"amount_micros":1}`))
					default:
						t.Errorf("unexpected billing path %s", r.URL.Path)
						w.WriteHeader(http.StatusNotFound)
					}
				}))
				defer server.Close()
				client := NewBillingClient(server.URL, "test-secret", "default")
				e := &modelrouter.RequestEnvelope{TenantID: "tenant-a", UserID: "user-a", RequestID: "req-final-route", Model: "public-alias", ProviderID: "initial", ModelID: "initial-model"}
				if err := client.Reserve(context.Background(), e, &ChatCompletionRequest{MaxTokens: 1}); err != nil {
					t.Fatal(err)
				}
				e.ProviderID, e.ModelID = "fallback", "fallback-model"
				inner := &billingRouteOrderWriter{events: &events}
				if failRoute {
					inner.routeErr = errors.New("route storage unavailable")
				}
				var audit AuditWriter = inner
				if async {
					audit = NewAsyncAuditWriter(inner, &fakeOutboxEnqueuer{})
				}
				writer := NewBillingAuditWriter(audit, client)
				ctx, cancel := context.WithCancel(context.Background())
				cancel()
				writer.FinalizeRequestLog(ctx, e, []byte(`{"usage":{"prompt_tokens":1,"completion_tokens":1}}`), "success", http.StatusOK, 1, nil)
				want := []string{"route:fallback:fallback-model", "settle", "audit"}
				if failRoute {
					want = []string{"route:fallback:fallback-model", "audit"}
				}
				if !reflect.DeepEqual(events, want) || inner.canceled {
					t.Fatalf("order=%v canceled=%v, want %v", events, inner.canceled, want)
				}
				_, held := client.trackingState(e.RequestID)
				if held != failRoute || (failRoute && e.BillingOutcome != "failed") {
					t.Fatalf("failed route must retain accounting evidence: held=%v outcome=%s", held, e.BillingOutcome)
				}
				if e.Model != "public-alias" {
					t.Fatalf("public billable model changed to %s", e.Model)
				}
			})
		}
	}
}

func TestBillingFinalRoutePersistenceIsTenantScoped(t *testing.T) {
	db, ctx, tenant, project, user := setupBillingUsageSourceDB(t)
	writer := NewRealAuditWriter(db, nil)
	initialProvider, initialModel := "route-initial-"+user, "route-initial-model-"+user
	finalProvider, finalModel := "route-final-"+user, "route-final-model-"+user
	for _, route := range [][2]string{{initialProvider, initialModel}, {finalProvider, finalModel}} {
		if _, err := db.Exec(ctx, `INSERT INTO providers(id,tenant_id,name,provider_type) VALUES($1,$2,$1,'openai')`, route[0], tenant); err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec(ctx, `INSERT INTO models(id,provider_id,model_name) VALUES($1,$2,'actual-model')`, route[1], route[0]); err != nil {
			t.Fatal(err)
		}
	}
	e := &modelrouter.RequestEnvelope{TenantID: tenant, ProjectID: project, UserID: user, RequestID: "route-" + user, ProviderID: initialProvider, ModelID: initialModel, Model: "public-alias", EndpointType: "chat_completion"}
	writer.EnsureRequestLog(ctx, e)
	e.ProviderID, e.ModelID = finalProvider, finalModel
	if err := writer.PersistBillingRoute(ctx, e); err != nil {
		t.Fatal(err)
	}
	var actualProvider, actualModel, status string
	if err := db.QueryRow(ctx, `SELECT provider_id,model_id,request_status FROM request_logs WHERE tenant_id=$1 AND request_id=$2`, tenant, e.RequestID).Scan(&actualProvider, &actualModel, &status); err != nil || actualProvider != finalProvider || actualModel != finalModel || status != "received" {
		t.Fatalf("route/status=%s/%s/%s err=%v", actualProvider, actualModel, status, err)
	}
	copy := *e
	copy.TenantID = tenant + "-foreign"
	if err := writer.PersistBillingRoute(ctx, &copy); err == nil {
		t.Fatal("foreign tenant request route was updated")
	}
	copy = *e
	copy.ModelID = initialModel
	if err := writer.PersistBillingRoute(ctx, &copy); err == nil {
		t.Fatal("provider/model mismatch was updated")
	}
	if err := db.QueryRow(ctx, `SELECT provider_id,model_id FROM request_logs WHERE tenant_id=$1 AND request_id=$2`, tenant, e.RequestID).Scan(&actualProvider, &actualModel); err != nil || actualProvider != finalProvider || actualModel != finalModel {
		t.Fatalf("rejected route modified original: %s/%s err=%v", actualProvider, actualModel, err)
	}
}
