package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/auth"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/config"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
	"github.com/jackc/pgx/v5/pgxpool"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

func TestKeyModelEnforcementAllProtocolPaths(t *testing.T) {
	for _, key := range []struct {
		name, agent, mode, gate string
		status                  int
	}{
		{"存量凭据", "", "block", "record_only", 403},
		{"存量凭据开闸", "", "block", "allow_block", 403},
		{"集成记录", "agent1", "record", "record_only", 200},
		{"集成记录开闸", "agent1", "record", "allow_block", 200},
		{"集成拦截未开闸", "agent1", "block", "record_only", 200},
		{"集成拦截开闸", "agent1", "block", "allow_block", 403},
	} {
		for _, path := range []string{"chat/completions", "messages", "responses", "embeddings", "images/generations"} {
			t.Run(key.name+path, func(t *testing.T) {
				t.Setenv("INTEGRATION_KEY_ENFORCEMENT", key.gate)
				cfg := &config.Config{SecurityAuditOnly: true}
				resolver := &MockModelResolver{}
				limiter := &MockRateLimitChecker{}
				security := &MockSecurityChecker{}
				audit := &MockAuditWriter{}
				caller := &MockProviderCaller{}
				factory := &MockProviderAdapterFactory{MockProviderCaller: caller}
				var handler http.HandlerFunc
				body := `{"model":"名单外模型","messages":[{"role":"user","content":"你好"}]}`
				switch path {
				case "chat/completions":
					handler = NewChatCompletionsHandler(cfg, resolver, limiter, security, audit, factory, nil, nil).Handler()
				case "messages":
					handler = NewMessagesHandler(cfg, resolver, limiter, security, audit, factory, nil, nil).Handler()
					body = `{"model":"名单外模型","max_tokens":10,"messages":[{"role":"user","content":"你好"}]}`
				case "responses":
					handler = NewResponsesHandler(cfg, resolver, limiter, security, audit, factory, nil, nil).Handler()
					body = `{"model":"名单外模型","input":"你好"}`
				case "embeddings":
					handler = NewEmbeddingsHandler(cfg, resolver, limiter, security, audit, factory).Handler()
					body = `{"model":"名单外模型","input":"你好"}`
				case "images/generations":
					handler = NewImagesHandler(cfg, resolver, limiter, security, audit, factory, nil).Handler()
					body = `{"model":"名单外模型","prompt":"一幅山水画"}`
				}
				ctx := setAuthInfo(context.Background(), "tenant-a", "project-a", "", "key1", "")
				ctx = context.WithValue(ctx, auth.KeyModelAllowlistKey, []string{"名单内模型"})
				ctx = context.WithValue(ctx, auth.KeyModelEnforcementKey, key.mode)
				ctx = context.WithValue(ctx, auth.AgentInstanceIDKey, key.agent)
				r := httptest.NewRequest("POST", "/v1/"+path, strings.NewReader(body)).WithContext(ctx)
				w := httptest.NewRecorder()
				handler(w, r)
				if w.Code != key.status {
					t.Fatalf("HTTP=%d，期望 %d：%s", w.Code, key.status, w.Body.String())
				}
				if key.status == 403 && len(caller.CallCalls) > 0 {
					t.Fatal("被拒绝的模型到达上游")
				}
				if key.status == 403 {
					if path == "messages" {
						var result struct {
							Error struct{ Type, Message string }
						}
						if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil || result.Error.Type != "permission_error" || !strings.HasPrefix(result.Error.Message, "model is not allowed by user policy") || !strings.Contains(result.Error.Message, "名单外模型") {
							t.Fatalf("Messages 原生拒绝合同变化：%s", w.Body.String())
						}
					} else if !strings.Contains(w.Body.String(), "key_model_not_allowed") {
						t.Fatalf("拒绝代码变化：%s", w.Body.String())
					}
				}
				if key.status == 200 && len(caller.CallCalls) != 1 {
					t.Fatalf("记录档没有真实调用上游：%d", len(caller.CallCalls))
				}
			})
		}
	}
}

func TestModelRecordObservationAuditAndModelsVisibility(t *testing.T) {
	t.Setenv("INTEGRATION_KEY_ENFORCEMENT", "record_only")
	ctx := setAuthInfo(context.Background(), "tenant-a", "project-a", "", "key1", "")
	ctx = context.WithValue(ctx, auth.AgentInstanceIDKey, "agent1")
	ctx = context.WithValue(ctx, auth.KeyModelEnforcementKey, "record")
	ctx = context.WithValue(ctx, auth.KeyModelAllowlistKey, []string{"模型甲"})
	ctx = context.WithValue(ctx, auth.KeyModelObservationKey, &auth.ModelObservation{})
	if !auth.UserModelVisible(ctx, "模型乙") {
		t.Fatal("记录档隐藏模型")
	}
	if len(auth.TakeModelObservations(ctx)) > 0 {
		t.Fatal("列举模型产生调用审计")
	}
	if !auth.UserModelAllowed(ctx, "模型乙") || !auth.UserFinalModelAllowed(ctx, "模型丙") {
		t.Fatal("记录档拒绝模型")
	}
	db := &mockDBExecutor{}
	writer := &RealAuditWriter{db: db}
	writer.FinalizeRequestLog(ctx, &modelrouter.RequestEnvelope{RequestID: "req1", TenantID: "tenant-a", ProjectID: "project-a"}, nil, "success", 200, 1, nil)
	note, event := false, false
	for _, q := range db.queries {
		if strings.Contains(q, "policy_note='key_model_outside_allowlist'") {
			note = true
		}
		if strings.Contains(q, "INSERT INTO security_events") {
			event = true
		}
	}
	if !note || !event {
		t.Fatalf("名单外审计缺失 note=%v event=%v", note, event)
	}
	if len(auth.TakeModelObservations(ctx)) > 0 {
		t.Fatal("重复发送模型命中")
	}
}

func TestKeyModelEnforcementRouteExecution(t *testing.T) {
	for _, agent := range []string{"", "agent1"} {
		for _, configured := range []string{"record", "block"} {
			for _, gate := range []string{"record_only", "allow_block"} {
				t.Run(agent+configured+gate, func(t *testing.T) {
					t.Setenv("INTEGRATION_KEY_ENFORCEMENT", gate)
					ctx := context.WithValue(context.Background(), auth.AgentInstanceIDKey, agent)
					ctx = context.WithValue(ctx, auth.KeyModelEnforcementKey, configured)
					ctx = context.WithValue(ctx, auth.KeyModelAllowlistKey, []string{"allowed/model"})
					selected := route("p1", "openai", "https://fixture.invalid", "vendor-model")
					engine := &executionTestEngine{hasPolicy: true, applied: true, plan: modelrouter.RoutePlan{Primary: selected}}
					caller := &MockProviderCaller{}
					factory := &MockProviderAdapterFactory{CallersByProviderID: map[string]ProviderCaller{"p1": caller}}
					_, err := executeModelRoutePlan(ctx, modelRouteExecutionInput{Engine: engine, CredentialResolver: executionCredentialResolver{"p1": "fixture"}, Factory: factory, Envelope: &modelrouter.RequestEnvelope{RequestID: "req1", TenantID: "tenant-a", Model: "logical/model", EndpointType: "chat"}, SecuredBody: []byte(`{"model":"logical/model"}`)})
					allowed := agent != "" && (configured == "record" || gate == "record_only")
					if (err == nil) != allowed {
						t.Fatalf("路由允许=%v，期望 %v：%v", err == nil, allowed, err)
					}
					if !allowed && len(caller.CallCalls) > 0 {
						t.Fatal("拒绝后调用上游")
					}
				})
			}
		}
	}
}

func TestIntegrationModelCatalogHTTPEnforcementMatrix(t *testing.T) {
	dsn := os.Getenv("INTEGRATION_ENFORCEMENT_TEST_DATABASE_URL")
	if dsn == "" {
		t.Fatal("未配置隔离的凭据测试数据库")
	}
	db, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx := context.Background()
	tenant := fmt.Sprintf("j1_catalog_%d", time.Now().UnixNano())
	for _, sql := range []string{
		`INSERT INTO tenants(id,name,edition,status,is_test) VALUES($1,$1,'enterprise','active',true)`,
		`INSERT INTO projects(id,tenant_id,name,status) VALUES($1||'_proj',$1,'fixture','active')`,
		`INSERT INTO users(id,tenant_id,username,role) VALUES($1||'_user',$1,'fixture','tenant_admin')`,
		`INSERT INTO providers(id,tenant_id,name,provider_type,base_url,auth_mode,status) VALUES($1||'_p',$1,'fixture','custom','https://example.invalid','api_key','active')`,
		`INSERT INTO provider_credentials(id,provider_id,credential_name,secret_ciphertext,kms_key_ref,status) VALUES($1||'_c',$1||'_p','fixture','fixture','fixture','active')`,
		`INSERT INTO models(id,provider_id,model_name,status) VALUES($1||'_m1',$1||'_p','模型甲','active'),($1||'_m2',$1||'_p','模型乙','active')`,
		`INSERT INTO model_endpoint_capability_overrides(id,tenant_id,model_id,endpoint_type,state,reason,actor_user_id,config_version) SELECT 'ov_'||m.id,$1,m.id,'chat','supported','fixture',$1||'_user',1 FROM models m WHERE m.provider_id=$1||'_p'`,
	} {
		if _, err = db.Exec(ctx, sql, tenant); err != nil {
			t.Fatal(err)
		}
	}
	defer func() {
		for _, sql := range []string{`DELETE FROM model_catalog_entries WHERE provider_id IN(SELECT id FROM providers WHERE tenant_id=$1)`, `DELETE FROM model_endpoint_capability_overrides WHERE tenant_id=$1`, `DELETE FROM models WHERE provider_id IN(SELECT id FROM providers WHERE tenant_id=$1)`, `DELETE FROM provider_credentials WHERE provider_id IN(SELECT id FROM providers WHERE tenant_id=$1)`, `DELETE FROM providers WHERE tenant_id=$1`, `DELETE FROM projects WHERE tenant_id=$1`, `DELETE FROM users WHERE tenant_id=$1`, `DELETE FROM tenants WHERE id=$1`} {
			if _, err := db.Exec(ctx, sql, tenant); err != nil {
				t.Error(err)
			}
		}
	}()
	for _, agent := range []string{"", "agent1"} {
		for _, configured := range []string{"record", "block"} {
			for _, gate := range []string{"record_only", "allow_block"} {
				t.Run(agent+configured+gate, func(t *testing.T) {
					t.Setenv("INTEGRATION_KEY_ENFORCEMENT", gate)
					c := setAuthInfo(context.Background(), tenant, tenant+"_proj", "", "key1", "")
					c = context.WithValue(c, auth.AgentInstanceIDKey, agent)
					c = context.WithValue(c, auth.KeyModelEnforcementKey, configured)
					c = context.WithValue(c, auth.KeyModelAllowlistKey, []string{"模型甲"})
					c = context.WithValue(c, auth.KeyModelObservationKey, &auth.ModelObservation{})
					w := httptest.NewRecorder()
					NewModelsHandler(db).Handler()(w, httptest.NewRequest("GET", "/v1/models", nil).WithContext(c))
					var got ModelsResponse
					if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil || w.Code != 200 {
						t.Fatal(w.Code, w.Body.String(), err)
					}
					want := 1
					if agent != "" && (configured == "record" || gate == "record_only") {
						want = 2
					}
					if len(got.Data) != want {
						t.Fatalf("模型可见数量=%d，期望 %d：%s", len(got.Data), want, w.Body.String())
					}
					if len(auth.TakeModelObservations(c)) != 0 {
						t.Fatal("列举模型产生调用命中")
					}
				})
			}
		}
	}
}
