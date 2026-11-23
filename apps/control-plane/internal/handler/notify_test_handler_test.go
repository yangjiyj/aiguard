package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/notify"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

type notifyTestStore struct {
	channels map[string]*repository.NotifyChannel // key: tenant|id
}

func (s *notifyTestStore) GetForTenant(_ context.Context, tenantID, id string) (*repository.NotifyChannel, error) {
	if ch, ok := s.channels[tenantID+"|"+id]; ok {
		return ch, nil
	}
	return nil, pgx.ErrNoRows
}

func (s *notifyTestStore) ListEnabled(context.Context, string) ([]*repository.NotifyChannel, error) {
	return nil, nil
}

type notifyAuditRecorder struct {
	budgetTestSystemRepo
	ops []*repository.AuditOperation
}

func (r *notifyAuditRecorder) CreateAuditOperation(_ context.Context, op *repository.AuditOperation) error {
	r.ops = append(r.ops, op)
	return nil
}

func callNotifyTest(t *testing.T, deps *Dependencies, tenantID, id string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/admin/v1/notify-channels/"+id+"/test", nil)
	req = withAlertUserCtx(req, tenantID, "u1")
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", id)
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	rr := httptest.NewRecorder()
	TestNotifyChannel(deps)(rr, req)
	return rr
}

func TestNotifyChannelTestEndpoint(t *testing.T) {
	store := &notifyTestStore{channels: map[string]*repository.NotifyChannel{
		// 内网地址会被 SSRF 防护拦截 → 可在不出网的情况下验证失败路径
		"t1|nc_loop": {ID: "nc_loop", TenantID: "t1", Type: "feishu", ConfigJSON: map[string]any{"webhook_url": "http://127.0.0.1:9/hook"}},
		"t1|nc_bad":  {ID: "nc_bad", TenantID: "t1", Type: "wecom", ConfigJSON: map[string]any{}},
	}}
	audit := &notifyAuditRecorder{}
	deps := &Dependencies{NotifyDispatcher: notify.NewDispatcherWithStore(store), SystemRepo: audit}

	t.Run("cross tenant is not found", func(t *testing.T) {
		rr := callNotifyTest(t, deps, "t2", "nc_loop")
		if rr.Code != http.StatusNotFound || !strings.Contains(rr.Body.String(), "通知渠道不存在") {
			t.Fatalf("code=%d body=%s", rr.Code, rr.Body.String())
		}
	})

	t.Run("ssrf target fails with chinese reason and audit", func(t *testing.T) {
		before := len(audit.ops)
		rr := callNotifyTest(t, deps, "t1", "nc_loop")
		if rr.Code != http.StatusBadGateway {
			t.Fatalf("code=%d body=%s", rr.Code, rr.Body.String())
		}
		var resp struct {
			Error struct{ Message string } `json:"error"`
		}
		_ = json.Unmarshal(rr.Body.Bytes(), &resp)
		if !strings.HasPrefix(resp.Error.Message, "测试消息发送失败：飞书地址不被允许") {
			t.Fatalf("message=%q", resp.Error.Message)
		}
		if strings.Contains(resp.Error.Message, "safetarget") || strings.Contains(resp.Error.Message, "127.0.0.1") {
			t.Fatalf("message leaks internals: %q", resp.Error.Message)
		}
		if len(audit.ops) != before+1 || audit.ops[len(audit.ops)-1].ActionType != "notify_channel.test" {
			t.Fatalf("audit not written: %+v", audit.ops)
		}
		if audit.ops[len(audit.ops)-1].ActionDetail["success"] != false {
			t.Fatalf("audit detail=%v", audit.ops[len(audit.ops)-1].ActionDetail)
		}
	})

	t.Run("invalid config fails in chinese", func(t *testing.T) {
		rr := callNotifyTest(t, deps, "t1", "nc_bad")
		if rr.Code != http.StatusBadGateway || !strings.Contains(rr.Body.String(), "企业微信配置无效") {
			t.Fatalf("code=%d body=%s", rr.Code, rr.Body.String())
		}
	})
}
