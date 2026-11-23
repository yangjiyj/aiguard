package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
	ai "github.com/yangjiyj/aiguard/packages/shared-go/agentintegration"
)

type metadataReadStore struct {
	IntegrationRepo
	tenant, key string
	query       repository.CredentialHitsQuery
	calls       int
	err         error
}

func (s *metadataReadStore) CredentialHits(_ context.Context, tenant string, q repository.CredentialHitsQuery) (*repository.CredentialHitsPage, error) {
	s.calls++
	s.tenant = tenant
	s.key = q.KeyID
	s.query = q
	if s.err != nil {
		return nil, s.err
	}
	return &repository.CredentialHitsPage{Data: []repository.CredentialHit{{ID: "evt1", KeyID: q.KeyID, CreatedAt: q.Since, Category: "dlp:openai_key", PolicyID: "policy1", Action: "audit"}}, Since: q.Since, Until: q.Until}, nil
}

func (s *metadataReadStore) CredentialRetentionStatus(_ context.Context, tenant, key string, now time.Time) (*repository.CredentialRetentionStatus, error) {
	s.calls++
	s.tenant = tenant
	s.key = key
	if s.err != nil {
		return nil, s.err
	}
	at := now.Add(-time.Hour)
	return &repository.CredentialRetentionStatus{KeyID: key, LogRetentionDays: 180, HasContentLogs24h: true, LastContentLogAt: &at}, nil
}

func TestIntegrationMetadataHTTPProjectionAndActor(t *testing.T) {
	for _, endpoint := range []string{"credential-hits", "retention-status"} {
		store := &metadataReadStore{}
		deps := &Dependencies{IntegrationRepo: store}
		h := GetIntegrationRetentionStatus(deps)
		if endpoint == "credential-hits" {
			h = ListIntegrationCredentialHits(deps)
		}
		w := httptest.NewRecorder()
		h(w, policyHandlerRequest("GET", "/admin/v1/integration/"+endpoint+"?key_id=key-a&tenant_id=foreign", "", "platform_connector"))
		if w.Code != 200 || store.tenant != "tenant-a" || store.key != "key-a" || w.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("元数据接口身份/租户/缓存边界错误：%d %s", w.Code, w.Body.String())
		}
		var obj map[string]json.RawMessage
		if err := json.Unmarshal(w.Body.Bytes(), &obj); err != nil {
			t.Fatal(err)
		}
		if endpoint == "retention-status" {
			for key := range obj {
				switch key {
				case "key_id", "log_retention_days", "has_content_logs_24h", "last_content_log_at":
				default:
					t.Errorf("多余留存响应字段：%s", key)
				}
			}
		} else {
			if len(obj["data"]) == 0 || len(obj["since"]) == 0 || len(obj["until"]) == 0 {
				t.Fatalf("缺少分页时间窗口：%s", w.Body.String())
			}
			if store.query.Until.Sub(store.query.Since) != 7*24*time.Hour {
				t.Fatal("默认查询不是最近七天")
			}
		}
		for _, role := range []string{"chat_user", "security_admin", "security_officer", "auditor"} {
			w = httptest.NewRecorder()
			h(w, policyHandlerRequest("GET", "/?key_id=key-a", "", role))
			if w.Code != 403 {
				t.Errorf("越权身份 %s：%d", role, w.Code)
			}
		}
		w = httptest.NewRecorder()
		h(w, httptest.NewRequest("GET", "/?key_id=key-a", nil))
		if w.Code != 401 {
			t.Fatal("未登录身份获得元数据")
		}
		for _, tc := range []struct {
			err    error
			status int
		}{{ai.ErrNotFound, 404}, {ai.ErrInvalid, 400}, {errors.New("正文测试标记：服务内部错误"), 503}} {
			store.err = tc.err
			w = httptest.NewRecorder()
			h(w, policyHandlerRequest("GET", "/?key_id=key-a", "", "platform_connector"))
			if w.Code != tc.status || strings.Contains(w.Body.String(), "正文测试标记") {
				t.Fatalf("错误响应泄露内部信息：%d %s", w.Code, w.Body.String())
			}
		}
	}
}

func TestCredentialHitsHTTPValidation(t *testing.T) {
	store := &metadataReadStore{}
	h := ListIntegrationCredentialHits(&Dependencies{IntegrationRepo: store})
	since := time.Now().UTC().Truncate(time.Second).Add(-7 * 24 * time.Hour)
	until := since.Add(7 * 24 * time.Hour)
	for _, query := range []string{
		"", "key_id=", "key_id=bad%20id", "key_id=key-a&since=bad", "key_id=key-a&until=bad",
		"key_id=key-a&since=" + url.QueryEscape(until.Format(time.RFC3339Nano)) + "&until=" + url.QueryEscape(since.Format(time.RFC3339Nano)),
		"key_id=key-a&since=" + url.QueryEscape(since.Add(-time.Second).Format(time.RFC3339Nano)) + "&until=" + url.QueryEscape(until.Format(time.RFC3339Nano)),
		"key_id=key-a&since=" + url.QueryEscape(until.Format(time.RFC3339Nano)) + "&until=" + url.QueryEscape(until.Format(time.RFC3339Nano)),
		"key_id=key-a&cursor=bad", "key_id=key-a&key_id=key-b", "key_id=key-a&limit=0", "key_id=key-a&limit=201", "key_id=key-a&limit=bad",
	} {
		w := httptest.NewRecorder()
		h(w, policyHandlerRequest("GET", "/?"+query, "", "platform_connector"))
		if w.Code != 400 {
			t.Errorf("非法查询未拒绝：%s %d %s", query, w.Code, w.Body.String())
		}
	}
	if store.calls != 0 {
		t.Fatalf("非法查询到达存储层：%d", store.calls)
	}
	w := httptest.NewRecorder()
	h(w, policyHandlerRequest("GET", "/?key_id=key-a&since="+url.QueryEscape(since.Format(time.RFC3339Nano))+"&until="+url.QueryEscape(until.Format(time.RFC3339Nano))+"&limit=2", "", "platform_connector"))
	if w.Code != 200 || store.query.Limit != 2 || !store.query.Since.Equal(since) || !store.query.Until.Equal(until) {
		t.Fatalf("七天合法边界被拒绝：%d %s", w.Code, w.Body.String())
	}
	retention := GetIntegrationRetentionStatus(&Dependencies{IntegrationRepo: store})
	for _, query := range []string{"", "key_id=bad%20id", "key_id=key-a&key_id=key-b"} {
		w = httptest.NewRecorder()
		retention(w, policyHandlerRequest("GET", "/?"+query, "", "platform_connector"))
		if w.Code != 400 {
			t.Errorf("非法留存凭据未拒绝 %s：%d", query, w.Code)
		}
	}
}

func TestIntegrationMetadataCapabilities(t *testing.T) {
	w := httptest.NewRecorder()
	IntegrationCapabilities(nil)(w, policyHandlerRequest("GET", "/", "", "platform_connector"))
	var got struct {
		Capabilities map[string]struct {
			Enabled bool
			Route   string
		} `json:"capabilities"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	for capability, path := range map[string]string{"credential_hits": "credential-hits", "retention_status": "retention-status"} {
		if c := got.Capabilities[capability]; !c.Enabled || c.Route != "GET /admin/v1/integration/"+path {
			t.Errorf("未声明只读能力 %s：%+v", capability, c)
		}
	}
}

var _ http.HandlerFunc = ListIntegrationCredentialHits(nil)
