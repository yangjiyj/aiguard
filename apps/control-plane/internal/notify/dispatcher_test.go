package notify

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

type fakeChannelStore struct {
	byTenant map[string]map[string]*repository.NotifyChannel
}

func (f *fakeChannelStore) GetForTenant(_ context.Context, tenantID, id string) (*repository.NotifyChannel, error) {
	if ch, ok := f.byTenant[tenantID][id]; ok {
		return ch, nil
	}
	return nil, errors.New("no rows in result set")
}

func (f *fakeChannelStore) ListEnabled(_ context.Context, tenantID string) ([]*repository.NotifyChannel, error) {
	var out []*repository.NotifyChannel
	for _, ch := range f.byTenant[tenantID] {
		if ch.Enabled {
			out = append(out, ch)
		}
	}
	return out, nil
}

func TestSendTestMessageDeliversChineseTextEvenWhenDisabled(t *testing.T) {
	allowWebhookTestTarget(t)
	var got map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &got)
		_, _ = w.Write([]byte(`{"code":0}`))
	}))
	defer srv.Close()
	store := &fakeChannelStore{byTenant: map[string]map[string]*repository.NotifyChannel{
		"t1": {"nc_1": {ID: "nc_1", TenantID: "t1", Type: "feishu", Enabled: false,
			ConfigJSON: map[string]any{"webhook_url": srv.URL}}},
	}}
	d := &Dispatcher{repo: store}
	if err := d.SendTestMessage(context.Background(), "t1", "nc_1"); err != nil {
		t.Fatalf("SendTestMessage: %v", err)
	}
	content, _ := got["content"].(map[string]any)
	text, _ := content["text"].(string)
	if !strings.Contains(text, TestMessageText) {
		t.Fatalf("test message text missing: %q", text)
	}
}

func TestSendTestMessageIsTenantScoped(t *testing.T) {
	store := &fakeChannelStore{byTenant: map[string]map[string]*repository.NotifyChannel{
		"t1": {"nc_1": {ID: "nc_1", TenantID: "t1", Type: "feishu", ConfigJSON: map[string]any{"webhook_url": "https://example.com"}}},
	}}
	d := &Dispatcher{repo: store}
	if err := d.SendTestMessage(context.Background(), "t2", "nc_1"); err == nil {
		t.Fatal("cross-tenant channel must not be reachable")
	}
}

func TestDispatchContinuesAfterChannelFailure(t *testing.T) {
	allowWebhookTestTarget(t)
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		_, _ = w.Write([]byte(`{"errcode":0}`))
	}))
	defer srv.Close()
	store := &fakeChannelStore{byTenant: map[string]map[string]*repository.NotifyChannel{
		"t1": {
			"bad":  {ID: "bad", Type: "feishu", Enabled: true, ConfigJSON: map[string]any{}},
			"good": {ID: "good", Type: "wecom", Enabled: true, ConfigJSON: map[string]any{"webhook_url": srv.URL}},
		},
	}}
	d := &Dispatcher{repo: store}
	if err := d.Dispatch(context.Background(), "t1", "high", "t", nil); err == nil {
		t.Fatal("expected first error to be reported")
	}
	if hits != 1 {
		t.Fatalf("good channel must still be delivered, hits=%d", hits)
	}
}

func TestNotifyChannelJSONUsesSnakeCase(t *testing.T) {
	b, _ := json.Marshal(repository.NotifyChannel{ID: "nc_1", Type: "wecom", ConfigJSON: map[string]any{"key": "k"}})
	s := string(b)
	for _, want := range []string{`"id":"nc_1"`, `"type":"wecom"`, `"config_json":`, `"enabled":`} {
		if !strings.Contains(s, want) {
			t.Fatalf("json %s missing %s", s, want)
		}
	}
}
