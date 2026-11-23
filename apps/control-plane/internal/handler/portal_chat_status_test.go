package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

type failingStatusSystemRepo struct{ *consoleTestSystemRepo }

func (failingStatusSystemRepo) GetBool(context.Context, string) (bool, error) {
	return false, errors.New("sorry, too many clients already")
}
func (failingStatusSystemRepo) Get(context.Context, string) (*repository.SystemSetting, error) {
	return nil, errors.New("sorry, too many clients already")
}

// 客户现场回归：数据库连接打满时，chat-portal-status 把读取失败答成 enabled=false，
// 门户据此整站显示「门户未启用」。读取失败必须返回 503，让门户区分「真关了」和「读不到」。
func TestPortalChatPortalStatusReadFailureIsServiceUnavailable(t *testing.T) {
	deps := &Dependencies{SystemRepo: failingStatusSystemRepo{newConsoleTestSystemRepo()}}
	rec := httptest.NewRecorder()
	GetPortalChatPortalStatus(deps).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/admin/v1/portal-integration/system/chat-portal-status", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("读取失败应返回 503，得到 %d %s", rec.Code, rec.Body.String())
	}
	var body map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if _, ok := body["enabled"]; ok {
		t.Fatalf("读取失败时不得给出 enabled 结论：%s", rec.Body.String())
	}
}

func TestPortalChatPortalStatusReportsStoredValue(t *testing.T) {
	for _, tc := range []struct {
		stored string
		want   bool
	}{{"true", true}, {"false", false}, {"", false}} {
		system := newConsoleTestSystemRepo()
		if tc.stored != "" {
			system.values["chat_portal_enabled"] = tc.stored
		}
		rec := httptest.NewRecorder()
		GetPortalChatPortalStatus(&Dependencies{SystemRepo: system}).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/x", nil))
		var body struct {
			Enabled bool `json:"enabled"`
		}
		if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &body) != nil || body.Enabled != tc.want {
			t.Fatalf("stored=%q status=%d body=%s want enabled=%v", tc.stored, rec.Code, rec.Body.String(), tc.want)
		}
	}
}

func (repo failingStatusSystemRepo) GetByKeys(ctx context.Context, keys []string) ([]*repository.SystemSetting, error) {
	return systemSettingsByKeysVia(ctx, repo.Get, keys)
}
