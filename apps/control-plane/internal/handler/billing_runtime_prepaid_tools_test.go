package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

// prepaidToolsSystemRepo 只回答 billing_prepaid_tools_visible 一个开关。
type prepaidToolsSystemRepo struct {
	MockSystemRepo
	visible string
}

func (r *prepaidToolsSystemRepo) Get(ctx context.Context, key string) (*repository.SystemSetting, error) {
	if key == BillingPrepaidToolsVisibleSettingKey && r.visible != "" {
		return &repository.SystemSetting{Key: key, Value: r.visible}, nil
	}
	return nil, nil
}

func (r *prepaidToolsSystemRepo) GetBool(ctx context.Context, key string) (bool, error) {
	setting, _ := r.Get(ctx, key)
	return setting != nil && (setting.Value == "true" || setting.Value == "1"), nil
}

func runtimeBody(t *testing.T, deps *Dependencies) map[string]any {
	t.Helper()
	req := withUserContext(httptest.NewRequest(http.MethodGet, "/admin/v1/billing/runtime", nil), &repository.User{ID: "admin", TenantID: "tenant_default", Role: "platform_admin"})
	rec := httptest.NewRecorder()
	GetBillingRuntime(deps)(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var body struct {
		Data map[string]any `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	return body.Data
}

// 预付费账户（高级）默认隐藏：只有 BILLING_MODE=prepaid 或系统设置显式打开才显示。
func TestBillingRuntimeReportsPrepaidToolsVisibility(t *testing.T) {
	cases := []struct {
		name, mode, setting string
		want                bool
	}{
		{name: "metering 默认隐藏", mode: "metering", want: false},
		{name: "off 默认隐藏", mode: "off", want: false},
		{name: "prepaid 恒显示", mode: "prepaid", want: true},
		{name: "metering 但系统设置打开", mode: "metering", setting: "true", want: true},
		{name: "系统设置显式关闭", mode: "metering", setting: "false", want: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			data := runtimeBody(t, &Dependencies{BillingMode: tc.mode, SystemRepo: &prepaidToolsSystemRepo{visible: tc.setting}})
			if got, _ := data["prepaid_tools_visible"].(bool); got != tc.want {
				t.Fatalf("prepaid_tools_visible=%v want %v (data=%v)", data["prepaid_tools_visible"], tc.want, data)
			}
			if data["mode"] == nil {
				t.Fatal("mode must still be reported")
			}
		})
	}
}

// 没有系统设置仓库时（极简部署/测试）不报错，按 BILLING_MODE 判定。
func TestBillingRuntimePrepaidToolsWithoutSystemRepo(t *testing.T) {
	data := runtimeBody(t, &Dependencies{BillingMode: "metering"})
	if got, _ := data["prepaid_tools_visible"].(bool); got {
		t.Fatal("metering without system repo must hide prepaid tools")
	}
}

func (r *prepaidToolsSystemRepo) GetByKeys(ctx context.Context, keys []string) ([]*repository.SystemSetting, error) {
	return systemSettingsByKeysVia(ctx, r.Get, keys)
}
