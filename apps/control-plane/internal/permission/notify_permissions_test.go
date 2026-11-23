package permission

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// 发送测试消息会真实外发，与渠道写操作同级：notify_channels:write + 系统管理员职责。
func TestNotifyChannelTestRouteUsesWritePermissionAndSystemSoD(t *testing.T) {
	got := Resolve(httptest.NewRequest(http.MethodPost, "/admin/v1/notify-channels/nc_abc123/test", nil))
	if got.RequirePlatformAdmin || got.Resource != "notify_channels" || got.Action != "write" || got.ScopeType != "tenant" {
		t.Fatalf("resolved to %+v, want notify_channels:write tenant", got)
	}
	if c := sodRouteTable["POST /admin/v1/notify-channels/{id}/test"]; c != SoDSystem {
		t.Fatalf("sod class=%q want %q", c, SoDSystem)
	}
}
