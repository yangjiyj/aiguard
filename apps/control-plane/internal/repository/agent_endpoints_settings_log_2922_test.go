package repository

import (
	"bytes"
	"context"
	"log"
	"os"
	"strings"
	"testing"

	"github.com/yangjiyj/aiguard/packages/shared-go/protection"
)

// 复审次要项：端侧防护项的 params_json 解析失败要记日志（参数按注册表默认值，动作照常生效）。
func TestEndpointProtectionSettings2922LogsUnreadableParamsDB(t *testing.T) {
	_, db := endpointModeTestRepo(t, `
		INSERT INTO protection_settings(tenant_id,item_key,action,params_json) VALUES ('tenant-a','endpoint.rule.builtin_env_files','block','[1,2]');
	`)
	var buf bytes.Buffer
	log.SetOutput(&buf)
	defer log.SetOutput(os.Stderr)
	settings, err := endpointProtectionSettings(context.Background(), db, "tenant-a")
	if err != nil {
		t.Fatal(err)
	}
	if settings.ActionFor("endpoint.rule.builtin_env_files") != protection.ActionBlock {
		t.Fatalf("the action still applies: %+v", settings)
	}
	if !strings.Contains(buf.String(), "endpoint.rule.builtin_env_files") || !strings.Contains(buf.String(), "tenant-a") {
		t.Fatalf("an unreadable params_json must be logged, got %q", buf.String())
	}
}
