package handler

import (
	"context"
	"errors"
	"testing"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

// 读防护项设置失败时不能按默认（告警放行）写准入结果，否则会覆盖已配置的阻断。
func TestRunMCPServerSyncFailsWithoutWriteWhenProtectionSettingsUnreadable(t *testing.T) {
	supply := &ws1FakeSupplyRepo{}
	deps := &Dependencies{MCPSupplyChainRepo: supply, ProtectionSettingsStore: &fakeProtectionStore{readErr: errors.New("db down")}}
	server := &repository.MCPServer{ID: "srv-1", TenantID: "tenant-a", Name: "files", ServerURL: "https://mcp.example/rpc", Status: "active", Capabilities: map[string]interface{}{}}
	fetch := func(context.Context, *repository.MCPServer) ([]mcpManifestTool, error) { return ws1Manifest, nil }
	scan := func(context.Context, string, string, string) ([]string, error) { return nil, nil }

	if _, err := runMCPServerSync(context.Background(), deps, "tenant-a", server, fetch, scan); err == nil {
		t.Fatal("unreadable protection settings must fail the sync")
	}
	if len(supply.inputs) != 0 {
		t.Fatalf("sync must not write admission results with default protections, wrote %d", len(supply.inputs))
	}
}

func TestMCPTenantProtectionsReadErrorAndMissingStore(t *testing.T) {
	if _, err := mcpTenantProtections(context.Background(), &Dependencies{ProtectionSettingsStore: &fakeProtectionStore{readErr: errors.New("db down")}}, "tenant-a"); err == nil {
		t.Fatal("read error must be returned")
	}
	settings, err := mcpTenantProtections(context.Background(), &Dependencies{}, "tenant-a")
	if err != nil || settings != nil {
		t.Fatalf("missing store keeps defaults: settings=%v err=%v", settings, err)
	}
}
