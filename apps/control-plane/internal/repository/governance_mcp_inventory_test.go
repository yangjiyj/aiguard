package repository

import (
	"testing"
	"time"
)

func TestToolGovernanceDirectMCPInventoryRequiresAuthenticatedProtocolMetadata(t *testing.T) {
	db, ctx := toolGovernanceDB(t)
	now := time.Now().UTC()
	_, err := db.Exec(ctx, `INSERT INTO tool_call_logs(id,tenant_id,tool_name,tool_type,event_kind,provenance,protocol,created_at) VALUES
	 ('direct','a','demo__read','mcp','invocation_proposed','mcp_gateway','mcp',$1),
	 ('declared','a','claimed__read','mcp','invocation_proposed','untrusted','chat_completions',$1)`, now.Add(-time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	items, _, err := NewToolCallLogRepository(db).GetObservedTools(ctx, "a", now.Add(-time.Hour*24), now)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 2 {
		t.Fatalf("items=%+v", items)
	}
	for _, item := range items {
		if item.MCPGatewayObserved != (item.ToolName == "demo__read") {
			t.Fatalf("untrusted classification treated as protocol fact: %+v", item)
		}
	}
}
