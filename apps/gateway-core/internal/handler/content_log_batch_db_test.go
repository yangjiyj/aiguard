package handler

import (
	"fmt"
	"reflect"
	"testing"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
)

// 批量写入与逐条写入落库结果必须逐行一致（角色、内容、tokens、message_index、会话、环境、用户、顺序），
// 父请求行只有一行，created_at 严格递增。
func TestWriteContentLogsBatchMatchesPerMessageOnPostgres(t *testing.T) {
	db, ctx, tenantID, projectID, providerID, modelID := setupAuditWriterNullUserFixture(t)
	w := &RealAuditWriter{db: &realDBExecutor{pool: db}}
	mk := func(rid string) *modelrouter.RequestEnvelope {
		return &modelrouter.RequestEnvelope{RequestID: rid, TenantID: tenantID, ProjectID: projectID, ClientID: "k",
			ProviderID: providerID, ModelID: modelID, SessionID: "sess-eq", EndpointType: "chat", EnvironmentScope: "customer"}
	}
	entries := make([]ContentLogEntry, 0, 30)
	for i := 0; i < 30; i++ {
		role := []string{"system", "user", "assistant", "tool"}[i%4]
		entries = append(entries, ContentLogEntry{Role: role, Content: fmt.Sprintf("消息 %d %s", i, role), MessageIndex: i * 2})
	}
	single, batched := mk("req_eq_single_"+tenantID), mk("req_eq_batch_"+tenantID)
	for _, e := range entries {
		w.WriteContentLogAnchored(ctx, single, e.Role, e.Content, e.Tokens, e.MessageIndex)
	}
	w.WriteContentLogsBatch(ctx, batched, entries)

	type row struct {
		Role, Content, Session, Scope string
		Tokens, Index                 int
		HasUser                       bool
	}
	load := func(requestID string) ([]row, bool) {
		rows, err := db.Query(ctx, `SELECT cl.role, cl.content, COALESCE(cl.session_id,''), cl.environment_scope, COALESCE(cl.tokens,0), COALESCE(cl.message_index,-1), cl.user_id IS NOT NULL, cl.created_at
			FROM content_logs cl JOIN request_logs rl ON rl.id = cl.request_id
			WHERE rl.tenant_id=$1 AND rl.request_id=$2 ORDER BY cl.created_at, cl.id`, tenantID, requestID)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		var out []row
		var last any
		increasing := true
		for rows.Next() {
			var r row
			var created any
			if err := rows.Scan(&r.Role, &r.Content, &r.Session, &r.Scope, &r.Tokens, &r.Index, &r.HasUser, &created); err != nil {
				t.Fatal(err)
			}
			if last != nil && fmt.Sprint(created) <= fmt.Sprint(last) {
				increasing = false
			}
			last = created
			out = append(out, r)
		}
		return out, increasing
	}
	a, _ := load(single.RequestID)
	b, increasing := load(batched.RequestID)
	if len(b) != len(entries) {
		t.Fatalf("批量应写入 %d 条，实际 %d", len(entries), len(b))
	}
	if !reflect.DeepEqual(a, b) {
		t.Fatalf("批量与逐条落库结果不一致\n逐条=%v\n批量=%v", a, b)
	}
	if !increasing {
		t.Fatal("批量写入的 created_at 必须严格递增，保持消息顺序")
	}
	var parents int
	if err := db.QueryRow(ctx, `SELECT COUNT(*) FROM request_logs WHERE tenant_id=$1 AND request_id=$2`, tenantID, batched.RequestID).Scan(&parents); err != nil || parents != 1 {
		t.Fatalf("父请求行应只有 1 行：%d %v", parents, err)
	}
}
