package handler

import (
	"context"
	"fmt"
	"testing"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
)

// 客户现场回归：父请求行改为 ON CONFLICT DO NOTHING + 回查 id 后，
// 一个请求逐条写入的消息必须全部落库、全部挂到同一个父请求行上，顺序不变；
// 父请求行先由 EnsureRequestLog 建好、内容后写时也必须挂得上。
// 写入次数的下降由 deploy/tests 下的测量脚本在独立库上量化（共享测试库有别的触发器写入）。
func TestWriteContentLogDoesNotRewriteExistingParentRequestLog(t *testing.T) {
	db, ctx, tenantID, projectID, providerID, modelID := setupAuditWriterNullUserFixture(t)
	w := &RealAuditWriter{db: &realDBExecutor{pool: db}}
	envelope := &modelrouter.RequestEnvelope{
		RequestID: "req_clparent_" + tenantID, TenantID: tenantID, ProjectID: projectID,
		ClientID: "key_clparent", ProviderID: providerID, ModelID: modelID,
		SessionID: "sess_clparent", EndpointType: "chat",
	}
	const messages = 30
	for i := 0; i < messages; i++ {
		role := "user"
		if i%2 == 1 {
			role = "assistant"
		}
		w.WriteContentLogAnchored(ctx, envelope, role, fmt.Sprintf("第 %d 条消息", i), 0, i)
	}

	var parents int64
	var parentID string
	if err := db.QueryRow(ctx, `SELECT COUNT(*), MIN(id) FROM request_logs WHERE tenant_id=$1 AND request_id=$2`, tenantID, envelope.RequestID).Scan(&parents, &parentID); err != nil {
		t.Fatal(err)
	}
	if parents != 1 {
		t.Fatalf("父请求行应只有 1 行，得到 %d", parents)
	}
	var stored, linked int64
	if err := db.QueryRow(ctx, `SELECT COUNT(*), COUNT(*) FILTER (WHERE request_id=$3) FROM content_logs WHERE tenant_id=$1 AND session_id=$2`, tenantID, "sess_clparent", parentID).Scan(&stored, &linked); err != nil {
		t.Fatal(err)
	}
	if stored != messages || linked != messages {
		t.Fatalf("消息应全部落库并挂到同一父行：stored=%d linked=%d want %d", stored, linked, messages)
	}
	var indexes []int
	rows, err := db.Query(context.Background(), `SELECT message_index FROM content_logs WHERE tenant_id=$1 AND request_id=$2 ORDER BY message_index`, tenantID, parentID)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var idx int
		if err := rows.Scan(&idx); err != nil {
			t.Fatal(err)
		}
		indexes = append(indexes, idx)
	}
	for i, idx := range indexes {
		if idx != i {
			t.Fatalf("message_index 应保持 0..%d 连续，第 %d 个是 %d", messages-1, i, idx)
		}
	}

	// 父行已由 EnsureRequestLog 先建好：后写的内容也要挂到这一行，而不是丢失或另建。
	pre := *envelope
	pre.RequestID = envelope.RequestID + "_pre"
	pre.SessionID = "sess_clparent_pre"
	w.EnsureRequestLog(ctx, &pre)
	w.WriteContentLogAnchored(ctx, &pre, "user", "先建父行再写内容", 0, 0)
	var preParent string
	var preLinked int64
	if err := db.QueryRow(ctx, `SELECT rl.id, (SELECT COUNT(*) FROM content_logs cl WHERE cl.request_id=rl.id) FROM request_logs rl WHERE rl.tenant_id=$1 AND rl.request_id=$2`, tenantID, pre.RequestID).Scan(&preParent, &preLinked); err != nil {
		t.Fatal(err)
	}
	if preLinked != 1 {
		t.Fatalf("父行已存在时内容应挂到该行：linked=%d", preLinked)
	}
}
