package handler

import (
	"context"
	"testing"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
)

// 2026-11-20 客户现场：Claude Code 走 API 直连没有会话 ID，留证会话退回到请求编号，
// 同一段被拦的原文每次重试都算“新会话”，171 次重试存了 171 份密文，同会话去重从未生效。
// 没有会话 ID 时改用会话归组键（ConversationKey）去重；两者都没有才退回请求编号。
func TestRawEvidenceDedupFallsBackToConversationKey(t *testing.T) {
	setRawEvidenceTestKey(t)
	db := &blockingRawEvidenceDB{}
	w := &RealAuditWriter{db: db}
	text := "Security gateway blocks any tool call containing the marker"
	for i, id := range []string{"req-a", "req-b", "req-c"} {
		env := &modelrouter.RequestEnvelope{RequestID: id, TenantID: "tenant-async", UserID: "u1", ConversationKey: "conv-claude-1"}
		w.WriteRawEvidence(context.Background(), env, RawEvidenceRecord{Direction: rawEvidenceInput, Role: "user", Index: i, Disposition: rawEvidenceBlocked, Text: text})
		w.flushRawEvidence()
	}
	if db.full != 1 || db.ref != 2 {
		t.Fatalf("same conversation without session id: full=%d ref=%d want 1 full + 2 references", db.full, db.ref)
	}
	if got := db.refArgs[0][2]; got != "conv:conv-claude-1" {
		t.Fatalf("reference session = %v, want conv:conv-claude-1", got)
	}
	// 另一个会话归组键不共用。
	w.WriteRawEvidence(context.Background(), &modelrouter.RequestEnvelope{RequestID: "req-d", TenantID: "tenant-async", UserID: "u1", ConversationKey: "conv-other"},
		RawEvidenceRecord{Direction: rawEvidenceInput, Role: "user", Disposition: rawEvidenceBlocked, Text: text})
	// 两者都没有：照旧按请求编号，不跨请求合并。
	w.WriteRawEvidence(context.Background(), &modelrouter.RequestEnvelope{RequestID: "req-e", TenantID: "tenant-async", UserID: "u1"},
		RawEvidenceRecord{Direction: rawEvidenceInput, Role: "user", Disposition: rawEvidenceBlocked, Text: text})
	w.flushRawEvidence()
	if db.full != 3 || db.ref != 2 {
		t.Fatalf("full=%d ref=%d want 3 full + 2 references", db.full, db.ref)
	}
}

func TestRawEvidenceSessionPrefersExplicitSession(t *testing.T) {
	env := &modelrouter.RequestEnvelope{RequestID: "req-1", SessionID: "sess-1", ConversationKey: "conv-1"}
	if got := rawEvidenceSessionID(env); got != "sess-1" {
		t.Fatalf("got %q want sess-1", got)
	}
}
