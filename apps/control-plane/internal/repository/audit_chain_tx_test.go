package repository

import (
	"context"
	"fmt"
	"testing"
	"time"
)

// 事务内追加：回滚时审计链记录一并消失；提交后整条链校验通过（与独立事务的 Append 同一套哈希/签名）。
func TestAuditChainAppendTxRollsBackWithCallerTransaction(t *testing.T) {
	db, repo := setupAuditChainTestDB(t)
	ctx := context.Background()
	tenant := fmt.Sprintf("tenant_actx_%d", time.Now().UnixNano())
	before, err := repo.Stats(ctx)
	if err != nil {
		t.Fatal(err)
	}

	tx, err := db.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err = repo.AppendTx(ctx, tx, tenant, "audit_op", tenant+"-rolled-back", map[string]any{"k": 1}); err != nil {
		t.Fatal(err)
	}
	if err = tx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	var n int
	if err = db.QueryRow(ctx, `SELECT count(*) FROM audit_chain WHERE tenant_id=$1`, tenant).Scan(&n); err != nil || n != 0 {
		t.Fatalf("回滚后不应有审计链记录：%d %v", n, err)
	}

	tx, err = db.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if err = repo.AppendTx(ctx, tx, tenant, "audit_op", fmt.Sprintf("%s-%d", tenant, i), map[string]any{"i": i, "action_type": "billing.currency.switch"}); err != nil {
			t.Fatal(err)
		}
	}
	if err = tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err = db.QueryRow(ctx, `SELECT count(*) FROM audit_chain WHERE tenant_id=$1`, tenant).Scan(&n); err != nil || n != 2 {
		t.Fatalf("提交后应有 2 条：%d %v", n, err)
	}
	// 与独立事务 Append 交错后整条链仍然连续可校验。
	if err = repo.Append(ctx, tenant, "audit_op", tenant+"-after", map[string]any{"after": true}); err != nil {
		t.Fatal(err)
	}
	after, err := repo.Stats(ctx)
	if err != nil {
		t.Fatal(err)
	}
	result, err := repo.Verify(ctx, before.MaxSeq+1, after.MaxSeq)
	if err != nil || !result.OK {
		t.Fatalf("链校验失败：%+v %v", result, err)
	}
}
