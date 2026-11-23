package billing

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// 价格写入与审计在同一个事务里：价格提交了审计一定在；价格没写成审计也不能单独留下「已创建」。

func pgAuditCount(t *testing.T, db *pgxpool.Pool, tenantID, action string) int {
	t.Helper()
	var n int
	if err := db.QueryRow(context.Background(), `SELECT COUNT(*) FROM audit_operations WHERE tenant_id=$1 AND action_type=$2`, tenantID, action).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func pgAuditSpec(actor string) *PriceAuditSpec {
	return &PriceAuditSpec{
		ActorUserID: actor, IPAddress: "192.0.2.10",
		CreateAction: "billing.price.create",
		Detail: func(r PriceAuditRecord) map[string]any {
			detail := map[string]any{"tenant_id": r.Price.TenantID, "model_name": r.Price.ModelName, "version": r.Price.Version, "zero_price_confirmed": r.ZeroConfirmed}
			if r.Previous != nil {
				detail["old_version"] = r.Previous.Version
			}
			return detail
		},
	}
}

func TestSaveModelPriceWritesAuditInTheSameTransaction(t *testing.T) {
	store, db, tenantID, userID := setupBillingStoreTest(t)
	ctx := context.Background()
	t.Cleanup(func() {
		_, _ = db.Exec(context.Background(), `DELETE FROM audit_operations WHERE tenant_id=$1`, tenantID)
	})

	result, err := store.SaveModelPrice(ctx, pgSubmit(tenantID, "audit-tx", pgFull()), SavePriceOptions{Audit: pgAuditSpec(userID)})
	if err != nil || result.Unchanged || result.AuditID == "" {
		t.Fatalf("first save: %#v err=%v", result, err)
	}
	var action, target, actor, ip string
	if err := db.QueryRow(ctx, `SELECT action_type,target_id,COALESCE(user_id,''),COALESCE(ip_address,'') FROM audit_operations WHERE id=$1 AND tenant_id=$2`, result.AuditID, tenantID).Scan(&action, &target, &actor, &ip); err != nil {
		t.Fatalf("the audit row must exist with the returned id: %v", err)
	}
	if action != "billing.price.create" || target != result.Price.ID || actor != userID || ip != "192.0.2.10" {
		t.Fatalf("audit row = %s/%s/%s/%s", action, target, actor, ip)
	}
	if result.AuditDetail == nil || result.AuditDetail["model_name"] != "audit-tx" {
		t.Fatalf("the committed audit detail must be handed back for the audit chain: %#v", result.AuditDetail)
	}
}

func TestSaveModelPriceRollsBackThePriceWhenTheAuditCannotBeWritten(t *testing.T) {
	store, _, tenantID, _ := setupBillingStoreTest(t)
	ctx := context.Background()
	// user_id 外键指向不存在的用户 → 审计 INSERT 失败 → 价格不能留下。
	// 不会静默吞掉：调用方必须看到错误。
	_, err := store.SaveModelPrice(ctx, pgSubmit(tenantID, "audit-rollback", pgFull()), SavePriceOptions{Audit: pgAuditSpec("user-that-does-not-exist")})
	if err == nil {
		t.Fatal("a failed audit write must fail the whole price write")
	}
	if got := pgVersionCount(t, store, tenantID, "audit-rollback"); got != 0 {
		t.Fatalf("price must be rolled back with the audit, versions=%d", got)
	}
}

func TestSaveModelPriceWritesRejectionAuditInItsOwnTransaction(t *testing.T) {
	store, db, tenantID, userID := setupBillingStoreTest(t)
	ctx := context.Background()
	t.Cleanup(func() {
		_, _ = db.Exec(context.Background(), `DELETE FROM audit_operations WHERE tenant_id=$1`, tenantID)
	})
	pgSeed(t, store, tenantID, "audit-zero", pgFull())

	spec := pgAuditSpec(userID)
	spec.ZeroRejectedAction = "billing.price.zero_rejected"
	spec.RejectedDetail = func(rejected *ZeroPriceError) map[string]any {
		return map[string]any{"tenant_id": tenantID, "old_version": rejected.Previous.Version}
	}
	_, err := store.SaveModelPrice(ctx, pgSubmit(tenantID, "audit-zero", DirectPrice{}), SavePriceOptions{Audit: spec})
	var zeroErr *ZeroPriceError
	if !errors.As(err, &zeroErr) {
		t.Fatalf("err = %v, want *ZeroPriceError", err)
	}
	if zeroErr.AuditID == "" || pgAuditCount(t, db, tenantID, "billing.price.zero_rejected") != 1 {
		t.Fatalf("the refusal must be audited durably (id=%q)", zeroErr.AuditID)
	}
	if got := pgVersionCount(t, store, tenantID, "audit-zero"); got != 1 {
		t.Fatalf("a refused zeroing must not add a version, versions=%d", got)
	}
}

func TestSaveModelPriceRecordsNonCriticalAuditForUnchangedSubmissions(t *testing.T) {
	store, db, tenantID, userID := setupBillingStoreTest(t)
	ctx := context.Background()
	t.Cleanup(func() {
		_, _ = db.Exec(context.Background(), `DELETE FROM audit_operations WHERE tenant_id=$1`, tenantID)
	})
	pgSeed(t, store, tenantID, "audit-same", pgFull())

	spec := pgAuditSpec(userID)
	spec.UnchangedAction = "billing.price.unchanged"
	result, err := store.SaveModelPrice(ctx, pgSubmit(tenantID, "audit-same", pgFull()), SavePriceOptions{Audit: spec})
	if err != nil || !result.Unchanged || result.AuditID == "" {
		t.Fatalf("unchanged save: %#v err=%v", result, err)
	}
	if pgAuditCount(t, db, tenantID, "billing.price.unchanged") != 1 || pgAuditCount(t, db, tenantID, "billing.price.create") != 0 {
		t.Fatal("an unchanged submission leaves exactly one billing.price.unchanged record and no create record")
	}
}

func TestSaveModelPriceWithoutAuditSpecWritesNoAudit(t *testing.T) {
	store, db, tenantID, _ := setupBillingStoreTest(t)
	if _, err := store.SaveModelPrice(context.Background(), pgSubmit(tenantID, "audit-none", pgFull()), SavePriceOptions{}); err != nil {
		t.Fatal(err)
	}
	if n := pgAuditCount(t, db, tenantID, "billing.price.create"); n != 0 {
		t.Fatalf("no audit spec means no audit row, got %d", n)
	}
	_ = time.Now
}
