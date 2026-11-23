package repository

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/yangjiyj/aiguard/packages/shared-go/protection"
)

// setupProtectionSettingsPGTest 连接已迁移（含迁移 999）的真实 Postgres。未设置
// PROTECTION_SETTINGS_TEST_DATABASE_URL 时跳过；库名不像一次性测试库时拒绝运行。
func setupProtectionSettingsPGTest(t *testing.T) (*pgxpool.Pool, *ProtectionSettingsRepository, func() string) {
	t.Helper()
	dsn := strings.TrimSpace(os.Getenv("PROTECTION_SETTINGS_TEST_DATABASE_URL"))
	if dsn == "" {
		t.Skip("PROTECTION_SETTINGS_TEST_DATABASE_URL is not set")
	}
	ctx := context.Background()
	db, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	var name string
	if err := db.QueryRow(ctx, `SELECT current_database()`).Scan(&name); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(name, "test") {
		t.Fatalf("refusing non-test database %q", name)
	}
	newTenant := func() string {
		suffix := make([]byte, 6)
		if _, err := rand.Read(suffix); err != nil {
			t.Fatal(err)
		}
		id := "prot-" + hex.EncodeToString(suffix)
		if _, err := db.Exec(ctx, `INSERT INTO tenants (id, name, is_test) VALUES ($1, $2, true)`, id, id); err != nil {
			t.Fatalf("create tenant: %v", err)
		}
		t.Cleanup(func() {
			if _, err := db.Exec(context.Background(), `DELETE FROM tenants WHERE id = $1`, id); err != nil {
				t.Errorf("cleanup tenant %s: %v", id, err)
			}
		})
		return id
	}
	return db, NewProtectionSettingsRepository(db), newTenant
}

func TestProtectionSettingsPGUpsertReturnsOnlyExistingRowsAsBefore(t *testing.T) {
	_, repo, newTenant := setupProtectionSettingsPGTest(t)
	ctx := context.Background()
	tenant := newTenant()

	before, err := repo.Upsert(ctx, tenant, "u1", map[string]protection.Setting{
		"agent.ssh_private_key": {Action: protection.ActionBlock},
	})
	if err != nil || len(before) != 0 {
		t.Fatalf("first upsert: before=%v err=%v", before, err)
	}
	before, err = repo.Upsert(ctx, tenant, "u2", map[string]protection.Setting{
		"agent.ssh_private_key": {Action: protection.ActionRecord},
		"agent.cloud_metadata":  {Action: protection.ActionConfirm},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(before) != 1 || before["agent.ssh_private_key"].Action != protection.ActionBlock {
		t.Fatalf("before must hold only the pre-existing row: %v", before)
	}
	rows, err := repo.StoredRows(ctx, tenant)
	if err != nil || len(rows) != 2 {
		t.Fatalf("rows=%v err=%v", rows, err)
	}
	for _, row := range rows {
		if row.UpdatedBy != "u2" || row.UpdatedAt == nil {
			t.Fatalf("updated_by/at not refreshed: %+v", row)
		}
	}
}

func TestProtectionSettingsPGEmptyParamsAreStoredAsAnEmptyObject(t *testing.T) {
	db, repo, newTenant := setupProtectionSettingsPGTest(t)
	ctx := context.Background()
	tenant := newTenant()
	if _, err := repo.Upsert(ctx, tenant, "u1", map[string]protection.Setting{
		"agent.ssh_private_key": {Action: protection.ActionBlock},                           // nil params
		"agent.cloud_metadata":  {Action: protection.ActionBlock, Params: map[string]any{}}, // empty params
	}); err != nil {
		t.Fatal(err)
	}
	var stored []string
	rs, err := db.Query(ctx, `SELECT params_json::text FROM protection_settings WHERE tenant_id=$1`, tenant)
	if err != nil {
		t.Fatal(err)
	}
	defer rs.Close()
	for rs.Next() {
		var text string
		if err := rs.Scan(&text); err != nil {
			t.Fatal(err)
		}
		stored = append(stored, text)
	}
	if len(stored) != 2 || stored[0] != "{}" || stored[1] != "{}" {
		t.Fatalf("params_json=%v", stored)
	}
	settings, err := repo.Settings(ctx, tenant)
	if err != nil || settings["agent.ssh_private_key"].Params == nil {
		t.Fatalf("settings=%v err=%v", settings, err)
	}
}

func TestProtectionSettingsPGReadDropsKeysRemovedFromTheRegistryAndKeepsRegistryOrder(t *testing.T) {
	db, repo, newTenant := setupProtectionSettingsPGTest(t)
	ctx := context.Background()
	tenant := newTenant()
	if _, err := db.Exec(ctx, `INSERT INTO protection_settings (tenant_id, item_key, action) VALUES ($1,'agent.removed_in_a_later_version','block')`, tenant); err != nil {
		t.Fatal(err)
	}
	// 按与注册表相反的顺序写入，读出必须仍按注册表顺序。
	all := protection.All()
	in := map[string]protection.Setting{}
	for i := len(all) - 1; i >= 0 && len(in) < 4; i-- {
		if all[i].Allows(protection.ActionBlock) && all[i].Group != protection.GroupAgentRestricted {
			in[all[i].Key] = protection.Setting{Action: protection.ActionBlock, Params: map[string]any{}}
		}
	}
	if _, err := repo.Upsert(ctx, tenant, "u1", in); err != nil {
		t.Fatal(err)
	}
	rows, err := repo.StoredRows(ctx, tenant)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != len(in) {
		t.Fatalf("removed key must be dropped: rows=%v", rows)
	}
	last := -1
	for _, row := range rows {
		pos := -1
		for i, item := range all {
			if item.Key == row.Key {
				pos = i
			}
		}
		if pos <= last {
			t.Fatalf("rows not in registry order: %v", rows)
		}
		last = pos
	}
	settings, err := repo.Settings(ctx, tenant)
	if err != nil || len(settings) != len(in) {
		t.Fatalf("settings=%v err=%v", settings, err)
	}
	if _, ok := settings["agent.removed_in_a_later_version"]; ok {
		t.Fatal("removed key leaked into settings")
	}
}

func TestProtectionSettingsPGCheckConstraintRejectsAnIllegalAction(t *testing.T) {
	db, repo, newTenant := setupProtectionSettingsPGTest(t)
	ctx := context.Background()
	tenant := newTenant()
	if _, err := db.Exec(ctx, `INSERT INTO protection_settings (tenant_id, item_key, action) VALUES ($1,'agent.ssh_private_key','deny')`, tenant); err == nil {
		t.Fatal("CHECK must reject an illegal action on direct insert")
	}
	if _, err := repo.Upsert(ctx, tenant, "u1", map[string]protection.Setting{
		"agent.ssh_private_key": {Action: "deny"},
	}); err == nil {
		t.Fatal("Upsert must fail on an illegal action")
	}
	if rows, err := repo.StoredRows(ctx, tenant); err != nil || len(rows) != 0 {
		t.Fatalf("a failed upsert must not leave rows: %v %v", rows, err)
	}
}

func TestProtectionSettingsPGTenantsAreIsolated(t *testing.T) {
	_, repo, newTenant := setupProtectionSettingsPGTest(t)
	ctx := context.Background()
	a, b := newTenant(), newTenant()
	if _, err := repo.Upsert(ctx, a, "ua", map[string]protection.Setting{"agent.ssh_private_key": {Action: protection.ActionBlock}}); err != nil {
		t.Fatal(err)
	}
	if rows, err := repo.StoredRows(ctx, b); err != nil || len(rows) != 0 {
		t.Fatalf("tenant b must not see tenant a rows: %v %v", rows, err)
	}
	before, err := repo.Upsert(ctx, b, "ub", map[string]protection.Setting{"agent.ssh_private_key": {Action: protection.ActionRecord}})
	if err != nil || len(before) != 0 {
		t.Fatalf("tenant b before=%v err=%v", before, err)
	}
	settings, err := repo.Settings(ctx, a)
	if err != nil || settings["agent.ssh_private_key"].Action != protection.ActionBlock {
		t.Fatalf("tenant a changed by tenant b: %v %v", settings, err)
	}
}

// 两个事务同时首次写同一个键：按租户串行化后，恰好一方旧值为空，另一方旧值等于前一方写入的值。
func TestProtectionSettingsPGConcurrentFirstWritesAreSerialised(t *testing.T) {
	_, repo, newTenant := setupProtectionSettingsPGTest(t)
	ctx := context.Background()
	const key = "agent.ssh_private_key"
	for round := 0; round < 20; round++ {
		tenant := newTenant()
		actions := [2]protection.Action{protection.ActionBlock, protection.ActionRecord}
		var before [2]map[string]protection.Setting
		var errs [2]error
		start := make(chan struct{})
		var wg sync.WaitGroup
		for i := range actions {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				<-start
				before[i], errs[i] = repo.Upsert(ctx, tenant, "u", map[string]protection.Setting{key: {Action: actions[i]}})
			}(i)
		}
		close(start)
		wg.Wait()
		if errs[0] != nil || errs[1] != nil {
			t.Fatalf("round %d: errs=%v", round, errs)
		}
		empty := 0
		for i := range before {
			other := actions[1-i]
			switch prev, ok := before[i][key]; {
			case !ok:
				empty++
			case prev.Action != other:
				t.Fatalf("round %d: writer %d saw %q, want the other writer's %q", round, i, prev.Action, other)
			}
		}
		if empty != 1 {
			t.Fatalf("round %d: exactly one writer must see no previous value, got %d (before=%v)", round, empty, before)
		}
		settings, err := repo.Settings(ctx, tenant)
		if err != nil || len(settings) != 1 {
			t.Fatalf("round %d: settings=%v err=%v", round, settings, err)
		}
	}
}
