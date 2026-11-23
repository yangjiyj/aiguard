package modelrouter

import (
	"context"
	"errors"
	"fmt"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// resolveFixture 在专用测试库里造一个独立租户：每个用例唯一前缀、结束即清理，
// 不碰其他租户与其他库。
type resolveFixture struct {
	t      *testing.T
	db     *pgxpool.Pool
	tenant string
	n      int
}

func newResolveFixture(t *testing.T) *resolveFixture {
	t.Helper()
	dsn := os.Getenv("CONTENT_LOGS_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("CONTENT_LOGS_TEST_DATABASE_URL not set; skipping DB test")
	}
	ctx := context.Background()
	db, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	f := &resolveFixture{t: t, db: db, tenant: fmt.Sprintf("mres_%d", time.Now().UnixNano())}
	f.exec(`INSERT INTO tenants(id,name,edition,status,is_test) VALUES($1::varchar,$1::varchar,'enterprise','active',true)`, f.tenant)
	t.Cleanup(func() {
		for _, sql := range []string{
			`DELETE FROM models WHERE provider_id IN (SELECT id FROM providers WHERE tenant_id=$1::varchar)`,
			`DELETE FROM provider_credentials WHERE provider_id IN (SELECT id FROM providers WHERE tenant_id=$1::varchar)`,
			`DELETE FROM providers WHERE tenant_id=$1::varchar`,
			`DELETE FROM tenants WHERE id=$1::varchar`,
		} {
			if _, err := db.Exec(context.Background(), sql, f.tenant); err != nil {
				t.Errorf("cleanup: %v", err)
			}
		}
	})
	return f
}

func (f *resolveFixture) exec(sql string, args ...any) {
	f.t.Helper()
	if _, err := f.db.Exec(context.Background(), sql, args...); err != nil {
		f.t.Fatal(err)
	}
}

// model 建一个模型。providerStatus / modelStatus 分别是供应商与模型的状态。
func (f *resolveFixture) model(name, providerStatus, modelStatus string) string {
	f.t.Helper()
	f.n++
	pid := fmt.Sprintf("%s_p%d", f.tenant, f.n)
	mid := fmt.Sprintf("%s_m%d", f.tenant, f.n)
	f.exec(`INSERT INTO providers(id,tenant_id,name,provider_type,base_url,auth_mode,status) VALUES($1,$2,$1,'anthropic','https://fixture.invalid','api_key',$3)`, pid, f.tenant, providerStatus)
	f.exec(`INSERT INTO models(id,provider_id,model_name,status) VALUES($1,$2,$3,$4)`, mid, pid, name, modelStatus)
	return mid
}

func (f *resolveFixture) resolve(name string) (*ModelRecord, error) {
	return NewModelRouter(f.db).ResolveModelWithDB(context.Background(), f.tenant, name)
}

func TestResolveModelExactNameIsUnchanged(t *testing.T) {
	f := newResolveFixture(t)
	f.model("anthropic/claude-opus-4-8", "active", "active")
	record, err := f.resolve("anthropic/claude-opus-4-8")
	if err != nil || record.ModelName != "anthropic/claude-opus-4-8" || record.AliasFrom != "" {
		t.Fatalf("exact hit changed: record=%+v err=%v", record, err)
	}
}

func TestResolveModelUnknownNameIsModelNotFoundNotAnInfrastructureError(t *testing.T) {
	f := newResolveFixture(t)
	f.model("anthropic/claude-opus-4-8", "active", "active")
	_, err := f.resolve("claude-opus-9-9")
	var miss *ModelNotFoundError
	if !errors.Is(err, ErrModelNotFound) || !errors.As(err, &miss) || miss.Reason != ModelMissNotFound {
		t.Fatalf("want not_found, got %T %v", err, err)
	}
}

func TestResolveModelUniqueLastSegmentResolvesToTheFullName(t *testing.T) {
	f := newResolveFixture(t)
	f.model("anthropic/claude-opus-4-8", "active", "active")
	f.model("anthropic/claude-sonnet-5-5", "active", "active")
	record, err := f.resolve("claude-opus-4-8")
	if err != nil {
		t.Fatal(err)
	}
	if record.ModelName != "anthropic/claude-opus-4-8" || record.AliasFrom != "claude-opus-4-8" {
		t.Fatalf("alias not applied: ModelName=%q AliasFrom=%q", record.ModelName, record.AliasFrom)
	}
}

func TestResolveModelAmbiguousLastSegmentIsNotGuessed(t *testing.T) {
	f := newResolveFixture(t)
	f.model("anthropic/claude-opus-4-8", "active", "active")
	f.model("vendor-b/claude-opus-4-8", "active", "active")
	_, err := f.resolve("claude-opus-4-8")
	var miss *ModelNotFoundError
	if !errors.Is(err, ErrModelNotFound) || !errors.As(err, &miss) || miss.Reason != ModelMissAmbiguous {
		t.Fatalf("want ambiguous, got %T %v", err, err)
	}
	want := []string{"anthropic/claude-opus-4-8", "vendor-b/claude-opus-4-8"}
	if !reflect.DeepEqual(miss.Candidates, want) {
		t.Fatalf("candidates=%v want=%v", miss.Candidates, want)
	}
}

// 同一个全名挂在两个供应商下（两条线路）算「恰好一个模型」，不是歧义。
func TestResolveModelSameFullNameOnTwoRoutesIsNotAmbiguous(t *testing.T) {
	f := newResolveFixture(t)
	f.model("anthropic/claude-opus-4-8", "active", "active")
	f.model("anthropic/claude-opus-4-8", "active", "active")
	record, err := f.resolve("claude-opus-4-8")
	if err != nil || record.ModelName != "anthropic/claude-opus-4-8" || record.AliasFrom != "claude-opus-4-8" {
		t.Fatalf("two routes of one model must alias: record=%+v err=%v", record, err)
	}
}

// 绝不做跨版本、去日期等模糊映射。
func TestResolveModelNeverFuzzyMatchesVersionsOrDates(t *testing.T) {
	f := newResolveFixture(t)
	f.model("anthropic/claude-opus-4-8", "active", "active")
	f.model("anthropic/claude-haiku-5-5", "active", "active")
	for _, name := range []string{
		"claude-opus-4-7",           // 跨版本
		"claude-haiku-5-5-20251001", // 带日期后缀
		"claude-haiku-5",            // 前缀截断
		"opus-4-8",                  // 后缀截断
		"claude-opus",               // 去版本
		"CLAUDE-OPUS-4-8",           // 大小写差异
		"anthropic/claude-opus-4-7", // 带前缀的错误名不走后缀匹配
		"other/claude-opus-4-8",     // 前缀不同的全名不走后缀匹配
	} {
		_, err := f.resolve(name)
		if !errors.Is(err, ErrModelNotFound) {
			t.Errorf("%q must not resolve, got %v", name, err)
		}
	}
}

func TestResolveModelRequestNameWithSlashDoesNotUseSuffixMatching(t *testing.T) {
	f := newResolveFixture(t)
	f.model("a/b/claude-opus-4-8", "active", "active")
	// "b/claude-opus-4-8" 含 "/"，必须精确命中，不做后缀匹配。
	if _, err := f.resolve("b/claude-opus-4-8"); !errors.Is(err, ErrModelNotFound) {
		t.Fatalf("name with slash must not suffix-match, got %v", err)
	}
	record, err := f.resolve("a/b/claude-opus-4-8")
	if err != nil || record.AliasFrom != "" {
		t.Fatalf("exact multi-slash name: %+v %v", record, err)
	}
}

func TestResolveModelInactiveIsReportedAsInactiveNotAsAlias(t *testing.T) {
	f := newResolveFixture(t)
	f.model("anthropic/claude-opus-4-8", "active", "disabled")
	for _, name := range []string{"anthropic/claude-opus-4-8", "claude-opus-4-8"} {
		_, err := f.resolve(name)
		var miss *ModelNotFoundError
		if !errors.Is(err, ErrModelNotFound) || !errors.As(err, &miss) {
			t.Fatalf("%q: want ModelNotFoundError, got %v", name, err)
		}
		if name == "anthropic/claude-opus-4-8" && miss.Reason != ModelMissInactive {
			t.Errorf("exact inactive name: reason=%q want inactive", miss.Reason)
		}
		if name == "claude-opus-4-8" && miss.Reason != ModelMissNotFound {
			t.Errorf("suffix of an inactive model must not alias: reason=%q", miss.Reason)
		}
	}
}

func TestResolveModelInactiveProviderIsInactive(t *testing.T) {
	f := newResolveFixture(t)
	f.model("anthropic/claude-opus-4-8", "disabled", "active")
	_, err := f.resolve("anthropic/claude-opus-4-8")
	var miss *ModelNotFoundError
	if !errors.As(err, &miss) || miss.Reason != ModelMissInactive {
		t.Fatalf("want inactive, got %v", err)
	}
}

// 一个停用、一个启用的同后缀模型：只有启用的参与别名解析。
func TestResolveModelAliasIgnoresInactiveSiblings(t *testing.T) {
	f := newResolveFixture(t)
	f.model("anthropic/claude-opus-4-8", "active", "active")
	f.model("vendor-b/claude-opus-4-8", "active", "disabled")
	record, err := f.resolve("claude-opus-4-8")
	if err != nil || record.ModelName != "anthropic/claude-opus-4-8" {
		t.Fatalf("inactive sibling must not make it ambiguous: %+v %v", record, err)
	}
}

func TestResolveModelOtherTenantModelsAreInvisible(t *testing.T) {
	f := newResolveFixture(t)
	other := newResolveFixture(t)
	other.model("anthropic/claude-opus-4-8", "active", "active")
	if _, err := f.resolve("claude-opus-4-8"); !errors.Is(err, ErrModelNotFound) {
		t.Fatalf("other tenant's model leaked: %v", err)
	}
}

// 数据库故障不能被说成「模型不存在」：否则会返回 404 并掩盖故障。
func TestResolveModelDatabaseFailureIsNotModelNotFound(t *testing.T) {
	f := newResolveFixture(t)
	f.model("anthropic/claude-opus-4-8", "active", "active")
	// 另开一个连接池再关掉，用它模拟数据库不可用；夹具自己的连接池留给清理使用。
	broken, err := pgxpool.New(context.Background(), os.Getenv("CONTENT_LOGS_TEST_DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	broken.Close()
	for _, name := range []string{"anthropic/claude-opus-4-8", "claude-opus-4-8", "no-such-model"} {
		_, err := NewModelRouter(broken).ResolveModelWithDB(context.Background(), f.tenant, name)
		if err == nil || errors.Is(err, ErrModelNotFound) {
			t.Fatalf("%q: database failure must stay an infrastructure error, got %v", name, err)
		}
	}
}
