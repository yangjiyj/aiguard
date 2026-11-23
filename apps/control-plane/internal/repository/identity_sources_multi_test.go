package repository

import (
	"context"
	"errors"
	"testing"
)

func newTestedIdentitySource(t *testing.T, repo *IdentitySourceRepository, tenantID, alias, name string) *IdentitySource {
	t.Helper()
	ctx := context.Background()
	src := &IdentitySource{
		TenantID: tenantID, DisplayName: name, IssuerURL: "https://" + name + ".example.com",
		ClientID: "client-" + name, ClientSecretEnc: "enc:v1:" + name, RuntimeAlias: alias,
	}
	if err := repo.UpsertDraft(ctx, src); err != nil {
		t.Fatalf("UpsertDraft %s: %v", name, err)
	}
	if err := repo.UpdateTestResult(ctx, tenantID, src.ID, src.Version, &TestResult{Success: true, TestedAt: "now"}); err != nil {
		t.Fatalf("UpdateTestResult %s: %v", name, err)
	}
	return src
}

func publishIdentitySourceAs(t *testing.T, repo *IdentitySourceRepository, src *IdentitySource, alias string) error {
	t.Helper()
	ctx := context.Background()
	if err := repo.MarkPublishing(ctx, src.TenantID, src.ID, src.Version); err != nil {
		t.Fatalf("MarkPublishing %s: %v", src.ID, err)
	}
	return repo.CommitPublication(ctx, PublicationCommit{
		TenantID: src.TenantID, SourceID: src.ID, ExpectedVersion: src.Version,
		RuntimeAlias: alias, ConfigDigest: "sha256:test", PublishedBy: "admin_user",
	})
}

// 9.2：同一租户下不同 alias 的身份源可以同时启用；发布某个 alias 的新版本只替换同 alias 的旧版本。
func TestIdentitySourcesMultipleAliasesCoexist(t *testing.T) {
	db := setupIdentityTestDB(t)
	ctx := context.Background()
	tenantID := setupIdentityTenant(t, db)
	repo := NewIdentitySourceRepository(db)

	def := newTestedIdentitySource(t, repo, tenantID, "", "idp-default")
	if err := publishIdentitySourceAs(t, repo, def, DefaultRuntimeAlias); err != nil {
		t.Fatalf("publish default: %v", err)
	}
	second := newTestedIdentitySource(t, repo, tenantID, "jjd-second0001", "idp-second")
	if err := publishIdentitySourceAs(t, repo, second, "jjd-second0001"); err != nil {
		t.Fatalf("publish second: %v", err)
	}

	gotDef, err := repo.GetByID(ctx, tenantID, def.ID)
	if err != nil || gotDef.Status != "active" || !gotDef.IsDefault || gotDef.RuntimeAlias != DefaultRuntimeAlias {
		t.Fatalf("default source must stay active/default: %+v %v", gotDef, err)
	}
	gotSecond, err := repo.GetByID(ctx, tenantID, second.ID)
	if err != nil || gotSecond.Status != "active" || gotSecond.IsDefault || gotSecond.RuntimeAlias != "jjd-second0001" {
		t.Fatalf("second source must be active, non-default, alias kept: %+v %v", gotSecond, err)
	}

	active, err := repo.ListActive(ctx, tenantID)
	if err != nil || len(active) != 2 || active[0].ID != def.ID || active[1].ID != second.ID {
		t.Fatalf("ListActive = %+v %v", active, err)
	}
	aliases, err := repo.ListAliases(ctx, tenantID)
	if err != nil || len(aliases) != 2 || aliases[0] != DefaultRuntimeAlias || aliases[1] != "jjd-second0001" {
		t.Fatalf("ListAliases = %v %v", aliases, err)
	}
	if a, _ := repo.GetActive(ctx, tenantID); a == nil || a.ID != def.ID {
		t.Fatalf("GetActive (no alias) must keep returning the default source: %+v", a)
	}
	if a, _ := repo.GetActiveByAlias(ctx, tenantID, "jjd-second0001"); a == nil || a.ID != second.ID {
		t.Fatalf("GetActiveByAlias = %+v", a)
	}

	// 第二个 alias 发布新版本：只停用它自己的旧版本。
	secondV2 := newTestedIdentitySource(t, repo, tenantID, "jjd-second0001", "idp-second-v2")
	if err := publishIdentitySourceAs(t, repo, secondV2, "jjd-second0001"); err != nil {
		t.Fatalf("publish second v2: %v", err)
	}
	if s, _ := repo.GetByID(ctx, tenantID, second.ID); s.Status != "disabled" {
		t.Fatalf("old version of same alias must be disabled, got %s", s.Status)
	}
	if s, _ := repo.GetByID(ctx, tenantID, def.ID); s.Status != "active" {
		t.Fatalf("other alias must not be touched, got %s", s.Status)
	}
}

// 9.2：发布方传入的 alias 与行上固定的 alias 不一致时拒绝，不改写。
func TestIdentitySourceCommitRejectsAliasMismatch(t *testing.T) {
	db := setupIdentityTestDB(t)
	ctx := context.Background()
	tenantID := setupIdentityTenant(t, db)
	repo := NewIdentitySourceRepository(db)

	src := newTestedIdentitySource(t, repo, tenantID, "jjd-mismatch01", "idp-mm")
	if err := publishIdentitySourceAs(t, repo, src, DefaultRuntimeAlias); !errors.Is(err, ErrIdentitySourceChanged) {
		t.Fatalf("alias mismatch must be rejected, got %v", err)
	}
	got, _ := repo.GetByID(ctx, tenantID, src.ID)
	if got.RuntimeAlias != "jjd-mismatch01" || got.Status == "active" {
		t.Fatalf("row must be unchanged: %+v", got)
	}
}

// 9.2：草稿更新不能借 ON CONFLICT 把行搬到另一个 alias。
func TestIdentitySourceUpsertDraftCannotChangeAlias(t *testing.T) {
	db := setupIdentityTestDB(t)
	ctx := context.Background()
	tenantID := setupIdentityTenant(t, db)
	repo := NewIdentitySourceRepository(db)

	src := &IdentitySource{TenantID: tenantID, DisplayName: "a", IssuerURL: "https://a.example.com", ClientID: "a", RuntimeAlias: "jjd-keepalias1"}
	if err := repo.UpsertDraft(ctx, src); err != nil {
		t.Fatalf("UpsertDraft: %v", err)
	}
	moved := *src
	moved.RuntimeAlias = DefaultRuntimeAlias
	if err := repo.UpsertDraft(ctx, &moved); !errors.Is(err, ErrIdentitySourceChanged) {
		t.Fatalf("alias change via upsert must be rejected, got %v", err)
	}
	if got, _ := repo.GetByID(ctx, tenantID, src.ID); got.RuntimeAlias != "jjd-keepalias1" {
		t.Fatalf("alias changed: %+v", got)
	}
}

// 9.2：迁移 930 的 CHECK 约束只接受 enterprise 或 jjd- 前缀的服务端派生 alias。
func TestIdentitySourceRuntimeAliasCheckConstraint(t *testing.T) {
	db := setupIdentityTestDB(t)
	tenantID := setupIdentityTenant(t, db)
	repo := NewIdentitySourceRepository(db)
	for _, bad := range []string{"other", "jjd-", "jjd-UPPER", "../enterprise", "jjd-a/b"} {
		src := &IdentitySource{TenantID: tenantID, DisplayName: "x", IssuerURL: "https://x.example.com", ClientID: "x", RuntimeAlias: bad}
		if err := repo.UpsertDraft(context.Background(), src); err == nil {
			t.Fatalf("alias %q must be rejected by the database", bad)
		}
	}
}
