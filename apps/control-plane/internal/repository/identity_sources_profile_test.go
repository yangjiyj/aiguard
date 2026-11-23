package repository

import (
	"context"
	"errors"
	"testing"
)

func TestIdentitySourceProfileOptionsDefaultsAndRoundTrip(t *testing.T) {
	db := setupIdentityTestDB(t)
	ctx := context.Background()
	tenantID := setupIdentityTenant(t, db)
	repo := NewIdentitySourceRepository(db)

	src := &IdentitySource{TenantID: tenantID, DisplayName: "默认", IssuerURL: "https://idp.example.com",
		ClientID: "c", ClientSecretEnc: "enc:v1:AA"}
	if err := repo.UpsertDraft(ctx, src); err != nil {
		t.Fatal(err)
	}
	got, _ := repo.GetByID(ctx, tenantID, src.ID)
	if got.SignatureMode != "jwks" || got.SkipProfileReview || got.UsernameClaim != "preferred_username" {
		t.Fatalf("默认值不对: %+v", got)
	}

	src.SignatureMode, src.SkipProfileReview, src.UsernameClaim = "none", true, "email"
	if err := repo.UpsertDraft(ctx, src); err != nil {
		t.Fatal(err)
	}
	got, _ = repo.GetByID(ctx, tenantID, src.ID)
	if got.SignatureMode != "none" || !got.SkipProfileReview || got.UsernameClaim != "email" {
		t.Fatalf("回读不对: %+v", got)
	}
	// 数据库兜底：非法枚举被 CHECK 拒绝。
	if _, err := db.Exec(ctx, `UPDATE identity_sources SET signature_mode='hmac' WHERE id=$1`, src.ID); err == nil {
		t.Fatal("非法 signature_mode 应被 CHECK 拒绝")
	}
}

func seedAdoptionSources(t *testing.T) (*IdentitySourceRepository, string, *IdentitySource, *IdentitySource) {
	db := setupIdentityTestDB(t)
	ctx := context.Background()
	tenantID := setupIdentityTenant(t, db)
	repo := NewIdentitySourceRepository(db)
	mk := func(name string) *IdentitySource {
		s := &IdentitySource{TenantID: tenantID, DisplayName: name, IssuerURL: "https://idp.example.com",
			ClientID: "c", ClientSecretEnc: "enc:v1:AA", RuntimeAlias: "enterprise"}
		if err := repo.UpsertDraft(ctx, s); err != nil {
			t.Fatal(err)
		}
		return s
	}
	old := mk("旧")
	if _, err := db.Exec(ctx, `UPDATE identity_sources SET status='disabled', publish_status='disabled' WHERE id=$1`, old.ID); err != nil {
		t.Fatal(err)
	}
	active := mk("现役")
	if _, err := db.Exec(ctx, `UPDATE identity_sources SET status='tested' WHERE id=$1`, active.ID); err != nil {
		t.Fatal(err)
	}
	active.Status = "tested"
	if err := commitTestIdentityPublication(ctx, repo, active, "admin"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, `UPDATE identity_sources SET publish_status='drifted' WHERE id=$1`, active.ID); err != nil {
		t.Fatal(err)
	}
	return repo, tenantID, old, active
}

func TestAdoptRuntimeSettingsOnlyTouchesTargetAndKeepsVersion(t *testing.T) {
	repo, tenantID, old, active := seedAdoptionSources(t)
	ctx := context.Background()
	before, _ := repo.GetByID(ctx, tenantID, active.ID)
	oldBefore, _ := repo.GetByID(ctx, tenantID, old.ID)

	res, err := repo.AdoptRuntimeSettings(ctx, AdoptRuntimeInput{
		TenantID: tenantID, SourceID: active.ID, Version: before.Version,
		SignatureMode: "none", UsernameClaim: "email", SkipProfileReview: true, ConfigDigest: "sha256:adopted",
	})
	if err != nil {
		t.Fatal(err)
	}
	after, _ := repo.GetByID(ctx, tenantID, active.ID)
	if after.SignatureMode != "none" || after.UsernameClaim != "email" || !after.SkipProfileReview ||
		after.ConfigDigest != "sha256:adopted" || after.Version != before.Version || after.AppliedVersion != before.AppliedVersion {
		t.Fatalf("after=%+v before=%+v", after, before)
	}
	oldAfter, _ := repo.GetByID(ctx, tenantID, old.ID)
	if oldAfter.SignatureMode != oldBefore.SignatureMode || oldAfter.UsernameClaim != oldBefore.UsernameClaim ||
		oldAfter.Version != oldBefore.Version || oldAfter.Status != "disabled" {
		t.Fatalf("同 alias 的其他记录不得被改动: %+v", oldAfter)
	}
	if len(res.SameAliasSources) != 1 || res.SameAliasSources[0].ID != old.ID {
		t.Fatalf("应提示同 alias 冲突记录: %+v", res)
	}
}

func TestAdoptRuntimeSettingsKeepsUsernameClaimWhenUnknown(t *testing.T) {
	repo, tenantID, _, active := seedAdoptionSources(t)
	ctx := context.Background()
	if _, err := repo.AdoptRuntimeSettings(ctx, AdoptRuntimeInput{
		TenantID: tenantID, SourceID: active.ID, Version: active.Version, SignatureMode: "none", ConfigDigest: "sha256:x",
	}); err != nil {
		t.Fatal(err)
	}
	after, _ := repo.GetByID(ctx, tenantID, active.ID)
	if after.UsernameClaim != "preferred_username" {
		t.Fatalf("无法反推时不得改写用户名取值: %s", after.UsernameClaim)
	}
}

func TestAdoptRuntimeSettingsRefusesNonActiveWhenAnotherIsActive(t *testing.T) {
	repo, tenantID, old, _ := seedAdoptionSources(t)
	_, err := repo.AdoptRuntimeSettings(context.Background(), AdoptRuntimeInput{
		TenantID: tenantID, SourceID: old.ID, Version: old.Version, SignatureMode: "none", ConfigDigest: "sha256:x",
	})
	if !errors.Is(err, ErrAdoptTargetNotActive) {
		t.Fatalf("err=%v", err)
	}
	// 跨租户/不存在
	_, err = repo.AdoptRuntimeSettings(context.Background(), AdoptRuntimeInput{
		TenantID: "other-tenant", SourceID: old.ID, Version: old.Version, SignatureMode: "none", ConfigDigest: "sha256:x",
	})
	if !errors.Is(err, ErrIdentitySourceChanged) {
		t.Fatalf("err=%v", err)
	}
}

func TestAdoptRuntimeSettingsRejectsStaleVersion(t *testing.T) {
	repo, tenantID, _, active := seedAdoptionSources(t)
	ctx := context.Background()
	read, _ := repo.GetByID(ctx, tenantID, active.ID)
	// 模拟读取之后被他人修改（版本递增）。
	if _, err := repo.db.Exec(ctx, `UPDATE identity_sources SET version=version+1, username_claim='sub' WHERE id=$1`, active.ID); err != nil {
		t.Fatal(err)
	}
	_, err := repo.AdoptRuntimeSettings(ctx, AdoptRuntimeInput{
		TenantID: tenantID, SourceID: active.ID, Version: read.Version,
		SignatureMode: "none", UsernameClaim: "email", SkipProfileReview: true, ConfigDigest: "sha256:stale",
	})
	if !errors.Is(err, ErrIdentitySourceChanged) {
		t.Fatalf("版本不一致必须拒绝: %v", err)
	}
	after, _ := repo.GetByID(ctx, tenantID, active.ID)
	if after.SignatureMode != "jwks" || after.UsernameClaim != "sub" || after.ConfigDigest == "sha256:stale" {
		t.Fatalf("被拒绝的采纳不得写库: %+v", after)
	}
}

func TestAdoptRuntimeSettingsRefusesEditingStatuses(t *testing.T) {
	db := setupIdentityTestDB(t)
	ctx := context.Background()
	tenantID := setupIdentityTenant(t, db)
	repo := NewIdentitySourceRepository(db)
	src := &IdentitySource{TenantID: tenantID, DisplayName: "草稿", IssuerURL: "https://idp.example.com",
		ClientID: "c", ClientSecretEnc: "enc:v1:AA"}
	if err := repo.UpsertDraft(ctx, src); err != nil {
		t.Fatal(err)
	}
	for _, status := range []string{"draft", "tested"} {
		if _, err := db.Exec(ctx, `UPDATE identity_sources SET status=$2 WHERE id=$1`, src.ID, status); err != nil {
			t.Fatal(err)
		}
		_, err := repo.AdoptRuntimeSettings(ctx, AdoptRuntimeInput{
			TenantID: tenantID, SourceID: src.ID, Version: src.Version, SignatureMode: "none", ConfigDigest: "sha256:x",
		})
		if !errors.Is(err, ErrAdoptTargetNotAdoptable) {
			t.Fatalf("status=%s err=%v", status, err)
		}
	}
}
