package repository

import (
	"context"
	"testing"
	"time"
)

func TestPersonalFilePagesAndLegacyRanksRespectOwner(t *testing.T) {
	db, tenant, user, _, _, _ := employeeKeyFixture(t)
	ctx := context.Background()
	repo := NewPortalUploadEventRepository(db)
	base := time.Now().UTC().Truncate(time.Second)
	for i := 1; i <= 3; i++ {
		if err := repo.Insert(ctx, PortalUploadEvent{ID: tenant + string(rune('0'+i)), TenantID: tenant, UserID: user, Filename: "same.txt", SHA256: "same", CreatedAt: base.Add(time.Duration(i) * time.Minute)}); err != nil {
			t.Fatal(err)
		}
	}
	for offset := 0; offset < 3; offset++ {
		items, total, err := repo.ListByUser(ctx, tenant, user, 1, offset)
		if err != nil || total != 3 || len(items) != 1 {
			t.Fatalf("page offset=%d total=%d err=%v", offset, total, err)
		}
	}
	index, err := repo.LegacyIndex(ctx, tenant, user, []PortalLegacyUploadPosition{{ID: "middle", SHA256: "unmatched", CreatedAt: base.Add(150 * time.Second)}, {ID: "covered", SHA256: "same", CreatedAt: base}})
	if err != nil || len(index) != 2 || index[0].Matched || index[0].GatewayBefore != 1 || !index[1].Matched {
		t.Fatalf("legacy ranks not scoped: err=%v", err)
	}
	empty, total, err := repo.ListByUser(ctx, "another-tenant", user, 10, 0)
	if err != nil || len(empty) != 0 || total != 0 {
		t.Fatal("other tenant received file history")
	}
}
