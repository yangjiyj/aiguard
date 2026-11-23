package repository

import (
	"context"
	"errors"
	"testing"

	"github.com/yangjiyj/aiguard/packages/shared-go/modelrouting"
)

func TestModelRoutingRepositoryNativeEndpointsRemainAvailable(t *testing.T) {
	for _, endpoint := range []string{"chat", "messages", "responses", "embeddings", "images", "files"} {
		t.Run(endpoint, func(t *testing.T) {
			f := setupModelRoutingTestDB(t)
			ctx := context.Background()
			providerID := f.tenantA + "_native"
			seedRoutingCandidate(t, f, f.tenantA, providerID, "native-model")
			if _, err := f.db.Exec(ctx, `UPDATE model_endpoint_capability_overrides SET endpoint_type=$2 WHERE tenant_id=$1`, f.tenantA, endpoint); err != nil {
				t.Fatal(err)
			}
			repo := NewModelRoutingRepository(f.db)
			overview, err := repo.Overview(ctx, f.tenantA)
			if err != nil || !overview.OutboundRouteAvailable || overview.MultiRouteModelCount != 0 {
				t.Fatalf("single %s route must be available without requiring multiple upstreams: overview=%+v err=%v", endpoint, overview, err)
			}
			if err := repo.ValidateProviderCandidates(ctx, f.tenantA, "native-model", "", []string{providerID}); err != nil {
				t.Fatalf("endpoint-independent policy rejected %s: %v", endpoint, err)
			}
			if err := repo.ValidateProviderCandidates(ctx, f.tenantA, "native-model", endpoint, []string{providerID}); err != nil {
				t.Fatalf("specific supported endpoint rejected: %v", err)
			}
			if endpoint != "chat" {
				if err := repo.ValidateProviderCandidates(ctx, f.tenantA, "native-model", "chat", []string{providerID}); !errors.Is(err, ErrModelRouteUnavailable) {
					t.Fatalf("specific unsupported Chat must remain unavailable: %v", err)
				}
			}
			if _, err := repo.UpsertDefault(ctx, f.tenantA, 0, routingConfig(providerID, modelrouting.StrategyPriority)); err != nil {
				t.Fatalf("save default for %s: %v", endpoint, err)
			}
			if _, err := repo.UpsertOverride(ctx, f.tenantA, "native-model", 0, routingConfig(providerID, modelrouting.StrategyFixed)); err != nil {
				t.Fatalf("save model rule for %s: %v", endpoint, err)
			}
			other, err := repo.Overview(ctx, f.tenantB)
			if err != nil || other.OutboundRouteAvailable {
				t.Fatalf("route leaked into another tenant: overview=%+v err=%v", other, err)
			}
			for _, invalid := range []struct{ name, apply, restore string }{
				{"pending_model", `UPDATE models SET status='pending' WHERE provider_id=$1`, `UPDATE models SET status='active' WHERE provider_id=$1`},
				{"disabled_provider", `UPDATE providers SET status='inactive' WHERE id=$1`, `UPDATE providers SET status='active' WHERE id=$1`},
				{"empty_credential", `UPDATE provider_credentials SET secret_ciphertext='' WHERE provider_id=$1`, `UPDATE provider_credentials SET secret_ciphertext='test-ciphertext' WHERE provider_id=$1`},
				{"unsupported_endpoint", `UPDATE model_endpoint_capability_overrides SET state='unsupported' WHERE model_id IN (SELECT id FROM models WHERE provider_id=$1)`, `UPDATE model_endpoint_capability_overrides SET state='supported' WHERE model_id IN (SELECT id FROM models WHERE provider_id=$1)`},
			} {
				if _, err := f.db.Exec(ctx, invalid.apply, providerID); err != nil {
					t.Fatal(err)
				}
				got, err := repo.Overview(ctx, f.tenantA)
				if err != nil || got.OutboundRouteAvailable {
					t.Fatalf("%s accepted: overview=%+v err=%v", invalid.name, got, err)
				}
				if err := repo.ValidateProviderCandidates(ctx, f.tenantA, "native-model", "", []string{providerID}); !errors.Is(err, ErrModelRouteUnavailable) {
					t.Fatalf("%s policy accepted: %v", invalid.name, err)
				}
				if _, err := f.db.Exec(ctx, invalid.restore, providerID); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}
