package rules

import (
	"testing"
	"time"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

func TestCompileCarriesExceptionExpiryIntoRuntimePackAndVersion(t *testing.T) {
	firstExpiry := time.Now().UTC().Add(24 * time.Hour).Truncate(time.Second)
	secondExpiry := firstExpiry.Add(time.Hour)
	makePack := func(expiry time.Time) RulePack {
		return Compile("tenant-a", nil, []*repository.ContentAuditException{{
			ID: "exc-1", TenantID: "tenant-a", ScopeType: "rule", RuleRef: "rule-1",
			Decision: "audit", Reason: "reviewed", ExpiresAt: &expiry, Enabled: true,
		}})
	}

	first := makePack(firstExpiry)
	second := makePack(secondExpiry)
	sameInstant := makePack(firstExpiry.In(time.FixedZone("other", -5*60*60)))
	if len(first.Exceptions) != 1 || first.Exceptions[0].ExpiresAt == nil || !first.Exceptions[0].ExpiresAt.Equal(firstExpiry) {
		t.Fatalf("compiled exception lost expiry: %+v", first.Exceptions)
	}
	if first.Version == second.Version {
		t.Fatal("exception expiry must participate in the rule-pack version")
	}
	if first.Version != sameInstant.Version {
		t.Fatal("the same expiry instant must have one canonical rule-pack version")
	}
}

func TestCompileIncludesExceptionChildScopeFlagInVersion(t *testing.T) {
	makePack := func(includeChildren bool) RulePack {
		return Compile("tenant-a", nil, []*repository.ContentAuditException{{
			ID: "exc-dept", TenantID: "tenant-a",
			ScopeType: "actor_department_v1", ScopeRef: "dept-a",
			IncludeChildren: includeChildren,
			Decision:        "audit", Reason: "reviewed", Enabled: true,
		}})
	}

	exact := makePack(false)
	descendants := makePack(true)
	if exact.Version == descendants.Version {
		t.Fatal("include_children must participate in the normalized rule-pack version")
	}
}
