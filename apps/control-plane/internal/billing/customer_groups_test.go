package billing

import (
	"context"
	"testing"
)

func TestCustomerGroupAssignmentAndDisabledFallback(t *testing.T) {
	store, _, tenantID, userID := setupBillingStoreTest(t)
	ctx := context.Background()

	groups, err := store.ListCustomerGroups(ctx, tenantID)
	if err != nil {
		t.Fatalf("list default customer group: %v", err)
	}
	if len(groups) != 1 || groups[0].Code != DefaultCustomerGroup || !groups[0].IsDefault || groups[0].RatioPPM != ratioScale {
		t.Fatalf("default customer groups = %#v", groups)
	}

	vip, err := store.CreateCustomerGroup(ctx, NewCustomerGroup{
		TenantID: tenantID, Code: "vip", Name: "VIP customers", Description: "contract pricing", RatioPPM: 800_000, CreatedBy: "admin-a",
	})
	if err != nil {
		t.Fatalf("create vip customer group: %v", err)
	}
	if vip.Code != "vip" || vip.Status != CustomerGroupActive || vip.IsDefault || vip.RatioPPM != 800_000 {
		t.Fatalf("created vip group = %#v", vip)
	}

	assigned, err := store.AssignCustomerGroup(ctx, tenantID, userID, vip.Code, "admin-a")
	if err != nil || assigned.Code != "vip" {
		t.Fatalf("assign vip group: group=%#v err=%v", assigned, err)
	}
	resolved, err := store.ResolveCustomerGroup(ctx, tenantID, userID)
	if err != nil || resolved != "vip" {
		t.Fatalf("resolved assigned group = %q err=%v", resolved, err)
	}
	resolvedGroup, err := store.ResolveCustomerGroupDetails(ctx, tenantID, userID)
	if err != nil || resolvedGroup.Code != "vip" || resolvedGroup.RatioPPM != 800_000 {
		t.Fatalf("resolved assigned group details = %#v err=%v", resolvedGroup, err)
	}

	customers, err := store.ListAdminCustomers(ctx, tenantID, 10)
	if err != nil {
		t.Fatalf("list grouped billing customers: %v", err)
	}
	if len(customers) != 1 || customers[0].CustomerGroup != "vip" || customers[0].GroupName != "VIP customers" {
		t.Fatalf("grouped billing customer = %#v", customers)
	}

	if _, err := store.UpdateCustomerGroup(ctx, tenantID, vip.ID, CustomerGroupUpdate{
		Name: vip.Name, Description: vip.Description, Status: CustomerGroupDisabled, RatioPPM: 750_000,
	}); err != nil {
		t.Fatalf("disable vip group: %v", err)
	}
	resolved, err = store.ResolveCustomerGroup(ctx, tenantID, userID)
	if err != nil || resolved != DefaultCustomerGroup {
		t.Fatalf("disabled group fallback = %q err=%v", resolved, err)
	}
}

func TestModelPriceAlwaysUsesTenantModelBasePrice(t *testing.T) {
	store, _, tenantID, _ := setupBillingStoreTest(t)
	price, err := store.CreateModelPrice(context.Background(), NewModelPrice{
		TenantID: tenantID, ModelName: "group-price-model", CustomerGroup: "missing",
		PricingMode: PricingModeDirect, Currency: "CNY", Status: PriceStatusActive,
		DirectPrice: DirectPrice{InputPerMillionMicros: 1, OutputPerMillionMicros: 2},
	})
	if err != nil || price.CustomerGroup != DefaultCustomerGroup {
		t.Fatalf("global model price = %#v err=%v", price, err)
	}
}
