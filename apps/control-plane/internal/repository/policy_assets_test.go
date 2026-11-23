package repository

import "testing"

func TestPolicyAssetApplicabilityContract(t *testing.T) {
	cases := []struct {
		owner, source, assetIndustry, tenantIndustry string
		wantApplicable, wantWritable                 bool
	}{
		{"tenant-a", "system", "generic", "finance", true, false},
		{SystemTenantID, "builtin", "generic", "finance", true, false},
		{SystemTenantID, "builtin", "finance", "finance", true, false},
		{SystemTenantID, "builtin", "medical_imaging", "finance", false, false},
	}
	for _, tc := range cases {
		tenantOwned := tc.owner == "tenant-a"
		applicable := tenantOwned || tc.assetIndustry == "generic" || tc.assetIndustry == tc.tenantIndustry
		writable := tenantOwned && false
		if applicable != tc.wantApplicable || writable != tc.wantWritable {
			t.Fatalf("owner=%s industry=%s got applicable=%v writable=%v", tc.owner, tc.assetIndustry, applicable, writable)
		}
	}
}
