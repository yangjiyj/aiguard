package roles

import "testing"

func TestCanViewRawEvidence(t *testing.T) {
	for role, want := range map[string]bool{SystemAdmin: true, LegacyAdmin: false, SecurityOfficer: true,
		Auditor: false, TenantAdmin: false, LegacyTenantOwner: false, DeptManager: false, Developer: false, Viewer: false, ChatUser: false, "": false} {
		if got := CanViewRawEvidence(role); got != want {
			t.Errorf("%q: got %v want %v", role, got, want)
		}
	}
}
