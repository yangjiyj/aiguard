package mcpadmission

import "testing"

func TestAdministratorBlockFollowsSourceNotReason(t *testing.T) {
	for _, s := range ContractSamples {
		if got := AdministratorBlock(s.Status, Source(s.ReviewedBy)); got != s.WantAdministrator {
			t.Errorf("%s: administrator=%v want %v", s.Name, got, s.WantAdministrator)
		}
	}
	if !AdministratorBlock("quarantined", "") {
		t.Fatal("missing source (older control plane) must count as administrator")
	}
}
