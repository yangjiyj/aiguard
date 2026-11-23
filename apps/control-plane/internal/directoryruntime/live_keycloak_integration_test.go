package directoryruntime

import (
	"context"
	"os"
	"testing"
)

// TestLiveKeycloakProviderIntegration is opt-in and verifies that the
// directory-runtime service account can publish and read back the managed
// Keycloak LDAP provider. It restores the prior provider configuration.
func TestLiveKeycloakProviderIntegration(t *testing.T) {
	input := ConfigInput{
		RuntimeURL:   os.Getenv("DIRECTORY_RUNTIME_INTEGRATION_URL"),
		ClientID:     os.Getenv("DIRECTORY_RUNTIME_INTEGRATION_CLIENT_ID"),
		ClientSecret: os.Getenv("DIRECTORY_RUNTIME_INTEGRATION_CLIENT_SECRET"),
	}
	if input.RuntimeURL == "" || input.ClientID == "" || input.ClientSecret == "" {
		t.Skip("set DIRECTORY_RUNTIME_INTEGRATION_* to run against Keycloak")
	}
	if os.Getenv("DIRECTORY_RUNTIME_INTEGRATION_BIND_PASSWORD") == "" {
		t.Skip("set DIRECTORY_RUNTIME_INTEGRATION_BIND_PASSWORD for LDAP sync")
	}
	config, err := LoadConfig(input)
	if err != nil {
		t.Fatalf("load integration configuration: %v", err)
	}
	client, err := config.NewClient()
	if err != nil {
		t.Fatalf("new Keycloak client: %v", err)
	}
	ctx := context.Background()
	before, err := client.Snapshot(ctx)
	if err != nil {
		t.Fatalf("snapshot existing provider: %v", err)
	}
	t.Cleanup(func() {
		if err := client.Restore(context.Background(), before); err != nil {
			t.Errorf("restore existing provider: %v", err)
		}
	})

	directoryConfig := DirectoryConfig{
		Kind:          KindActiveDirectory,
		ConnectionURL: "ldaps://dc-sim.ad.jjdguard.test:636",
		BindDN:        "administrator@AD.JJDGUARD.TEST",
		BindPassword:  os.Getenv("DIRECTORY_RUNTIME_INTEGRATION_BIND_PASSWORD"),
		UsersDN:       "CN=Users,DC=ad,DC=jjdguard,DC=test",
	}
	digest, err := ComputeDigest(directoryConfig)
	if err != nil {
		t.Fatalf("compute expected digest: %v", err)
	}
	if err := client.Apply(ctx, directoryConfig, digest); err != nil {
		t.Fatalf("apply provider: %v", err)
	}
	snapshot, err := client.Snapshot(ctx)
	if err != nil {
		t.Fatalf("read published provider: %v", err)
	}
	if !snapshot.Exists {
		t.Fatal("expected provider after apply")
	}
	for key, values := range snapshot.Component.Config {
		t.Logf("readback config: %s values=%d", key, len(values))
	}
	status, err := client.Status(ctx)
	if err != nil {
		t.Fatalf("read published provider: %v", err)
	}
	if err := client.FullSync(ctx); err != nil {
		t.Fatalf("full sync: %v", err)
	}
	if !status.Exists || !status.Enabled {
		t.Fatalf("unexpected published status: %+v", status)
	}
}
