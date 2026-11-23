package directoryruntime

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPublishRollsBackWhenReadbackDigestDiffers(t *testing.T) {
	client := &fakeRuntimeClient{
		statuses: []RuntimeStatus{
			{Exists: false},
			{Exists: true, Enabled: true, Digest: "sha256:wrong"},
		},
		snapshot: RuntimeSnapshot{Exists: false},
	}
	orchestrator := NewOrchestrator(client)

	_, err := orchestrator.Publish(context.Background(), testDirectoryConfig())
	require.ErrorIs(t, err, ErrPublishVerification)
	require.Equal(t, 1, client.applyCalls)
	require.Equal(t, 1, client.restoreCalls)
}

func TestPublishReappliesMatchingConfigForCredentialRotation(t *testing.T) {
	digest, err := ComputeDigest(testDirectoryConfig())
	require.NoError(t, err)
	client := &fakeRuntimeClient{statuses: []RuntimeStatus{{Exists: true, Enabled: true, Digest: digest}}}
	publication, err := NewOrchestrator(client).Publish(context.Background(), testDirectoryConfig())
	require.NoError(t, err)
	require.False(t, publication.AlreadyCurrent)
	require.Equal(t, 1, client.applyCalls)
	require.Zero(t, client.restoreCalls)
}

func testDirectoryConfig() DirectoryConfig {
	return DirectoryConfig{
		Kind:          KindActiveDirectory,
		ConnectionURL: "ldaps://dc.corp.test:636",
		BindDN:        "CN=svc,DC=corp,DC=test",
		BindPassword:  "super-secret",
		UsersDN:       "OU=Users,DC=corp,DC=test",
	}
}

type fakeRuntimeClient struct {
	statuses     []RuntimeStatus
	snapshot     RuntimeSnapshot
	applyCalls   int
	restoreCalls int
}

func (client *fakeRuntimeClient) Status(context.Context) (RuntimeStatus, error) {
	if len(client.statuses) == 0 {
		return RuntimeStatus{}, errors.New("unexpected status call")
	}
	status := client.statuses[0]
	client.statuses = client.statuses[1:]
	return status, nil
}

func (client *fakeRuntimeClient) Snapshot(context.Context) (RuntimeSnapshot, error) {
	return client.snapshot, nil
}

func (client *fakeRuntimeClient) Apply(context.Context, DirectoryConfig, string) error {
	client.applyCalls++
	return nil
}

func (client *fakeRuntimeClient) Restore(context.Context, RuntimeSnapshot) error {
	client.restoreCalls++
	return nil
}

func TestDisableReturnsSnapshotAfterVerifiedRuntimeDisable(t *testing.T) {
	client := &fakeRuntimeClient{
		snapshot: RuntimeSnapshot{Exists: true, Component: ComponentRepresentation{
			ID: "directory-component", Config: map[string][]string{"enabled": {"true"}},
		}},
		statuses: []RuntimeStatus{{Exists: true, Enabled: false}},
	}
	snapshot, err := NewOrchestrator(client).Disable(context.Background())
	require.NoError(t, err)
	require.True(t, snapshot.Exists)
	require.Equal(t, 1, client.restoreCalls)
}

func TestDisableRollsBackWhenReadbackRemainsEnabled(t *testing.T) {
	client := &fakeRuntimeClient{
		snapshot: RuntimeSnapshot{Exists: true, Component: ComponentRepresentation{
			ID: "directory-component", Config: map[string][]string{"enabled": {"true"}},
		}},
		statuses: []RuntimeStatus{{Exists: true, Enabled: true}},
	}
	_, err := NewOrchestrator(client).Disable(context.Background())
	require.ErrorIs(t, err, ErrPublishVerification)
	require.Equal(t, 2, client.restoreCalls)
}
