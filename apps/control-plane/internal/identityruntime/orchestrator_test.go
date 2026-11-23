package identityruntime

import (
	"context"
	"errors"
	"testing"
)

type fakeRuntimeClient struct {
	snapshot      RuntimeSnapshot
	snapshotErr   error
	statuses      []RuntimeStatus
	statusErrors  []error
	applyErr      error
	restoreErr    error
	disableErr    error
	snapshotCalls int
	statusCalls   int
	applyCalls    int
	restoreCalls  int
	disableCalls  int
	restored      RuntimeSnapshot
	applied       DesiredIdentitySource
}

func (f *fakeRuntimeClient) Snapshot(_ context.Context, realm, alias string) (RuntimeSnapshot, error) {
	f.snapshotCalls++
	if err := validateRuntimeCoordinates(realm, alias); err != nil {
		return RuntimeSnapshot{}, err
	}
	return f.snapshot, f.snapshotErr
}

func (f *fakeRuntimeClient) Status(_ context.Context, realm, alias string) (RuntimeStatus, error) {
	f.statusCalls++
	if err := validateRuntimeCoordinates(realm, alias); err != nil {
		return RuntimeStatus{}, err
	}
	index := f.statusCalls - 1
	var status RuntimeStatus
	if len(f.statuses) > 0 {
		if index >= len(f.statuses) {
			index = len(f.statuses) - 1
		}
		status = f.statuses[index]
	}
	var err error
	if len(f.statusErrors) > 0 {
		errorIndex := f.statusCalls - 1
		if errorIndex >= len(f.statusErrors) {
			errorIndex = len(f.statusErrors) - 1
		}
		err = f.statusErrors[errorIndex]
	}
	return status, err
}

func (f *fakeRuntimeClient) Apply(_ context.Context, desired DesiredIdentitySource) error {
	f.applyCalls++
	f.applied = desired
	return f.applyErr
}

func (f *fakeRuntimeClient) Restore(_ context.Context, snapshot RuntimeSnapshot) error {
	f.restoreCalls++
	f.restored = snapshot
	return f.restoreErr
}

func (f *fakeRuntimeClient) Disable(_ context.Context, realm, alias string) error {
	f.disableCalls++
	if err := validateRuntimeCoordinates(realm, alias); err != nil {
		return err
	}
	return f.disableErr
}

func TestPublishRestoresSnapshotOnReadbackMismatch(t *testing.T) {
	desired := testDesiredIdentitySource(t)
	old := RuntimeSnapshot{Realm: RealmName, Alias: ProviderAlias, Exists: true, Digest: "sha256:old"}
	fake := &fakeRuntimeClient{
		snapshot: old,
		statuses: []RuntimeStatus{
			{Exists: true, Enabled: true, Digest: "sha256:old"},
			{Exists: true, Enabled: true, Digest: "sha256:different"},
		},
	}
	orchestrator := NewOrchestrator(fake)
	_, err := orchestrator.Publish(context.Background(), desired)
	if !errors.Is(err, ErrPublishVerification) {
		t.Fatalf("error=%v", err)
	}
	if fake.restoreCalls != 1 || fake.restored.Digest != old.Digest {
		t.Fatalf("restore calls=%d snapshot=%#v", fake.restoreCalls, fake.restored)
	}
}

func TestPublishIsIdempotentWhenDigestAndStructureMatch(t *testing.T) {
	desired := testDesiredIdentitySource(t)
	fake := &fakeRuntimeClient{statuses: []RuntimeStatus{{
		Exists: true, Enabled: true, Digest: desired.Digest, Drifted: false,
	}}}
	orchestrator := NewOrchestrator(fake)
	publication, err := orchestrator.Publish(context.Background(), desired)
	if err != nil {
		t.Fatal(err)
	}
	if !publication.AlreadyCurrent || publication.Digest != desired.Digest ||
		fake.snapshotCalls != 0 || fake.applyCalls != 0 {
		t.Fatalf("publication=%#v fake=%#v", publication, fake)
	}
}

func TestPublishRepairsStructuralDriftEvenWhenDigestMatches(t *testing.T) {
	desired := testDesiredIdentitySource(t)
	fake := &fakeRuntimeClient{
		snapshot: RuntimeSnapshot{Realm: RealmName, Alias: ProviderAlias, Exists: true},
		statuses: []RuntimeStatus{
			{Exists: true, Enabled: true, Digest: desired.Digest, Drifted: true},
			{Exists: true, Enabled: true, Digest: desired.Digest, Drifted: false},
		},
	}
	publication, err := NewOrchestrator(fake).Publish(context.Background(), desired)
	if err != nil {
		t.Fatal(err)
	}
	if publication.AlreadyCurrent || fake.applyCalls != 1 {
		t.Fatalf("publication=%#v applyCalls=%d", publication, fake.applyCalls)
	}
}

func TestPublishRestoresAfterApplyFailure(t *testing.T) {
	desired := testDesiredIdentitySource(t)
	old := RuntimeSnapshot{Realm: RealmName, Alias: ProviderAlias, Exists: true, Digest: "sha256:old"}
	fake := &fakeRuntimeClient{
		snapshot: old,
		statuses: []RuntimeStatus{{Exists: true, Enabled: true, Digest: "sha256:old"}},
		applyErr: ErrRuntimeUnavailable,
	}
	_, err := NewOrchestrator(fake).Publish(context.Background(), desired)
	if !errors.Is(err, ErrRuntimeUnavailable) || fake.restoreCalls != 1 {
		t.Fatalf("error=%v restoreCalls=%d", err, fake.restoreCalls)
	}
}

func TestPublishReportsRollbackFailure(t *testing.T) {
	desired := testDesiredIdentitySource(t)
	fake := &fakeRuntimeClient{
		snapshot: RuntimeSnapshot{Realm: RealmName, Alias: ProviderAlias, Exists: true},
		statuses: []RuntimeStatus{{Exists: true}},
		applyErr: ErrRuntimeUnavailable, restoreErr: ErrRuntimeUnavailable,
	}
	_, err := NewOrchestrator(fake).Publish(context.Background(), desired)
	if !errors.Is(err, ErrRollbackFailed) {
		t.Fatalf("error=%v", err)
	}
}

func TestPublishPreservesContextCancellation(t *testing.T) {
	desired := testDesiredIdentitySource(t)
	fake := &fakeRuntimeClient{statusErrors: []error{context.Canceled}}
	_, err := NewOrchestrator(fake).Publish(context.Background(), desired)
	if !errors.Is(err, context.Canceled) || fake.applyCalls != 0 || fake.restoreCalls != 0 {
		t.Fatalf("error=%v fake=%#v", err, fake)
	}
}

func TestDisableReturnsPreviousSnapshotAfterVerifiedDisable(t *testing.T) {
	desired := testDesiredIdentitySource(t)
	old := RuntimeSnapshot{
		Realm: RealmName, Alias: ProviderAlias, Exists: true,
		Provider: ProviderRepresentation{Alias: ProviderAlias, ProviderID: "oidc", Enabled: true},
	}
	fake := &fakeRuntimeClient{
		snapshot: old,
		statuses: []RuntimeStatus{{Exists: true, Enabled: false, Digest: desired.Digest}},
	}
	previous, err := NewOrchestrator(fake).Disable(context.Background(), desired)
	if err != nil {
		t.Fatal(err)
	}
	if !previous.Exists || fake.disableCalls != 1 || fake.restoreCalls != 0 {
		t.Fatalf("previous=%#v fake=%#v", previous, fake)
	}
}

func TestDisableRestoresWhenReadbackRemainsEnabled(t *testing.T) {
	desired := testDesiredIdentitySource(t)
	old := RuntimeSnapshot{
		Realm: RealmName, Alias: ProviderAlias, Exists: true,
		Provider: ProviderRepresentation{Alias: ProviderAlias, ProviderID: "oidc", Enabled: true},
	}
	fake := &fakeRuntimeClient{
		snapshot: old,
		statuses: []RuntimeStatus{{Exists: true, Enabled: true, Digest: desired.Digest}},
	}
	_, err := NewOrchestrator(fake).Disable(context.Background(), desired)
	if !errors.Is(err, ErrPublishVerification) || fake.restoreCalls != 1 {
		t.Fatalf("error=%v fake=%#v", err, fake)
	}
}

func TestDisableIsIdempotentWhenProviderDoesNotExist(t *testing.T) {
	desired := testDesiredIdentitySource(t)
	fake := &fakeRuntimeClient{
		snapshot: RuntimeSnapshot{Realm: RealmName, Alias: ProviderAlias, Exists: false},
	}
	previous, err := NewOrchestrator(fake).Disable(context.Background(), desired)
	if err != nil || previous.Exists || fake.disableCalls != 0 {
		t.Fatalf("previous=%#v error=%v fake=%#v", previous, err, fake)
	}
}

func TestStatusCombinesDigestStructureAndEnabledState(t *testing.T) {
	desired := testDesiredIdentitySource(t)
	cases := []struct {
		name   string
		status RuntimeStatus
		drift  bool
	}{
		{name: "matching", status: RuntimeStatus{Exists: true, Enabled: true, Digest: desired.Digest}, drift: false},
		{name: "digest", status: RuntimeStatus{Exists: true, Enabled: true, Digest: "sha256:other"}, drift: true},
		{name: "structure", status: RuntimeStatus{Exists: true, Enabled: true, Digest: desired.Digest, Drifted: true}, drift: true},
		{name: "disabled", status: RuntimeStatus{Exists: true, Enabled: false, Digest: desired.Digest}, drift: true},
		{name: "missing", status: RuntimeStatus{Exists: false}, drift: true},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			fake := &fakeRuntimeClient{statuses: []RuntimeStatus{testCase.status}}
			status, err := NewOrchestrator(fake).Status(context.Background(), desired)
			if err != nil {
				t.Fatal(err)
			}
			if status.Drifted != testCase.drift {
				t.Fatalf("status=%#v", status)
			}
		})
	}
}

func TestRestoreDelegatesOnlyTrustedSnapshotCoordinates(t *testing.T) {
	fake := &fakeRuntimeClient{}
	orchestrator := NewOrchestrator(fake)
	if err := orchestrator.Restore(context.Background(), RuntimeSnapshot{Realm: "master", Alias: ProviderAlias}); !errors.Is(err, ErrInvalidRuntimeTarget) {
		t.Fatalf("error=%v", err)
	}
	if fake.restoreCalls != 0 {
		t.Fatalf("restoreCalls=%d", fake.restoreCalls)
	}
	snapshot := RuntimeSnapshot{Realm: RealmName, Alias: ProviderAlias, Exists: false}
	if err := orchestrator.Restore(context.Background(), snapshot); err != nil {
		t.Fatal(err)
	}
	if fake.restoreCalls != 1 {
		t.Fatalf("restoreCalls=%d", fake.restoreCalls)
	}
}
