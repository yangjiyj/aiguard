package identityruntime

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"time"
)

const rollbackTimeout = 10 * time.Second

type RuntimeClient interface {
	Snapshot(context.Context, string, string) (RuntimeSnapshot, error)
	Status(context.Context, string, string) (RuntimeStatus, error)
	Apply(context.Context, DesiredIdentitySource) error
	Restore(context.Context, RuntimeSnapshot) error
	Disable(context.Context, string, string) error
}

type Orchestrator struct {
	client RuntimeClient
}

func NewOrchestrator(client RuntimeClient) *Orchestrator {
	return &Orchestrator{client: client}
}

func (o *Orchestrator) Publish(ctx context.Context, desired DesiredIdentitySource) (Publication, error) {
	if o == nil || o.client == nil {
		return Publication{}, ErrRuntimeUnavailable
	}
	if err := ctx.Err(); err != nil {
		return Publication{}, err
	}
	digest, err := verifyDesiredDigest(desired)
	if err != nil {
		return Publication{}, err
	}
	desired.Digest = digest

	current, err := o.client.Status(ctx, RealmName, desired.Alias)
	if err != nil {
		return Publication{}, err
	}
	if current.Exists && current.Enabled && !current.Drifted && current.Digest == digest {
		return Publication{Digest: digest, AlreadyCurrent: true}, nil
	}

	snapshot, err := o.client.Snapshot(ctx, RealmName, desired.Alias)
	if err != nil {
		return Publication{}, err
	}
	if err := o.client.Apply(ctx, desired); err != nil {
		if restoreErr := o.restoreAfterFailure(ctx, snapshot); restoreErr != nil {
			return Publication{}, ErrRollbackFailed
		}
		return Publication{}, err
	}

	readback, readbackErr := o.client.Status(ctx, RealmName, desired.Alias)
	if readbackErr != nil || !readback.Exists || !readback.Enabled || readback.Drifted || readback.Digest != digest {
		if restoreErr := o.restoreAfterFailure(ctx, snapshot); restoreErr != nil {
			return Publication{}, ErrRollbackFailed
		}
		return Publication{}, ErrPublishVerification
	}
	return Publication{Digest: digest, Previous: snapshot}, nil
}

func (o *Orchestrator) Disable(ctx context.Context, desired DesiredIdentitySource) (RuntimeSnapshot, error) {
	if o == nil || o.client == nil {
		return RuntimeSnapshot{}, ErrRuntimeUnavailable
	}
	if err := validateRuntimeCoordinates(desired.Realm, desired.Alias); err != nil {
		return RuntimeSnapshot{}, err
	}
	if err := ctx.Err(); err != nil {
		return RuntimeSnapshot{}, err
	}
	snapshot, err := o.client.Snapshot(ctx, RealmName, desired.Alias)
	if err != nil {
		return RuntimeSnapshot{}, err
	}
	if !snapshot.Exists || !snapshot.Provider.Enabled {
		return snapshot, nil
	}
	if err := o.client.Disable(ctx, RealmName, desired.Alias); err != nil {
		if restoreErr := o.restoreAfterFailure(ctx, snapshot); restoreErr != nil {
			return RuntimeSnapshot{}, ErrRollbackFailed
		}
		return RuntimeSnapshot{}, err
	}
	readback, readbackErr := o.client.Status(ctx, RealmName, desired.Alias)
	if readbackErr != nil || !readback.Exists || readback.Enabled {
		if restoreErr := o.restoreAfterFailure(ctx, snapshot); restoreErr != nil {
			return RuntimeSnapshot{}, ErrRollbackFailed
		}
		return RuntimeSnapshot{}, ErrPublishVerification
	}
	return snapshot, nil
}

func (o *Orchestrator) Status(ctx context.Context, desired DesiredIdentitySource) (RuntimeStatus, error) {
	if o == nil || o.client == nil {
		return RuntimeStatus{}, ErrRuntimeUnavailable
	}
	expected, err := expectedDigest(desired)
	if err != nil {
		return RuntimeStatus{}, err
	}
	status, err := o.client.Status(ctx, RealmName, desired.Alias)
	if err != nil {
		return RuntimeStatus{}, err
	}
	status.Drifted = status.Drifted || !status.Exists || !status.Enabled || status.Digest != expected
	return status, nil
}

// Observe 只读反推运行态选项（采纳运行态用），不写运行态。
func (o *Orchestrator) Observe(ctx context.Context, desired DesiredIdentitySource) (ObservedSettings, error) {
	if o == nil || o.client == nil {
		return ObservedSettings{}, ErrRuntimeUnavailable
	}
	if err := validateRuntimeCoordinates(RealmName, desired.Alias); err != nil {
		return ObservedSettings{}, err
	}
	observer, ok := o.client.(interface {
		Observe(context.Context, string, string) (ObservedSettings, error)
	})
	if !ok {
		return ObservedSettings{}, ErrRuntimeUnavailable
	}
	return observer.Observe(ctx, RealmName, desired.Alias)
}

func (o *Orchestrator) Restore(ctx context.Context, snapshot RuntimeSnapshot) error {
	if o == nil || o.client == nil {
		return ErrRuntimeUnavailable
	}
	if err := validateRuntimeCoordinates(snapshot.Realm, snapshot.Alias); err != nil {
		return err
	}
	return o.client.Restore(ctx, snapshot)
}

func (o *Orchestrator) restoreAfterFailure(ctx context.Context, snapshot RuntimeSnapshot) error {
	recoveryCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), rollbackTimeout)
	defer cancel()
	return o.client.Restore(recoveryCtx, snapshot)
}

func expectedDigest(desired DesiredIdentitySource) (string, error) {
	if err := validateRuntimeCoordinates(desired.Realm, desired.Alias); err != nil {
		return "", err
	}
	if desired.Digest == "" {
		return verifyDesiredDigest(desired)
	}
	if !validConfigDigest(desired.Digest) {
		return "", ErrInvalidDesiredSource
	}
	return desired.Digest, nil
}

func validConfigDigest(digest string) bool {
	if !strings.HasPrefix(digest, "sha256:") || len(digest) != len("sha256:")+sha256.Size*2 {
		return false
	}
	_, err := hex.DecodeString(strings.TrimPrefix(digest, "sha256:"))
	return err == nil
}

var _ RuntimeClient = (*Client)(nil)
