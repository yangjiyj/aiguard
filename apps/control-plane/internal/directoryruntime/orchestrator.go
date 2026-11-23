package directoryruntime

import (
	"context"
	"errors"
	"log"
)

var (
	ErrRuntimeUnavailable  = errors.New("directory runtime unavailable")
	ErrPublishVerification = errors.New("directory publish verification failed")
	ErrRollbackFailed      = errors.New("directory runtime rollback failed")
)

type RuntimeSnapshot struct {
	Exists    bool
	Component ComponentRepresentation
}

type RuntimeStatus struct {
	Exists  bool
	Enabled bool
	Digest  string
	Drifted bool
}

type Publication struct {
	Digest         string
	AlreadyCurrent bool
	Previous       RuntimeSnapshot
}

type RuntimeClient interface {
	Status(context.Context) (RuntimeStatus, error)
	Snapshot(context.Context) (RuntimeSnapshot, error)
	Apply(context.Context, DirectoryConfig, string) error
	Restore(context.Context, RuntimeSnapshot) error
}

type Orchestrator struct {
	client RuntimeClient
}

func NewOrchestrator(client RuntimeClient) *Orchestrator {
	return &Orchestrator{client: client}
}

func (orchestrator *Orchestrator) Publish(ctx context.Context, config DirectoryConfig) (Publication, error) {
	if orchestrator == nil || orchestrator.client == nil {
		return Publication{}, ErrRuntimeUnavailable
	}
	if err := ctx.Err(); err != nil {
		return Publication{}, err
	}
	digest, err := ComputeDigest(config)
	if err != nil {
		return Publication{}, err
	}

	snapshot, err := orchestrator.client.Snapshot(ctx)
	if err != nil {
		return Publication{}, err
	}
	if err := orchestrator.client.Apply(ctx, config, digest); err != nil {
		log.Printf("directory runtime publication apply failed")
		return Publication{}, orchestrator.restoreAfterFailure(ctx, snapshot, err)
	}
	readback, err := orchestrator.client.Status(ctx)
	if err != nil || !readback.Exists || !readback.Enabled || readback.Drifted || readback.Digest != digest {
		log.Printf("directory runtime publication verification failed readback_error=%t exists=%t enabled=%t drifted=%t digest_matches=%t", err != nil, readback.Exists, readback.Enabled, readback.Drifted, readback.Digest == digest)
		return Publication{}, orchestrator.restoreAfterFailure(ctx, snapshot, ErrPublishVerification)
	}
	return Publication{Digest: digest, Previous: snapshot}, nil
}

func (orchestrator *Orchestrator) restoreAfterFailure(ctx context.Context, snapshot RuntimeSnapshot, original error) error {
	if err := orchestrator.client.Restore(context.WithoutCancel(ctx), snapshot); err != nil {
		return ErrRollbackFailed
	}
	return original
}
func (orchestrator *Orchestrator) FullSync(ctx context.Context) error {
	if orchestrator == nil || orchestrator.client == nil {
		return ErrRuntimeUnavailable
	}
	client, ok := orchestrator.client.(interface{ FullSync(context.Context) error })
	if !ok {
		return ErrRuntimeUnavailable
	}
	return client.FullSync(ctx)
}

// Status 透传运行态客户端的状态读回，用于总览探活（不修改运行态）。
// RuntimeStatus 反映当前已发布组件是否启用、digest 是否匹配。
// 运行态不可达时返回非 nil 错误，由调用方降级为 runtime_healthy=false。
func (orchestrator *Orchestrator) Status(ctx context.Context) (RuntimeStatus, error) {
	if orchestrator == nil || orchestrator.client == nil {
		return RuntimeStatus{}, ErrRuntimeUnavailable
	}
	if err := ctx.Err(); err != nil {
		return RuntimeStatus{}, err
	}
	return orchestrator.client.Status(ctx)
}

func (orchestrator *Orchestrator) Disable(ctx context.Context) (RuntimeSnapshot, error) {
	if orchestrator == nil || orchestrator.client == nil {
		return RuntimeSnapshot{}, ErrRuntimeUnavailable
	}
	if err := ctx.Err(); err != nil {
		return RuntimeSnapshot{}, err
	}
	snapshot, err := orchestrator.client.Snapshot(ctx)
	if err != nil {
		return RuntimeSnapshot{}, err
	}
	if !snapshot.Exists || snapshot.Component.ID == "" {
		return RuntimeSnapshot{}, ErrRuntimeUnavailable
	}
	disabled := cloneRuntimeSnapshot(snapshot)
	disabled.Component.Config["enabled"] = []string{"false"}
	if err := orchestrator.client.Restore(ctx, disabled); err != nil {
		return RuntimeSnapshot{}, orchestrator.restoreAfterFailure(ctx, snapshot, err)
	}
	readback, err := orchestrator.client.Status(ctx)
	if err != nil || !readback.Exists || readback.Enabled {
		return RuntimeSnapshot{}, orchestrator.restoreAfterFailure(ctx, snapshot, ErrPublishVerification)
	}
	return snapshot, nil
}

func (orchestrator *Orchestrator) Restore(ctx context.Context, snapshot RuntimeSnapshot) error {
	if orchestrator == nil || orchestrator.client == nil {
		return ErrRuntimeUnavailable
	}
	return orchestrator.client.Restore(ctx, snapshot)
}

func cloneRuntimeSnapshot(snapshot RuntimeSnapshot) RuntimeSnapshot {
	clone := snapshot
	clone.Component.Config = make(map[string][]string, len(snapshot.Component.Config))
	for key, values := range snapshot.Component.Config {
		clone.Component.Config[key] = append([]string(nil), values...)
	}
	return clone
}
