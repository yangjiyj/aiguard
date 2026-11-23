package handler

import (
	"context"
	"errors"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/directoryruntime"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

var ErrDirectoryRuntimeUnavailable = errors.New("directory runtime unavailable")

// DirectoryRuntime 是目录身份运行态的依赖抽象。Status 用于总览探活，
// 其余方法用于发布与同步。运行态不可达时 Status 返回非 nil 错误，
// 调用方据此把总览降级为 runtime_healthy=false 而非 500。
type DirectoryRuntime interface {
	Publish(context.Context, directoryruntime.DirectoryConfig) (directoryruntime.Publication, error)
	FullSync(context.Context) error
	Status(context.Context) (directoryruntime.RuntimeStatus, error)
}

func publishDirectorySource(ctx context.Context, runtime DirectoryRuntime, source *repository.DirectorySource, bindPassword string) error {
	if runtime == nil || source == nil || bindPassword == "" {
		return ErrDirectoryRuntimeUnavailable
	}
	_, err := runtime.Publish(ctx, directoryruntime.DirectoryConfig{
		Kind:          directoryruntime.DirectoryKind(source.Kind),
		ConnectionURL: source.ConnectionURL,
		BindDN:        source.BindDN,
		BindPassword:  bindPassword,
		UsersDN:       source.UsersDN,
	})
	if err != nil {
		return err
	}
	return runtime.FullSync(ctx)
}
