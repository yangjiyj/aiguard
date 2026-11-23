package main

import (
	"log"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/identitybinding"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/permission"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
	"github.com/jackc/pgx/v5/pgxpool"
)

type identityBindingRuntime struct {
	Service      *identitybinding.BindingService
	Reconciler   *identitybinding.Reconciler
	WorkerConfig identitybinding.WorkerConfig
}

func newIdentityBindingRuntime(
	db *pgxpool.Pool,
	checker *permission.Checker,
) identityBindingRuntime {
	store := repository.NewUserIdentityLinkRepository(db)
	service := identitybinding.NewService(store)
	reconciler := identitybinding.NewReconciler(
		store,
		identitybinding.NewPermissionCacheInvalidatorAdapter(checker),
		identitybinding.NewUncachedModelAuthorizationInvalidator(),
	)
	workerConfig := identitybinding.WorkerConfig{
		ErrorObserver: func(stage string, err error) {
			log.Printf(
				"component=identity_binding event=cache_invalidation_worker_error stage=%s error=%q",
				stage, err.Error(),
			)
		},
	}
	return identityBindingRuntime{
		Service: service, Reconciler: reconciler, WorkerConfig: workerConfig,
	}
}
