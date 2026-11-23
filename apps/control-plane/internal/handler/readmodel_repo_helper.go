package handler

import (
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

// repositoryForReadModels builds the read-only evidence repository from the
// read-model dependency set. All queries are SELECT-only.
func repositoryForReadModels(deps ReadModelDeps) *repository.ServiceHealthReadModelRepository {
	return repository.NewServiceHealthReadModelRepository(deps.DB)
}
