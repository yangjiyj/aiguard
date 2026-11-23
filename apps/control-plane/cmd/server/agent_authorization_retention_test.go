package main

import (
	"context"
	"testing"
	"time"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

type blockingAgentAuthorizationRetentionRepo struct {
	started  chan struct{}
	canceled chan struct{}
}

func (repo *blockingAgentAuthorizationRetentionRepo) PruneExpiredData(ctx context.Context) (repository.AgentAuthorizationCleanupResult, error) {
	close(repo.started)
	<-ctx.Done()
	close(repo.canceled)
	return repository.AgentAuthorizationCleanupResult{Backlog: true}, ctx.Err()
}

func TestAgentAuthorizationRetentionCronPropagatesCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	repo := &blockingAgentAuthorizationRetentionRepo{
		started:  make(chan struct{}),
		canceled: make(chan struct{}),
	}
	startAgentAuthorizationRetentionCron(ctx, repo)

	select {
	case <-repo.started:
	case <-time.After(time.Second):
		t.Fatal("startup cleanup did not begin")
	}
	cancel()
	select {
	case <-repo.canceled:
	case <-time.After(time.Second):
		t.Fatal("cleanup did not observe context cancellation")
	}
}
