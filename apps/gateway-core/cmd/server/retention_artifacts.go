package main

import (
	"context"
	"log"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/yangjiyj/aiguard/packages/shared-go/retentionstore"
)

type artifactRetentionTarget interface {
	SetRetentionArtifactStore(retentionstore.Store)
}

func configureGatewayArtifactRetentionStore(ctx context.Context, db *pgxpool.Pool, localRoot string, targets ...artifactRetentionTarget) string {
	if len(targets) == 0 {
		return "disabled"
	}
	config, err := retentionstore.LoadConfig(ctx, db, localRoot)
	if err != nil {
		log.Printf("load gateway retention storage config failed: %v", err)
		return "error"
	}
	store, err := retentionstore.NewStore(config)
	if err != nil {
		log.Printf("gateway retention store init failed (backend=%s): %v", config.Backend, err)
		return "error"
	}
	for _, target := range targets {
		if target != nil {
			target.SetRetentionArtifactStore(store)
		}
	}
	log.Printf("Gateway artifact retention store initialized backend=%s", config.Backend)
	return "ok"
}
