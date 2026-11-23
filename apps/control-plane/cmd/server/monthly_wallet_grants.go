package main

import (
	"context"
	"log"
	"time"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/billing"
)

type monthlyWalletGrantFunc func(context.Context, time.Time, int) (billing.MonthlyWalletGrantResult, error)

// Admission uses the same grant transaction, so a delayed tick cannot deny a
// funded account at the month boundary. Each tick processes one bounded batch.
func startMonthlyWalletGrants(ctx context.Context, grant monthlyWalletGrantFunc) <-chan struct{} {
	done := make(chan struct{})
	go func() {
		defer close(done)
		run := func(label string) {
			runCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
			defer cancel()
			result, err := grant(runCtx, time.Now().UTC(), 500)
			if err != nil {
				log.Printf("[monthly_wallet] %s synchronized=%d failed=%d backlog=%v: %v", label, result.Synchronized, result.Failed, result.Backlog, err)
			} else if result.Attempted > 0 || result.Backlog {
				log.Printf("[monthly_wallet] %s synchronized=%d backlog=%v", label, result.Synchronized, result.Backlog)
			}
		}
		run("startup")
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				run("scheduled")
			}
		}
	}()
	return done
}
