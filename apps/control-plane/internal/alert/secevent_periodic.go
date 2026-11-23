package alert

import (
	"context"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/alertconfig"
	"time"
)

// RunPeriodic is the production scheduler and is exercised against PostgreSQL.
func (b *SecEventBridge) RunPeriodic(ctx context.Context, maxBatches int, report func(int, error)) {
	drain := func() {
		n, err := b.DrainBatches(ctx, maxBatches)
		if report != nil {
			report(n, err)
		}
	}
	drain()
	ticker := time.NewTicker(alertconfig.BridgeInterval())
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			drain()
		}
	}
}
