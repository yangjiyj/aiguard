package notifydispatch

import (
	"context"

	internalnotify "github.com/yangjiyj/aiguard/apps/control-plane/internal/notify"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Dispatcher struct {
	inner *internalnotify.Dispatcher
}

func New(db *pgxpool.Pool) *Dispatcher {
	return &Dispatcher{inner: internalnotify.NewDispatcher(repository.NewNotifyChannelsRepository(db))}
}

func (d *Dispatcher) DispatchChannel(ctx context.Context, tenantID, channelID, severity, title string, body map[string]any) error {
	return d.inner.DispatchChannel(ctx, tenantID, channelID, severity, title, body)
}
