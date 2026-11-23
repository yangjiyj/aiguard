package handler

import "sync"

type providerSyncKey struct {
	tenantID   string
	providerID string
}

type providerSyncGate struct {
	inFlight sync.Map
}

func (g *providerSyncGate) tryStart(tenantID, providerID string) bool {
	_, loaded := g.inFlight.LoadOrStore(providerSyncKey{tenantID: tenantID, providerID: providerID}, struct{}{})
	return !loaded
}

func (g *providerSyncGate) finish(tenantID, providerID string) {
	g.inFlight.Delete(providerSyncKey{tenantID: tenantID, providerID: providerID})
}
