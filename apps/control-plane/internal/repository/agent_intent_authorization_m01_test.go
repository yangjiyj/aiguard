package repository

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/yangjiyj/aiguard/packages/shared-go/agentintent"
	"github.com/jackc/pgx/v5"
)

type m01FailingRow struct{ err error }

func (r m01FailingRow) Scan(...any) error { return r.err }

type m01FailingQuerier struct{ err error }

func (q m01FailingQuerier) Query(context.Context, string, ...any) (pgx.Rows, error) {
	return nil, q.err
}
func (q m01FailingQuerier) QueryRow(context.Context, string, ...any) pgx.Row {
	return m01FailingRow{q.err}
}

// T22IR-M01 boundary: an infrastructure error while walking the delegation chain
// is returned as an error (409/unavailable, F03 scope), never disguised as a deny.
func TestResolveT13RowInfrastructureErrorIsNotDeny(t *testing.T) {
	dbDown := errors.New("db down")
	item := expectedT13Facet{facet: agentintent.AuthorizationFacet{Action: "file_write", ResourceType: "file", ResourceID: "/tmp/x"}, key: "k"}
	res, err := resolveT13Row(context.Background(), m01FailingQuerier{dbDown}, "tenant", item,
		resolvedT13AuthorizationRow{principalID: "p"}, time.Now())
	if !errors.Is(err, dbDown) || res.Reason != "" || res.Allowed {
		t.Fatalf("infra error: res=%+v err=%v, want the db error and no resolution", res, err)
	}
	if !isDelegationChainFault(ErrAgentAuthorizationPrincipalUnauthorized) || !isDelegationChainFault(ErrAgentAuthorizationInvalid) || isDelegationChainFault(dbDown) {
		t.Fatal("chain-fault classification changed")
	}
	if safeIntentDecisionReason(t13DelegationChainDeniedReason) != "delegation_parent_inactive" {
		t.Fatal("delegation deny reason is not passed through")
	}
}
