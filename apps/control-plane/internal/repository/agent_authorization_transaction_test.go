package repository

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

type fakeAuthorizationGrant struct {
	id            string
	action        string
	resourceType  string
	resourceID    string
	conditions    string
	expiresAt     time.Time
	quotaMax      int64
	windowSeconds int
}

type fakeAuthorizationDelegationEdge struct {
	id, parentID, childID, projectID string
	expiresAt                        time.Time
	parentStatus                     string
	parentExpiresAt                  time.Time
}

type fakeAuthorizationRequestRow struct {
	requestHash string
	state       string
	decision    []byte
	grantID     string
	expiresAt   time.Time
}

type fakeAuthorizationDBState struct {
	transactionStart         time.Time
	databaseNow              time.Time
	tenantID                 string
	principalID              string
	credentialHash           string
	principalExpires         time.Time
	principalActive          bool
	grant                    *fakeAuthorizationGrant
	requests                 map[string]*fakeAuthorizationRequestRow
	usage                    map[string]int64
	lastWindowStart          time.Time
	beginCount               int
	commitCount              int
	rollbackCount            int
	finalDecisionAt          time.Time
	finalDecisionCount       int
	delegation               *fakeAuthorizationDelegationEdge
	parentGrantID            string
	parentGrant              *fakeAuthorizationGrant
	databaseNowAfterDecision time.Time
	databaseNowAfterLookup   time.Time
	quotaWriteCount          int
}

type fakeAuthorizationDB struct {
	agentAuthorizationDatabase
	state *fakeAuthorizationDBState
}

func (db *fakeAuthorizationDB) Begin(context.Context) (pgx.Tx, error) {
	db.state.beginCount++
	return &fakeAuthorizationTx{state: db.state, transactionStart: db.state.transactionStart, requestsBefore: cloneFakeAuthorizationRequests(db.state.requests), usageBefore: cloneFakeAuthorizationUsage(db.state.usage), lastWindowStartBefore: db.state.lastWindowStart}, nil
}

type fakeAuthorizationTx struct {
	pgx.Tx
	state                 *fakeAuthorizationDBState
	transactionStart      time.Time
	committed             bool
	requestsBefore        map[string]*fakeAuthorizationRequestRow
	usageBefore           map[string]int64
	lastWindowStartBefore time.Time
}

func cloneFakeAuthorizationRequests(input map[string]*fakeAuthorizationRequestRow) map[string]*fakeAuthorizationRequestRow {
	output := make(map[string]*fakeAuthorizationRequestRow, len(input))
	for key, row := range input {
		copyRow := *row
		copyRow.decision = append([]byte(nil), row.decision...)
		output[key] = &copyRow
	}
	return output
}

func cloneFakeAuthorizationUsage(input map[string]int64) map[string]int64 {
	output := make(map[string]int64, len(input))
	for key, used := range input {
		output[key] = used
	}
	return output
}

func (tx *fakeAuthorizationTx) dbNow(query string) time.Time {
	if strings.Contains(query, "clock_timestamp()") {
		return tx.state.databaseNow
	}
	return tx.transactionStart
}

func (tx *fakeAuthorizationTx) hasTenantPrincipalScope(args []any, tenantIndex, principalIndex int) bool {
	if len(args) <= tenantIndex || len(args) <= principalIndex {
		return false
	}
	tenantID, tenantOK := args[tenantIndex].(string)
	principalID, principalOK := args[principalIndex].(string)
	return tenantOK && principalOK && tenantID == tx.state.tenantID && principalID == tx.state.principalID
}

func (tx *fakeAuthorizationTx) QueryRow(_ context.Context, query string, args ...any) pgx.Row {
	switch {
	case strings.Contains(query, "SELECT credential_hash, expires_at"):
		if !tx.hasTenantPrincipalScope(args, 1, 0) || !tx.state.principalActive {
			return fakeAuthorizationRow{err: pgx.ErrNoRows}
		}
		return fakeAuthorizationRow{values: []any{tx.state.credentialHash, tx.state.principalExpires}}
	case strings.TrimSpace(query) == "SELECT clock_timestamp()":
		return fakeAuthorizationRow{values: []any{tx.state.databaseNow}}
	case strings.Contains(query, "SELECT parent_principal_id::text FROM agent_delegations"):
		edge := tx.state.delegation
		if edge != nil && len(args) > 1 && args[0] == tx.state.tenantID && args[1] == edge.childID {
			return fakeAuthorizationRow{values: []any{edge.parentID}}
		}
		return fakeAuthorizationRow{err: pgx.ErrNoRows}
	case strings.Contains(query, "FROM agent_delegations d JOIN agent_authorization_principals"):
		edge := tx.state.delegation
		if edge == nil || len(args) < 2 || args[0] != tx.state.tenantID || args[1] != edge.childID {
			return fakeAuthorizationRow{err: pgx.ErrNoRows}
		}
		return fakeAuthorizationRow{values: []any{
			edge.id, edge.parentID, edge.childID, edge.projectID, edge.expiresAt,
			nil, edge.parentStatus, edge.parentExpiresAt, nil,
		}}
	case strings.Contains(query, "SELECT EXISTS(SELECT 1 FROM agent_delegations"):
		return fakeAuthorizationRow{values: []any{false}}
	case strings.Contains(query, "FROM agent_delegation_grants m JOIN agent_authorization_grants"):
		edge, parent := tx.state.delegation, tx.state.parentGrant
		if edge == nil || parent == nil || len(args) < 6 ||
			args[0] != tx.state.tenantID || args[1] != edge.id || args[2] != edge.childID ||
			args[3] != tx.state.grant.id || args[4] != edge.parentID {
			return fakeAuthorizationRow{err: pgx.ErrNoRows}
		}
		now, ok := args[5].(time.Time)
		if !ok || !parent.expiresAt.After(now) {
			return fakeAuthorizationRow{err: pgx.ErrNoRows}
		}
		return fakeAuthorizationRow{values: []any{
			tx.state.parentGrantID, edge.parentID, parent.action, parent.resourceType,
			parent.resourceID, parent.conditions, parent.expiresAt, parent.quotaMax, parent.windowSeconds,
		}}
	case strings.Contains(query, "p.expires_at>$4") && strings.Contains(query, "g.expires_at>$4"):
		if len(args) < 5 || !tx.hasTenantPrincipalScope(args, 1, 0) || args[2] != tx.state.credentialHash {
			return fakeAuthorizationRow{err: errors.New("final leaf recheck omitted trusted identity")}
		}
		now, ok := args[3].(time.Time)
		if !ok {
			return fakeAuthorizationRow{err: errors.New("final leaf recheck omitted shared decision time")}
		}
		principalActive := tx.state.principalActive && tx.state.principalExpires.After(now)
		grantActive := true
		if args[4] != nil {
			grantID, ok := args[4].(string)
			grant := tx.state.grant
			grantActive = ok && grant != nil && grant.id == grantID && grant.expiresAt.After(now)
		}
		return fakeAuthorizationRow{values: []any{principalActive, grantActive}}
	case strings.Contains(query, "SELECT request_hash, state, decision_json"):
		if !tx.hasTenantPrincipalScope(args, 0, 1) {
			return fakeAuthorizationRow{err: errors.New("request lookup omitted tenant/principal scope")}
		}
		row := tx.state.requests[args[2].(string)]
		if row == nil {
			return fakeAuthorizationRow{err: pgx.ErrNoRows}
		}
		if !tx.state.databaseNowAfterLookup.IsZero() {
			tx.state.databaseNow = tx.state.databaseNowAfterLookup
		}
		return fakeAuthorizationRow{values: []any{row.requestHash, row.state, row.decision, row.grantID}}
	case strings.Contains(query, "WITH decision_clock AS MATERIALIZED"):
		tx.state.finalDecisionCount++
		if strings.Count(query, "clock_timestamp()") != 1 ||
			!strings.Contains(query, "p.credential_hash=$3") ||
			!strings.Contains(query, "g.id=$4") {
			return fakeAuthorizationRow{err: errors.New("final authorization query must use one shared clock and bind trusted identity")}
		}
		if !tx.hasTenantPrincipalScope(args, 1, 0) || args[2] != tx.state.credentialHash {
			return fakeAuthorizationRow{err: errors.New("final authorization query omitted tenant/principal/credential scope")}
		}
		checkAt := tx.state.databaseNow
		if !tx.state.finalDecisionAt.IsZero() {
			checkAt = tx.state.finalDecisionAt
		}
		principalActive := tx.state.principalActive && tx.state.principalExpires.After(checkAt)
		grantActive := true
		if args[3] != nil {
			grantID, ok := args[3].(string)
			if !ok {
				return fakeAuthorizationRow{err: errors.New("final grant id is not text")}
			}
			grant := tx.state.grant
			grantActive = grant != nil && grant.id == grantID && grant.expiresAt.After(checkAt)
		}
		return fakeAuthorizationRow{values: []any{principalActive, grantActive}}
	case strings.Contains(query, "SELECT g.id::text, g.conditions_json::text"):
		if !tx.hasTenantPrincipalScope(args, 0, 1) {
			return fakeAuthorizationRow{err: errors.New("grant lookup omitted tenant/principal scope")}
		}
		grant := tx.state.grant
		if grant == nil ||
			grant.action != args[2].(string) ||
			grant.resourceType != args[3].(string) ||
			grant.resourceID != args[4].(string) ||
			!grant.expiresAt.After(tx.dbNow(query)) {
			return fakeAuthorizationRow{err: pgx.ErrNoRows}
		}
		return fakeAuthorizationRow{values: []any{
			grant.id, grant.conditions, grant.expiresAt, grant.quotaMax, grant.windowSeconds,
		}}
	case strings.Contains(query, "INSERT INTO agent_authorization_usage"):
		tenantID, tenantOK := args[0].(string)
		principalID, principalOK := args[1].(string)
		edge := tx.state.delegation
		principalScoped := tx.hasTenantPrincipalScope(args, 0, 1)
		parentScoped := edge != nil && principalOK && principalID == edge.parentID
		if !tenantOK || tenantID != tx.state.tenantID || (!principalScoped && !parentScoped) {
			return fakeAuthorizationRow{err: errors.New("quota update omitted tenant/principal scope")}
		}
		grantID := args[2].(string)
		windowSeconds := int64(args[3].(int))
		quotaMaxIndex := 4
		now := tx.dbNow(query)
		if len(args) >= 6 {
			var ok bool
			now, ok = args[4].(time.Time)
			if !ok {
				return fakeAuthorizationRow{err: errors.New("ancestor quota update omitted database time")}
			}
			quotaMaxIndex = 5
		}
		quotaMax := args[quotaMaxIndex].(int64)
		windowStart := time.Unix((now.Unix()/windowSeconds)*windowSeconds, 0).UTC()
		key := grantID + "/" + windowStart.Format(time.RFC3339Nano)
		used := tx.state.usage[key]
		if used >= quotaMax {
			return fakeAuthorizationRow{err: pgx.ErrNoRows}
		}
		used++
		tx.state.usage[key] = used
		tx.state.lastWindowStart = windowStart
		tx.state.quotaWriteCount++
		return fakeAuthorizationRow{values: []any{used}}
	default:
		return fakeAuthorizationRow{err: fmt.Errorf("unexpected QueryRow SQL: %s", query)}
	}
}

func (tx *fakeAuthorizationTx) Exec(_ context.Context, query string, args ...any) (pgconn.CommandTag, error) {
	switch {
	case strings.Contains(query, "pg_advisory_xact_lock"):
		return pgconn.NewCommandTag("SELECT 1"), nil
	case strings.HasPrefix(strings.TrimSpace(query), "SAVEPOINT"),
		strings.HasPrefix(strings.TrimSpace(query), "RELEASE SAVEPOINT"),
		strings.HasPrefix(strings.TrimSpace(query), "ROLLBACK TO SAVEPOINT"),
		strings.Contains(query, "INSERT INTO agent_delegation_calls"):
		return pgconn.NewCommandTag("OK"), nil
	case strings.Contains(query, "INSERT INTO agent_authorization_requests"):
		if !tx.hasTenantPrincipalScope(args, 0, 1) {
			return pgconn.CommandTag{}, errors.New("request insert omitted tenant/principal scope")
		}
		key := args[2].(string)
		requestHash := args[3].(string)
		row := tx.state.requests[key]
		if row == nil || !row.expiresAt.After(tx.dbNow(query)) {
			tx.state.requests[key] = &fakeAuthorizationRequestRow{
				requestHash: requestHash,
				state:       "pending",
				expiresAt:   tx.dbNow(query).Add(AgentAuthorizationIdempotencyTTL),
			}
		}
		return pgconn.NewCommandTag("INSERT 0 1"), nil
	case strings.Contains(query, "SET state='complete'"):
		if !tx.hasTenantPrincipalScope(args, 2, 3) {
			return pgconn.CommandTag{}, errors.New("decision update omitted tenant/principal scope")
		}
		key := args[4].(string)
		row := tx.state.requests[key]
		if row == nil {
			return pgconn.CommandTag{}, fmt.Errorf("decision update has no idempotency row")
		}
		row.state = "complete"
		row.decision = append([]byte(nil), args[0].([]byte)...)
		if args[1] == nil {
			row.grantID = ""
		} else {
			row.grantID = args[1].(string)
		}
		if !tx.state.databaseNowAfterDecision.IsZero() {
			tx.state.databaseNow = tx.state.databaseNowAfterDecision
		}
		return pgconn.NewCommandTag("UPDATE 1"), nil
	default:
		return pgconn.CommandTag{}, fmt.Errorf("unexpected Exec SQL: %s", query)
	}
}

func (tx *fakeAuthorizationTx) Commit(context.Context) error {
	tx.committed = true
	tx.state.commitCount++
	return nil
}

func (tx *fakeAuthorizationTx) Rollback(context.Context) error {
	tx.state.rollbackCount++
	if !tx.committed {
		tx.state.requests = tx.requestsBefore
		tx.state.usage = tx.usageBefore
		tx.state.lastWindowStart = tx.lastWindowStartBefore
	}
	return nil
}

type fakeAuthorizationRow struct {
	values []any
	err    error
}

func (row fakeAuthorizationRow) Scan(dest ...any) error {
	if row.err != nil {
		return row.err
	}
	if len(dest) != len(row.values) {
		return fmt.Errorf("Scan got %d destinations for %d values", len(dest), len(row.values))
	}
	for i, value := range row.values {
		switch target := dest[i].(type) {
		case *string:
			converted, ok := value.(string)
			if !ok {
				return fmt.Errorf("Scan value %d is %T, want string", i, value)
			}
			*target = converted
		case *[]byte:
			converted, ok := value.([]byte)
			if !ok {
				return fmt.Errorf("Scan value %d is %T, want []byte", i, value)
			}
			*target = append((*target)[:0], converted...)
		case *bool:
			converted, ok := value.(bool)
			if !ok {
				return fmt.Errorf("Scan value %d is %T, want bool", i, value)
			}
			*target = converted
		case *time.Time:
			converted, ok := value.(time.Time)
			if !ok {
				return fmt.Errorf("Scan value %d is %T, want time.Time", i, value)
			}
			*target = converted
		case **time.Time:
			if value == nil {
				*target = nil
				continue
			}
			converted, ok := value.(time.Time)
			if !ok {
				return fmt.Errorf("Scan value %d is %T, want nullable time.Time", i, value)
			}
			copyValue := converted
			*target = &copyValue
		case *int64:
			converted, ok := value.(int64)
			if !ok {
				return fmt.Errorf("Scan value %d is %T, want int64", i, value)
			}
			*target = converted
		case *int:
			converted, ok := value.(int)
			if !ok {
				return fmt.Errorf("Scan value %d is %T, want int", i, value)
			}
			*target = converted
		default:
			return fmt.Errorf("unsupported Scan destination %T", dest[i])
		}
	}
	return nil
}

func newFakeAuthorizationRepository(transactionStart, databaseNow, principalExpires time.Time, grant *fakeAuthorizationGrant) (*AgentAuthorizationRepository, *fakeAuthorizationDBState, TrustedAgentPrincipal) {
	state := &fakeAuthorizationDBState{
		transactionStart: transactionStart,
		databaseNow:      databaseNow,
		tenantID:         "tenant-1",
		principalID:      "principal-1",
		credentialHash:   strings.Repeat("a", 64),
		principalExpires: principalExpires,
		principalActive:  true,
		grant:            grant,
		requests:         map[string]*fakeAuthorizationRequestRow{},
		usage:            map[string]int64{},
	}
	principal := TrustedAgentPrincipal{
		ID:             "principal-1",
		TenantID:       "tenant-1",
		CredentialHash: state.credentialHash,
		ExpiresAt:      principalExpires,
	}
	return NewAgentAuthorizationRepository(&fakeAuthorizationDB{state: state}), state, principal
}

func validFakeAuthorizationRequest() AgentAuthorizationRequest {
	return AgentAuthorizationRequest{
		Action: "records.read", ResourceType: "record", ResourceID: "record-17",
		Context: map[string]any{"environment": "staging"}, IdempotencyKey: "request-2026-000001",
	}
}

func validFakeAuthorizationGrant(expires time.Time) *fakeAuthorizationGrant {
	conditions, _ := json.Marshal(map[string]any{"environment": "staging"})
	return &fakeAuthorizationGrant{
		id: "grant-1", action: "records.read", resourceType: "record", resourceID: "record-17",
		conditions: string(conditions), expiresAt: expires, quotaMax: 3, windowSeconds: 60,
	}
}

func TestAgentAuthorizationTransactionAllowReplayAndQuotaUsesPostLockWindow(t *testing.T) {
	txStart := time.Date(2026, 9, 25, 12, 0, 59, 900000000, time.UTC)
	dbNow := time.Date(2026, 9, 25, 12, 1, 0, 100000000, time.UTC)
	grant := validFakeAuthorizationGrant(dbNow.Add(time.Hour))
	repo, state, principal := newFakeAuthorizationRepository(txStart, dbNow, dbNow.Add(time.Hour), grant)
	request := validFakeAuthorizationRequest()

	first, err := repo.Authorize(context.Background(), principal, request)
	if err != nil {
		t.Fatalf("first authorization failed: %v", err)
	}
	if !first.Allowed || first.Reason != "allowed" || first.GrantID != "grant-1" {
		t.Fatalf("unexpected first decision: %+v", first)
	}
	if want := time.Date(2026, 9, 25, 12, 1, 0, 0, time.UTC); !state.lastWindowStart.Equal(want) {
		t.Fatalf("quota charged to %s, want post-lock database window %s", state.lastWindowStart, want)
	}
	if got := totalFakeUsage(state); got != 1 {
		t.Fatalf("quota used after first decision=%d, want 1", got)
	}

	replay, err := repo.Authorize(context.Background(), principal, request)
	if err != nil {
		t.Fatalf("same-key replay failed: %v", err)
	}
	if !replay.Allowed || replay.GrantID != first.GrantID {
		t.Fatalf("replay changed decision: first=%+v replay=%+v", first, replay)
	}
	if got := totalFakeUsage(state); got != 1 {
		t.Fatalf("same-key replay consumed quota again: used=%d", got)
	}

	changed := request
	changed.ResourceID = "record-18"
	if _, err := repo.Authorize(context.Background(), principal, changed); !errors.Is(err, ErrAgentAuthorizationIdempotencyConflict) {
		t.Fatalf("changed request with same key error=%v, want idempotency conflict", err)
	}
	if got := totalFakeUsage(state); got != 1 {
		t.Fatalf("conflicting replay changed quota: used=%d", got)
	}
}

func TestAgentAuthorizationTransactionScopesTenantAndPrincipalBeforeWrites(t *testing.T) {
	now := time.Date(2026, 9, 25, 12, 1, 0, 0, time.UTC)
	for _, tc := range []struct {
		name   string
		mutate func(*TrustedAgentPrincipal)
	}{
		{name: "cross tenant", mutate: func(principal *TrustedAgentPrincipal) { principal.TenantID = "tenant-2" }},
		{name: "wrong principal", mutate: func(principal *TrustedAgentPrincipal) { principal.ID = "principal-2" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			repo, state, principal := newFakeAuthorizationRepository(now, now, now.Add(time.Hour), validFakeAuthorizationGrant(now.Add(time.Hour)))
			tc.mutate(&principal)

			if _, err := repo.Authorize(context.Background(), principal, validFakeAuthorizationRequest()); !errors.Is(err, ErrAgentAuthorizationPrincipalUnauthorized) {
				t.Fatalf("mismatched trusted identity error=%v, want unauthorized", err)
			}
			if len(state.requests) != 0 || totalFakeUsage(state) != 0 {
				t.Fatalf("mismatched trusted identity caused writes: requests=%d usage=%d", len(state.requests), totalFakeUsage(state))
			}
			if state.commitCount != 0 {
				t.Fatalf("mismatched trusted identity committed: commits=%d", state.commitCount)
			}
		})
	}
}

func TestAgentAuthorizationTransactionDefaultDenyPersistsWithoutQuota(t *testing.T) {
	now := time.Date(2026, 9, 25, 12, 1, 0, 0, time.UTC)
	repo, state, principal := newFakeAuthorizationRepository(now, now, now.Add(time.Hour), nil)
	decision, err := repo.Authorize(context.Background(), principal, validFakeAuthorizationRequest())
	if err != nil {
		t.Fatalf("default-deny authorization returned error: %v", err)
	}
	if decision.Allowed || decision.Reason != "no_matching_grant" {
		t.Fatalf("unexpected default-deny decision: %+v", decision)
	}
	if state.requests[decision.IdempotencyKey] == nil || state.requests[decision.IdempotencyKey].state != "complete" {
		t.Fatal("default-deny decision was not persisted as complete")
	}
	if got := totalFakeUsage(state); got != 0 {
		t.Fatalf("default-deny consumed quota: used=%d", got)
	}
}

func TestAgentAuthorizationTransactionRejectsRotatedCredentialBeforeWrites(t *testing.T) {
	now := time.Date(2026, 9, 25, 12, 1, 0, 0, time.UTC)
	repo, state, principal := newFakeAuthorizationRepository(now, now, now.Add(time.Hour), validFakeAuthorizationGrant(now.Add(time.Hour)))
	state.credentialHash = strings.Repeat("b", 64)

	if _, err := repo.Authorize(context.Background(), principal, validFakeAuthorizationRequest()); !errors.Is(err, ErrAgentAuthorizationPrincipalUnauthorized) {
		t.Fatalf("rotated credential error=%v, want unauthorized", err)
	}
	if len(state.requests) != 0 || totalFakeUsage(state) != 0 {
		t.Fatalf("rotated credential caused writes: requests=%d usage=%d", len(state.requests), totalFakeUsage(state))
	}
	if state.commitCount != 0 {
		t.Fatalf("rotated credential committed transaction: commits=%d", state.commitCount)
	}
}

func TestAgentAuthorizationTransactionQuotaLimitDeniesWithoutIncrement(t *testing.T) {
	now := time.Date(2026, 9, 25, 12, 1, 0, 0, time.UTC)
	grant := validFakeAuthorizationGrant(now.Add(time.Hour))
	repo, state, principal := newFakeAuthorizationRepository(now, now, now.Add(time.Hour), grant)
	windowStart := time.Unix((now.Unix()/int64(grant.windowSeconds))*int64(grant.windowSeconds), 0).UTC()
	usageKey := grant.id + "/" + windowStart.Format(time.RFC3339Nano)
	state.usage[usageKey] = grant.quotaMax

	decision, err := repo.Authorize(context.Background(), principal, validFakeAuthorizationRequest())
	if err != nil {
		t.Fatalf("quota-limited request returned error: %v", err)
	}
	if decision.Allowed || decision.Reason != "quota_exceeded" {
		t.Fatalf("quota limit did not default-deny: %+v", decision)
	}
	if got := state.usage[usageKey]; got != grant.quotaMax {
		t.Fatalf("quota usage changed at the limit: used=%d want=%d", got, grant.quotaMax)
	}
	if row := state.requests[decision.IdempotencyKey]; row == nil || row.state != "complete" {
		t.Fatal("quota-exceeded decision was not completed")
	}
}

func TestAgentAuthorizationDelegatedAncestorExpiryBeforeCommitRollsBackAllowAndQuota(t *testing.T) {
	initial := time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)
	expiredAt := initial.Add(5 * time.Second)
	finalNow := expiredAt.Add(time.Second)

	for _, expiryKind := range []string{"delegation", "parent principal", "parent grant"} {
		t.Run(expiryKind, func(t *testing.T) {
			childGrant := validFakeAuthorizationGrant(finalNow.Add(time.Hour))
			childGrant.conditions = `{"environment":"staging","project_id":"project-1"}`
			repo, state, principal := newFakeAuthorizationRepository(initial, initial, finalNow.Add(time.Hour), childGrant)
			principal.ID = "child-1"
			state.principalID = principal.ID
			edgeExpiry, parentExpiry, parentGrantExpiry := finalNow.Add(time.Hour), finalNow.Add(time.Hour), finalNow.Add(time.Hour)
			switch expiryKind {
			case "delegation":
				edgeExpiry = expiredAt
			case "parent principal":
				parentExpiry = expiredAt
			case "parent grant":
				parentGrantExpiry = expiredAt
			}
			state.delegation = &fakeAuthorizationDelegationEdge{
				id: "delegation-1", parentID: "parent-1", childID: principal.ID,
				projectID: "project-1", expiresAt: edgeExpiry,
				parentStatus: "active", parentExpiresAt: parentExpiry,
			}
			state.parentGrantID = "parent-grant"
			state.parentGrant = validFakeAuthorizationGrant(parentGrantExpiry)
			state.parentGrant.conditions = `{"environment":"staging","project_id":"project-1"}`
			state.databaseNowAfterDecision = finalNow

			if _, err := repo.Authorize(context.Background(), principal, validFakeAuthorizationRequest()); !errors.Is(err, ErrAgentAuthorizationPrincipalUnauthorized) {
				t.Fatalf("expired %s authorization error=%v, want unauthorized", expiryKind, err)
			}
			if state.quotaWriteCount != 2 {
				t.Fatalf("quota writes attempted=%d, want child and ancestor quota writes before final recheck", state.quotaWriteCount)
			}
			if state.commitCount != 0 || state.rollbackCount != 1 {
				t.Fatalf("transaction outcome commits=%d rollbacks=%d, want 0/1", state.commitCount, state.rollbackCount)
			}
			if len(state.requests) != 0 || totalFakeUsage(state) != 0 {
				t.Fatalf("expired ancestry left persisted allow/quota state: requests=%d usage=%d", len(state.requests), totalFakeUsage(state))
			}
		})
	}
}

func TestAgentAuthorizationDelegatedCompletedReplayRechecksAncestorExpiry(t *testing.T) {
	initial := time.Date(2026, 9, 26, 13, 0, 0, 0, time.UTC)
	expiredAt := initial.Add(5 * time.Second)
	finalNow := expiredAt.Add(time.Second)

	for _, expiryKind := range []string{"delegation", "parent principal", "parent grant"} {
		t.Run(expiryKind, func(t *testing.T) {
			childGrant := validFakeAuthorizationGrant(finalNow.Add(time.Hour))
			childGrant.conditions = `{"environment":"staging","project_id":"project-1"}`
			repo, state, principal := newFakeAuthorizationRepository(initial, initial, finalNow.Add(time.Hour), childGrant)
			principal.ID = "child-1"
			state.principalID = principal.ID
			edgeExpiry, parentExpiry, parentGrantExpiry := finalNow.Add(time.Hour), finalNow.Add(time.Hour), finalNow.Add(time.Hour)
			switch expiryKind {
			case "delegation":
				edgeExpiry = expiredAt
			case "parent principal":
				parentExpiry = expiredAt
			case "parent grant":
				parentGrantExpiry = expiredAt
			}
			state.delegation = &fakeAuthorizationDelegationEdge{
				id: "delegation-1", parentID: "parent-1", childID: principal.ID,
				projectID: "project-1", expiresAt: edgeExpiry,
				parentStatus: "active", parentExpiresAt: parentExpiry,
			}
			state.parentGrantID = "parent-grant"
			state.parentGrant = validFakeAuthorizationGrant(parentGrantExpiry)
			state.parentGrant.conditions = `{"environment":"staging","project_id":"project-1"}`

			request := validFakeAuthorizationRequest()
			bindDelegatedProject(&request, "project-1")
			requestHash, err := agentAuthorizationRequestHash(request)
			if err != nil {
				t.Fatal(err)
			}
			priorDecision, err := json.Marshal(AgentAuthorizationDecision{
				Allowed: true, Reason: "allowed", PrincipalID: principal.ID,
				Action: request.Action, ResourceType: request.ResourceType, ResourceID: request.ResourceID,
				IdempotencyKey: request.IdempotencyKey, GrantID: childGrant.id,
			})
			if err != nil {
				t.Fatal(err)
			}
			state.requests[request.IdempotencyKey] = &fakeAuthorizationRequestRow{
				requestHash: requestHash, state: "complete", decision: priorDecision,
				grantID: childGrant.id, expiresAt: initial.Add(time.Hour),
			}
			state.databaseNowAfterLookup = finalNow

			if _, err := repo.Authorize(context.Background(), principal, validFakeAuthorizationRequest()); !errors.Is(err, ErrAgentAuthorizationPrincipalUnauthorized) {
				t.Fatalf("expired %s cached allow error=%v, want unauthorized", expiryKind, err)
			}
			if state.commitCount != 0 || state.rollbackCount != 1 {
				t.Fatalf("transaction outcome commits=%d rollbacks=%d, want 0/1", state.commitCount, state.rollbackCount)
			}
			if row := state.requests[request.IdempotencyKey]; row == nil || row.state != "complete" {
				t.Fatal("cached request row was unexpectedly changed by failed replay")
			}
			if totalFakeUsage(state) != 0 {
				t.Fatalf("cached replay consumed quota: used=%d", totalFakeUsage(state))
			}
		})
	}
}

func TestAgentAuthorizationTransactionRechecksPrincipalExpiryAfterLockWait(t *testing.T) {
	txStart := time.Date(2026, 9, 25, 12, 0, 0, 0, time.UTC)
	dbNow := txStart.Add(30 * time.Second)
	principalExpiry := txStart.Add(10 * time.Second)
	repo, state, principal := newFakeAuthorizationRepository(txStart, dbNow, principalExpiry, validFakeAuthorizationGrant(dbNow.Add(time.Hour)))

	if _, err := repo.Authorize(context.Background(), principal, validFakeAuthorizationRequest()); !errors.Is(err, ErrAgentAuthorizationPrincipalUnauthorized) {
		t.Fatalf("expired principal error=%v, want unauthorized", err)
	}
	if len(state.requests) != 0 || totalFakeUsage(state) != 0 {
		t.Fatalf("expired principal caused writes: requests=%d usage=%d", len(state.requests), totalFakeUsage(state))
	}
}

func TestAgentAuthorizationTransactionRechecksGrantExpiryAndIdempotencyExpiryWithDatabaseClock(t *testing.T) {
	txStart := time.Date(2026, 9, 25, 12, 0, 0, 0, time.UTC)
	dbNow := txStart.Add(30 * time.Second)
	request := validFakeAuthorizationRequest()

	t.Run("grant expired during lock wait", func(t *testing.T) {
		grant := validFakeAuthorizationGrant(txStart.Add(10 * time.Second))
		repo, state, principal := newFakeAuthorizationRepository(txStart, dbNow, dbNow.Add(time.Hour), grant)
		decision, err := repo.Authorize(context.Background(), principal, request)
		if err != nil {
			t.Fatalf("expired grant should deny: %v", err)
		}
		if decision.Allowed || decision.Reason != "no_matching_grant" || totalFakeUsage(state) != 0 {
			t.Fatalf("expired grant was not default-denied: decision=%+v usage=%d", decision, totalFakeUsage(state))
		}
	})

	t.Run("cached allow expires during lock wait and is reevaluated", func(t *testing.T) {
		grant := validFakeAuthorizationGrant(dbNow.Add(time.Hour))
		repo, state, principal := newFakeAuthorizationRepository(txStart, dbNow, dbNow.Add(time.Hour), grant)
		requestHash, err := agentAuthorizationRequestHash(request)
		if err != nil {
			t.Fatal(err)
		}
		priorDecision, _ := json.Marshal(AgentAuthorizationDecision{
			Allowed: true, Reason: "allowed", PrincipalID: principal.ID, Action: request.Action,
			ResourceType: request.ResourceType, ResourceID: request.ResourceID,
			IdempotencyKey: request.IdempotencyKey, GrantID: grant.id,
		})
		state.requests[request.IdempotencyKey] = &fakeAuthorizationRequestRow{
			requestHash: requestHash, state: "complete", decision: priorDecision,
			grantID: grant.id, expiresAt: txStart.Add(5 * time.Second),
		}

		decision, err := repo.Authorize(context.Background(), principal, request)
		if err != nil {
			t.Fatalf("expired idempotency entry should be reevaluated: %v", err)
		}
		if !decision.Allowed || totalFakeUsage(state) != 1 {
			t.Fatalf("expired cache was replayed instead of reevaluated: decision=%+v usage=%d", decision, totalFakeUsage(state))
		}
	})

	t.Run("cached allow is denied after grant expiry", func(t *testing.T) {
		grant := validFakeAuthorizationGrant(txStart.Add(10 * time.Second))
		repo, state, principal := newFakeAuthorizationRepository(txStart, dbNow, dbNow.Add(time.Hour), grant)
		requestHash, err := agentAuthorizationRequestHash(request)
		if err != nil {
			t.Fatal(err)
		}
		priorDecision, _ := json.Marshal(AgentAuthorizationDecision{
			Allowed: true, Reason: "allowed", PrincipalID: principal.ID, Action: request.Action,
			ResourceType: request.ResourceType, ResourceID: request.ResourceID,
			IdempotencyKey: request.IdempotencyKey, GrantID: grant.id,
		})
		state.requests[request.IdempotencyKey] = &fakeAuthorizationRequestRow{
			requestHash: requestHash, state: "complete", decision: priorDecision,
			grantID: grant.id, expiresAt: dbNow.Add(time.Hour),
		}

		decision, err := repo.Authorize(context.Background(), principal, request)
		if err != nil {
			t.Fatalf("expired cached grant should return a denial: %v", err)
		}
		if decision.Allowed || decision.Reason != "grant_expired" || decision.GrantID != "" {
			t.Fatalf("expired cached allow was not invalidated: %+v", decision)
		}
		if got := totalFakeUsage(state); got != 0 {
			t.Fatalf("cached replay consumed quota: used=%d", got)
		}
	})
}

func TestAgentAuthorizationTransactionUsesOneFinalDecisionTimestamp(t *testing.T) {
	txStart := time.Date(2026, 9, 25, 12, 0, 0, 0, time.UTC)
	dbNow := txStart.Add(time.Minute)
	request := validFakeAuthorizationRequest()

	seedCachedAllow := func(state *fakeAuthorizationDBState, principal TrustedAgentPrincipal, grant *fakeAuthorizationGrant) {
		requestHash, err := agentAuthorizationRequestHash(request)
		if err != nil {
			t.Fatal(err)
		}
		priorDecision, _ := json.Marshal(AgentAuthorizationDecision{
			Allowed: true, Reason: "allowed", PrincipalID: principal.ID, Action: request.Action,
			ResourceType: request.ResourceType, ResourceID: request.ResourceID,
			IdempotencyKey: request.IdempotencyKey, GrantID: grant.id,
		})
		state.requests[request.IdempotencyKey] = &fakeAuthorizationRequestRow{
			requestHash: requestHash, state: "complete", decision: priorDecision,
			grantID: grant.id, expiresAt: dbNow.Add(time.Hour),
		}
	}
	assertFinalDecisionCount := func(t *testing.T, state *fakeAuthorizationDBState) {
		t.Helper()
		if state.finalDecisionCount != 1 {
			t.Fatalf("final authorization SQL calls=%d, want exactly 1", state.finalDecisionCount)
		}
	}
	assertFreshRollback := func(t *testing.T, state *fakeAuthorizationDBState) {
		t.Helper()
		assertFinalDecisionCount(t, state)
		if got := totalFakeUsage(state); got != 0 {
			t.Fatalf("failed authorization changed quota: used=%d", got)
		}
		if len(state.requests) != 0 {
			t.Fatalf("failed fresh authorization escaped rollback: requests=%d", len(state.requests))
		}
		if state.commitCount != 0 {
			t.Fatalf("failed authorization committed: commits=%d", state.commitCount)
		}
	}

	t.Run("fresh principal expires during final query and rolls back", func(t *testing.T) {
		grant := validFakeAuthorizationGrant(dbNow.Add(time.Hour))
		repo, state, principal := newFakeAuthorizationRepository(txStart, dbNow, dbNow.Add(time.Second), grant)
		state.finalDecisionAt = dbNow.Add(2 * time.Second)
		if _, err := repo.Authorize(context.Background(), principal, request); !errors.Is(err, ErrAgentAuthorizationPrincipalUnauthorized) {
			t.Fatalf("expired principal error=%v, want unauthorized", err)
		}
		assertFreshRollback(t, state)
	})

	t.Run("cached principal expires during final query and rolls back replay", func(t *testing.T) {
		grant := validFakeAuthorizationGrant(dbNow.Add(time.Hour))
		repo, state, principal := newFakeAuthorizationRepository(txStart, dbNow, dbNow.Add(time.Second), grant)
		seedCachedAllow(state, principal, grant)
		state.finalDecisionAt = dbNow.Add(2 * time.Second)
		if _, err := repo.Authorize(context.Background(), principal, request); !errors.Is(err, ErrAgentAuthorizationPrincipalUnauthorized) {
			t.Fatalf("expired cached principal error=%v, want unauthorized", err)
		}
		assertFinalDecisionCount(t, state)
		if totalFakeUsage(state) != 0 || state.commitCount != 0 {
			t.Fatalf("expired cached principal changed quota or committed: usage=%d commits=%d", totalFakeUsage(state), state.commitCount)
		}
		row := state.requests[request.IdempotencyKey]
		if row == nil || row.state != "complete" {
			t.Fatal("rollback did not preserve the original cached request")
		}
		var saved AgentAuthorizationDecision
		if err := json.Unmarshal(row.decision, &saved); err != nil || !saved.Allowed {
			t.Fatalf("cached allow changed despite rollback: decision=%+v err=%v", saved, err)
		}
	})

	t.Run("fresh grant expires during final query and rolls back quota", func(t *testing.T) {
		grant := validFakeAuthorizationGrant(dbNow.Add(time.Second))
		repo, state, principal := newFakeAuthorizationRepository(txStart, dbNow, dbNow.Add(time.Hour), grant)
		state.finalDecisionAt = dbNow.Add(2 * time.Second)
		if _, err := repo.Authorize(context.Background(), principal, request); !errors.Is(err, ErrAgentAuthorizationGrantExpired) {
			t.Fatalf("expired fresh grant error=%v, want grant-expired error", err)
		}
		assertFreshRollback(t, state)
	})

	t.Run("cached grant expires during final query and persists denial without quota", func(t *testing.T) {
		grant := validFakeAuthorizationGrant(dbNow.Add(time.Second))
		repo, state, principal := newFakeAuthorizationRepository(txStart, dbNow, dbNow.Add(time.Hour), grant)
		seedCachedAllow(state, principal, grant)
		state.finalDecisionAt = dbNow.Add(2 * time.Second)
		decision, err := repo.Authorize(context.Background(), principal, request)
		if err != nil {
			t.Fatalf("expired cached grant should become a denial: %v", err)
		}
		if decision.Allowed || decision.Reason != "grant_expired" || decision.GrantID != "" {
			t.Fatalf("cached allow survived grant expiry: %+v", decision)
		}
		assertFinalDecisionCount(t, state)
		row := state.requests[request.IdempotencyKey]
		if row == nil || row.state != "complete" || row.grantID != "" {
			t.Fatal("expired cached grant denial was not persisted")
		}
		var saved AgentAuthorizationDecision
		if err := json.Unmarshal(row.decision, &saved); err != nil || saved.Allowed || saved.Reason != "grant_expired" {
			t.Fatalf("cached grant denial was not saved: decision=%+v err=%v", saved, err)
		}
		if got := totalFakeUsage(state); got != 0 {
			t.Fatalf("cached replay consumed quota: used=%d", got)
		}
	})

	t.Run("strict principal boundary expires at equality", func(t *testing.T) {
		grant := validFakeAuthorizationGrant(dbNow.Add(time.Hour))
		equality := dbNow.Add(time.Second)
		repo, state, principal := newFakeAuthorizationRepository(txStart, dbNow, equality, grant)
		state.finalDecisionAt = equality
		if _, err := repo.Authorize(context.Background(), principal, request); !errors.Is(err, ErrAgentAuthorizationPrincipalUnauthorized) {
			t.Fatalf("principal equality boundary error=%v, want unauthorized", err)
		}
		assertFreshRollback(t, state)
	})

	t.Run("strict grant boundary expires at equality on cached replay", func(t *testing.T) {
		equality := dbNow.Add(time.Second)
		grant := validFakeAuthorizationGrant(equality)
		repo, state, principal := newFakeAuthorizationRepository(txStart, dbNow, dbNow.Add(time.Hour), grant)
		seedCachedAllow(state, principal, grant)
		state.finalDecisionAt = equality
		decision, err := repo.Authorize(context.Background(), principal, request)
		if err != nil {
			t.Fatalf("grant equality boundary should deny replay: %v", err)
		}
		assertFinalDecisionCount(t, state)
		if decision.Allowed || decision.Reason != "grant_expired" {
			t.Fatalf("grant equality boundary allowed cached request: %+v", decision)
		}
	})
}

func totalFakeUsage(state *fakeAuthorizationDBState) int64 {
	var total int64
	for _, used := range state.usage {
		total += used
	}
	return total
}

func TestAgentAuthorizationIdempotencyBindsRunInstanceAndToolCallContext(t *testing.T) {
	now := time.Date(2026, 9, 25, 12, 1, 0, 100000000, time.UTC)
	repo, state, principal := newFakeAuthorizationRepository(now, now, now.Add(time.Hour), validFakeAuthorizationGrant(now.Add(time.Hour)))
	request := validFakeAuthorizationRequest()
	request.Context = map[string]any{"environment": "staging", "run_id": "run-123", "instance_id": "instance-456", "tool_call_id": "call-789"}

	first, err := repo.Authorize(context.Background(), principal, request)
	if err != nil || !first.Allowed {
		t.Fatalf("first authorization failed: decision=%+v err=%v", first, err)
	}
	replay, err := repo.Authorize(context.Background(), principal, request)
	if err != nil || !replay.Allowed || replay.GrantID != first.GrantID {
		t.Fatalf("identical T13 context replay failed: first=%+v replay=%+v err=%v", first, replay, err)
	}
	if got := totalFakeUsage(state); got != 1 {
		t.Fatalf("same-key context replay charged quota %d times", got)
	}

	changed := request
	changed.Context = map[string]any{"environment": "staging", "run_id": "run-123", "instance_id": "instance-456", "tool_call_id": "call-999"}
	if _, err := repo.Authorize(context.Background(), principal, changed); !errors.Is(err, ErrAgentAuthorizationIdempotencyConflict) {
		t.Fatalf("changed T13 context error=%v, want idempotency conflict", err)
	}
	if got := totalFakeUsage(state); got != 1 {
		t.Fatalf("changed-context conflict charged quota %d times", got)
	}
}
