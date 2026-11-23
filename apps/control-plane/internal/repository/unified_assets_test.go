package repository

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

func TestUnifiedAssetIdentityIsTenantAndInstanceScoped(t *testing.T) {
	nativeID := unifiedEndpointAssetNativeID("skill", "deploy")
	if nativeID != "skill\x1edeploy" {
		t.Fatalf("native ID=%q", nativeID)
	}
	first := stableUnifiedAssetID("uaa_", "tenant-a", "agent_endpoint", "endpoint-a", nativeID)
	if again := stableUnifiedAssetID("uaa_", "tenant-a", "agent_endpoint", "endpoint-a", nativeID); first != again {
		t.Fatalf("repeat identity changed: %q != %q", first, again)
	}
	if otherTenant := stableUnifiedAssetID("uaa_", "tenant-b", "agent_endpoint", "endpoint-a", nativeID); first == otherTenant {
		t.Fatal("same source identity collapsed across tenants")
	}
	if otherEndpoint := stableUnifiedAssetID("uaa_", "tenant-a", "agent_endpoint", "endpoint-b", nativeID); first == otherEndpoint {
		t.Fatal("same-host distinct Agent endpoint collapsed")
	}
	// Version and hash live in observations/instances; a stable native identity
	// remains stable when its reported content changes.
	if changedVersion := stableUnifiedAssetID("uaa_", "tenant-a", "agent_endpoint", "endpoint-a", nativeID); first != changedVersion {
		t.Fatal("version data changed canonical asset identity")
	}
	if key := unifiedAssetInstanceKey(); key != "__source_native_identity__" {
		t.Fatalf("hash-less source identity projection key=%q", key)
	}
}

func TestUnifiedAssetIndicatorsRequireEvidence(t *testing.T) {
	tests := []struct {
		name                                     string
		instances, managed, observed, controlled int
		want                                     agentUnifiedAssetIndicators
	}{
		{"catalog-only", 0, 0, 0, 0, agentUnifiedAssetIndicators{controlState: "not_evidenced"}},
		{"discovered-only", 1, 0, 0, 0, agentUnifiedAssetIndicators{discovered: true, controlState: "not_evidenced"}},
		{"managed-but-not-observed", 1, 1, 0, 0, agentUnifiedAssetIndicators{discovered: true, managed: true, controlState: "not_evidenced"}},
		{"observed-not-controlled", 1, 1, 1, 0, agentUnifiedAssetIndicators{discovered: true, managed: true, observed: true, controlState: "not_evidenced"}},
		{"control-proof", 1, 1, 1, 1, agentUnifiedAssetIndicators{discovered: true, managed: true, observed: true, controlled: true, controlState: "evidenced"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := deriveAgentUnifiedAssetIndicators(tt.instances, tt.managed, tt.observed, tt.controlled); got != tt.want {
				t.Fatalf("got %+v want %+v", got, tt.want)
			}
		})
	}
}

func TestUnifiedAssetSourceRefRejectsUntrustedNamespaceSeparators(t *testing.T) {
	valid := AgentAssetSourceRef{SourceType: "identity_event", SourceNamespace: "producer-verified-by-server", NativeID: "asset:123"}
	if !validAgentAssetSourceRef(valid) {
		t.Fatal("valid source ref rejected")
	}
	for _, bad := range []AgentAssetSourceRef{
		{SourceType: "unknown", SourceNamespace: "ns", NativeID: "id"},
		{SourceType: "identity_event", SourceNamespace: "ns\x1fother", NativeID: "id"},
		{SourceType: "agent_endpoint", SourceNamespace: "ns", NativeID: "id\x1eother"},
		{SourceType: "agent_endpoint", SourceNamespace: "endpoint-a", NativeID: "skill\x1edeploy"},
		{SourceType: "identity_event", SourceNamespace: " ", NativeID: "id"},
		{SourceType: "identity_event", SourceNamespace: " ns", NativeID: "id"},
		{SourceType: "identity_event", SourceNamespace: strings.Repeat("n", 256), NativeID: "id"},
		{SourceType: "identity_event", SourceNamespace: "ns", NativeID: strings.Repeat("i", 513)},
	} {
		if validAgentAssetSourceRef(bad) {
			t.Errorf("accepted invalid source ref %+v", bad)
		}
	}
}

func TestUnifiedAssetSQLAndMigrationKeepTenantAndHistoryBoundaries(t *testing.T) {
	body, err := os.ReadFile("unified_assets.go")
	if err != nil {
		t.Fatal(err)
	}
	source := string(body)
	for _, required := range []string{
		"a.tenant_id=$1",
		"WHERE o.tenant_id=$1 AND s.asset_id=$2",
		"WHERE tenant_id=$1 AND id=$2 AND merged_into_id IS NULL",
		"ON CONFLICT (tenant_id,source_ref_id,source_event_id) DO NOTHING",
		"SELECT pg_advisory_xact_lock(hashtext($1))",
		"last_observed_at<=$10",
		"last_seen<=$4",
	} {
		if !strings.Contains(source, required) {
			t.Errorf("missing tenant/history/idempotence contract %q", required)
		}
	}
	if strings.Contains(source, "UPDATE agent_unified_asset_observations") {
		t.Fatal("merge rewrites immutable observation history")
	}
	migrationPath := filepath.Join("..", "..", "..", "..", "deploy", "migrations", "860_unified_agent_assets.sql")
	migration, err := os.ReadFile(migrationPath)
	if err != nil {
		t.Fatal(err)
	}
	sql := string(migration)
	lockAt := strings.Index(sql, "LOCK TABLE agent_endpoint_assets IN SHARE MODE;")
	sourceReadAt := strings.Index(sql, "FROM agent_endpoint_assets")
	if !strings.HasPrefix(strings.TrimSpace(sql), "BEGIN;") || lockAt < 0 || sourceReadAt < lockAt {
		t.Fatal("migration must hold the legacy source table lock before reading it inside its transaction")
	}
	for _, required := range []string{
		"LOCK TABLE agent_endpoint_assets IN SHARE MODE;",
		"octet_length(asset_type || chr(30) || name) > 512",
		"LEAST(last_seen, now())",
		"LEAST(i.last_seen, now())",
		"UNIQUE (tenant_id, source_type, source_namespace, native_id)",
		"FOREIGN KEY (tenant_id, asset_id)",
		"FOREIGN KEY (tenant_id, owner_user_id)",
		"UNIQUE (tenant_id, source_ref_id, source_event_id)",
		"'legacy_snapshot'",
		"'__source_native_identity__' AS instance_key",
	} {
		if !strings.Contains(sql, required) {
			t.Errorf("migration missing contract %q", required)
		}
	}
}

type unifiedAssetFakeRow struct {
	value interface{}
	err   error
}

func (r unifiedAssetFakeRow) Scan(dest ...interface{}) error {
	if r.err != nil {
		return r.err
	}
	if len(dest) != 1 {
		return fmt.Errorf("unexpected scan target count %d", len(dest))
	}
	switch target := dest[0].(type) {
	case *string:
		value, ok := r.value.(string)
		if !ok {
			return fmt.Errorf("expected string row value, got %T", r.value)
		}
		*target = value
	case *time.Time:
		value, ok := r.value.(time.Time)
		if !ok {
			return fmt.Errorf("expected time row value, got %T", r.value)
		}
		*target = value
	default:
		return fmt.Errorf("unsupported scan target %T", dest[0])
	}
	return nil
}

type unifiedAssetAdvisoryLockManager struct {
	mu    sync.Mutex
	locks map[string]*sync.Mutex
}

func (m *unifiedAssetAdvisoryLockManager) acquire(key string, contendedSignal chan<- string) (func(), bool) {
	m.mu.Lock()
	if m.locks == nil {
		m.locks = map[string]*sync.Mutex{}
	}
	lock := m.locks[key]
	if lock == nil {
		lock = &sync.Mutex{}
		m.locks[key] = lock
	}
	m.mu.Unlock()
	if lock.TryLock() {
		return lock.Unlock, false
	}
	if contendedSignal != nil {
		contendedSignal <- key
	}
	lock.Lock()
	return lock.Unlock, true
}

type unifiedAssetFakeTx struct {
	existingAssetID      string
	canonicalAssetID     string
	createdAssetID       string
	createdSourceRefID   string
	sourceRefLookups     int
	nativeID             string
	instanceAssetID      string
	instanceObservedAt   time.Time
	assetObservedAt      time.Time
	observationSourceAt  time.Time
	receivedAt           time.Time
	assetInsertCapped    bool
	instanceInsertCapped bool
	lockManager          *unifiedAssetAdvisoryLockManager
	lockAcquired         chan string
	aggregateDisplayName string
	aggregateLastSeen    time.Time
	observationTimes     []time.Time
	unlocks              []func()
}

func (tx *unifiedAssetFakeTx) Exec(_ context.Context, query string, args ...any) (pgconn.CommandTag, error) {
	if strings.Contains(query, "pg_advisory_xact_lock") {
		key := args[0].(string)
		if tx.lockManager != nil {
			unlock, _ := tx.lockManager.acquire(key, nil)
			tx.unlocks = append(tx.unlocks, unlock)
			if tx.lockAcquired != nil {
				tx.lockAcquired <- key
			}
		}
		return pgconn.NewCommandTag("SELECT 1"), nil
	}
	switch {
	case strings.Contains(query, "INSERT INTO agent_unified_assets"):
		tx.createdAssetID = args[0].(string)
		tx.assetInsertCapped = strings.Contains(query, "LEAST($6,clock_timestamp())")
	case strings.Contains(query, "INSERT INTO agent_asset_source_refs"):
		tx.createdSourceRefID = args[0].(string)
		tx.createdAssetID = args[2].(string)
		tx.nativeID = args[5].(string)
	case strings.Contains(query, "INSERT INTO agent_unified_asset_instances"):
		tx.instanceAssetID = args[2].(string)
		tx.instanceInsertCapped = strings.Contains(query, "LEAST($15,clock_timestamp())")
	case strings.Contains(query, "UPDATE agent_unified_asset_instances SET"):
		tx.instanceObservedAt = args[9].(time.Time)
	case strings.Contains(query, "UPDATE agent_unified_assets SET"):
		name := args[2].(string)
		observedAt := args[3].(time.Time)
		tx.assetObservedAt = observedAt
		if name != "" && (!strings.Contains(query, "last_seen<=$4") || !tx.aggregateLastSeen.After(observedAt)) {
			tx.aggregateDisplayName = name
		}
		if tx.aggregateLastSeen.IsZero() || observedAt.After(tx.aggregateLastSeen) {
			tx.aggregateLastSeen = observedAt
		}
	}
	return pgconn.NewCommandTag("UPDATE 1"), nil
}

func (tx *unifiedAssetFakeTx) QueryRow(_ context.Context, query string, args ...any) pgx.Row {
	switch {
	case strings.Contains(query, "SELECT asset_id FROM agent_asset_source_refs"):
		tx.sourceRefLookups++
		tx.nativeID = args[3].(string)
		if tx.existingAssetID != "" {
			return unifiedAssetFakeRow{value: tx.existingAssetID}
		}
		if tx.sourceRefLookups == 1 {
			return unifiedAssetFakeRow{err: pgx.ErrNoRows}
		}
		if tx.createdAssetID != "" {
			return unifiedAssetFakeRow{value: tx.createdAssetID}
		}
		return unifiedAssetFakeRow{err: errors.New("source ref row not present")}
	case strings.Contains(query, "SELECT id FROM agent_asset_source_refs"):
		return unifiedAssetFakeRow{value: tx.createdSourceRefID}
	case strings.Contains(query, "SELECT COALESCE(merged_into_id,id) FROM agent_unified_assets"):
		lookupID := args[1].(string)
		if lookupID == tx.createdAssetID || lookupID == tx.existingAssetID {
			return unifiedAssetFakeRow{value: tx.canonicalAssetID}
		}
		return unifiedAssetFakeRow{err: pgx.ErrNoRows}
	case strings.Contains(query, "INSERT INTO agent_unified_asset_observations"):
		tx.observationSourceAt = args[7].(time.Time)
		tx.observationTimes = append(tx.observationTimes, tx.observationSourceAt)
		receivedAt := tx.receivedAt
		if receivedAt.IsZero() {
			receivedAt = time.Date(2026, 9, 25, 0, 0, 0, 0, time.UTC)
		}
		return unifiedAssetFakeRow{value: receivedAt}
	default:
		return unifiedAssetFakeRow{err: fmt.Errorf("unexpected QueryRow: %s", query)}
	}
}

func (tx *unifiedAssetFakeTx) ReleaseLocks() {
	for i := len(tx.unlocks) - 1; i >= 0; i-- {
		tx.unlocks[i]()
	}
	tx.unlocks = nil
}

func TestUpsertUnifiedEndpointAssetNewAndExistingSourceRef(t *testing.T) {
	tests := []struct {
		name            string
		existingAssetID string
		wantLookups     int
	}{
		{name: "new source ref", wantLookups: 2},
		{name: "existing source ref", existingAssetID: "uaa-existing", wantLookups: 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tx := &unifiedAssetFakeTx{existingAssetID: tt.existingAssetID, canonicalAssetID: "uaa-canonical"}
			record := &agentEventRecord{
				ID:         "event-1",
				OccurredAt: time.Date(2026, 9, 25, 0, 0, 0, 0, time.UTC),
				Asset:      &agentEventAsset{AssetType: "skill", Name: "deploy", Present: true, Evidence: []byte("{}")},
			}
			if err := upsertUnifiedEndpointAsset(context.Background(), tx, "tenant-a", "endpoint-a", record); err != nil {
				t.Fatalf("endpoint asset ingest failed: %v", err)
			}
			if tx.nativeID != "skill\x1edeploy" {
				t.Fatalf("native ID=%q", tx.nativeID)
			}
			if tx.instanceAssetID != "uaa-canonical" {
				t.Fatalf("instance asset ID=%q", tx.instanceAssetID)
			}
			if tx.sourceRefLookups != tt.wantLookups {
				t.Fatalf("source-ref lookup count=%d want %d", tx.sourceRefLookups, tt.wantLookups)
			}
			if tt.existingAssetID == "" && (tx.createdAssetID == "" || tx.createdSourceRefID == "") {
				t.Fatalf("new source ref was not created: %+v", tx)
			}
			if tt.existingAssetID != "" && tx.createdSourceRefID != "" {
				t.Fatalf("existing source ref was unexpectedly replaced: %+v", tx)
			}
		})
	}
}

func TestUpsertUnifiedEndpointAssetRejectsInvalidComponents(t *testing.T) {
	invalid := []*agentEventAsset{
		{AssetType: "skill\x1ebad", Name: "deploy"},
		{AssetType: "skill", Name: "deploy\x1ebad"},
		{AssetType: "skill", Name: strings.Repeat("n", 512)},
	}
	for _, asset := range invalid {
		record := &agentEventRecord{Asset: asset}
		err := upsertUnifiedEndpointAsset(context.Background(), &unifiedAssetFakeTx{}, "tenant-a", "endpoint-a", record)
		if !errors.Is(err, ErrAgentAssetInvalidInput) {
			t.Errorf("asset component %+v error=%v, want invalid input", asset, err)
		}
	}
	record := &agentEventRecord{Asset: &agentEventAsset{AssetType: "skill", Name: "deploy"}}
	if err := upsertUnifiedEndpointAsset(context.Background(), &unifiedAssetFakeTx{}, "tenant-a", "endpoint\x1fother", record); !errors.Is(err, ErrAgentAssetInvalidInput) {
		t.Errorf("endpoint namespace separator error=%v, want invalid input", err)
	}
	if err := upsertUnifiedEndpointAsset(context.Background(), &unifiedAssetFakeTx{}, "tenant-a", strings.Repeat("e", 256), record); !errors.Is(err, ErrAgentAssetInvalidInput) {
		t.Errorf("oversized endpoint namespace error=%v, want invalid input", err)
	}
}

func TestUpsertUnifiedEndpointAssetAcceptsNativeIDAtSchemaLimit(t *testing.T) {
	tx := &unifiedAssetFakeTx{canonicalAssetID: "uaa-canonical"}
	record := &agentEventRecord{
		ID:         "event-boundary",
		OccurredAt: time.Date(2026, 9, 25, 0, 0, 0, 0, time.UTC),
		Asset:      &agentEventAsset{AssetType: "t", Name: strings.Repeat("n", 510), Present: true, Evidence: []byte("{}")},
	}
	if err := upsertUnifiedEndpointAsset(context.Background(), tx, "tenant-a", "endpoint-a", record); err != nil {
		t.Fatalf("512-byte native identity rejected: %v", err)
	}
	if len(tx.nativeID) != 512 {
		t.Fatalf("native identity length=%d want 512", len(tx.nativeID))
	}
}

func TestUpsertUnifiedEndpointAssetCapsFutureWatermarksAtDatabaseReceipt(t *testing.T) {
	receivedAt := time.Date(2026, 9, 25, 0, 0, 0, 0, time.UTC)
	sourceOccurredAt := receivedAt.Add(24 * time.Hour)
	tx := &unifiedAssetFakeTx{canonicalAssetID: "uaa-canonical", receivedAt: receivedAt}
	record := &agentEventRecord{
		ID:         "event-future-clock",
		OccurredAt: sourceOccurredAt,
		Asset:      &agentEventAsset{AssetType: "skill", Name: "deploy", Present: true, Evidence: []byte("{}")},
	}
	if err := upsertUnifiedEndpointAsset(context.Background(), tx, "tenant-a", "endpoint-a", record); err != nil {
		t.Fatalf("endpoint asset ingest failed: %v", err)
	}
	if !tx.assetInsertCapped || !tx.instanceInsertCapped {
		t.Fatalf("initial current rows are not SQL-capped to database time: %+v", tx)
	}
	if !tx.instanceObservedAt.Equal(receivedAt) || !tx.assetObservedAt.Equal(receivedAt) {
		t.Fatalf("current watermarks exceeded trusted receipt: instance=%s asset=%s received=%s",
			tx.instanceObservedAt, tx.assetObservedAt, receivedAt)
	}
	if !tx.observationSourceAt.Equal(sourceOccurredAt) {
		t.Fatalf("source history time changed: got %s want %s", tx.observationSourceAt, sourceOccurredAt)
	}
}

func TestUpsertUnifiedEndpointAssetStaleObservationDoesNotRegressAggregateDisplayName(t *testing.T) {
	baselineAt := time.Date(2026, 9, 25, 12, 0, 0, 0, time.UTC)
	staleAt := baselineAt.Add(-24 * time.Hour)
	tx := &unifiedAssetFakeTx{
		existingAssetID:  "uaa-canonical",
		canonicalAssetID: "uaa-canonical",
		receivedAt:       baselineAt.Add(24 * time.Hour),
	}
	accept := func(id string, at time.Time, name, hash string) {
		t.Helper()
		record := &agentEventRecord{
			ID: id, OccurredAt: at, EndpointID: "endpoint-a",
			InstanceKey: "aiprobe:source-1", UnifiedNativeID: "aiprobe:source-1",
			Asset: &agentEventAsset{
				AssetType: "cli_agent", Name: name, Version: "v1", Source: "aiprobe",
				Hash: hash, Present: true, ScanStatus: "complete", Evidence: []byte("{}"),
			},
		}
		if err := upsertUnifiedEndpointAsset(context.Background(), tx, "tenant-a", "endpoint-a", record); err != nil {
			t.Fatalf("upsert report %s: %v", id, err)
		}
	}

	accept("baseline", baselineAt, "Current name", "sha256:baseline")
	if tx.aggregateDisplayName != "Current name" || !tx.aggregateLastSeen.Equal(baselineAt) {
		t.Fatalf("baseline projection display=%q last_seen=%s", tx.aggregateDisplayName, tx.aggregateLastSeen)
	}
	accept("stale", staleAt, "Older name", "sha256:stale")
	if tx.aggregateDisplayName != "Current name" {
		t.Fatalf("stale report regressed aggregate display name to %q", tx.aggregateDisplayName)
	}
	if !tx.aggregateLastSeen.Equal(baselineAt) {
		t.Fatalf("stale report regressed aggregate last_seen to %s", tx.aggregateLastSeen)
	}
	if len(tx.observationTimes) != 2 || !tx.observationTimes[0].Equal(baselineAt) || !tx.observationTimes[1].Equal(staleAt) {
		t.Fatalf("stale observation history was not appended: %v", tx.observationTimes)
	}
}

type unifiedAssetEmptyRows struct{}

func (unifiedAssetEmptyRows) Close()                                       {}
func (unifiedAssetEmptyRows) Err() error                                   { return nil }
func (unifiedAssetEmptyRows) CommandTag() pgconn.CommandTag                { return pgconn.NewCommandTag("") }
func (unifiedAssetEmptyRows) FieldDescriptions() []pgconn.FieldDescription { return nil }
func (unifiedAssetEmptyRows) Next() bool                                   { return false }
func (unifiedAssetEmptyRows) Scan(...any) error                            { return errors.New("no rows") }
func (unifiedAssetEmptyRows) Values() ([]any, error)                       { return nil, errors.New("no rows") }
func (unifiedAssetEmptyRows) RawValues() [][]byte                          { return nil }
func (unifiedAssetEmptyRows) Conn() *pgx.Conn                              { return nil }

type unifiedAssetMergeLockFakeTx struct {
	manager   *unifiedAssetAdvisoryLockManager
	contended chan string
	queried   chan struct{}
	unlocks   []func()
}

func (tx *unifiedAssetMergeLockFakeTx) Exec(_ context.Context, query string, args ...any) (pgconn.CommandTag, error) {
	if strings.Contains(query, "pg_advisory_xact_lock") {
		key := args[0].(string)
		unlock, _ := tx.manager.acquire(key, tx.contended)
		tx.unlocks = append(tx.unlocks, unlock)
	}
	return pgconn.NewCommandTag("SELECT 1"), nil
}

func (tx *unifiedAssetMergeLockFakeTx) Query(context.Context, string, ...any) (pgx.Rows, error) {
	tx.queried <- struct{}{}
	return unifiedAssetEmptyRows{}, nil
}

func (tx *unifiedAssetMergeLockFakeTx) ReleaseLocks() {
	for i := len(tx.unlocks) - 1; i >= 0; i-- {
		tx.unlocks[i]()
	}
	tx.unlocks = nil
}

func TestUnifiedAssetUpsertAndMergeSerializeOnTenantLock(t *testing.T) {
	manager := &unifiedAssetAdvisoryLockManager{}
	upsertTx := &unifiedAssetFakeTx{
		existingAssetID: "uaa-existing", canonicalAssetID: "uaa-existing",
		lockManager: manager, lockAcquired: make(chan string, 4),
	}
	defer upsertTx.ReleaseLocks()
	upsertDone := make(chan error, 1)
	go func() {
		record := &agentEventRecord{
			ID:         "event-serial",
			OccurredAt: time.Date(2026, 9, 25, 0, 0, 0, 0, time.UTC),
			Asset:      &agentEventAsset{AssetType: "skill", Name: "deploy", Present: true, Evidence: []byte("{}")},
		}
		upsertDone <- upsertUnifiedEndpointAsset(context.Background(), upsertTx, "tenant-a", "endpoint-a", record)
	}()
	select {
	case key := <-upsertTx.lockAcquired:
		if key != unifiedAssetTenantLockKey("tenant-a") {
			t.Fatalf("upsert first lock=%q", key)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("upsert did not acquire the tenant write lock")
	}
	if err := <-upsertDone; err != nil {
		t.Fatalf("upsert failed: %v", err)
	}
	mergeTx := &unifiedAssetMergeLockFakeTx{
		manager: manager, contended: make(chan string, 1), queried: make(chan struct{}, 1),
	}
	defer mergeTx.ReleaseLocks()
	mergeDone := make(chan error, 1)
	go func() {
		_, err := mergeAgentUnifiedAssetTx(context.Background(), mergeTx, "tenant-a", "uaa-source", "uaa-target")
		mergeDone <- err
	}()
	select {
	case key := <-mergeTx.contended:
		if key != unifiedAssetTenantLockKey("tenant-a") {
			t.Fatalf("merge contended on unexpected lock %q", key)
		}
	case <-mergeTx.queried:
		t.Fatal("merge reached row locking while upsert held the tenant lock")
	case <-time.After(2 * time.Second):
		t.Fatal("merge did not contend on the shared tenant lock")
	}
	select {
	case <-mergeTx.queried:
		t.Fatal("merge reached row locking before upsert released the tenant lock")
	default:
	}
	upsertTx.ReleaseLocks()
	select {
	case <-mergeTx.queried:
	case <-time.After(2 * time.Second):
		t.Fatal("merge did not continue after upsert released the tenant lock")
	}
	if err := <-mergeDone; err != nil {
		t.Fatalf("merge failed: %v", err)
	}
	mergeTx.ReleaseLocks()
}
