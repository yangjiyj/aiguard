package repository

import (
	"context"
	"testing"
	"time"
)

// benignFindings 构造一个只含良性内容安全 finding 的 body_json（不触发任何 TTL 保护闸）。
func benignFindings() map[string]any {
	return map[string]any{"matched": map[string]any{"findings": []any{
		map[string]any{"type": "content_safety", "category": "illegal_violence_terror"},
	}}}
}

// TestAlertGroupUpsertPersistsLifecycleFields 验证 UpsertOpen 写入并回读 7 个新生命周期列。
func TestAlertGroupUpsertPersistsLifecycleFields(t *testing.T) {
	db, tenantID := setupAlertGroupTestDB(t)
	repo := NewAlertGroupRepository(db)
	ctx := context.Background()

	principal := tenantID + "|ip:192.168.1.5"
	created, isNew, err := repo.UpsertOpen(ctx, AlertGroupUpsertInput{
		TenantID:          tenantID,
		GroupKey:          "gk_lifecycle_1",
		Severity:          "high",
		AlertType:         "security_event",
		Title:             "t",
		OccurredAt:        time.Now().UTC(),
		BodyJSON:          map[string]any{"x": 1},
		EffectiveSeverity: "low",
		DispositionClass:  "informational",
		ClassKey:          "ck_bank_card",
		PrincipalKey:      principal,
		IsCanary:          true,
		Stage:             "output",
	})
	if err != nil {
		t.Fatalf("upsert: %v", err)
	}
	if !isNew {
		t.Fatalf("expected new group")
	}
	got, err := repo.GetByID(ctx, tenantID, created.ID)
	if err != nil {
		t.Fatalf("getbyid: %v", err)
	}
	if got.EffectiveSeverity != "low" {
		t.Errorf("effective_severity=%q want low", got.EffectiveSeverity)
	}
	if got.DispositionClass != "informational" {
		t.Errorf("disposition_class=%q want informational", got.DispositionClass)
	}
	if got.ClassKey != "ck_bank_card" {
		t.Errorf("class_key=%q want ck_bank_card", got.ClassKey)
	}
	if got.PrincipalKey != principal {
		t.Errorf("principal_key=%q want %q", got.PrincipalKey, principal)
	}
	if !got.IsCanary {
		t.Errorf("is_canary=false want true")
	}
	if got.Stage != "output" {
		t.Errorf("stage=%q want output", got.Stage)
	}
}

// TestAutoCloseStaleResolvesStaleBenignInputGroup 验证陈旧、input 侧、无高价值 finding 的组被 TTL 自动关为 resolved。
func TestAutoCloseStaleResolvesStaleBenignInputGroup(t *testing.T) {
	db, tenantID := setupAlertGroupTestDB(t)
	repo := NewAlertGroupRepository(db)
	ctx := context.Background()

	stale := time.Now().UTC().Add(-30 * 24 * time.Hour)
	g, _, err := repo.UpsertOpen(ctx, AlertGroupUpsertInput{
		TenantID: tenantID, GroupKey: "gk_benign", Severity: "high", AlertType: "security_event",
		Title: "t", OccurredAt: stale, Stage: "input", BodyJSON: benignFindings(),
	})
	if err != nil {
		t.Fatalf("upsert: %v", err)
	}

	n, err := repo.AutoCloseStale(ctx, time.Now().UTC(), 14*24*time.Hour, FaultQuietTTL, 1000)
	if err != nil {
		t.Fatalf("autoclose: %v", err)
	}
	if n < 1 {
		t.Fatalf("expected at least 1 closed, got %d", n)
	}

	got, err := repo.GetByID(ctx, tenantID, g.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Status != AlertGroupStatusResolved {
		t.Fatalf("expected resolved, got %s", got.Status)
	}
	var by string
	if err := db.QueryRow(ctx, `SELECT COALESCE(disposition_by,'') FROM alert_groups WHERE id=$1`, g.ID).Scan(&by); err != nil {
		t.Fatalf("query disposition_by: %v", err)
	}
	if by != "system_ttl" {
		t.Fatalf("expected disposition_by=system_ttl, got %q", by)
	}
}

// TestAutoCloseStaleProtectsGuardedGroups 验证三闸 + 高价值 finding + 未回填 stage 的组永不被 TTL 自动关。
func TestAutoCloseStaleProtectsGuardedGroups(t *testing.T) {
	db, tenantID := setupAlertGroupTestDB(t)
	repo := NewAlertGroupRepository(db)
	ctx := context.Background()
	stale := time.Now().UTC().Add(-30 * 24 * time.Hour)

	mk := func(gk string, mut func(*AlertGroupUpsertInput)) string {
		in := AlertGroupUpsertInput{
			TenantID: tenantID, GroupKey: gk, Severity: "high", AlertType: "security_event",
			Title: "t", OccurredAt: stale, Stage: "input", BodyJSON: benignFindings(),
		}
		mut(&in)
		g, _, err := repo.UpsertOpen(ctx, in)
		if err != nil {
			t.Fatalf("upsert %s: %v", gk, err)
		}
		return g.ID
	}

	guarded := map[string]string{
		"canary":       mk("gk_canary", func(in *AlertGroupUpsertInput) { in.IsCanary = true }),
		"output":       mk("gk_output", func(in *AlertGroupUpsertInput) { in.Stage = "output" }),
		"unbackfilled": mk("gk_nostage", func(in *AlertGroupUpsertInput) { in.Stage = "" }),
		"secret": mk("gk_secret", func(in *AlertGroupUpsertInput) {
			in.BodyJSON = map[string]any{"matched": map[string]any{"findings": []any{
				map[string]any{"type": "secret", "category": "openai_key"}}}}
		}),
		"syscmd": mk("gk_syscmd", func(in *AlertGroupUpsertInput) {
			in.BodyJSON = map[string]any{"matched": map[string]any{"findings": []any{
				map[string]any{"type": "content_safety", "category": "illegal_system_command_instructions"}}}}
		}),
	}

	if _, err := repo.AutoCloseStale(ctx, time.Now().UTC(), 14*24*time.Hour, FaultQuietTTL, 1000); err != nil {
		t.Fatalf("autoclose: %v", err)
	}
	for name, id := range guarded {
		got, err := repo.GetByID(ctx, tenantID, id)
		if err != nil {
			t.Fatalf("get %s: %v", name, err)
		}
		if got.Status != AlertGroupStatusOpen {
			t.Errorf("guarded group %s should stay open, got %s", name, got.Status)
		}
	}
}

// TestAutoCloseStaleSkipsFreshGroup 验证未过 TTL 的组不被关。
func TestAutoCloseStaleSkipsFreshGroup(t *testing.T) {
	db, tenantID := setupAlertGroupTestDB(t)
	repo := NewAlertGroupRepository(db)
	ctx := context.Background()

	g, _, err := repo.UpsertOpen(ctx, AlertGroupUpsertInput{
		TenantID: tenantID, GroupKey: "gk_fresh", Severity: "high", AlertType: "security_event",
		Title: "t", OccurredAt: time.Now().UTC(), Stage: "input", BodyJSON: benignFindings(),
	})
	if err != nil {
		t.Fatalf("upsert: %v", err)
	}
	if _, err := repo.AutoCloseStale(ctx, time.Now().UTC(), 14*24*time.Hour, FaultQuietTTL, 1000); err != nil {
		t.Fatalf("autoclose: %v", err)
	}
	got, err := repo.GetByID(ctx, tenantID, g.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Status != AlertGroupStatusOpen {
		t.Fatalf("fresh group should stay open, got %s", got.Status)
	}
}

// pureFaultFindings 构造运行故障组真实的 body_json 形态：只有运行侧元数据，
// 不含任何安全 finding（现网写入点全都如此，逐个核对见 AutoCloseStale 注释）。
func pureFaultFindings() map[string]any {
	return map[string]any{"matched": map[string]any{
		"findings":                   []any{},
		"counts_as_security_finding": false,
		"category":                   "system",
	}}
}

// TestAutoCloseStaleResolvesQuietRuntimeFaultGroup 验证运行故障组走独立静默窗：
// stage 未回填不保护它（故障没有可靠的 stage 可言），只有静默满 faultTTL 才关，
// 且 disposition_note 与低危留观区分开。金丝雀与高价值 finding 的保护另见
// TestAutoCloseStaleProtectsRuntimeFaultGroupsCarryingEvidence。
func TestAutoCloseStaleResolvesQuietRuntimeFaultGroup(t *testing.T) {
	db, tenantID := setupAlertGroupTestDB(t)
	repo := NewAlertGroupRepository(db)
	ctx := context.Background()
	now := time.Now().UTC()

	upsert := func(groupKey string, occurredAt time.Time, alertType string, body map[string]any, stage string) string {
		g, _, err := repo.UpsertOpen(ctx, AlertGroupUpsertInput{
			TenantID: tenantID, GroupKey: groupKey, Severity: "low", AlertType: alertType,
			Title: "t", OccurredAt: occurredAt, Stage: stage, BodyJSON: body,
		})
		if err != nil {
			t.Fatalf("upsert %s: %v", groupKey, err)
		}
		return g.ID
	}

	quiet := upsert("gk_fault_quiet", now.Add(-7*time.Hour), "runtime_fault", pureFaultFindings(), "")
	fresh := upsert("gk_fault_fresh", now.Add(-1*time.Hour), "runtime_fault", pureFaultFindings(), "")
	// 同一时刻的非故障组：它的 TTL 是 14 天，绝不能被 6 小时窗误关。
	benign := upsert("gk_benign_7h", now.Add(-7*time.Hour), "security_event", benignFindings(), "input")

	if _, err := repo.AutoCloseStale(ctx, now, 14*24*time.Hour, FaultQuietTTL, 1000); err != nil {
		t.Fatalf("autoclose: %v", err)
	}

	got, err := repo.GetByID(ctx, tenantID, quiet)
	if err != nil {
		t.Fatalf("get quiet: %v", err)
	}
	if got.Status != AlertGroupStatusResolved {
		t.Fatalf("quiet fault should be resolved, got %s", got.Status)
	}
	var by, note string
	if err := db.QueryRow(ctx, `SELECT COALESCE(disposition_by,''), COALESCE(disposition_note,'') FROM alert_groups WHERE id=$1`, quiet).Scan(&by, &note); err != nil {
		t.Fatalf("query quiet disposition: %v", err)
	}
	if by != "system_ttl" || note != "auto_closed_fault_quiet" {
		t.Fatalf("quiet fault disposition=(%q,%q) want (system_ttl,auto_closed_fault_quiet)", by, note)
	}

	for name, id := range map[string]string{"fresh_fault": fresh, "benign_in_window": benign} {
		row, err := repo.GetByID(ctx, tenantID, id)
		if err != nil {
			t.Fatalf("get %s: %v", name, err)
		}
		if row.Status != AlertGroupStatusOpen {
			t.Errorf("%s should stay open, got %s", name, row.Status)
		}
	}
}

// TestAutoCloseStaleProtectsRuntimeFaultGroupsCarryingEvidence 是护栏回归：运行故障分支
// 豁免 stage，但不豁免 canary 与高价值 finding。现网所有故障事件写入点都不带安全 finding，
// 所以这几组不该出现——一旦出现（或将来某个写入点改了），它们必须留在收件箱里，
// 而不是 6 小时后安静地变成 resolved。金丝雀还有一条独立路径：is_canary 走 sticky-OR，
// 组上那个标记一旦为真就永不复位，所以它必须自己就能挡住关闭。
func TestAutoCloseStaleProtectsRuntimeFaultGroupsCarryingEvidence(t *testing.T) {
	db, tenantID := setupAlertGroupTestDB(t)
	repo := NewAlertGroupRepository(db)
	ctx := context.Background()
	now := time.Now().UTC()

	upsert := func(groupKey string, body map[string]any, isCanary bool) string {
		g, _, err := repo.UpsertOpen(ctx, AlertGroupUpsertInput{
			TenantID: tenantID, GroupKey: groupKey, Severity: "low", AlertType: "runtime_fault",
			Title: "t", OccurredAt: now.Add(-30 * 24 * time.Hour), Stage: "", BodyJSON: body,
			IsCanary: isCanary,
		})
		if err != nil {
			t.Fatalf("upsert %s: %v", groupKey, err)
		}
		return g.ID
	}
	withFinding := func(f map[string]any) map[string]any {
		return map[string]any{"matched": map[string]any{"findings": []any{f}}}
	}

	guarded := map[string]string{
		"canary_flag": upsert("gk_fault_canary_flag", pureFaultFindings(), true),
		"canary_finding": upsert("gk_fault_canary_finding", withFinding(
			map[string]any{"type": "content_safety", "category": "agent_canary_token_leak"}), false),
		"secret_finding": upsert("gk_fault_secret", withFinding(
			map[string]any{"type": "secret", "category": "openai_key"}), false),
		"classified_finding": upsert("gk_fault_classified", withFinding(
			map[string]any{"type": "content_safety", "category": "classified_cn"}), false),
	}

	if _, err := repo.AutoCloseStale(ctx, now, 14*24*time.Hour, FaultQuietTTL, 1000); err != nil {
		t.Fatalf("autoclose: %v", err)
	}
	for name, id := range guarded {
		got, err := repo.GetByID(ctx, tenantID, id)
		if err != nil {
			t.Fatalf("get %s: %v", name, err)
		}
		if got.Status != AlertGroupStatusOpen {
			t.Errorf("runtime-fault group %s carries redline evidence and must stay open, got %s",
				name, got.Status)
		}
	}
}

// TestFaultQuietTTLIsSixHours 把 6 小时静默窗钉成常量契约：改这个数字等于改运维承诺，
// 必须是有意为之并同步文档。
func TestFaultQuietTTLIsSixHours(t *testing.T) {
	if FaultQuietTTL != 6*time.Hour {
		t.Fatalf("FaultQuietTTL=%s, want 6h", FaultQuietTTL)
	}
}
