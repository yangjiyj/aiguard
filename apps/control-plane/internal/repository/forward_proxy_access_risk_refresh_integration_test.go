package repository

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// 本文件验证 RefreshRecentRiskColumns「只写真正变化的行」。
//
// 背景:该刷新每 2 分钟把最近 15 分钟的全部 request_logs 行无条件重写一遍,
// 值没变也产生新元组版本,在慢盘现场放大 WAL 与死元组。
//
// 隔离方式:每个测试在专用测试库里新建一个临时 schema,只放 5 张表的 LIKE 副本,
// 连接池 search_path 只指向该 schema(不含 public)。刷新 SQL 里的表名都是未限定的,
// 因此只会碰到测试自己造的行;万一副本缺表会直接报错,不会悄悄落到 public 的真实数据上。
// LIKE 不复制触发器与外键:request_logs 上现有触发器都只监听其他列
// (proxy_mode / agent_* 等),不会被 risk_state、has_retained_content 的更新触发。

const riskRefreshWindow = 15 * time.Minute

// riskRefreshFixtureTables 是刷新 SQL(含风险/留存表达式)实际引用到的表。
var riskRefreshFixtureTables = []string{
	"tenants",
	"request_logs",
	"security_events",
	"access_content_logs",
	"content_logs",
	"content_log_entries",
	"content_log_bodies",
	"content_logs_legacy",
}

const (
	riskRefreshStrongFinding = `{"findings":[{"type":"secret","category":"aws_secret_key","rule_id":"secret_aws_secret_key","severity":"high"}]}`
	riskRefreshWeakFinding   = `{"findings":[{"type":"prompt_injection","category":"structured_template_injection","rule_id":"prompt_injection_template_injection","severity":"high"}]}`
	riskRefreshInputAudit    = `{"stage":"input","findings":[{"type":"secret","category":"aws_secret_key","rule_id":"secret_aws_secret_key","severity":"high"}]}`
)

// riskRefreshLegacySQL 是改动前 RefreshRecentRiskColumns 的原样 SQL,
// 留在测试里作为逐行对照的基准(用例 a)。它复用同一个 SET 子句,
// 所以对照出来的差别只可能来自「新增的 WHERE 过滤」。不要为了让测试通过而修改它。
func riskRefreshLegacySQL() string {
	return fmt.Sprintf("UPDATE request_logs rl SET %s WHERE rl.tenant_id IN (SELECT id FROM tenants) AND rl.created_at >= $1", forwardProxyRiskColumnsSetClause())
}

// 不依赖数据库的文本断言:最终 SQL 里「写入的值」与「用来比较的值」必须来自同一份
// 表达式文本(防漂移),并且两列都要用 IS DISTINCT FROM 比较(NULL 安全)。
func TestRecentRiskColumnsRefreshQueryComparesTheValuesItWrites(t *testing.T) {
	query := recentRiskColumnsRefreshQuery()
	riskExpr := forwardProxyRiskExpr()
	contentExpr := forwardProxyHasRetainedContentExpr()
	for _, want := range []string{
		"SET risk_state = " + riskExpr,
		", has_retained_content = " + contentExpr,
		"rl.risk_state IS DISTINCT FROM (" + riskExpr + ")",
		"rl.has_retained_content IS DISTINCT FROM (" + contentExpr + ")",
		"rl.tenant_id IN (SELECT id FROM tenants)",
		"rl.created_at >= $1",
	} {
		if !strings.Contains(query, want) {
			head := want
			if len(head) > 90 {
				head = head[:90] + "..."
			}
			t.Errorf("refresh query is missing %q", head)
		}
	}
	if !strings.Contains(query, ") OR rl.has_retained_content IS DISTINCT FROM (") {
		t.Errorf("the two column comparisons must be OR-ed so a change in either column triggers the write")
	}
}

type riskRefreshEnv struct {
	db     *pgxpool.Pool
	schema string
}

func riskRefreshAdminPool(t *testing.T) (*pgxpool.Pool, string) {
	t.Helper()
	dsn := os.Getenv("CONTENT_LOGS_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("CONTENT_LOGS_TEST_DATABASE_URL is not set")
	}
	admin, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatalf("connect admin pool: %v", err)
	}
	t.Cleanup(admin.Close)
	return admin, dsn
}

// newRiskRefreshEnv 建一个隔离 schema 并返回只指向它的单连接池。
// 单连接是为了让 pg_stat_force_next_flush() 与随后的统计读取落在同一个后端上,
// 否则 UPDATE 产生的待上报统计可能还留在另一条连接里,n_tup_upd 会读到旧值。
func newRiskRefreshEnv(t *testing.T, admin *pgxpool.Pool, dsn string) riskRefreshEnv {
	t.Helper()
	ctx := context.Background()
	schema := "risk_refresh_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	quoted := pgx.Identifier{schema}.Sanitize()
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+quoted); err != nil {
		t.Fatalf("create schema: %v", err)
	}
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatalf("parse dsn: %v", err)
	}
	cfg.MaxConns = 1
	cfg.ConnConfig.RuntimeParams["search_path"] = schema
	db, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatalf("connect isolated pool: %v", err)
	}
	// 先关池再删 schema(与同包其他夹具一致,db.Close 必须放进 Cleanup 而非 defer)。
	t.Cleanup(func() {
		db.Close()
		if _, err := admin.Exec(ctx, "DROP SCHEMA IF EXISTS "+quoted+" CASCADE"); err != nil {
			t.Logf("drop schema %s: %v", schema, err)
		}
	})
	for _, table := range riskRefreshFixtureTables {
		stmt := fmt.Sprintf("CREATE TABLE %s (LIKE public.%s INCLUDING ALL)", pgx.Identifier{table}.Sanitize(), pgx.Identifier{table}.Sanitize())
		if _, err := db.Exec(ctx, stmt); err != nil {
			t.Fatalf("clone table %s: %v", table, err)
		}
	}
	if _, err := db.Exec(ctx, `CREATE FUNCTION mirror_fixture_content() RETURNS trigger LANGUAGE plpgsql SET search_path FROM CURRENT AS $$ BEGIN
 INSERT INTO content_logs_legacy SELECT NEW.*; RETURN NEW; END $$;
 CREATE TRIGGER mirror_fixture_content AFTER INSERT ON content_logs FOR EACH ROW EXECUTE FUNCTION mirror_fixture_content()`); err != nil {
		t.Fatal(err)
	}
	return riskRefreshEnv{db: db, schema: schema}
}

type riskRefreshRequest struct {
	id         string
	tenantID   string
	createdAt  time.Time
	status     string // 空 = success
	proxyMode  string // 空 = forward
	inputAudit string // 空 = NULL
}

type riskRefreshSeed struct {
	env      riskRefreshEnv
	tenantID string
	now      time.Time

	// 各场景的 request_id:
	normalID        string // 无任何风险信号
	riskEventID     string // 强信号事件(action=audit) -> risk
	blockedStatusID string // request_status=blocked -> blocked
	blockedEventID  string // 强信号事件(action=block) -> blocked
	weakEventID     string // 仅弱信号事件 -> normal
	auditRiskID     string // input_audit_result 带强 finding -> risk
	contentACLID    string // access_content_logs 有留存内容 -> has_retained_content
	contentCLID     string // content_logs 有留存内容(非 forward) -> has_retained_content
	outsideWindowID string // 窗口外的风险行,刷新不应触碰
	unknownTenantID string // 租户不在 tenants 表,刷新不应触碰
}

func (s *riskRefreshSeed) insertRequest(t *testing.T, r riskRefreshRequest) {
	t.Helper()
	status, mode := r.status, r.proxyMode
	if status == "" {
		status = "success"
	}
	if mode == "" {
		mode = "forward"
	}
	if _, err := s.env.db.Exec(context.Background(), `
		INSERT INTO request_logs (id, request_id, tenant_id, endpoint_type, request_status, proxy_mode,
			proxy_target_host, proxy_access_type_resolved, input_audit_result, created_at)
		VALUES ($1, $1, $2, 'proxy', $3, $4, 'api.example.test', 'llm', NULLIF($5, '')::jsonb, $6)`,
		r.id, r.tenantID, status, mode, r.inputAudit, r.createdAt); err != nil {
		t.Fatalf("insert request %s: %v", r.id, err)
	}
}

func (s *riskRefreshSeed) insertEvent(t *testing.T, id, requestID, action, matched string) {
	t.Helper()
	if _, err := s.env.db.Exec(context.Background(), `
		INSERT INTO security_events (id, request_id, tenant_id, project_id, event_type, severity, action_taken, matched_summary, created_at)
		VALUES ($1, $2, $3, 'project_default', 'security_check', 'high', $4, $5::jsonb, $6)`,
		id, requestID, s.tenantID, action, matched, s.now); err != nil {
		t.Fatalf("insert event %s: %v", id, err)
	}
}

func (s *riskRefreshSeed) insertAccessContent(t *testing.T, requestID, content string) {
	t.Helper()
	if _, err := s.env.db.Exec(context.Background(),
		`INSERT INTO access_content_logs (request_id, tenant_id, request_content_redacted) VALUES ($1, $2, $3)`,
		requestID, s.tenantID, content); err != nil {
		t.Fatalf("insert access_content_logs for %s: %v", requestID, err)
	}
}

// seedRiskRefresh 造一批覆盖「风险三态 × 留存内容 × 窗口/租户边界」的请求。
// risk_state / has_retained_content 全部留 NULL,模拟「尚未计算」。
func seedRiskRefresh(t *testing.T, env riskRefreshEnv) *riskRefreshSeed {
	t.Helper()
	ctx := context.Background()
	suffix := strings.ReplaceAll(uuid.NewString(), "-", "")[:12]
	s := &riskRefreshSeed{
		env:             env,
		tenantID:        "tenant_rr_" + suffix,
		now:             time.Now().UTC(),
		normalID:        "rr_normal_" + suffix,
		riskEventID:     "rr_risk_event_" + suffix,
		blockedStatusID: "rr_blocked_status_" + suffix,
		blockedEventID:  "rr_blocked_event_" + suffix,
		weakEventID:     "rr_weak_event_" + suffix,
		auditRiskID:     "rr_audit_risk_" + suffix,
		contentACLID:    "rr_content_acl_" + suffix,
		contentCLID:     "rr_content_cl_" + suffix,
		outsideWindowID: "rr_outside_window_" + suffix,
		unknownTenantID: "rr_unknown_tenant_" + suffix,
	}
	if _, err := env.db.Exec(ctx, `INSERT INTO tenants (id, name, edition, status, is_test) VALUES ($1, $1, 'enterprise', 'active', TRUE)`, s.tenantID); err != nil {
		t.Fatalf("insert tenant: %v", err)
	}
	inWindow := s.now.Add(-5 * time.Minute)

	s.insertRequest(t, riskRefreshRequest{id: s.normalID, tenantID: s.tenantID, createdAt: inWindow})

	s.insertRequest(t, riskRefreshRequest{id: s.riskEventID, tenantID: s.tenantID, createdAt: inWindow})
	s.insertEvent(t, "evt_"+s.riskEventID, s.riskEventID, "audit", riskRefreshStrongFinding)

	s.insertRequest(t, riskRefreshRequest{id: s.blockedStatusID, tenantID: s.tenantID, createdAt: inWindow, status: "blocked"})

	s.insertRequest(t, riskRefreshRequest{id: s.blockedEventID, tenantID: s.tenantID, createdAt: inWindow})
	s.insertEvent(t, "evt_"+s.blockedEventID, s.blockedEventID, "block", riskRefreshStrongFinding)

	// 仅有弱信号事件:表达式把它当 normal(与 TestListForwardProxyAccessTreatsWeakAuditSignalsAsNormal 同口径)。
	s.insertRequest(t, riskRefreshRequest{id: s.weakEventID, tenantID: s.tenantID, createdAt: inWindow})
	s.insertEvent(t, "evt_"+s.weakEventID, s.weakEventID, "security_audit_only", riskRefreshWeakFinding)

	s.insertRequest(t, riskRefreshRequest{id: s.auditRiskID, tenantID: s.tenantID, createdAt: inWindow, inputAudit: riskRefreshInputAudit})

	s.insertRequest(t, riskRefreshRequest{id: s.contentACLID, tenantID: s.tenantID, createdAt: inWindow})
	s.insertAccessContent(t, s.contentACLID, "hello")

	s.insertRequest(t, riskRefreshRequest{id: s.contentCLID, tenantID: s.tenantID, createdAt: inWindow, proxyMode: "chat_completion"})
	if _, err := env.db.Exec(ctx, `INSERT INTO content_logs (request_id, tenant_id, role, content) VALUES ($1, $2, 'user', 'hi there')`, s.contentCLID, s.tenantID); err != nil {
		t.Fatalf("insert content_logs: %v", err)
	}

	// 窗口外的风险行:刷新不应触碰。
	s.insertRequest(t, riskRefreshRequest{id: s.outsideWindowID, tenantID: s.tenantID, createdAt: s.now.Add(-2 * time.Hour)})
	s.insertEvent(t, "evt_"+s.outsideWindowID, s.outsideWindowID, "audit", riskRefreshStrongFinding)

	// 租户不在 tenants 表:旧 SQL 的 tenant_id IN (SELECT id FROM tenants) 会把它排除。
	// 副本由 LIKE 建出、不带外键,所以可以直接插入。
	s.insertRequest(t, riskRefreshRequest{id: s.unknownTenantID, tenantID: "tenant_missing_" + suffix, createdAt: inWindow})
	return s
}

type riskColumns struct {
	RiskState          *string
	HasRetainedContent *bool
}

func (c riskColumns) String() string {
	rs, hc := "NULL", "NULL"
	if c.RiskState != nil {
		rs = *c.RiskState
	}
	if c.HasRetainedContent != nil {
		hc = fmt.Sprint(*c.HasRetainedContent)
	}
	return "risk_state=" + rs + " has_retained_content=" + hc
}

func readRiskColumns(t *testing.T, db *pgxpool.Pool) map[string]riskColumns {
	t.Helper()
	rows, err := db.Query(context.Background(), `SELECT id, risk_state, has_retained_content FROM request_logs`)
	if err != nil {
		t.Fatalf("read risk columns: %v", err)
	}
	defer rows.Close()
	out := map[string]riskColumns{}
	for rows.Next() {
		var id string
		var c riskColumns
		if err := rows.Scan(&id, &c.RiskState, &c.HasRetainedContent); err != nil {
			t.Fatalf("scan risk columns: %v", err)
		}
		out[id] = c
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate risk columns: %v", err)
	}
	return out
}

// readWholeRows 把每一行转成规范化 JSON 文本,用来比较「整行」而不只是两个风险列。
func readWholeRows(t *testing.T, db *pgxpool.Pool) map[string]string {
	t.Helper()
	rows, err := db.Query(context.Background(), `SELECT id, to_jsonb(rl)::text FROM request_logs rl`)
	if err != nil {
		t.Fatalf("read whole rows: %v", err)
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var id, doc string
		if err := rows.Scan(&id, &doc); err != nil {
			t.Fatalf("scan whole rows: %v", err)
		}
		out[id] = doc
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate whole rows: %v", err)
	}
	return out
}

// copyTableRows 把 from schema 里某表的全部行复制到 to schema 的同名表(生成列不能显式插入,已排除)。
func copyTableRows(t *testing.T, admin *pgxpool.Pool, from, to, table string) {
	t.Helper()
	// content_logs 的夹具触发器已把行镜像进 content_logs_legacy，再复制一次会重复插入。
	if table == "content_logs_legacy" {
		return
	}
	ctx := context.Background()
	rows, err := admin.Query(ctx, `
		SELECT a.attname
		FROM pg_attribute a
		JOIN pg_class c ON c.oid = a.attrelid
		JOIN pg_namespace n ON n.oid = c.relnamespace
		WHERE n.nspname = $1 AND c.relname = $2 AND a.attnum > 0 AND NOT a.attisdropped AND a.attgenerated = ''
		ORDER BY a.attnum`, from, table)
	if err != nil {
		t.Fatalf("list columns of %s.%s: %v", from, table, err)
	}
	var cols []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			rows.Close()
			t.Fatalf("scan column name: %v", err)
		}
		cols = append(cols, pgx.Identifier{name}.Sanitize())
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate columns of %s.%s: %v", from, table, err)
	}
	list := strings.Join(cols, ", ")
	stmt := fmt.Sprintf("INSERT INTO %s (%s) SELECT %s FROM %s",
		pgx.Identifier{to, table}.Sanitize(), list, list, pgx.Identifier{from, table}.Sanitize())
	if _, err := admin.Exec(ctx, stmt); err != nil {
		t.Fatalf("copy %s from %s to %s: %v", table, from, to, err)
	}
}

// requestLogsUpdateCount 返回隔离表 request_logs 在 pg_stat_user_tables 里的累计 n_tup_upd。
// 先 pg_stat_force_next_flush():否则会话内的统计可能尚未落入共享内存而读到旧值。
// 该函数 PG15 起才有;不存在时返回 ok=false,调用方跳过这条交叉验证(RowsAffected 断言仍然生效)。
func requestLogsUpdateCount(t *testing.T, db *pgxpool.Pool) (updates int64, ok bool) {
	t.Helper()
	ctx := context.Background()
	// track_counts 关闭时计数器不会动,交叉验证没有意义,直接跳过。
	var trackCounts string
	if err := db.QueryRow(ctx, `SHOW track_counts`).Scan(&trackCounts); err != nil {
		t.Fatalf("show track_counts: %v", err)
	}
	if trackCounts != "on" {
		return 0, false
	}
	var hasForce bool
	if err := db.QueryRow(ctx, `SELECT to_regprocedure('pg_stat_force_next_flush()') IS NOT NULL`).Scan(&hasForce); err != nil {
		t.Fatalf("probe pg_stat_force_next_flush: %v", err)
	}
	if !hasForce {
		return 0, false
	}
	if _, err := db.Exec(ctx, `SELECT pg_stat_force_next_flush()`); err != nil {
		t.Fatalf("pg_stat_force_next_flush: %v", err)
	}
	if err := db.QueryRow(ctx, `SELECT n_tup_upd FROM pg_stat_user_tables WHERE relid = 'request_logs'::regclass`).Scan(&updates); err != nil {
		t.Fatalf("read n_tup_upd: %v", err)
	}
	return updates, true
}

// 用例 (a):同一批数据上,新实现第一次刷新的结果必须与改动前的旧 SQL 逐行一致。
func TestRefreshRecentRiskColumnsFirstRunMatchesLegacySQL(t *testing.T) {
	admin, dsn := riskRefreshAdminPool(t)
	ctx := context.Background()

	envNew := newRiskRefreshEnv(t, admin, dsn)
	seed := seedRiskRefresh(t, envNew)

	// 另建一个 schema,灌入与 envNew 完全相同的行,用来跑旧 SQL。
	envLegacy := newRiskRefreshEnv(t, admin, dsn)
	for _, table := range riskRefreshFixtureTables {
		copyTableRows(t, admin, envNew.schema, envLegacy.schema, table)
	}

	legacyTag, err := envLegacy.db.Exec(ctx, riskRefreshLegacySQL(), time.Now().Add(-riskRefreshWindow))
	if err != nil {
		t.Fatalf("legacy refresh: %v", err)
	}
	updated, err := NewRequestLogRepository(envNew.db).RefreshRecentRiskColumns(ctx, riskRefreshWindow)
	if err != nil {
		t.Fatalf("new refresh: %v", err)
	}

	newRows := readWholeRows(t, envNew.db)
	legacyRows := readWholeRows(t, envLegacy.db)
	if len(newRows) != len(legacyRows) {
		t.Fatalf("row count differs: new=%d legacy=%d", len(newRows), len(legacyRows))
	}
	for id, want := range legacyRows {
		if have, ok := newRows[id]; !ok || have != want {
			t.Errorf("row %s differs from legacy SQL:\n new:    %s\n legacy: %s", id, have, want)
		}
	}

	// 窗口内行的两列都从 NULL 变成了非 NULL,所以「真正更新的行数」应等于旧 SQL 影响的行数。
	if updated != legacyTag.RowsAffected() {
		t.Errorf("first refresh rows = %d, legacy rows = %d (every in-window row starts NULL, so they must be equal)", updated, legacyTag.RowsAffected())
	}

	// 抽查关键语义,避免「两边都错得一样」。
	cols := readRiskColumns(t, envNew.db)
	assertRisk := func(id, wantRisk string, wantContent bool) {
		t.Helper()
		c := cols[id]
		if c.RiskState == nil || c.HasRetainedContent == nil {
			t.Errorf("row %s was not computed: {%s}", id, c)
			return
		}
		if *c.RiskState != wantRisk || *c.HasRetainedContent != wantContent {
			t.Errorf("row %s: got {%s}, want risk_state=%s has_retained_content=%v", id, c, wantRisk, wantContent)
		}
	}
	assertRisk(seed.normalID, "normal", false)
	assertRisk(seed.riskEventID, "risk", false)
	assertRisk(seed.blockedStatusID, "blocked", false)
	assertRisk(seed.blockedEventID, "blocked", false)
	assertRisk(seed.weakEventID, "normal", false)
	assertRisk(seed.auditRiskID, "risk", false)
	assertRisk(seed.contentACLID, "normal", true)
	assertRisk(seed.contentCLID, "normal", true)
	for _, id := range []string{seed.outsideWindowID, seed.unknownTenantID} {
		if c := cols[id]; c.RiskState != nil || c.HasRetainedContent != nil {
			t.Errorf("row %s must stay untouched (outside window / unknown tenant), got {%s}", id, c)
		}
	}
}

// 用例 (b):数据没变时再刷新一次,必须更新 0 行(RowsAffected 与 n_tup_upd 双重证明)。
func TestRefreshRecentRiskColumnsSecondRunUpdatesNothing(t *testing.T) {
	admin, dsn := riskRefreshAdminPool(t)
	ctx := context.Background()
	env := newRiskRefreshEnv(t, admin, dsn)
	seedRiskRefresh(t, env)
	repo := NewRequestLogRepository(env.db)

	first, err := repo.RefreshRecentRiskColumns(ctx, riskRefreshWindow)
	if err != nil {
		t.Fatalf("first refresh: %v", err)
	}
	if first == 0 {
		t.Fatalf("first refresh should compute the NULL rows, got 0")
	}
	before := readWholeRows(t, env.db)
	updBefore, statsOK := requestLogsUpdateCount(t, env.db)

	second, err := repo.RefreshRecentRiskColumns(ctx, riskRefreshWindow)
	if err != nil {
		t.Fatalf("second refresh: %v", err)
	}
	if second != 0 {
		t.Errorf("second refresh on unchanged data must update 0 rows, got %d", second)
	}
	if statsOK {
		if updAfter, _ := requestLogsUpdateCount(t, env.db); updAfter != updBefore {
			t.Errorf("n_tup_upd moved from %d to %d on unchanged data; expected no new row versions", updBefore, updAfter)
		}
	} else {
		t.Log("pg_stat_force_next_flush unavailable; n_tup_upd cross-check skipped")
	}
	after := readWholeRows(t, env.db)
	for id, want := range before {
		if after[id] != want {
			t.Errorf("row %s changed on a no-op refresh:\n before: %s\n after:  %s", id, want, after[id])
		}
	}
}

// 用例 (c):只有一行的风险来源变化时,只更新那一行。
func TestRefreshRecentRiskColumnsOnlyWritesChangedRow(t *testing.T) {
	admin, dsn := riskRefreshAdminPool(t)
	ctx := context.Background()
	env := newRiskRefreshEnv(t, admin, dsn)
	seed := seedRiskRefresh(t, env)
	repo := NewRequestLogRepository(env.db)

	if _, err := repo.RefreshRecentRiskColumns(ctx, riskRefreshWindow); err != nil {
		t.Fatalf("seed refresh: %v", err)
	}

	// 延迟到达的安全事件:原本 normal 的行变成 risk(只此一行)。
	seed.insertEvent(t, "evt_late_"+seed.normalID, seed.normalID, "audit", riskRefreshStrongFinding)
	updBefore, statsOK := requestLogsUpdateCount(t, env.db)
	n, err := repo.RefreshRecentRiskColumns(ctx, riskRefreshWindow)
	if err != nil {
		t.Fatalf("refresh after late event: %v", err)
	}
	if n != 1 {
		t.Errorf("only the row that gained a security event may be written, rows updated = %d", n)
	}
	if statsOK {
		if updAfter, _ := requestLogsUpdateCount(t, env.db); updAfter-updBefore != 1 {
			t.Errorf("n_tup_upd delta = %d, want 1", updAfter-updBefore)
		}
	}
	if c := readRiskColumns(t, env.db)[seed.normalID]; c.RiskState == nil || *c.RiskState != "risk" {
		t.Errorf("row %s should have become risk, got {%s}", seed.normalID, c)
	}

	// 再追加一条留存内容:另一行 has_retained_content 由 false 变 true,同样只写那一行。
	seed.insertAccessContent(t, seed.riskEventID, "late content")
	updBefore, _ = requestLogsUpdateCount(t, env.db)
	n, err = repo.RefreshRecentRiskColumns(ctx, riskRefreshWindow)
	if err != nil {
		t.Fatalf("refresh after late content: %v", err)
	}
	if n != 1 {
		t.Errorf("only the row that gained retained content may be written, rows updated = %d", n)
	}
	if statsOK {
		if updAfter, _ := requestLogsUpdateCount(t, env.db); updAfter-updBefore != 1 {
			t.Errorf("n_tup_upd delta = %d, want 1", updAfter-updBefore)
		}
	}
	if c := readRiskColumns(t, env.db)[seed.riskEventID]; c.HasRetainedContent == nil || !*c.HasRetainedContent {
		t.Errorf("row %s should now have retained content, got {%s}", seed.riskEventID, c)
	}

	// 收尾:数据稳定后再刷新必须回到 0。
	if n, err = repo.RefreshRecentRiskColumns(ctx, riskRefreshWindow); err != nil || n != 0 {
		t.Errorf("settled data must refresh to 0 rows, got n=%d err=%v", n, err)
	}
}

// 补充:窗口内「值已过期」的行必须仍被纠正(防止过滤写成永远不更新),且只纠正它。
func TestRefreshRecentRiskColumnsCorrectsStaleValue(t *testing.T) {
	admin, dsn := riskRefreshAdminPool(t)
	ctx := context.Background()
	env := newRiskRefreshEnv(t, admin, dsn)
	seed := seedRiskRefresh(t, env)
	repo := NewRequestLogRepository(env.db)

	if _, err := repo.RefreshRecentRiskColumns(ctx, riskRefreshWindow); err != nil {
		t.Fatalf("seed refresh: %v", err)
	}
	if _, err := env.db.Exec(ctx, `UPDATE request_logs SET risk_state = 'normal', has_retained_content = TRUE WHERE id = $1`, seed.blockedEventID); err != nil {
		t.Fatalf("corrupt row: %v", err)
	}
	n, err := repo.RefreshRecentRiskColumns(ctx, riskRefreshWindow)
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if n != 1 {
		t.Errorf("exactly the corrupted row must be rewritten, rows updated = %d", n)
	}
	c := readRiskColumns(t, env.db)[seed.blockedEventID]
	if c.RiskState == nil || *c.RiskState != "blocked" || c.HasRetainedContent == nil || *c.HasRetainedContent {
		t.Errorf("corrupted row not corrected: {%s}", c)
	}
}

// 补充:只有一列为 NULL、另一列已是正确值时,该行也必须被更新。
// 若误用 <> 而不是 IS DISTINCT FROM,NULL <> x 得 NULL,「NULL OR false」仍是 NULL,这种行会被永远漏掉。
func TestRefreshRecentRiskColumnsTreatsSingleNullColumnAsChanged(t *testing.T) {
	admin, dsn := riskRefreshAdminPool(t)
	ctx := context.Background()
	env := newRiskRefreshEnv(t, admin, dsn)
	seed := seedRiskRefresh(t, env)
	repo := NewRequestLogRepository(env.db)

	if _, err := repo.RefreshRecentRiskColumns(ctx, riskRefreshWindow); err != nil {
		t.Fatalf("seed refresh: %v", err)
	}
	if _, err := env.db.Exec(ctx, `UPDATE request_logs SET risk_state = NULL WHERE id = $1`, seed.riskEventID); err != nil {
		t.Fatalf("null risk_state: %v", err)
	}
	if _, err := env.db.Exec(ctx, `UPDATE request_logs SET has_retained_content = NULL WHERE id = $1`, seed.contentACLID); err != nil {
		t.Fatalf("null has_retained_content: %v", err)
	}
	n, err := repo.RefreshRecentRiskColumns(ctx, riskRefreshWindow)
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if n != 2 {
		t.Errorf("both half-NULL rows must be rewritten, rows updated = %d", n)
	}
	cols := readRiskColumns(t, env.db)
	if c := cols[seed.riskEventID]; c.RiskState == nil || *c.RiskState != "risk" {
		t.Errorf("risk_state NULL row not restored: {%s}", c)
	}
	if c := cols[seed.contentACLID]; c.HasRetainedContent == nil || !*c.HasRetainedContent {
		t.Errorf("has_retained_content NULL row not restored: {%s}", c)
	}
}
