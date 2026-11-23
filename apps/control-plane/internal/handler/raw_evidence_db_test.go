package handler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/audit_chain"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
	"github.com/yangjiyj/aiguard/packages/shared-go/secrets"
)

// rawEvidenceChainWriter 是审计链存储桩：记录同步追加次数，fail 时每次都失败。
type rawEvidenceChainWriter struct {
	mu   sync.Mutex
	n    int
	fail bool
}

func (c *rawEvidenceChainWriter) Append(context.Context, string, string, string, map[string]any) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.fail {
		return errors.New("audit chain storage unavailable")
	}
	c.n++
	return nil
}

func (c *rawEvidenceChainWriter) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.n
}

// failingAuditSystemRepo 让操作审计写入失败，其余照常。
type failingAuditSystemRepo struct{ SystemRepo }

func (failingAuditSystemRepo) CreateAuditOperation(context.Context, *repository.AuditOperation) error {
	return errors.New("audit_operations unavailable")
}

func rawEvidenceRouter(deps *Dependencies) http.Handler {
	r := chi.NewRouter()
	r.Get("/admin/v1/audit/raw-evidence", ListRawEvidence(deps))
	r.Get("/admin/v1/audit/raw-evidence/settings", GetRawEvidenceSettings(deps))
	r.Put("/admin/v1/audit/raw-evidence/settings", UpdateRawEvidenceSettings(deps))
	r.Post("/admin/v1/audit/raw-evidence/{id}/reveal", RevealRawEvidence(deps))
	return r
}

func rawEvidenceCall(h http.Handler, method, target, body, tenant, userID, role string) *httptest.ResponseRecorder {
	return rawEvidenceCallAs(h, method, target, body,
		&repository.User{ID: userID, TenantID: tenant, Role: role, Username: userID},
		&repository.Session{ID: "sess-" + userID, UserID: userID, TenantID: tenant, Role: role})
}

// rawEvidenceCallAs 与线上认证中间件一样同时放入用户与会话；session 为 nil 表示没有会话。
func rawEvidenceCallAs(h http.Handler, method, target, body string, user *repository.User, session *repository.Session) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, target, strings.NewReader(body))
	ctx := context.WithValue(req.Context(), auth.UserKey, user)
	if session != nil {
		ctx = context.WithValue(ctx, auth.SessionKey, session)
	}
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w
}

// 一次性 PostgreSQL（迁移已应用）。CONTENT_LOGS_TEST_DATABASE_URL 未设置时跳过。
func TestRawEvidenceConsoleDatabase(t *testing.T) {
	dsn := os.Getenv("CONTENT_LOGS_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set CONTENT_LOGS_TEST_DATABASE_URL to run raw evidence integration test")
	}
	t.Setenv("JJD_PROVIDER_SECRET_KEY", "raw-evidence-test-secret-0123456789")
	t.Setenv("JJD_SECRETS_CIPHER", "")
	ctx := context.Background()
	db, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	// t.Cleanup 按注册的逆序执行：连接池最先注册、最后关闭，下面的清理语句才真的生效。
	// （原来的 defer db.Close() 先于 t.Cleanup 执行，清理静默失败，开关停在 false、数据残留，
	// 紧接着跑网关 TestRawEvidenceWrittenEncryptedOnPostgres 必定失败。）
	t.Cleanup(db.Close)
	suffix := time.Now().UnixNano()
	tenant := fmt.Sprintf("tenant_rawev_%d", suffix)
	other := fmt.Sprintf("tenant_rawev_other_%d", suffix)
	officer := fmt.Sprintf("user_rawev_%d", suffix)
	mustExec := func(sql string, args ...interface{}) {
		if _, err := db.Exec(ctx, sql, args...); err != nil {
			t.Fatalf("exec %q: %v", sql, err)
		}
	}
	for _, id := range []string{tenant, other} {
		mustExec(`INSERT INTO tenants (id, name, edition, status, is_test) VALUES ($1, $1, 'enterprise', 'active', TRUE)`, id)
	}
	mustExec(`INSERT INTO users (id, tenant_id, username, role, status) VALUES ($1, $2, $1, 'security_officer', 'active')`, officer, tenant)
	// 清理失败要让测试失败，不能静默残留（共享库上其他用例会被开关/数据污染）。
	cleanupExec := func(sql string, args ...interface{}) {
		if _, err := db.Exec(context.Background(), sql, args...); err != nil {
			t.Errorf("cleanup %q: %v", sql, err)
		}
	}
	t.Cleanup(func() {
		cleanupExec(`DELETE FROM content_raw_evidence WHERE tenant_id IN ($1,$2)`, tenant, other)
		cleanupExec(`DELETE FROM audit_operations WHERE user_id = $1`, officer)
		cleanupExec(`DELETE FROM users WHERE tenant_id = $1`, tenant)
		cleanupExec(`DELETE FROM tenants WHERE id IN ($1,$2)`, tenant, other)
		cleanupExec(`UPDATE system_settings SET value='true' WHERE key='raw_evidence_enabled'`)
	})

	const original = "身份证 110101199003071234 手机 13800138000"
	insert := func(tenantID, requestID, direction string, index int, disposition, blockID string, ruleIDs, ruleNames []string, text string) string {
		sessionID := "sess_" + requestID
		cipher, err := secrets.EncryptRawEvidence([]byte(text), secrets.RawEvidenceAAD(tenantID, requestID, "u_writer", sessionID, direction, index, disposition))
		if err != nil {
			t.Fatal(err)
		}
		mac, err := secrets.RawEvidenceContentMAC(tenantID, []byte(text))
		if err != nil {
			t.Fatal(err)
		}
		var id string
		if err := db.QueryRow(ctx, `INSERT INTO content_raw_evidence (tenant_id, request_id, session_id, user_id, direction, role, message_index, disposition, block_id,
			rule_ids, rule_names, content_ciphertext, content_hmac, content_chars, original_chars) VALUES ($1,$2,$3,'u_writer',$4,'user',$5,$6,NULLIF($7,''),$8,$9,$10,$11,$12,$12) RETURNING id`,
			tenantID, requestID, sessionID, direction, index, disposition, blockID, ruleIDs, ruleNames, cipher, mac, len([]rune(text))).Scan(&id); err != nil {
			t.Fatal(err)
		}
		return id
	}
	reqA, reqB := fmt.Sprintf("req_a_%d", suffix), fmt.Sprintf("req_b_%d", suffix)
	idMasked := insert(tenant, reqA, "input", 0, "masked", "", []string{"r-id"}, []string{"身份证号"}, original)
	idBlocked := insert(tenant, reqB, "input", 1, "blocked", "evt_blk_1", []string{"r-key"}, []string{"密钥"}, "密钥 sk-ZZTOP77")
	idOther := insert(other, reqA, "input", 0, "masked", "", []string{}, []string{}, "别的租户的原文")
	// 994 约束：非引用行必须带 enc:v3 密文（NULL 时 LIKE 为 NULL，CHECK 曾被放过，还会占住去重键）；
	// 引用行必须不带密文。两种违规都要被库拒绝。
	for name, sql := range map[string]string{
		"non_ref_without_ciphertext": `INSERT INTO content_raw_evidence (tenant_id, request_id, session_id, direction, role, disposition, content_ciphertext, content_hmac)
			VALUES ($1, 'req_null_cipher', 's_null', 'input', 'user', 'masked', NULL, decode(repeat('cd',32),'hex'))`,
		"ref_with_ciphertext": `INSERT INTO content_raw_evidence (tenant_id, request_id, session_id, direction, role, disposition, content_ciphertext, content_hmac, ref_evidence_id)
			VALUES ($1, 'req_ref_cipher', 's_null', 'input', 'user', 'masked', 'enc:v3:x', decode(repeat('cd',32),'hex'), 'cre_x')`,
	} {
		if _, err := db.Exec(ctx, sql, tenant); err == nil || !strings.Contains(err.Error(), "content_raw_evidence_cipher_check") {
			t.Fatalf("%s must be rejected by content_raw_evidence_cipher_check, got %v", name, err)
		}
	}

	chain := &rawEvidenceChainWriter{}
	deps := &Dependencies{DB: db, SystemRepo: repository.NewSystemRepository(db), AuditAppender: audit_chain.NewAppender(chain, false)}
	h := rawEvidenceRouter(deps)
	reveal := func(id, body, tenantID, role string) *httptest.ResponseRecorder {
		return rawEvidenceCall(h, http.MethodPost, "/admin/v1/audit/raw-evidence/"+id+"/reveal", body, tenantID, officer, role)
	}
	auditCount := func() int {
		var n int
		_ = db.QueryRow(ctx, `SELECT COUNT(*) FROM audit_operations WHERE user_id=$1 AND action_type='reveal_raw_evidence'`, officer).Scan(&n)
		return n
	}

	// 身份检查与现有内容留证一致：应急指派账号、会话与用户不一致、跨租户会话、没有会话都拒绝。
	revealPath := "/admin/v1/audit/raw-evidence/" + idMasked + "/reveal"
	for name, tc := range map[string]struct {
		user    *repository.User
		session *repository.Session
		status  int
	}{
		"emergency": {&repository.User{ID: officer, TenantID: tenant, Role: "security_officer", DepartmentAssignmentMode: "emergency"},
			&repository.Session{UserID: officer, TenantID: tenant}, http.StatusForbidden},
		"session_other_user": {&repository.User{ID: officer, TenantID: tenant, Role: "security_officer"},
			&repository.Session{UserID: "someone_else", TenantID: tenant}, http.StatusUnauthorized},
		"session_other_tenant": {&repository.User{ID: officer, TenantID: tenant, Role: "security_officer"},
			&repository.Session{UserID: officer, TenantID: other}, http.StatusUnauthorized},
		"no_session": {&repository.User{ID: officer, TenantID: tenant, Role: "security_officer"}, nil, http.StatusUnauthorized},
	} {
		for _, call := range []struct{ method, path, body string }{
			{http.MethodGet, "/admin/v1/audit/raw-evidence", ""},
			{http.MethodPost, revealPath, `{"reason":"例行核查"}`},
		} {
			w := rawEvidenceCallAs(h, call.method, call.path, call.body, tc.user, tc.session)
			if w.Code != tc.status || strings.Contains(w.Body.String(), "110101") {
				t.Fatalf("%s %s %s status=%d want %d: %s", name, call.method, call.path, w.Code, tc.status, w.Body.String())
			}
		}
	}
	// 角色：审计员、租户管理员、开发者、旧 admin 角色值都不能列出或查看。
	for _, role := range []string{"auditor", "tenant_admin", "developer", "dept_manager", "chat_user", "admin", "tenant_owner"} {
		if w := rawEvidenceCall(h, http.MethodGet, "/admin/v1/audit/raw-evidence", "", tenant, officer, role); w.Code != http.StatusForbidden {
			t.Fatalf("%s list status=%d", role, w.Code)
		}
		if w := reveal(idMasked, `{"reason":"例行核查"}`, tenant, role); w.Code != http.StatusForbidden {
			t.Fatalf("%s reveal status=%d", role, w.Code)
		}
	}
	if auditCount() != 0 {
		t.Fatal("denied requests must not look like reveals")
	}

	// 事由可选，但长度上限保留（防滥用）；请求体不是 JSON 也拒绝。被拒绝的不返回原文、不写审计。
	for _, body := range []string{`{"reason":"` + strings.Repeat("长", 201) + `"}`, `not-json`, `{"reason":123}`} {
		if w := reveal(idMasked, body, tenant, "security_officer"); w.Code != http.StatusBadRequest || strings.Contains(w.Body.String(), "110101") {
			t.Fatalf("body %q status=%d %s", body, w.Code, w.Body.String())
		}
	}
	if auditCount() != 0 {
		t.Fatal("rejected reveal wrote audit")
	}

	// 跨租户读不到。
	if w := reveal(idOther, `{"reason":"越权尝试"}`, tenant, "security_officer"); w.Code != http.StatusNotFound {
		t.Fatalf("cross tenant status=%d", w.Code)
	}

	// 安全保密员与系统管理员可查看；返回原文，审计里有事由但没有原文。
	for _, role := range []string{"security_officer", "platform_admin"} {
		before := auditCount()
		w := reveal(idMasked, `{"reason":"核查泄露线索 TICKET-1"}`, tenant, role)
		if w.Code != http.StatusOK {
			t.Fatalf("%s reveal status=%d %s", role, w.Code, w.Body.String())
		}
		var out struct {
			Text        string `json:"text"`
			RequestID   string `json:"request_id"`
			Disposition string `json:"disposition"`
		}
		_ = json.Unmarshal(w.Body.Bytes(), &out)
		if out.Text != original || out.RequestID != reqA || out.Disposition != "masked" {
			t.Fatalf("bad reveal payload %s", w.Body.String())
		}
		if w.Header().Get("Cache-Control") != "no-store" {
			t.Fatal("reveal must not be cacheable")
		}
		if auditCount() != before+1 {
			t.Fatalf("%s reveal not audited", role)
		}
	}
	var detail string
	if err := db.QueryRow(ctx, `SELECT action_detail::text FROM audit_operations WHERE user_id=$1 AND action_type='reveal_raw_evidence' ORDER BY created_at DESC LIMIT 1`, officer).Scan(&detail); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(detail, reqA) || !strings.Contains(detail, "TICKET-1") || strings.Contains(detail, "110101") || strings.Contains(detail, "13800138000") {
		t.Fatalf("audit detail wrong: %s", detail)
	}
	if got := chain.count(); got != 2 {
		t.Fatalf("each reveal must be appended to the audit chain synchronously: %d", got)
	}

	// 不填事由也能直接查看：照样返回原文，审计照样记谁、何时、哪个请求、哪条留证、规则，事由记空。
	for i, body := range []string{``, `{}`, `{"reason":"  "}`, `{"reason":"abc"}`} {
		before := auditCount()
		w := reveal(idMasked, body, tenant, "security_officer")
		if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "110101199003071234") {
			t.Fatalf("optional reason body %q status=%d %s", body, w.Code, w.Body.String())
		}
		if auditCount() != before+1 || chain.count() != 3+i {
			t.Fatalf("optional reason body %q not audited (ops=%d chain=%d)", body, auditCount()-before, chain.count())
		}
	}
	var noReason struct {
		UserID string                 `json:"user_id"`
		Detail map[string]interface{} `json:"detail"`
	}
	var detailRaw []byte
	if err := db.QueryRow(ctx, `SELECT user_id, action_detail FROM audit_operations WHERE user_id=$1 AND action_type='reveal_raw_evidence' AND action_detail->>'reason' = '' ORDER BY created_at DESC LIMIT 1`, officer).Scan(&noReason.UserID, &detailRaw); err != nil {
		t.Fatalf("reveal without reason must still be audited with an empty reason: %v", err)
	}
	_ = json.Unmarshal(detailRaw, &noReason.Detail)
	if noReason.Detail["evidence_id"] != idMasked || noReason.Detail["request_id"] != reqA || noReason.Detail["rule_ids"] == nil || noReason.Detail["reason"] != "" {
		t.Fatalf("audit detail without reason wrong: %s", detailRaw)
	}

	// 审计写失败（操作审计、审计链、审计链未配置任一）：5xx，且响应里不含原文、不解密。
	failing := map[string]*Dependencies{
		"audit_operations": {DB: db, SystemRepo: failingAuditSystemRepo{SystemRepo: deps.SystemRepo}, AuditAppender: deps.AuditAppender},
		"audit_chain":      {DB: db, SystemRepo: deps.SystemRepo, AuditAppender: audit_chain.NewAppender(&rawEvidenceChainWriter{fail: true}, false)},
		"chain_disabled":   {DB: db, SystemRepo: deps.SystemRepo, AuditAppender: audit_chain.NewAppender(nil, true)},
		"chain_missing":    {DB: db, SystemRepo: deps.SystemRepo},
	}
	for name, failDeps := range failing {
		w := rawEvidenceCall(rawEvidenceRouter(failDeps), http.MethodPost, "/admin/v1/audit/raw-evidence/"+idMasked+"/reveal", `{"reason":"审计故障演练"}`, tenant, officer, "security_officer")
		if w.Code < 500 || strings.Contains(w.Body.String(), "110101") || strings.Contains(w.Body.String(), "13800138000") || strings.Contains(w.Body.String(), `"text"`) {
			t.Fatalf("%s failure must not return plaintext: status=%d %s", name, w.Code, w.Body.String())
		}
	}

	// 密文被搬到别的行（AAD 不符）解不开：不会返回任何内容。
	mustExec(`UPDATE content_raw_evidence SET request_id=$1 WHERE id=$2`, reqA+"_moved", idBlocked)
	if w := reveal(idBlocked, `{"reason":"篡改检测"}`, tenant, "security_officer"); w.Code != http.StatusInternalServerError || strings.Contains(w.Body.String(), "ZZTOP77") {
		t.Fatalf("moved ciphertext status=%d %s", w.Code, w.Body.String())
	}
	mustExec(`UPDATE content_raw_evidence SET request_id=$1 WHERE id=$2`, reqB, idBlocked)
	// 有库写权限者把留证改挂到别的用户/会话下：同样解不开。
	for _, col := range []string{"user_id", "session_id"} {
		mustExec(`UPDATE content_raw_evidence SET `+col+`='someone_else' WHERE id=$1`, idBlocked)
		if w := reveal(idBlocked, `{"reason":"改挂检测"}`, tenant, "security_officer"); w.Code != http.StatusInternalServerError || strings.Contains(w.Body.String(), "ZZTOP77") {
			t.Fatalf("re-attached %s status=%d %s", col, w.Code, w.Body.String())
		}
	}
	mustExec(`UPDATE content_raw_evidence SET user_id='u_writer', session_id=$1 WHERE id=$2`, "sess_"+reqB, idBlocked)
	if w := reveal(idBlocked, `{"reason":"复原核对"}`, tenant, "security_officer"); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "ZZTOP77") || !strings.Contains(w.Body.String(), `"truncated":false`) {
		t.Fatalf("restored row status=%d %s", w.Code, w.Body.String())
	}
	// 截断留痕：查看时返回截断标记与原始长度。
	mustExec(`UPDATE content_raw_evidence SET content_truncated=TRUE, original_chars=600000 WHERE id=$1`, idMasked)
	if w := reveal(idMasked, `{"reason":"截断标记核对"}`, tenant, "security_officer"); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"truncated":true`) || !strings.Contains(w.Body.String(), `"original_chars":600000`) {
		t.Fatalf("truncated flag status=%d %s", w.Code, w.Body.String())
	}

	// 定位：按请求编号、阻断编号、规则。列表不含原文与密文。
	for target, want := range map[string]int{
		"?request_id=" + reqA:            1,
		"?block_id=evt_blk_1":            1,
		"?rule=" + url.QueryEscape("密钥"): 1,
		"?rule=R-ID":                     1,
		"?disposition=blocked":           1,
		"?direction=output":              0,
		"?request_id=not-existing":       0,
	} {
		w := rawEvidenceCall(h, http.MethodGet, "/admin/v1/audit/raw-evidence"+target, "", tenant, officer, "security_officer")
		if w.Code != http.StatusOK {
			t.Fatalf("%s status=%d %s", target, w.Code, w.Body.String())
		}
		var out struct {
			Items []map[string]interface{}
			Total int
		}
		_ = json.Unmarshal(w.Body.Bytes(), &out)
		// 其他用例遗留的同租户数据只有上面两条，数量精确核对。
		if len(out.Items) != want || out.Total != want {
			t.Fatalf("%s got %d/%d want %d: %s", target, len(out.Items), out.Total, want, w.Body.String())
		}
		if strings.Contains(w.Body.String(), "enc:v3") || strings.Contains(w.Body.String(), "110101") || strings.Contains(w.Body.String(), "ZZTOP77") ||
			strings.Contains(w.Body.String(), "content_sha256") || strings.Contains(w.Body.String(), "content_hmac") {
			t.Fatalf("list leaked ciphertext or plaintext: %s", w.Body.String())
		}
	}
	if w := rawEvidenceCall(h, http.MethodGet, "/admin/v1/audit/raw-evidence?direction=sideways", "", tenant, officer, "security_officer"); w.Code != http.StatusBadRequest {
		t.Fatalf("invalid direction status=%d", w.Code)
	}

	// 独立开关：默认开；关闭写审计。开关是全局设置（对全部租户生效）：安全保密员只能查看，
	// 只有系统管理员能改（审查 I-4）。
	w := rawEvidenceCall(h, http.MethodGet, "/admin/v1/audit/raw-evidence/settings", "", tenant, officer, "security_officer")
	if !strings.Contains(w.Body.String(), `"enabled":true`) {
		t.Fatalf("default must be enabled: %s", w.Body.String())
	}
	for _, role := range []string{"auditor", "security_officer", "admin", "tenant_admin"} {
		if w := rawEvidenceCall(h, http.MethodPut, "/admin/v1/audit/raw-evidence/settings", `{"enabled":false}`, tenant, officer, role); w.Code != http.StatusForbidden {
			t.Fatalf("%s toggle status=%d", role, w.Code)
		}
	}
	var unchanged string
	_ = db.QueryRow(ctx, `SELECT value FROM system_settings WHERE key='raw_evidence_enabled'`).Scan(&unchanged)
	if unchanged != "true" {
		t.Fatalf("denied toggle changed the global setting: %q", unchanged)
	}
	if w := rawEvidenceCall(h, http.MethodPut, "/admin/v1/audit/raw-evidence/settings", `{"enabled":false}`, tenant, officer, "platform_admin"); w.Code != http.StatusOK {
		t.Fatalf("toggle status=%d %s", w.Code, w.Body.String())
	}
	var value string
	_ = db.QueryRow(ctx, `SELECT value FROM system_settings WHERE key='raw_evidence_enabled'`).Scan(&value)
	if value != "false" {
		t.Fatalf("setting not stored: %q", value)
	}
	var n int
	_ = db.QueryRow(ctx, `SELECT COUNT(*) FROM audit_operations WHERE user_id=$1 AND action_type='update_raw_evidence_setting'`, officer).Scan(&n)
	if n != 1 {
		t.Fatalf("toggle not audited: %d", n)
	}

	// 保留期：过期留证随内容留证的保留期清理。
	mustExec(`UPDATE content_raw_evidence SET created_at = NOW() - INTERVAL '400 days' WHERE id = $1`, idBlocked)
	deleted, err := repository.NewRawEvidenceRepository(db).DeleteOlderThan(ctx, 90)
	if err != nil || deleted < 1 {
		t.Fatalf("retention deleted=%d err=%v", deleted, err)
	}
	var left int
	_ = db.QueryRow(ctx, `SELECT COUNT(*) FROM content_raw_evidence WHERE id = ANY($1)`, []string{idMasked, idBlocked}).Scan(&left)
	if left != 1 {
		t.Fatalf("left=%d want only the unexpired row", left)
	}

	// 去重后的可追溯：同一会话后续请求只有一行引用（不含密文，指向首条）。按后续请求 ID 能定位，
	// 查看时解密首条、返回的是后续请求的元数据；权限与审计约束不变。
	insertRef := func(requestID, sessionID, refID string) string {
		var id string
		if err := db.QueryRow(ctx, `INSERT INTO content_raw_evidence (tenant_id, request_id, session_id, user_id, direction, role, message_index, disposition,
			rule_ids, rule_names, content_ciphertext, content_hmac, content_chars, original_chars, ref_evidence_id)
			SELECT tenant_id, $2, $3, user_id, direction, role, 4, disposition, rule_ids, rule_names, NULL, content_hmac, content_chars, original_chars, $4
			FROM content_raw_evidence WHERE tenant_id=$1 AND id=$5 RETURNING id`, tenant, requestID, sessionID, refID, idMasked).Scan(&id); err != nil {
			t.Fatal(err)
		}
		return id
	}
	reqLater := reqA + "_r2"
	idRef := insertRef(reqLater, "sess_"+reqA, idMasked)
	w = rawEvidenceCall(h, http.MethodGet, "/admin/v1/audit/raw-evidence?request_id="+reqLater, "", tenant, officer, "security_officer")
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"ref_evidence_id":"`+idMasked+`"`) || !strings.Contains(w.Body.String(), `"total":1`) {
		t.Fatalf("later request cannot be located: %d %s", w.Code, w.Body.String())
	}
	before := auditCount()
	w = reveal(idRef, ``, tenant, "security_officer")
	var refOut struct {
		Text         string `json:"text"`
		RequestID    string `json:"request_id"`
		MessageIndex int    `json:"message_index"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &refOut)
	if w.Code != http.StatusOK || refOut.Text != original || refOut.RequestID != reqLater || refOut.MessageIndex != 4 || auditCount() != before+1 {
		t.Fatalf("reveal via reference: %d %s", w.Code, w.Body.String())
	}
	var refDetail string
	_ = db.QueryRow(ctx, `SELECT action_detail::text FROM audit_operations WHERE user_id=$1 AND action_type='reveal_raw_evidence' ORDER BY created_at DESC LIMIT 1`, officer).Scan(&refDetail)
	if !strings.Contains(refDetail, idRef) || !strings.Contains(refDetail, reqLater) || !strings.Contains(refDetail, idMasked) {
		t.Fatalf("reference reveal audit must name the reference, the later request and the first evidence: %s", refDetail)
	}
	for _, role := range []string{"auditor", "tenant_admin"} {
		if w := reveal(idRef, ``, tenant, role); w.Code != http.StatusForbidden {
			t.Fatalf("%s reveal via reference status=%d", role, w.Code)
		}
	}
	// 引用指向别的会话、或首条已过保留期（已删除）：404，不返回原文。
	for name, id := range map[string]string{
		"other_session": insertRef(reqA+"_r3", "another_session", idMasked),
		"first_expired": insertRef(reqA+"_r4", "sess_"+reqA, "cre_gone"),
	} {
		if w := reveal(id, ``, tenant, "security_officer"); w.Code != http.StatusNotFound || strings.Contains(w.Body.String(), "110101") {
			t.Fatalf("%s status=%d %s", name, w.Code, w.Body.String())
		}
	}

	// 保留期先后：各行按自己的 created_at 过期。首条先过期被删时，引用行（更新）保留到自己的保留期，
	// 列表里仍能按请求 ID 看到命中元数据，但查看原文返回 404（密文已随首条按期销毁，不为引用延长保留）。
	mustExec(`UPDATE content_raw_evidence SET created_at = NOW() - INTERVAL '400 days' WHERE id = $1`, idMasked)
	if _, err := repository.NewRawEvidenceRepository(db).DeleteOlderThan(ctx, 90); err != nil {
		t.Fatal(err)
	}
	var refLeft, firstLeft int
	_ = db.QueryRow(ctx, `SELECT COUNT(*) FILTER (WHERE id=$1), COUNT(*) FILTER (WHERE id=$2) FROM content_raw_evidence`, idRef, idMasked).Scan(&refLeft, &firstLeft)
	if refLeft != 1 || firstLeft != 0 {
		t.Fatalf("retention: ref=%d first=%d want ref kept and first deleted", refLeft, firstLeft)
	}
	if w := rawEvidenceCall(h, http.MethodGet, "/admin/v1/audit/raw-evidence?request_id="+reqLater, "", tenant, officer, "security_officer"); !strings.Contains(w.Body.String(), `"total":1`) {
		t.Fatalf("reference row must stay listed until its own retention: %s", w.Body.String())
	}
	if w := reveal(idRef, ``, tenant, "security_officer"); w.Code != http.StatusNotFound || strings.Contains(w.Body.String(), "110101") || !strings.Contains(w.Body.String(), "保留期") {
		t.Fatalf("reference to expired first evidence status=%d %s", w.Code, w.Body.String())
	}
}
