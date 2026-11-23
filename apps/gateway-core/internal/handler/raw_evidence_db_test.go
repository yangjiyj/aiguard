package handler

import (
	"context"
	"strings"
	"testing"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
	"github.com/yangjiyj/aiguard/packages/shared-go/secrets"
)

// 经真实审计写入器落库：只存密文、AAD 绑定、开关关闭不写、同槽位重试不重复。
func TestRawEvidenceWrittenEncryptedOnPostgres(t *testing.T) {
	db, ctx, tenantID, projectID, providerID, modelID := setupAuditWriterNullUserFixture(t)
	t.Setenv("JJD_PROVIDER_SECRET_KEY", "gateway-raw-evidence-test-secret-01234")
	t.Setenv("JJD_SECRETS_CIPHER", "")
	t.Cleanup(func() {
		_, _ = db.Exec(context.Background(), `DELETE FROM content_raw_evidence WHERE tenant_id=$1`, tenantID)
		_, _ = db.Exec(context.Background(), `UPDATE system_settings SET value='true' WHERE key='raw_evidence_enabled'`)
	})
	w := &RealAuditWriter{db: &realDBExecutor{pool: db}}
	audit := &AsyncAuditWriter{syncWriter: w} // 与线上同样经包装层透传
	env := &modelrouter.RequestEnvelope{RequestID: "req_raw_" + tenantID, TenantID: tenantID, ProjectID: projectID, ClientID: "k",
		ProviderID: providerID, ModelID: modelID, SessionID: "sess-raw", EndpointType: "chat", EnvironmentScope: "customer"}

	h := &ChatCompletionsHandler{
		securityClient: &MockSecurityChecker{InputAction: "mask", InputMasked: "电话 <MASKED>",
			InputFindings: []SecurityFinding{{Type: "pii", Category: "phone", RuleID: "r-phone", RuleName: "手机号"}}},
		auditWriter: &billingNoopAudit{AsyncAuditWriter: audit},
	}
	req := &ChatCompletionRequest{Model: "gpt-4", Messages: []Message{{Role: "user", Content: jsonQuote("电话 13800138000")}}}
	if res := h.applyChatInputSecurity(withBlockLedger(ctx), env, req); res.err != nil {
		t.Fatal(res.err)
	}
	if got := messageText(req.Messages[0].Content); strings.Contains(got, "13800138000") {
		t.Fatalf("original reached upstream payload: %q", got)
	}
	w.flushRawEvidence() // 留证在后台写库

	var cipher, direction, disposition string
	var rules []string
	var chars int
	if err := db.QueryRow(ctx, `SELECT content_ciphertext, direction, disposition, rule_ids, content_chars FROM content_raw_evidence WHERE tenant_id=$1 AND request_id=$2`,
		tenantID, env.RequestID).Scan(&cipher, &direction, &disposition, &rules, &chars); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(cipher, "13800138000") || !strings.HasPrefix(cipher, "enc:v3:") || direction != "input" || disposition != "masked" || len(rules) != 1 || chars != len([]rune("电话 13800138000")) {
		t.Fatalf("bad stored row: %s %s %s %v %d", cipher, direction, disposition, rules, chars)
	}
	plain, err := secrets.DecryptRawEvidence(cipher, secrets.RawEvidenceAAD(tenantID, env.RequestID, "", "sess-raw", "input", 0, "masked"))
	if err != nil || string(plain) != "电话 13800138000" {
		t.Fatalf("decrypt: %q %v", plain, err)
	}
	// 去重摘要是带密钥的 HMAC，不是可离线核对的无盐 SHA-256。
	var bareSHA bool
	if err := db.QueryRow(ctx, `SELECT content_hmac = sha256(convert_to($3, 'UTF8')) FROM content_raw_evidence WHERE tenant_id=$1 AND request_id=$2`,
		tenantID, env.RequestID, "电话 13800138000").Scan(&bareSHA); err != nil || bareSHA {
		t.Fatalf("content_hmac must not be a bare sha256: %v %v", bareSHA, err)
	}
	// 同槽位重试不重复。
	audit.WriteRawEvidence(ctx, env, RawEvidenceRecord{Direction: "input", Role: "user", Index: 0, Disposition: "masked", Text: "电话 13800138000"})
	w.flushRawEvidence()
	var n int
	_ = db.QueryRow(ctx, `SELECT COUNT(*) FROM content_raw_evidence WHERE tenant_id=$1`, tenantID).Scan(&n)
	if n != 1 {
		t.Fatalf("duplicate rows: %d", n)
	}
	// 去重：同一会话后续轮次（新请求编号）重发同一原文不再存；换一个写入器实例（模拟另一台网关，
	// 没有进程内去重记忆）也由库里的唯一索引挡住；换会话则另存一份。
	nextRound := *env
	nextRound.RequestID = env.RequestID + "_r2"
	audit.WriteRawEvidence(ctx, &nextRound, RawEvidenceRecord{Direction: "input", Role: "user", Index: 3, Disposition: "masked", Text: "电话 13800138000"})
	w.flushRawEvidence()
	other := &RealAuditWriter{db: &realDBExecutor{pool: db}}
	nextRound.RequestID = env.RequestID + "_r3"
	other.WriteRawEvidence(ctx, &nextRound, RawEvidenceRecord{Direction: "input", Role: "user", Index: 5, Disposition: "masked", Text: "电话 13800138000"})
	other.flushRawEvidence()
	_ = db.QueryRow(ctx, `SELECT COUNT(*) FROM content_raw_evidence WHERE tenant_id=$1 AND content_ciphertext IS NOT NULL`, tenantID).Scan(&n)
	if n != 1 {
		t.Fatalf("same session same original stored %d times", n)
	}
	// 后续两个请求（含另一台网关写的）各有一行引用：不含密文，指向首条，按各自请求 ID 可定位。
	var firstID string
	if err := db.QueryRow(ctx, `SELECT id FROM content_raw_evidence WHERE tenant_id=$1 AND request_id=$2`, tenantID, env.RequestID).Scan(&firstID); err != nil {
		t.Fatal(err)
	}
	for _, rid := range []string{env.RequestID + "_r2", env.RequestID + "_r3"} {
		var ref string
		var cipherNull bool
		var idx int
		if err := db.QueryRow(ctx, `SELECT COALESCE(ref_evidence_id,''), content_ciphertext IS NULL, message_index FROM content_raw_evidence WHERE tenant_id=$1 AND request_id=$2`,
			tenantID, rid).Scan(&ref, &cipherNull, &idx); err != nil {
			t.Fatalf("later request %s cannot be located: %v", rid, err)
		}
		if ref != firstID || !cipherNull || idx == 0 {
			t.Fatalf("reference row for %s wrong: ref=%q cipherNull=%v index=%d", rid, ref, cipherNull, idx)
		}
	}
	if _, err := db.Exec(ctx, `DELETE FROM content_raw_evidence WHERE tenant_id=$1 AND ref_evidence_id IS NOT NULL`, tenantID); err != nil {
		t.Fatal(err)
	}
	otherSession := *env
	otherSession.RequestID, otherSession.SessionID = env.RequestID+"_s2", "sess-raw-2"
	audit.WriteRawEvidence(ctx, &otherSession, RawEvidenceRecord{Direction: "input", Role: "user", Index: 0, Disposition: "masked", Text: "电话 13800138000"})
	w.flushRawEvidence()
	_ = db.QueryRow(ctx, `SELECT COUNT(*) FROM content_raw_evidence WHERE tenant_id=$1 AND content_ciphertext IS NOT NULL`, tenantID).Scan(&n)
	if n != 2 {
		t.Fatalf("another session must keep its own evidence: %d", n)
	}
	if _, err := db.Exec(ctx, `DELETE FROM content_raw_evidence WHERE tenant_id=$1 AND session_id='sess-raw-2'`, tenantID); err != nil {
		t.Fatal(err)
	}
	// 其他表不得出现原文。
	var leaked int
	_ = db.QueryRow(ctx, `SELECT (SELECT COUNT(*) FROM content_logs WHERE tenant_id=$1 AND content LIKE '%13800138000%') + (SELECT COUNT(*) FROM security_events WHERE tenant_id=$1 AND matched_summary::text LIKE '%13800138000%')`, tenantID).Scan(&leaked)
	if leaked != 0 {
		t.Fatalf("plaintext leaked into %d other rows", leaked)
	}
	// 超长原文截断要留痕：标记截断并记录原始长度。
	long := strings.Repeat("长", rawEvidenceMaxRunes+7)
	audit.WriteRawEvidence(ctx, env, RawEvidenceRecord{Direction: "output", Role: "assistant", Index: 0, Disposition: "masked", Text: long})
	w.flushRawEvidence()
	var truncated bool
	var stored, original int
	if err := db.QueryRow(ctx, `SELECT content_truncated, content_chars, original_chars FROM content_raw_evidence WHERE tenant_id=$1 AND direction='output'`,
		tenantID).Scan(&truncated, &stored, &original); err != nil {
		t.Fatal(err)
	}
	if !truncated || stored != rawEvidenceMaxRunes || original != rawEvidenceMaxRunes+7 {
		t.Fatalf("truncation not recorded: %v %d %d", truncated, stored, original)
	}
	if _, err := db.Exec(ctx, `DELETE FROM content_raw_evidence WHERE tenant_id=$1 AND direction='output'`, tenantID); err != nil {
		t.Fatal(err)
	}
	// 开关关闭：不再新增。
	if _, err := db.Exec(ctx, `UPDATE system_settings SET value='false' WHERE key='raw_evidence_enabled'`); err != nil {
		t.Fatal(err)
	}
	audit.WriteRawEvidence(ctx, env, RawEvidenceRecord{Direction: "output", Role: "assistant", Index: 0, Disposition: "blocked", Text: "不应保存"})
	w.flushRawEvidence()
	_ = db.QueryRow(ctx, `SELECT COUNT(*) FROM content_raw_evidence WHERE tenant_id=$1`, tenantID).Scan(&n)
	if n != 1 {
		t.Fatalf("switch off still wrote: %d", n)
	}
	// 没有数据加密密钥：宁可不留证。
	if _, err := db.Exec(ctx, `UPDATE system_settings SET value='true' WHERE key='raw_evidence_enabled'`); err != nil {
		t.Fatal(err)
	}
	t.Setenv("JJD_PROVIDER_SECRET_KEY", "")
	t.Setenv("JJD_MASTER_KEY", "")
	audit.WriteRawEvidence(ctx, env, RawEvidenceRecord{Direction: "output", Role: "assistant", Index: 0, Disposition: "blocked", Text: "无密钥不落库"})
	w.flushRawEvidence()
	_ = db.QueryRow(ctx, `SELECT COUNT(*) FROM content_raw_evidence WHERE tenant_id=$1`, tenantID).Scan(&n)
	if n != 1 {
		t.Fatalf("wrote without key: %d", n)
	}
}

// billingNoopAudit 让 AsyncAuditWriter 满足 AuditWriter 接口所需的其余方法（由嵌入提供），仅用于本测试。
type billingNoopAudit struct{ *AsyncAuditWriter }
