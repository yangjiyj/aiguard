package handler

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/audit_chain"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/rules"
)

type filePolicyChainSnapshot struct {
	eventType string
	payload   map[string]any
}

type filePolicyChainWriter struct{ got chan filePolicyChainSnapshot }

func (w *filePolicyChainWriter) Append(_ context.Context, _, eventType, _ string, payload map[string]any) error {
	w.got <- filePolicyChainSnapshot{eventType: eventType, payload: payload}
	return nil
}

// 真实 logAudit 和 Appender 必须在到达仓储边界前消除嵌套业务结构体的字段顺序。
func TestLogAuditFilePolicyUsesCanonicalSnapshot(t *testing.T) {
	w := &filePolicyChainWriter{got: make(chan filePolicyChainSnapshot, 1)}
	deps := &Dependencies{SystemRepo: &capturingSystemRepo{}, AuditAppender: audit_chain.NewAppender(w, false)}
	req := httptest.NewRequest("POST", "/x", nil)
	req = req.WithContext(context.WithValue(req.Context(), auth.UserKey, &repository.User{ID: "u", TenantID: "t"}))
	logAudit(req, deps, "content_file_policy.update", map[string]any{"policy": rules.FilePolicy{
		AllowedTypes: []string{"pdf"}, BlockedTypes: []string{"exe"}, ReviewTypes: []string{"zip"},
		MaxFileMB: 100, MaxZipRatio: 200, MaxAttachments: 10, ContentDlpEnabled: true,
	}}, "file_policy", "default")
	select {
	case snapshot := <-w.got:
		if snapshot.eventType != "audit_op" {
			t.Fatalf("事件类型错误：%s", snapshot.eventType)
		}
		raw, err := json.Marshal(snapshot.payload)
		if err != nil {
			t.Fatal(err)
		}
		const want = `{"policy":{"allowed_types":["pdf"],"blocked_types":["exe"],"content_dlp_enabled":true,"max_attachments":10,"max_file_mb":100,"max_zip_ratio":200,"review_types":["zip"]}}`
		if string(raw) != want {
			t.Fatalf("写入未按键排序：%s", raw)
		}
		// 与仓储相同，摘要和存储使用同一份规范化字节，并以合成密钥检查完整链校验。
		frozen, err := audit_chain.CanonicalPayload(snapshot.payload)
		if err != nil || string(frozen) != want {
			t.Fatalf("仓储输入变化：%s，%v", frozen, err)
		}
		alg, _ := audit_chain.AlgorithmByName(audit_chain.AlgSHA256)
		sum := sha256.Sum256([]byte(want))
		ph := alg.PayloadHash(frozen)
		if ph != hex.EncodeToString(sum[:]) {
			t.Fatal("新记录摘要未使用排序编码")
		}
		ch := alg.ChainHash("prev", ph, 1)
		key := []byte("本地测试密钥")
		if detail := audit_chain.VerifyRecordedRow(alg, key, "prev", true, "prev", snapshot.eventType, frozen, ph, ch, alg.Sign(ch, key), 1); detail != "" {
			t.Fatal(detail)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("未收到文件策略审计快照")
	}
}
