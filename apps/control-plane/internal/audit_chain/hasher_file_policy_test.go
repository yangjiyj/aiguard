package audit_chain

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/emmansun/gmsm/sm3"
)

func filePolicyByteHash(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

func TestRecordedFilePolicyFieldSamples(t *testing.T) {
	raw, err := os.ReadFile("testdata/legacy_file_policy_rows.json")
	if err != nil {
		t.Fatal(err)
	}
	var rows []struct {
		Seq         int64           `json:"seq"`
		EventType   string          `json:"event_type"`
		HashAlg     string          `json:"hash_alg"`
		Payload     json.RawMessage `json:"payload"`
		PayloadHash string          `json:"payload_hash"`
	}
	if err := json.Unmarshal(raw, &rows); err != nil {
		t.Fatal(err)
	}
	if len(rows) != 3 {
		t.Fatalf("现场样本数：%d", len(rows))
	}
	for _, row := range rows {
		t.Run(strconv.FormatInt(row.Seq, 10), func(t *testing.T) {
			alg, ok := AlgorithmByName(row.HashAlg)
			if !ok {
				t.Fatal("未知算法")
			}
			if alg.PayloadHash(row.Payload) == row.PayloadHash {
				t.Fatal("样本应复现旧编码差异")
			}
			if !RecordedPayloadMatches(alg, row.EventType, row.Payload, row.PayloadHash) {
				t.Fatal("现场文件策略摘要校验失败")
			}
			for _, event := range []string{"", "security_event", "audit_op.other"} {
				if RecordedPayloadMatches(alg, event, row.Payload, row.PayloadHash) {
					t.Fatalf("兼容范围越界：%q", event)
				}
			}
			// 使用合成密钥验证调用方仍强制检查链接、链摘要和签名。
			key := []byte("本地测试密钥")
			chain := alg.ChainHash("prev", row.PayloadHash, row.Seq)
			sig := alg.Sign(chain, key)
			check := func(prev, ch, signature string) string {
				return VerifyRecordedRow(alg, key, "prev", true, prev, row.EventType, row.Payload, row.PayloadHash, ch, signature, row.Seq)
			}
			if got := check("prev", chain, sig); got != "" {
				t.Fatal(got)
			}
			for want, got := range map[string]string{
				"prev_hash mismatch":  check("other", chain, sig),
				"chain_hash mismatch": check("prev", strings.Repeat("0", 64), sig),
				"signature invalid":   check("prev", chain, strings.Repeat("0", 64)),
			} {
				if got != want {
					t.Fatalf("期望 %s，实际 %s", want, got)
				}
			}
		})
	}
}

func TestRecordedFilePolicyRejectsTamperingAndOtherOrder(t *testing.T) {
	alg, _ := AlgorithmByName(AlgSHA256)
	const original = `{"policy":{"allowed_types":["pdf"],"blocked_types":["exe"],"review_types":["zip"],"max_file_mb":100,"max_zip_ratio":100,"max_attachments":10,"content_dlp_enabled":true}}`
	recorded := filePolicyByteHash(original)
	for _, changed := range []string{
		strings.Replace(original, `"pdf"`, `"txt"`, 1),
		strings.Replace(original, `100`, `101`, 1),
		strings.Replace(original, `true`, `false`, 1),
		strings.Replace(original, `{"policy":`, `{"extra":1,"policy":`, 1),
		strings.Replace(original, `"allowed_types":`, `"unknown":1,"allowed_types":`, 1),
		strings.Replace(original, `100`, `100.5`, 1),
		`{"policy":[]}`,
	} {
		if RecordedPayloadMatches(alg, "audit_op", json.RawMessage(changed), recorded) {
			t.Fatalf("接受了篡改：%s", changed)
		}
	}
	const otherOrder = `{"policy":{"max_file_mb":100,"allowed_types":["pdf"],"blocked_types":["exe"],"review_types":["zip"],"max_zip_ratio":100,"max_attachments":10,"content_dlp_enabled":true}}`
	if RecordedPayloadMatches(alg, "audit_op", json.RawMessage(original), filePolicyByteHash(otherOrder)) {
		t.Fatal("接受了未知字段顺序的摘要")
	}
}

func TestLegacyFilePolicyStrictSchema(t *testing.T) {
	for _, raw := range []string{
		`{}`, `{"policy":null}`, `{"policy":[]}`, `{"policy":"x"}`,
		`{"policy":{},"extra":1}`, `{"policy":{"unknown":1}}`,
		`{"policy":{"Allowed_Types":["pdf"]}}`,
		`{"policy":{"allowed_types":[]}}`, `{"policy":{"allowed_types":null}}`,
		`{"policy":{"allowed_types":[null]}}`, `{"policy":{"allowed_types":[1]}}`,
		`{"policy":{"content_dlp_enabled":false}}`, `{"policy":{"content_dlp_enabled":null}}`,
	} {
		if _, err := LegacyFilePolicyPayloadHash(json.RawMessage(raw), AlgSHA256); !errors.Is(err, errLegacyPayload) {
			t.Fatalf("应拒绝有损或未知结构：%s，错误：%v", raw, err)
		}
	}
	for _, field := range []string{"max_file_mb", "max_zip_ratio", "max_attachments"} {
		for _, value := range []string{"-1", "1.5", "0", "null", `"1"`, "9223372036854775808"} {
			raw := json.RawMessage(`{"policy":{"` + field + `":` + value + `}}`)
			if _, err := LegacyFilePolicyPayloadHash(raw, AlgSHA256); !errors.Is(err, errLegacyPayload) {
				t.Fatalf("应拒绝 %s，错误：%v", raw, err)
			}
		}
	}
	// 空对象是旧结构体全部省略零值后的合法编码；字符串沿用 Go 的 HTML 转义。
	for _, raw := range []string{`{"policy":{}}`, `{"policy":{"allowed_types":["<>&中文"],"max_file_mb":1,"content_dlp_enabled":true}}`} {
		for _, name := range []string{"", AlgSHA256, AlgSM3} {
			encoded := strings.NewReplacer("<", `\u003c`, ">", `\u003e`, "&", `\u0026`).Replace(raw)
			want := filePolicyByteHash(encoded)
			if name == AlgSM3 {
				sum := sm3.Sum([]byte(encoded))
				want = hex.EncodeToString(sum[:])
			}
			got, err := LegacyFilePolicyPayloadHash(json.RawMessage(raw), name)
			if err != nil || got != want {
				t.Fatalf("算法 %s 摘要 %s，期望 %s：%v", name, got, want, err)
			}
		}
	}
	if _, err := LegacyFilePolicyPayloadHash(json.RawMessage(`{"policy":{}}`), "unknown"); err == nil {
		t.Fatal("未知算法必须失败")
	}
}

// 不依赖数据库复核原有目录结构体和浮点兼容路径，历史字节不由当前规范化器生成。
func TestLegacyCatalogAndFloatCompatibilityWithoutDatabase(t *testing.T) {
	const catalog = `{"provider_id":"p","result":{"created":1,"updated":0,"deactivated":0,"reappeared":0,"skipped":0,"verified":0,"verification_failed":0,"total_seen":1,"pending":0,"selected_matched":0,"verification_failures":[],"removed_model_ids":[],"synced_at":"2026-10-08T11:29:40Z"}}`
	alg, _ := AlgorithmByName(AlgSHA256)
	if got, err := LegacyCatalogPayloadHash(json.RawMessage(catalog), AlgSHA256); err != nil || got != filePolicyByteHash(catalog) {
		t.Fatalf("目录历史编码回归：%s，%v", got, err)
	}
	if !RecordedPayloadMatches(alg, "audit_op", json.RawMessage(catalog), filePolicyByteHash(catalog)) {
		t.Fatal("目录历史摘要不匹配")
	}
	for _, raw := range []string{`{"number":1e-7}`, `{"number":1e+21}`} {
		if !RecordedPayloadMatches(alg, "audit_op", json.RawMessage(raw), filePolicyByteHash(raw)) {
			t.Fatalf("浮点历史摘要不匹配：%s", raw)
		}
	}
	for _, number := range []string{"9007199254740993", "0.10000000000000001", "1e-400"} {
		if _, err := LegacyFloatPayloadHash(json.RawMessage(`{"number":`+number+`}`), AlgSHA256); !errors.Is(err, errLegacyPayload) {
			t.Fatalf("接受了有损浮点候选：%s，%v", number, err)
		}
	}
}

// 2.9.22 起文件策略多了处置与压缩包字段。新记录走当前规范编码校验；
// 旧编码的兼容范围不扩大到新字段（冻结结构体保持不变）。
func TestFilePolicyWithConfigurableActionsUsesCurrentEncodingOnly(t *testing.T) {
	alg, _ := AlgorithmByName(AlgSHA256)
	payload := json.RawMessage(`{"policy":{"allowed_types":["pdf"],"max_file_mb":100,"max_zip_ratio":100,"max_attachments":10,"executable_action":"block","unknown_action":"alert_allow","max_zip_nested":5,"file_reference_lookup_failure_action":"allow"}}`)
	recorded := alg.PayloadHash(payload)
	if recorded == "" || !RecordedPayloadMatches(alg, "audit_op", payload, recorded) {
		t.Fatal("带新字段的文件策略审计记录必须能按当前编码校验")
	}
	if _, err := LegacyFilePolicyPayloadHash(payload, AlgSHA256); !errors.Is(err, errLegacyPayload) {
		t.Fatalf("旧编码兼容不应接受新字段：%v", err)
	}
	if RecordedPayloadMatches(alg, "audit_op", payload, filePolicyByteHash(string(payload))) {
		t.Fatal("新字段记录不能借旧编码按原始字节通过")
	}
}
