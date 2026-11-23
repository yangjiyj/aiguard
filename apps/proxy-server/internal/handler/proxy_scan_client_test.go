package handler

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/yangjiyj/aiguard/packages/shared-go/filereference"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

// proxy SecurityClient 的 /scan-objects/ 客户端测试（object_id 大文件路径 + file_id verdict）。

func newTestSecurityClient(t *testing.T, handler http.HandlerFunc) (*SecurityClient, *httptest.Server) {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	return NewSecurityClient(srv.URL), srv
}

func TestUploadScanObjectReturnsObjectID(t *testing.T) {
	var gotBody []byte
	cli, _ := newTestSecurityClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "PUT" {
			t.Fatalf("method = %s want PUT", r.Method)
		}
		gotBody, _ = io.ReadAll(r.Body)
		if r.URL.Query().Get("tenant_id") != "t1" {
			t.Fatalf("missing tenant_id query")
		}
		if r.URL.Query().Get("file_id") != "file-1" {
			t.Fatalf("missing file_id query")
		}
		w.WriteHeader(200)
		w.Write([]byte(`{"object_id":"obj_abc","sha256":"deadbeef","size":123}`))
	})
	info, err := cli.UploadScanObject(context.Background(), "t1", "r1", "u1", "openai", "file-1", "a.docx", "text/plain", strings.NewReader("hello body"))
	if err != nil {
		t.Fatalf("UploadScanObject: %v", err)
	}
	if info.ObjectID != "obj_abc" || info.SHA256 != "deadbeef" || info.Size != 123 {
		t.Fatalf("unexpected info: %+v", info)
	}
	if string(gotBody) != "hello body" {
		t.Fatalf("body not streamed: %q", gotBody)
	}
}

func TestUploadScanObjectErrorOnNon200(t *testing.T) {
	cli, _ := newTestSecurityClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(507) // 高水位
		w.Write([]byte(`watermark`))
	})
	_, err := cli.UploadScanObject(context.Background(), "t1", "r1", "", "", "f", "a", "text/plain", strings.NewReader("x"))
	if err == nil {
		t.Fatalf("non-200 must return error")
	}
}

func TestLookupFileVerdictBlock(t *testing.T) {
	cli, _ := newTestSecurityClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Fatalf("method = %s want GET", r.Method)
		}
		if !strings.Contains(r.URL.Path, "verdict") {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		if r.URL.Query().Get("file_id") != "bad" {
			t.Fatalf("missing file_id")
		}
		w.WriteHeader(200)
		w.Write([]byte(`{"status":"block","hit_categories":["phone_cn"],"sha256":""}`))
	})
	v, err := cli.LookupFileVerdict(context.Background(), "t1", "u1", "openai", "bad")
	if err != nil {
		t.Fatalf("LookupFileVerdict: %v", err)
	}
	if v.Status != "block" {
		t.Fatalf("status = %s want block", v.Status)
	}
	if len(v.HitCategories) != 1 || v.HitCategories[0] != "phone_cn" {
		t.Fatalf("hit_categories: %+v", v.HitCategories)
	}
}

func TestLookupFileVerdictNotFound(t *testing.T) {
	cli, _ := newTestSecurityClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte(`{"status":"not_found"}`))
	})
	v, _ := cli.LookupFileVerdict(context.Background(), "t1", "", "", "never")
	if v.Status != "not_found" {
		t.Fatalf("want not_found, got %s", v.Status)
	}
}

func TestConsumeScanObject(t *testing.T) {
	called := false
	cli, _ := newTestSecurityClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "DELETE" {
			t.Fatalf("method = %s want DELETE", r.Method)
		}
		called = true
		w.WriteHeader(200)
		w.Write([]byte(`{"deleted":"x"}`))
	})
	if err := cli.ConsumeScanObject(context.Background(), "t1", "obj_x"); err != nil {
		t.Fatalf("ConsumeScanObject: %v", err)
	}
	if !called {
		t.Fatalf("DELETE not called")
	}
}

func TestLookupFileVerdictJSONShape(t *testing.T) {
	// 确保 verdict 响应解析稳健（缺字段不崩）
	cli, _ := newTestSecurityClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte(`{}`))
	})
	v, err := cli.LookupFileVerdict(context.Background(), "t1", "", "", "f")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if v.Status != "" {
		t.Fatalf("empty status expected, got %q", v.Status)
	}
	_, _ = json.Marshal(v) // 序列化不崩
}

func TestCheckFileIDVerdictsBlocks(t *testing.T) {
	os.Setenv("SECURITY_FILE_CONTENT_DLP_ENABLED", "true")
	t.Cleanup(func() { os.Unsetenv("SECURITY_FILE_CONTENT_DLP_ENABLED") })
	cli, _ := newTestSecurityClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte(`{"status":"block","hit_categories":["phone_cn"]}`))
	})
	atts := []ExtractedAttachment{{ReferenceID: "file-bad"}}
	if !cli.checkFileIDVerdicts(context.Background(), "t1", "openai", atts) {
		t.Fatalf("block verdict should block")
	}
}

// 2.9.22（任务 4.2）：检测未完成、没有检测记录、查询失败不再写死阻断，按租户文件策略的
// unverified_file_reference_action / file_reference_lookup_failure_action 处置（缺省告警放行），
// 与网关同一口径。原三条“必拦”用例改为“配成禁止时拦、缺省不拦”。
func TestCheckFileIDVerdictsPendingFollowsPolicy(t *testing.T) {
	cli, _ := newTestSecurityClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte(`{"status":"pending"}`))
	})
	atts := []ExtractedAttachment{{ReferenceID: "file-pending"}}
	if cli.checkFileIDVerdicts(context.Background(), "t1", "openai", atts) {
		t.Fatalf("pending verdict must not block by default")
	}
	cli.WithFileReferencePolicyReader(staticProxyFileReferencePolicy{Unverified: filereference.Block, LookupFailure: filereference.AlertAllow})
	if !cli.checkFileIDVerdicts(context.Background(), "t1", "openai", atts) {
		t.Fatalf("pending verdict should block when unverified_file_reference_action=block")
	}
}

func TestCheckFileIDVerdictsAllowPasses(t *testing.T) {
	os.Setenv("SECURITY_FILE_CONTENT_DLP_ENABLED", "true")
	t.Cleanup(func() { os.Unsetenv("SECURITY_FILE_CONTENT_DLP_ENABLED") })
	cli, _ := newTestSecurityClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte(`{"status":"allow"}`))
	})
	atts := []ExtractedAttachment{{ReferenceID: "file-ok"}}
	if cli.checkFileIDVerdicts(context.Background(), "t1", "openai", atts) {
		t.Fatalf("allow verdict should not block")
	}
}

func TestCheckFileIDVerdictsNotFoundFollowsPolicy(t *testing.T) {
	cli, _ := newTestSecurityClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte(`{"status":"not_found"}`))
	})
	atts := []ExtractedAttachment{{ReferenceID: "never"}}
	if cli.checkFileIDVerdicts(context.Background(), "t1", "openai", atts) {
		t.Fatalf("not_found must not block by default")
	}
	cli.WithFileReferencePolicyReader(staticProxyFileReferencePolicy{Unverified: filereference.Block, LookupFailure: filereference.AlertAllow})
	if !cli.checkFileIDVerdicts(context.Background(), "t1", "openai", atts) {
		t.Fatalf("not_found should block when unverified_file_reference_action=block")
	}
}

func TestCheckFileIDVerdictsLookupFailureFollowsPolicy(t *testing.T) {
	cli, _ := newTestSecurityClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
	})
	atts := []ExtractedAttachment{{ReferenceID: "f"}}
	if cli.checkFileIDVerdicts(context.Background(), "t1", "openai", atts) {
		t.Fatalf("lookup failure must not block by default")
	}
	cli.WithFileReferencePolicyReader(staticProxyFileReferencePolicy{Unverified: filereference.AlertAllow, LookupFailure: filereference.Block})
	if !cli.checkFileIDVerdicts(context.Background(), "t1", "openai", atts) {
		t.Fatalf("lookup failure should block when file_reference_lookup_failure_action=block")
	}
}

func TestCheckFileIDVerdictsIgnoresFileDLPSwitch(t *testing.T) {
	// 2.9.22：主路径一直不看文件 DLP 开关（原先写死 true），引用处置只看文件策略；
	// 原用例“DLP 关闭时不查、不拦”只覆盖测试专用包装，随之改为与主路径一致。
	os.Unsetenv("SECURITY_FILE_CONTENT_DLP_ENABLED")
	called := false
	cli, _ := newTestSecurityClient(t, func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(200)
		w.Write([]byte(`{"status":"block"}`))
	})
	atts := []ExtractedAttachment{{ReferenceID: "f"}}
	if !cli.checkFileIDVerdicts(context.Background(), "t1", "openai", atts) || !called {
		t.Fatalf("block verdict must block regardless of the file DLP switch (called=%v)", called)
	}
}

func TestFileIDVerdictGateExplainsReason(t *testing.T) {
	for status, want := range map[string]string{
		"block":     "引用的文件已被安全检测判定为阻断",
		"pending":   "引用的文件安全检测尚未完成",
		"not_found": "引用的文件没有安全检测记录",
	} {
		cli, _ := newTestSecurityClient(t, func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(200)
			w.Write([]byte(`{"status":"` + status + `"}`))
		})
		cli.WithFileReferencePolicyReader(staticProxyFileReferencePolicy{Unverified: filereference.Block, LookupFailure: filereference.Block})
		gate := cli.fileIDVerdictGate(context.Background(), "t1", "openai", []ExtractedAttachment{{ReferenceID: "f"}})
		if !gate.blocked || len(gate.findings) != 1 || gate.findings[0]["matched_text_preview"] != want {
			t.Fatalf("%s: 拦截提示应写明 %q，实际 %+v", status, want, gate)
		}
	}
	cli, _ := newTestSecurityClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte(`{"status":"not_found"}`))
	})
	gate := cli.fileIDVerdictGate(context.Background(), "t1", "openai", []ExtractedAttachment{{ReferenceID: "f"}})
	if gate.blocked || len(gate.findings) != 1 || gate.findings[0]["action"] != "alert" {
		t.Fatalf("缺省告警放行应留一条 alert 命中：%+v", gate)
	}
}

type staticProxyFileReferencePolicy filereference.Policy

func (p staticProxyFileReferencePolicy) Policy(context.Context, string) filereference.Policy {
	return filereference.Policy(p)
}

func TestCheckFileIDVerdictsSkipEmptyRef(t *testing.T) {
	os.Setenv("SECURITY_FILE_CONTENT_DLP_ENABLED", "true")
	t.Cleanup(func() { os.Unsetenv("SECURITY_FILE_CONTENT_DLP_ENABLED") })
	called := false
	cli, _ := newTestSecurityClient(t, func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(200)
		w.Write([]byte(`{"status":"block"}`))
	})
	atts := []ExtractedAttachment{{ReferenceID: ""}}
	if cli.checkFileIDVerdicts(context.Background(), "t1", "openai", atts) {
		t.Fatalf("empty ref should not block")
	}
	if called {
		t.Fatalf("empty ref should not call engine")
	}
}

// —— materializeObjects 真实链路测试（UploadScanObject 被真实调用，不只单元测试桩）——

func TestMaterializeObjects_LargeFileUsesObjectID(t *testing.T) {
	os.Setenv("SECURITY_FILE_CONTENT_DLP_ENABLED", "true")
	t.Cleanup(func() { os.Unsetenv("SECURITY_FILE_CONTENT_DLP_ENABLED") })

	uploaded := 0
	consumed := []string{}
	cli, _ := newTestSecurityClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "PUT" && strings.Contains(r.URL.Path, "/scan-objects") {
			uploaded++
			// 读上传字节
			_, _ = io.Copy(io.Discard, r.Body)
			w.WriteHeader(200)
			w.Write([]byte(`{"object_id":"obj_large_1","sha256":"deadbeef","size":700000}`))
			return
		}
		if r.Method == "DELETE" {
			consumed = append(consumed, r.URL.Path)
			w.WriteHeader(200)
			w.Write([]byte(`{"deleted":"obj_large_1"}`))
			return
		}
		w.WriteHeader(200)
		w.Write([]byte(`{"action":"audit"}`))
	})
	// 构造 >512KB 的附件（data_base64 解码后约 700KB）
	big := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte("x"), 700*1024))
	atts := []ExtractedAttachment{{
		Source:      "multipart",
		FileName:    "big.docx",
		ContentType: "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
		DataBase64:  big,
	}}
	ctx := context.Background()
	got, uploadedIDs, failed := cli.materializeObjects(ctx, "t1", "req1", "openai", atts)
	if uploaded != 1 {
		t.Fatalf("expected 1 upload to /scan-objects, got %d", uploaded)
	}
	if len(got) != 1 || got[0]["object_id"] != "obj_large_1" {
		t.Fatalf("entry should carry object_id: %+v", got)
	}
	if _, hasB64 := got[0]["data_base64"]; hasB64 {
		t.Fatalf("large file must NOT carry data_base64 (守§8红线)")
	}
	if len(uploadedIDs) != 1 || uploadedIDs[0] != "obj_large_1" {
		t.Fatalf("uploadedIDs: %+v", uploadedIDs)
	}
	if failed {
		t.Fatalf("successful upload must not report materialization failure")
	}
	// 检测后 consume 清理
	cli.consumeObjects(ctx, "t1", uploadedIDs)
	if len(consumed) != 1 || !strings.Contains(consumed[0], "obj_large_1") {
		t.Fatalf("object not consumed after detect: %+v", consumed)
	}
}

func TestMaterializeObjects_SmallFileInlined(t *testing.T) {
	os.Setenv("SECURITY_FILE_CONTENT_DLP_ENABLED", "true")
	t.Cleanup(func() { os.Unsetenv("SECURITY_FILE_CONTENT_DLP_ENABLED") })

	uploadCalled := false
	cli, _ := newTestSecurityClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "PUT" {
			uploadCalled = true
		}
		w.WriteHeader(200)
		w.Write([]byte(`{"object_id":"x","sha256":"y","size":100}`))
	})
	// 小文件（1KB）→ 内联 data_base64，不上传
	small := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte("x"), 1024))
	atts := []ExtractedAttachment{{FileName: "s.txt", ContentType: "text/plain", DataBase64: small}}
	got, uploaded, failed := cli.materializeObjects(context.Background(), "t1", "r", "openai", atts)
	if uploadCalled {
		t.Fatalf("small file should not be uploaded")
	}
	if len(uploaded) != 0 {
		t.Fatalf("no uploads expected")
	}
	if got[0]["data_base64"] != small {
		t.Fatalf("small file should inline data_base64")
	}
	if failed {
		t.Fatalf("small inline file must not report materialization failure")
	}
}

func TestMaterializeObjects_DisabledUsesPlainContext(t *testing.T) {
	os.Unsetenv("SECURITY_FILE_CONTENT_DLP_ENABLED")
	uploadCalled := false
	cli, _ := newTestSecurityClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "PUT" {
			uploadCalled = true
		}
		w.WriteHeader(200)
		w.Write([]byte(`{}`))
	})
	big := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte("x"), 700*1024))
	atts := []ExtractedAttachment{{FileName: "big.docx", ContentType: "text/plain", DataBase64: big}}
	got, uploaded, failed := cli.materializeObjects(context.Background(), "t1", "r", "openai", atts)
	if uploadCalled || len(uploaded) != 0 {
		t.Fatalf("disabled should not upload")
	}
	// 关闭时直接走 attachmentContext（含 data_base64，现状）
	if got[0]["data_base64"] != big {
		t.Fatalf("disabled should inline as-is")
	}
	if failed {
		t.Fatalf("disabled mode must not report materialization failure")
	}
}

func TestMaterializeObjects_UploadFailureBlocks(t *testing.T) {
	os.Setenv("SECURITY_FILE_CONTENT_DLP_ENABLED", "true")
	t.Cleanup(func() { os.Unsetenv("SECURITY_FILE_CONTENT_DLP_ENABLED") })
	// /scan-objects/ 上传失败（500）
	cli, _ := newTestSecurityClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "PUT" {
			w.WriteHeader(500)
			w.Write([]byte(`watermark`))
			return
		}
		w.WriteHeader(200)
		w.Write([]byte(`{}`))
	})
	big := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte("x"), 700*1024))
	atts := []ExtractedAttachment{{FileName: "big.docx", ContentType: "text/plain", DataBase64: big}}
	got, uploaded, failed := cli.materializeObjects(context.Background(), "t1", "r", "openai", atts)
	if len(uploaded) != 0 {
		t.Fatalf("failed upload should not produce object_id")
	}
	// 标记不可用（引擎侧按解析失败阻断，不放行），且不回退内联大 base64
	if got[0]["object_id_unavailable"] == "" {
		t.Fatalf("upload failure should mark object_id_unavailable: %+v", got[0])
	}
	if _, hasB64 := got[0]["data_base64"]; hasB64 {
		t.Fatalf("must not fall back to inlining large base64 on upload failure")
	}
	if !failed {
		t.Fatalf("upload failure must be reported to CheckInput")
	}
}

// Engine failure is an inspection gap: recorded and forwarded, even for files.
func TestCheckInput_FileRequestEngineFailureIsRecordedWhenDLPEnabled(t *testing.T) {
	t.Setenv("SECURITY_FILE_CONTENT_DLP_ENABLED", "true")
	engine := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`not-json`))
	}))
	t.Cleanup(engine.Close)

	body := "--b\r\nContent-Disposition: form-data; name=\"file\"; filename=\"secret.txt\"\r\nContent-Type: text/plain\r\n\r\nsecret\r\n--b--\r\n"
	req := httptest.NewRequest(http.MethodPost, "https://api.example.com/v1/chat/completions", strings.NewReader(body))
	req.Header.Set("Content-Type", "multipart/form-data; boundary=b")

	action, findings, _ := NewSecurityClient(engine.URL).CheckInput(
		req.Context(), "tenant-a", "request-a", req,
	)

	if action != "audit" || len(findings) == 0 {
		t.Fatalf("file request must be recorded and forwarded when engine fails, action=%q findings=%+v", action, findings)
	}
}

func TestCheckInput_AuditOnlyFileEngineFailureAllows(t *testing.T) {
	t.Setenv("SECURITY_FILE_CONTENT_DLP_ENABLED", "true")
	t.Setenv("SECURITY_AUDIT_ONLY", "true")
	engine := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`not-json`))
	}))
	t.Cleanup(engine.Close)

	body := "--b\r\nContent-Disposition: form-data; name=\"file\"; filename=\"secret.txt\"\r\nContent-Type: text/plain\r\n\r\nsecret\r\n--b--\r\n"
	req := httptest.NewRequest(http.MethodPost, "https://api.example.com/v1/chat/completions", strings.NewReader(body))
	req.Header.Set("Content-Type", "multipart/form-data; boundary=b")

	action, findings, _ := NewSecurityClient(engine.URL).CheckInput(
		req.Context(), "tenant-a", "request-audit", req,
	)

	if action != "audit" {
		t.Fatalf("audit-only file engine failure must allow with audit, action=%q findings=%+v", action, findings)
	}
}

func TestCheckInput_FileIDVerdictBlocksWhenContentDLPDisabled(t *testing.T) {
	t.Setenv("SECURITY_FILE_CONTENT_DLP_ENABLED", "")
	verdictCalls := 0
	client, _ := newTestSecurityClient(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/scan-objects/verdict":
			verdictCalls++
			if r.URL.Query().Get("file_id") == "" {
				t.Fatalf("file_id verdict lookup must carry a normalized reference: %s", r.URL.RawQuery)
			}
			_, _ = w.Write([]byte(`{"status":"block"}`))
		case "/check-input/":
			_, _ = w.Write([]byte(`{"action":"allow","findings":[]}`))
		default:
			t.Fatalf("unexpected security request path: %s", r.URL.Path)
		}
	})

	req := httptest.NewRequest(http.MethodPost, "https://api.openai.com/v1/responses",
		strings.NewReader(`{"model":"gpt-test","input":[{"role":"user","content":[{"type":"input_file","file_id":"file-blocked","filename":"report.pdf"}]}]}`))
	req.Header.Set("Content-Type", "application/json")

	action, findings, _ := client.CheckInput(req.Context(), "tenant-a", "request-file-id", req)
	if action != "block" {
		t.Fatalf("file_id verdict must block even when content DLP is disabled, action=%q findings=%+v", action, findings)
	}
	if verdictCalls != 1 {
		t.Fatalf("expected one file_id verdict lookup, got %d", verdictCalls)
	}
}

func TestCheckInput_PureTextEngineFailureKeepsExistingAuditMode(t *testing.T) {
	t.Setenv("SECURITY_FILE_CONTENT_DLP_ENABLED", "true")
	engine := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`not-json`))
	}))
	t.Cleanup(engine.Close)

	req := httptest.NewRequest(
		http.MethodPost,
		"https://api.example.com/v1/chat/completions",
		strings.NewReader(`{"messages":[{"role":"user","content":"hello"}]}`),
	)
	req.Header.Set("Content-Type", "application/json")

	action, _, _ := NewSecurityClient(engine.URL).CheckInput(
		req.Context(), "tenant-a", "request-text", req,
	)

	if action != "audit" {
		t.Fatalf("pure text request must preserve existing failure mode, action=%q", action)
	}
}

func TestCheckInput_LargeObjectUploadFailureIsRecordedBeforeCheckInput(t *testing.T) {
	t.Setenv("SECURITY_FILE_CONTENT_DLP_ENABLED", "true")
	checkInputCalls := 0
	engine := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut {
			w.WriteHeader(http.StatusInsufficientStorage)
			return
		}
		checkInputCalls++
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"action":"allow","findings":[]}`))
	}))
	t.Cleanup(engine.Close)

	raw := bytes.Repeat([]byte("x"), objectIDThreshold+1)
	body := "--b\r\nContent-Disposition: form-data; name=\"file\"; filename=\"large.docx\"\r\nContent-Type: application/vnd.openxmlformats-officedocument.wordprocessingml.document\r\n\r\n" + string(raw) + "\r\n--b--\r\n"
	req := httptest.NewRequest(http.MethodPost, "https://api.example.com/v1/chat/completions", strings.NewReader(body))
	req.Header.Set("Content-Type", "multipart/form-data; boundary=b")

	action, _, _ := NewSecurityClient(engine.URL).CheckInput(
		req.Context(), "tenant-a", "request-large", req,
	)

	if action != "audit" {
		t.Fatalf("object upload failure is an inspection gap and must be recorded, action=%q", action)
	}
	if checkInputCalls != 0 {
		t.Fatalf("materialization failure must stop before check-input, calls=%d", checkInputCalls)
	}
}

func TestCheckInput_DeclaredOversizedRequestIsRecordedWhenDLPDisabled(t *testing.T) {
	t.Setenv("SECURITY_FILE_CONTENT_DLP_ENABLED", "false")
	t.Setenv("SECURITY_FILE_CONTENT_MAX_REQUEST_MB", "1")
	engineCalled := false
	engine := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		engineCalled = true
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(engine.Close)

	req := httptest.NewRequest(http.MethodPost, "https://api.example.com/v1/chat/completions", strings.NewReader("tiny"))
	req.ContentLength = 1024*1024 + 1
	action, findings, _ := NewSecurityClient(engine.URL).CheckInput(
		req.Context(), "tenant-a", "request-too-large-dlp-off", req,
	)
	// The hard size limit still stops inspection before the engine, but an
	// uninspected request is recorded and forwarded, never blocked.
	if action != "audit" || len(findings) == 0 {
		t.Fatalf("oversized request must be recorded with a finding, action=%q findings=%+v", action, findings)
	}
	if engineCalled {
		t.Fatal("oversized request must not be sent to the engine")
	}
}

func TestCheckInput_DeclaredOversizedRequestIsRecordedBeforeReadingBody(t *testing.T) {
	t.Setenv("SECURITY_FILE_CONTENT_DLP_ENABLED", "true")
	t.Setenv("SECURITY_FILE_CONTENT_MAX_REQUEST_MB", "1")
	engineCalled := false
	engine := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		engineCalled = true
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(engine.Close)

	req := httptest.NewRequest(http.MethodPost, "https://api.example.com/v1/chat/completions", strings.NewReader("tiny"))
	req.ContentLength = 1024*1024 + 1

	action, findings, _ := NewSecurityClient(engine.URL).CheckInput(
		req.Context(), "tenant-a", "request-too-large", req,
	)

	if action != "audit" || len(findings) == 0 {
		t.Fatalf("oversized request must be recorded with a finding, action=%q findings=%+v", action, findings)
	}
	if engineCalled {
		t.Fatalf("oversized request must not be sent to the engine")
	}
}

func TestCheckInput_DeclaredOversizedRequestAuditsWithoutConsumingBody(t *testing.T) {
	t.Setenv("SECURITY_FILE_CONTENT_DLP_ENABLED", "true")
	t.Setenv("SECURITY_AUDIT_ONLY", "true")
	t.Setenv("SECURITY_FILE_CONTENT_MAX_REQUEST_MB", "1")
	engineCalled := false
	engine := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		engineCalled = true
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(engine.Close)

	req := httptest.NewRequest(http.MethodPost, "https://api.example.com/v1/chat/completions", strings.NewReader("tiny"))
	req.ContentLength = 1024*1024 + 1

	action, findings, _ := NewSecurityClient(engine.URL).CheckInput(
		req.Context(), "tenant-a", "request-too-large-audit", req,
	)

	if action != "audit" || len(findings) != 1 || findings[0]["action"] != "audit" {
		t.Fatalf("audit-only oversized request must be recorded without blocking, action=%q findings=%+v", action, findings)
	}
	if engineCalled {
		t.Fatal("oversized request must not call the engine")
	}
	forwarded, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatalf("read request body after audit: %v", err)
	}
	if string(forwarded) != "tiny" {
		t.Fatalf("audit path consumed declared oversized request body: %q", forwarded)
	}
}

func TestCheckInput_StreamedOversizedRequestAuditPreservesBody(t *testing.T) {
	t.Setenv("SECURITY_FILE_CONTENT_DLP_ENABLED", "true")
	t.Setenv("SECURITY_AUDIT_ONLY", "true")
	t.Setenv("SECURITY_FILE_CONTENT_MAX_REQUEST_MB", "1")
	engineCalled := false
	engine := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		engineCalled = true
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(engine.Close)

	body := bytes.Repeat([]byte("x"), 1024*1024+2)
	req := httptest.NewRequest(http.MethodPost, "https://api.example.com/v1/chat/completions", bytes.NewReader(body))
	req.ContentLength = -1

	action, findings, _ := NewSecurityClient(engine.URL).CheckInput(
		req.Context(), "tenant-a", "request-streamed-too-large-audit", req,
	)

	if action != "audit" || len(findings) != 1 || findings[0]["action"] != "audit" {
		t.Fatalf("audit-only streamed oversized request must be recorded without blocking, action=%q findings=%+v", action, findings)
	}
	if engineCalled {
		t.Fatal("oversized request must not call the engine")
	}
	forwarded, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatalf("read request body after audit: %v", err)
	}
	if !bytes.Equal(forwarded, body) {
		t.Fatalf("audit path truncated streamed request body: got=%d want=%d", len(forwarded), len(body))
	}
}

// A body-size guard runs before decoding and cannot establish a file threat.
func TestCheckInput_RequestCapacityIsOperational(t *testing.T) {
	for _, auditOnly := range []bool{false, true} {
		for _, streamed := range []bool{false, true} {
			t.Run(fmt.Sprintf("audit=%t/stream=%t", auditOnly, streamed), func(t *testing.T) {
				t.Setenv("SECURITY_FILE_CONTENT_MAX_REQUEST_MB", "1")
				t.Setenv("SECURITY_AUDIT_ONLY", fmt.Sprint(auditOnly))
				body := strings.Repeat("x", 1024*1024+2)
				req := httptest.NewRequest(http.MethodPost, "https://api.example.com/v1/responses", strings.NewReader(body))
				if streamed {
					req.ContentLength = -1
				}
				action, findings, meta := NewSecurityClient("http://127.0.0.1:1").CheckInput(req.Context(), "tenant", "capacity", req)
				// Capacity is an inspection gap in both postures: recorded, forwarded.
				wantAction := "audit"
				if action != wantAction || meta == nil || meta.SemanticStatus != "incomplete" || meta.SemanticReason != "request_body_limit_exceeded" {
					t.Fatalf("capacity must be recorded as incomplete and forwarded: action=%s meta=%+v", action, meta)
				}
				if len(findings) != 1 || findings[0]["type"] != "system" || countProxySecurityFindings(findings) != 0 {
					t.Fatalf("capacity is not a security finding: %+v", findings)
				}
				record := ProxyAuditRecord{InputSemanticStatus: meta.SemanticStatus, InputSemanticReason: meta.SemanticReason}
				summary := buildSecurityEventSummaryForRecord(record, "input", findings)
				if summary["counts_as_security_finding"] != false || summary["findings_count"] != 0 {
					t.Fatalf("capacity leaked into threat counts: %+v", summary)
				}
				if auditOnly {
					forwarded, err := io.ReadAll(req.Body)
					if err != nil || string(forwarded) != body {
						t.Fatal("audit must preserve the complete request body")
					}
				}
			})
		}
	}
}

// 独立代理写的文件引用命中与网关同一形态（类别、规则编号、规则名、级别都来自 filereference）。
func TestFileIDVerdictGateFindingMatchesSharedShape(t *testing.T) {
	cli, _ := newTestSecurityClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte(`{"status":"pending"}`))
	})
	cli.WithFileReferencePolicyReader(staticProxyFileReferencePolicy{Unverified: filereference.Block, LookupFailure: filereference.AlertAllow})
	gate := cli.fileIDVerdictGate(context.Background(), "t1", "openai", []ExtractedAttachment{{ReferenceID: "f"}})
	want := filereference.Decide("pending", nil, filereference.Policy{Unverified: filereference.Block, LookupFailure: filereference.AlertAllow}).Finding()
	if !gate.blocked || len(gate.findings) != 1 {
		t.Fatalf("应拦截并留一条命中：%+v", gate)
	}
	got := gate.findings[0]
	if got["category"] != want.Category || got["rule_id"] != want.RuleID || got["rule_name"] != want.RuleName ||
		got["severity"] != want.Severity || got["action"] != "block" || got["rule_type"] != "file_reference" {
		t.Fatalf("命中形态与共享表不一致：%+v want %+v", got, want)
	}
}

// 复审追加：独立代理与网关同一口径——未经扫描的文件引用命中先过内容例外（rule_ref=file-id-unverified），
// 命中例外不拦不告警、只记录；没有例外照拦；查询失败不过例外。
func fileReferenceExceptionServer(t *testing.T, verdictStatus int, exceptionRule string, applyCalls *int) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/scan-objects/verdict":
			if verdictStatus != http.StatusOK {
				w.WriteHeader(verdictStatus)
				return
			}
			w.Write([]byte(`{"status":"not_found"}`))
		case "/apply-context/":
			*applyCalls++
			var req struct {
				TenantID    string           `json:"tenant_id"`
				RawFindings []map[string]any `json:"raw_findings"`
			}
			_ = json.NewDecoder(r.Body).Decode(&req)
			if req.TenantID != "t1" {
				t.Errorf("tenant_id=%q", req.TenantID)
			}
			for _, finding := range req.RawFindings {
				if exceptionRule != "" && finding["rule_id"] == exceptionRule {
					finding["exception_id"] = "exc-file-ref"
					finding["action"] = "audit"
				}
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"action": "audit", "findings": req.RawFindings})
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
		}
	}
}

func TestFileIDVerdictGateUnverifiedBlockHonoursContentException(t *testing.T) {
	blockAll := staticProxyFileReferencePolicy{Unverified: filereference.Block, LookupFailure: filereference.Block}
	atts := []ExtractedAttachment{{ReferenceID: "f"}}

	var calls int
	cli, _ := newTestSecurityClient(t, fileReferenceExceptionServer(t, http.StatusOK, "file-id-unverified", &calls))
	cli.WithFileReferencePolicyReader(blockAll)
	gate := cli.fileIDVerdictGate(context.Background(), "t1", "openai", atts)
	if gate.blocked || calls != 1 || len(gate.findings) != 1 ||
		gate.findings[0]["action"] != "audit" || gate.findings[0]["exception_id"] != "exc-file-ref" {
		t.Fatalf("命中例外应放行、只记录：%+v calls=%d", gate, calls)
	}

	calls = 0
	cli, _ = newTestSecurityClient(t, fileReferenceExceptionServer(t, http.StatusOK, "", &calls))
	cli.WithFileReferencePolicyReader(blockAll)
	if gate := cli.fileIDVerdictGate(context.Background(), "t1", "openai", atts); !gate.blocked {
		t.Fatalf("没有例外照拦：%+v", gate)
	}

	calls = 0
	cli, _ = newTestSecurityClient(t, fileReferenceExceptionServer(t, http.StatusInternalServerError, "file-id-lookup-failed", &calls))
	cli.WithFileReferencePolicyReader(blockAll)
	if gate := cli.fileIDVerdictGate(context.Background(), "t1", "openai", atts); !gate.blocked || calls != 0 {
		t.Fatalf("查询失败是故障类，不过例外：%+v calls=%d", gate, calls)
	}
}

// 合流前次要项：独立代理一次请求里所有该过例外的命中合成一次 /apply-context/，单独限时，
// 缺省告警放行时引擎已有会提升告警的命中就不核对。
type proxyExceptionProbe struct {
	calls, findings int
	delay           time.Duration
	exceptionRule   string
}

func proxyExceptionServer(t *testing.T, probe *proxyExceptionProbe) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/scan-objects/verdict":
			w.Write([]byte(`{"status":"not_found"}`))
		case "/apply-context/":
			probe.calls++
			var req struct {
				RawFindings []map[string]any `json:"raw_findings"`
			}
			_ = json.NewDecoder(r.Body).Decode(&req)
			probe.findings = len(req.RawFindings)
			if probe.delay > 0 {
				time.Sleep(probe.delay)
			}
			for _, finding := range req.RawFindings {
				if probe.exceptionRule != "" && finding["rule_id"] == probe.exceptionRule {
					finding["exception_id"] = "exc-file-ref"
					finding["action"] = "audit"
				}
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"action": "audit", "findings": req.RawFindings})
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
		}
	}
}

func TestFileIDVerdictGateExceptionsUseOneCallPerRequest(t *testing.T) {
	probe := &proxyExceptionProbe{exceptionRule: "file-id-unverified"}
	cli, _ := newTestSecurityClient(t, proxyExceptionServer(t, probe))
	cli.WithFileReferencePolicyReader(staticProxyFileReferencePolicy{Unverified: filereference.Block, LookupFailure: filereference.Block})
	gate := cli.fileIDVerdictGate(context.Background(), "t1", "openai", []ExtractedAttachment{{ReferenceID: "a"}, {ReferenceID: "b"}})
	if gate.blocked || probe.calls != 1 || probe.findings != 2 || len(gate.findings) != 2 {
		t.Fatalf("两个引用合成一次核对且都放行：%+v calls=%d findings=%d", gate, probe.calls, probe.findings)
	}
	for _, finding := range gate.findings {
		if finding["exception_id"] != "exc-file-ref" || finding["action"] != "audit" {
			t.Fatalf("命中例外只记录：%+v", finding)
		}
	}
}

func TestFileIDVerdictGateExceptionTimeoutKeepsDisposition(t *testing.T) {
	saved := proxyFileReferenceExceptionTimeout
	proxyFileReferenceExceptionTimeout = 50 * time.Millisecond
	t.Cleanup(func() { proxyFileReferenceExceptionTimeout = saved })
	if saved != filereference.ExceptionCheckTimeout {
		t.Fatalf("缺省超时应为 %s：%s", filereference.ExceptionCheckTimeout, saved)
	}
	probe := &proxyExceptionProbe{exceptionRule: "file-id-unverified", delay: 500 * time.Millisecond}
	cli, _ := newTestSecurityClient(t, proxyExceptionServer(t, probe))
	cli.WithFileReferencePolicyReader(staticProxyFileReferencePolicy{Unverified: filereference.Block, LookupFailure: filereference.Block})
	started := time.Now()
	gate := cli.fileIDVerdictGate(context.Background(), "t1", "openai", []ExtractedAttachment{{ReferenceID: "a"}})
	if !gate.blocked || time.Since(started) > 400*time.Millisecond {
		t.Fatalf("超时按原处置拦且不等满引擎：%+v elapsed=%s", gate, time.Since(started))
	}
}

func TestReferenceAlertExceptionsSkippedWhenEngineFindingsRaiseAlert(t *testing.T) {
	probe := &proxyExceptionProbe{exceptionRule: "file-id-unverified"}
	cli, _ := newTestSecurityClient(t, proxyExceptionServer(t, probe))
	gate := cli.fileIDVerdictGate(context.Background(), "t1", "openai", []ExtractedAttachment{{ReferenceID: "a"}})
	if gate.blocked || probe.calls != 0 || len(gate.findings) != 1 {
		t.Fatalf("缺省告警放行：先不核对，等引擎结果：%+v calls=%d", gate, probe.calls)
	}
	engineFindings := []map[string]interface{}{{"type": "pii", "category": "phone_cn", "action": "audit"}}
	if alerts := cli.resolveReferenceAlerts(context.Background(), &gate, engineFindings); probe.calls != 0 || alerts[0]["exception_id"] != nil {
		t.Fatalf("引擎已有告警命中时不核对：calls=%d %+v", probe.calls, alerts)
	}
	gate = cli.fileIDVerdictGate(context.Background(), "t1", "openai", []ExtractedAttachment{{ReferenceID: "a"}})
	if alerts := cli.resolveReferenceAlerts(context.Background(), &gate, nil); probe.calls != 1 || alerts[0]["exception_id"] != "exc-file-ref" {
		t.Fatalf("没有其他告警命中时核对一次并压掉：calls=%d %+v", probe.calls, alerts)
	}
}
