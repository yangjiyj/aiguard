package handler

// 复审 M-3：上游对 202/204 或 ContentLength==0 的响应常常仍带 Content-Encoding: gzip 头但没有任何字节。
// gzip.NewReader 读空体会返回 EOF，被误判为「声明 gzip 但无法解压」而 502。空体应跳过解压。
// 复审 M-2：Streamable DELETE 要像 HandleGet 一样显式处理 mcpResponseNotForwarded。

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
)

func gzipHeaderEmptyBodyUpstream(t *testing.T, status int) *httptest.Server {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Encoding", "gzip")
		w.WriteHeader(status)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestM3_EmptyBodyWithGzipHeaderIsNotAnError(t *testing.T) {
	for _, status := range []int{http.StatusAccepted, http.StatusNoContent} {
		up := gzipHeaderEmptyBodyUpstream(t, status)
		env := newGzipProxyEnv(t, up.URL)
		notif := `{"jsonrpc":"2.0","method":"notifications/initialized"}`
		w := env.do(t, http.MethodPost, notif, nil)
		// R2 之后通知的 2xx 统一回下游 202（通知无需响应体）；本用例关心的是「空体 + gzip 头不再 502」。
		if w.Code != http.StatusAccepted {
			t.Fatalf("上游 %d + 空体 + gzip 头：通知应回 202，实际 %d %q", status, w.Code, w.Body.String())
		}
	}
}

func TestM3_DecodeSkipsEmptyBodiesButStillDecodesRealGzip(t *testing.T) {
	// 单元：ContentLength==0
	resp := &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Encoding": {"gzip"}}, ContentLength: 0, Body: io.NopCloser(strings.NewReader(""))}
	if err := mcpDecodeUpstreamResponse(resp); err != nil {
		t.Fatalf("ContentLength==0 应跳过解压: %v", err)
	}
	if resp.Header.Get("Content-Encoding") != "" {
		t.Fatalf("空体跳过解压后不应继续声明 Content-Encoding")
	}
	// 单元：204（长度未知也跳过）
	r204 := &http.Response{StatusCode: http.StatusNoContent, Header: http.Header{"Content-Encoding": {"gzip"}}, ContentLength: -1, Body: io.NopCloser(strings.NewReader(""))}
	if err := mcpDecodeUpstreamResponse(r204); err != nil {
		t.Fatalf("204 应跳过解压: %v", err)
	}
	// 有内容的真 gzip 仍然解压；损坏的 gzip 仍然拒绝
	real := &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Encoding": {"gzip"}}, ContentLength: -1, Body: io.NopCloser(strings.NewReader(string(gz(t, "hello"))))}
	if err := mcpDecodeUpstreamResponse(real); err != nil {
		t.Fatal(err)
	}
	if b, _ := io.ReadAll(real.Body); string(b) != "hello" {
		t.Fatalf("真 gzip 应解压: %q", b)
	}
	bad := &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Encoding": {"gzip"}}, ContentLength: -1, Body: io.NopCloser(strings.NewReader("not gzip at all"))}
	if err := mcpDecodeUpstreamResponse(bad); err == nil {
		t.Fatal("损坏的 gzip 仍应拒绝")
	}
}

func TestM3_NonEmptyStatus200WithGzipHeaderAndNoBytesIsStillAnError(t *testing.T) {
	// 200 + 声明 gzip + 长度未知 + 无字节：不是「空体应答」，保持原有严格判定（无法解压）。
	r := &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Encoding": {"gzip"}}, ContentLength: -1, Body: io.NopCloser(strings.NewReader(""))}
	if err := mcpDecodeUpstreamResponse(r); err == nil {
		t.Fatal("200 且长度未知的空 gzip 流不应被悄悄放过")
	}
}

// M-2：Streamable DELETE 命中会话校验失败（合成的未转发响应）时，审计口径与 GET 一致。
func TestM2_DeleteForgedSessionIsAuditedAsNotForwarded(t *testing.T) {
	up := newSessUpstream(t)
	env := newGzipProxyEnv(t, up.srv.URL)
	db := &execRecordingAuditDB{fakeMCPAuditDB: *newFakeAuditDB()}
	env.handler.auditRecorder = &mcpProxyAuditRecorder{db: db}
	before := up.hitCount()
	h := map[string]string{"Mcp-Session-Id": "forged", "MCP-Protocol-Version": "2025-11-25"}
	w := doAsKey(env, "key-a", http.MethodDelete, "", h)
	if w.Code != http.StatusNotFound || up.hitCount() != before {
		t.Fatalf("伪造会话 DELETE: %d hits+%d", w.Code, up.hitCount()-before)
	}
	if !strings.Contains(w.Body.String(), "mcp_session_not_found") {
		t.Fatalf("应回给客户端明确的 mcp_session_not_found，而不是被改写成上游错误: %q", w.Body.String())
	}
	if w.Header().Get("Content-Type") != "application/json" {
		t.Fatalf("未转发的合成响应应保留 JSON 内容类型: %q", w.Header().Get("Content-Type"))
	}
	if len(db.execArgs) == 0 {
		t.Fatalf("DELETE 的未转发响应必须写轻审计")
	}
	// mcpAccessUpsertArgs 的第 9 个参数是 request_status，第 10 个是上游状态码。
	last := db.execArgs[len(db.execArgs)-1]
	if last[8] != "failed" || last[9] != http.StatusNotFound {
		t.Fatalf("DELETE 未转发应按 failed/404 审计，实际 status=%v code=%v", last[8], last[9])
	}
}

// execRecordingAuditDB 在假 DB 之上记录轻审计（直写路径）的参数。
type execRecordingAuditDB struct {
	fakeMCPAuditDB
	execArgs [][]any
}

func (d *execRecordingAuditDB) Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	d.execArgs = append(d.execArgs, append([]any(nil), args...))
	return d.fakeMCPAuditDB.Exec(ctx, sql, args...)
}

// M-2 的区分性测试：未转发的合成响应即便是 2xx（例如将来某个短路返回 204），DELETE 也必须按 failed 审计，
// 不能被「状态码 < 400」误记为已转发成功。用把桥接换成返回 204 的未转发响应来构造这种情形。
func TestM2_DeleteNotForwarded2xxIsStillAuditedAsFailed(t *testing.T) {
	env := newBridgeEnv(t, bridgeOpts{profile: "legacy-sse-relative-endpoint", caseIndex: 0})
	db := &execRecordingAuditDB{fakeMCPAuditDB: *newFakeAuditDB()}
	env.handler.auditRecorder = &mcpProxyAuditRecorder{db: db}
	// 让桥接对 DELETE 返回「未转发」的 204：通过测试钩子替换 forwardMCPUpstream 的结果。
	env.handler.testForwardOverride = func(*http.Request) *http.Response { return mcpNotForwardedEmpty(http.StatusNoContent) }
	h := map[string]string{"Mcp-Session-Id": "mcpgw-whatever", "MCP-Protocol-Version": "2025-03-26"}
	w := doAsKey(env, "key-a", http.MethodDelete, "", h)
	if w.Code != http.StatusNoContent {
		t.Fatalf("合成 204 应原样回给客户端: %d", w.Code)
	}
	if len(db.execArgs) == 0 {
		t.Fatalf("必须写轻审计")
	}
	last := db.execArgs[len(db.execArgs)-1]
	if last[8] != "failed" {
		t.Fatalf("未转发的响应不论状态码都必须记 failed，实际 %v", last[8])
	}
}
