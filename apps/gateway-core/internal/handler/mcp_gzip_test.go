package handler

// 验收缺陷 D2：网关数据面不处理 gzip。下游（如 Cursor、Claude Code）常带 Accept-Encoding: gzip，
// 网关原样透传给上游；上游回压缩体后，网关把压缩字节当成 JSON 校验，结果 502。

import (
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

func gz(t *testing.T, s string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	_, _ = zw.Write([]byte(s))
	_ = zw.Close()
	return buf.Bytes()
}

// gzipUpstream 是“只要客户端说得出 gzip 就压缩”的上游，并记录收到的 Accept-Encoding。
func gzipUpstream(t *testing.T, bodyFor func(method string) string, contentType string) (*httptest.Server, func() []string) {
	t.Helper()
	var mu sync.Mutex
	var seen []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		mu.Lock()
		seen = append(seen, r.Header.Get("Accept-Encoding"))
		mu.Unlock()
		method := ""
		if i := strings.Index(string(raw), `"method":"`); i >= 0 {
			rest := string(raw)[i+10:]
			method = rest[:strings.Index(rest, `"`)]
		}
		payload := bodyFor(method)
		w.Header().Set("Content-Type", contentType)
		if strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
			w.Header().Set("Content-Encoding", "gzip")
			_, _ = w.Write(gz(t, payload))
			return
		}
		_, _ = w.Write([]byte(payload))
	}))
	t.Cleanup(srv.Close)
	return srv, func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), seen...)
	}
}

func newGzipProxyEnv(t *testing.T, upstreamURL string) *bridgeEnv {
	t.Helper()
	env := newBridgeEnv(t, bridgeOpts{profile: "streamable-mixed", caseIndex: 0})
	route, _ := env.handler.serverCache.get("tenant_test\x1fmcp_srv1")
	route.ServerURL, route.Transport, route.Capabilities = upstreamURL+"/mcp", "streamable_http", map[string]interface{}{}
	route.AuthCiphertext = ""
	env.handler.targetClientResolver = loopbackResolver()
	return env
}

const gzListJSON = `{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"echo","description":"回显文本","inputSchema":{"type":"object"}}]}}`

// 下游带 Accept-Encoding: gzip：此前网关会把压缩字节当 JSON 校验而 502。
func TestD2_DownstreamAcceptEncodingGzipDoesNotBreakNonStreaming(t *testing.T) {
	srv, seen := gzipUpstream(t, func(string) string { return gzListJSON }, "application/json")
	env := newGzipProxyEnv(t, srv.URL)
	w := env.do(t, http.MethodPost, rpcBody(2, "tools/list", ""), map[string]string{"Accept-Encoding": "gzip, deflate, br"})
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"echo"`) {
		t.Fatalf("a client advertising gzip must still get a valid tools/list: %d %q", w.Code, w.Body.String())
	}
	for _, ae := range seen() {
		if ae != "identity" {
			t.Fatalf("网关转发上游必须显式 Accept-Encoding: identity，实际 %q", ae)
		}
	}
	if w.Header().Get("Content-Encoding") != "" {
		t.Fatalf("网关写给下游的是已校验的明文，不得残留上游的 Content-Encoding: %q", w.Header().Get("Content-Encoding"))
	}
}

// 即使不带 Accept-Encoding，上游强制回 gzip（Go 的 Transport 自己加 gzip 头时会透明解压，但显式 identity 之后不会），
// 网关也要能处理：有界解压后再校验。
func TestD2_UpstreamForcedGzipIsDecompressedWithinBounds(t *testing.T) {
	forced := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("Content-Encoding", "gzip")
		_, _ = w.Write(gz(t, gzListJSON))
	}))
	t.Cleanup(forced.Close)
	env := newGzipProxyEnv(t, forced.URL)
	w := env.do(t, http.MethodPost, rpcBody(2, "tools/list", ""), nil)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"echo"`) {
		t.Fatalf("forced-gzip upstream must be decompressed: %d %q", w.Code, w.Body.String())
	}
}

// zip 炸弹：很小的压缩体解压后远超容量上限，必须在上限处截断并拒绝，不能耗尽内存。
func TestD2_GzipBombIsRejectedAtTheCapacityLimit(t *testing.T) {
	bomb := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Encoding", "gzip")
		var buf bytes.Buffer
		zw := gzip.NewWriter(&buf)
		_, _ = zw.Write([]byte(`{"jsonrpc":"2.0","id":2,"result":{"pad":"`))
		chunk := bytes.Repeat([]byte("A"), 1<<20)
		for i := 0; i < int(maxMCPNonStreamingResponseBytes>>20)+8; i++ { // 解压后 > 上限
			_, _ = zw.Write(chunk)
		}
		_, _ = zw.Write([]byte(`"}}`))
		_ = zw.Close()
		if buf.Len() > 256<<10 {
			t.Errorf("fixture sanity: the bomb must be tiny when compressed, got %d bytes", buf.Len())
		}
		_, _ = w.Write(buf.Bytes())
	}))
	t.Cleanup(bomb.Close)
	env := newGzipProxyEnv(t, bomb.URL)
	w := env.do(t, http.MethodPost, rpcBody(2, "tools/list", ""), nil)
	if w.Code != http.StatusBadGateway {
		t.Fatalf("a decompression bomb must be rejected with 502, got %d (body %d bytes)", w.Code, w.Body.Len())
	}
	if w.Body.Len() > 4<<10 {
		t.Fatalf("the error body must be small, not the inflated payload: %d bytes", w.Body.Len())
	}
}

// 不支持的压缩算法（br / zstd / deflate）不得被当成 JSON 校验：明确报错而不是乱码 502 原因。
func TestD2_UnsupportedContentEncodingIsRejectedClearly(t *testing.T) {
	br := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Encoding", "br")
		_, _ = w.Write([]byte{0x1b, 0x2c, 0x00, 0x01})
	}))
	t.Cleanup(br.Close)
	env := newGzipProxyEnv(t, br.URL)
	w := env.do(t, http.MethodPost, rpcBody(2, "tools/list", ""), nil)
	if w.Code != http.StatusBadGateway || !strings.Contains(w.Body.String(), "压缩") {
		t.Fatalf("unsupported encodings must yield a clear Chinese 502: %d %q", w.Code, w.Body.String())
	}
}

// SSE 流式分支：上游以 text/event-stream 回压缩流时同样要能处理（逐事件校验前先解压）。
func TestD2_GzipEventStreamResponseIsHandled(t *testing.T) {
	stream := "event: message\ndata: " + gzListJSON + "\n\n"
	srv, seen := gzipUpstream(t, func(string) string { return stream }, "text/event-stream")
	env := newGzipProxyEnv(t, srv.URL)
	w := env.do(t, http.MethodPost, rpcBody(2, "tools/list", ""), map[string]string{"Accept-Encoding": "gzip", "Accept": "application/json, text/event-stream"})
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"echo"`) {
		t.Fatalf("gzip SSE must be decoded: %d %q", w.Code, w.Body.String())
	}
	for _, ae := range seen() {
		if ae != "identity" {
			t.Fatalf("SSE 路径同样要显式 identity，实际 %q", ae)
		}
	}
}

// 经 mixed 画像（tools/list 回 gzip + 大小写混用的 Content-Type）跑网关全链路。
func TestD2_MixedProfileToolsListThroughGateway(t *testing.T) {
	env := newBridgeEnv(t, bridgeOpts{profile: "streamable-mixed", caseIndex: 0, caps: map[string]interface{}{"detected_transport": "streamable_http"}})
	h := map[string]string{"Accept-Encoding": "gzip, deflate", "Accept": "application/json, text/event-stream"}
	init := env.do(t, http.MethodPost, bridgeInitBody, h)
	if init.Code != http.StatusOK {
		t.Fatalf("initialize: %d %s", init.Code, init.Body.String())
	}
	if sid := init.Header().Get("Mcp-Session-Id"); sid != "" {
		h["Mcp-Session-Id"] = sid
	}
	h["MCP-Protocol-Version"] = "2025-11-25"
	list := env.do(t, http.MethodPost, rpcBody(2, "tools/list", ""), h)
	if list.Code != http.StatusOK || !strings.Contains(list.Body.String(), `"echo"`) {
		t.Fatalf("mixed 画像 tools/list（上游回 gzip）经网关必须成功: %d %q", list.Code, list.Body.String())
	}
}

var _ = context.Background

// 解压层自己的上限必须生效，而不是依赖下游某个分支恰好也有上限（SSE 直通分支没有按整体解压后大小截断的读取）。
func TestD2_DecodeLayerEnforcesItsOwnLimit(t *testing.T) {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	chunk := bytes.Repeat([]byte("A"), 1<<20)
	total := int(mcpDecodeLimit>>20) + 64 // 解压后远超上限（几十 MB），压缩后只有几十 KB
	for i := 0; i < total; i++ {
		_, _ = zw.Write(chunk)
	}
	_ = zw.Close()
	if buf.Len() > 512<<10 {
		t.Fatalf("fixture sanity: bomb must be tiny when compressed, got %d", buf.Len())
	}
	resp := &http.Response{Header: http.Header{"Content-Encoding": {"gzip"}}, ContentLength: -1, Body: io.NopCloser(&buf)}
	if err := mcpDecodeUpstreamResponse(resp); err != nil {
		t.Fatal(err)
	}
	n, err := io.Copy(io.Discard, resp.Body)
	if err == nil || !strings.Contains(err.Error(), "解压后超过容量上限") {
		t.Fatalf("reading past the limit must fail with the bomb error, got n=%d err=%v", n, err)
	}
	if n > mcpDecodeLimit {
		t.Fatalf("must stop at the limit (%d), but delivered %d bytes", mcpDecodeLimit, n)
	}
	if resp.Header.Get("Content-Encoding") != "" || resp.Header.Get("Content-Length") != "" {
		t.Fatalf("decoded responses must not keep encoding/length headers: %v", resp.Header)
	}
}

// 恰好等于上限的解压结果不算超限（边界）。
func TestD2_DecodeLayerAcceptsPayloadExactlyAtTheLimit(t *testing.T) {
	old := mcpDecodeLimit
	mcpDecodeLimit = 1024
	defer func() { mcpDecodeLimit = old }()
	resp := &http.Response{Header: http.Header{"Content-Encoding": {"gzip"}}, ContentLength: -1, Body: io.NopCloser(bytes.NewReader(gz(t, strings.Repeat("x", 1024))))}
	if err := mcpDecodeUpstreamResponse(resp); err != nil {
		t.Fatal(err)
	}
	b, err := io.ReadAll(resp.Body)
	if err != nil || len(b) != 1024 {
		t.Fatalf("a payload of exactly the limit must be delivered intact: n=%d err=%v", len(b), err)
	}
	over := &http.Response{Header: http.Header{"Content-Encoding": {"gzip"}}, ContentLength: -1, Body: io.NopCloser(bytes.NewReader(gz(t, strings.Repeat("x", 1025))))}
	if err := mcpDecodeUpstreamResponse(over); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadAll(over.Body); err == nil {
		t.Fatal("one byte over the limit must be rejected")
	}
}
