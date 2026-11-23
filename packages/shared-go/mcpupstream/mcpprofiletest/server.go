// Package mcpprofiletest 提供“厂商画像”mock 上游：用 httptest 模拟各家托管 MCP 服务的接入差异
// （鉴权位置、未鉴权失败形态、旧 SSE、协议版本偏差等），供 shared-go / control-plane / gateway-core
// 三处测试共用。画像只描述“上游长什么样”，被测代码里没有任何按厂商的分支。
package mcpprofiletest

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// AuthSpec 描述上游期望的鉴权。
type AuthSpec struct {
	Mode     string // "" 不鉴权 | header | query
	Name     string // 头名或 query 参数名
	Template string // 如 "Bearer {secret}"
	Secret   string
	Unauth   string // 未鉴权形态：amap | zhipu | dashscope | plain401 | oauth | jsonrpc401
	Optional bool   // 鉴权可选（魔搭）
}

func (a AuthSpec) ok(r *http.Request) bool {
	if a.Mode == "" || a.Optional {
		return true
	}
	want := strings.Replace(a.Template, "{secret}", a.Secret, 1)
	switch a.Mode {
	case "header":
		return r.Header.Get(a.Name) == want
	case "query":
		return r.URL.Query().Get(a.Name) == want
	}
	return false
}

// Options 描述一个画像的上游行为。
type Options struct {
	Name            string
	Prefix          string
	StreamablePath  string // 相对 Prefix；"" 表示不提供 Streamable
	SSEPath         string // 相对 Prefix；"" 表示不提供旧 SSE
	MessagePath     string // 旧 SSE 的 POST 端点，默认 /messages
	StreamAuth      AuthSpec
	SSEAuth         AuthSpec
	RequireHeaders  map[string]string
	Version         string // 固定协商版本；VersionFromPath 时忽略
	VersionFromPath bool   // 路径形如 /v/<版本>/mcp
	Endpoint        string // relative | absolute | crossorigin
	Heartbeat       bool   // 心跳 + 注释行 + 缺省事件名 + 多行 data + CRLF
	PingEvents      bool   // 周期性发 event: ping（真实事件，用于复现“上游事件续命”）
	// PathSecret 非空表示“密钥在 URL 路径里”：路径形如 <Prefix><密钥>/<相对路径>。
	// 密钥段按路径段解码后比较；错误或缺失返回 401。SSE 的 endpoint 事件返回的路径同样带密钥段
	// （真实厂商如此），用于验证网关 / 控制面不把 endpoint 路径写进日志与错误。
	PathSecret string
	Mixed      bool   // initialize 回带 charset 的 JSON、tools/call 回 SSE、session id 大小写混用、initialized 回 404
	Pagination string // "" 正常两页 | weird
}

// Req 是上游收到的一次请求记录。
type Req struct {
	Method      string
	Path        string
	EscapedPath string
	RawQuery    string
	Header      http.Header
	Body        []byte
}

// Case 是一个画像下的一组接入用例（同一上游的不同端点 / 不同配置）。
type Case struct {
	Name      string
	URL       string // 登记的 server_url（不含密钥）
	Transport string // mcp_servers.transport 列值
	Caps      map[string]interface{}
	Secret    string

	WantOK        bool
	WantTransport string // 连接成功后实际使用的 transport
	WantKind      string // 失败时的错误类别
	WantMsg       string // 失败时中文文案需包含的片段
	WantProtocol  string // 成功时协商出的有效版本
	WantRawProto  string // 前向兼容时上游原始版本
	Tools         []string
	CallTool      string
	CallArgs      map[string]interface{}
	WantCallText  string
}

// Instance 是运行中的画像。
type Instance struct {
	Name   string
	Server *httptest.Server
	Victim *httptest.Server // 跨源 endpoint 的“受害者”服务
	Cases  []Case

	s *srv
}

func (i *Instance) URL() string { return i.Server.URL }

// Requests 返回上游收到的全部请求（拷贝）。
func (i *Instance) Requests() []Req {
	i.s.mu.Lock()
	defer i.s.mu.Unlock()
	return append([]Req(nil), i.s.reqs...)
}

// ToolCalls 返回上游实际收到的 tools/call 工具名。
func (i *Instance) ToolCalls() []string {
	i.s.mu.Lock()
	defer i.s.mu.Unlock()
	return append([]string(nil), i.s.toolCalls...)
}

// VictimHits 返回跨源 endpoint 受害者收到的请求数（应恒为 0）。
// SetMessageStatus 让旧 SSE 的消息端点之后对任何 POST 都回给定状态码；0 恢复正常。
func (i *Instance) SetMessageStatus(code int) { atomic.StoreInt32(&i.s.messageStatus, int32(code)) }

func (i *Instance) VictimHits() int32 { return atomic.LoadInt32(&i.s.victimHits) }

// OpenStreams 返回当前打开的旧 SSE 长流数。
func (i *Instance) OpenStreams() int { return int(atomic.LoadInt32(&i.s.openStreams)) }

// KillStreams 服务端主动断开所有旧 SSE 长流（模拟上游断流）。
func (i *Instance) KillStreams() {
	i.s.mu.Lock()
	defer i.s.mu.Unlock()
	for _, sess := range i.s.sessions {
		sess.kill()
	}
}

// Reset 清空记录。
func (i *Instance) Reset() {
	i.s.mu.Lock()
	i.s.reqs, i.s.toolCalls = nil, nil
	i.s.mu.Unlock()
	atomic.StoreInt32(&i.s.victimHits, 0)
}

type sseSession struct {
	id   string
	ch   chan []byte
	done chan struct{}
	once sync.Once
}

func (s *sseSession) kill() { s.once.Do(func() { close(s.done) }) }

type srv struct {
	o           Options
	victimURL   string
	mu          sync.Mutex
	reqs        []Req
	toolCalls   []string
	sessions    map[string]*sseSession
	seq         int
	victimHits  int32
	openStreams int32
	// messageStatus 非 0 时，旧 SSE 的消息端点对任何 POST 都回该状态码（text/plain），用于模拟上游对通知回非 2xx（R2）。
	messageStatus int32
}

var versionPath = regexp.MustCompile(`^/v/([^/]+)(/.*)$`)

// StartServer 起一个按 Options 行为的上游（不含 Cases）。
func StartServer(t testing.TB, o Options) *Instance {
	t.Helper()
	if o.MessagePath == "" {
		o.MessagePath = "/messages"
	}
	s := &srv{o: o, sessions: map[string]*sseSession{}}
	inst := &Instance{Name: o.Name, s: s}
	if o.Endpoint == "crossorigin" {
		inst.Victim = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			atomic.AddInt32(&s.victimHits, 1)
			w.WriteHeader(http.StatusAccepted)
		}))
		t.Cleanup(inst.Victim.Close)
		s.victimURL = inst.Victim.URL
	}
	inst.Server = httptest.NewServer(s)
	t.Cleanup(func() {
		inst.KillStreams()
		inst.Server.CloseClientConnections()
		inst.Server.Close()
	})
	return inst
}

func (s *srv) record(r *http.Request, body []byte) {
	s.mu.Lock()
	s.reqs = append(s.reqs, Req{Method: r.Method, Path: r.URL.Path, EscapedPath: r.URL.EscapedPath(), RawQuery: r.URL.RawQuery, Header: r.Header.Clone(), Body: body})
	s.mu.Unlock()
}

func (s *srv) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(io.LimitReader(r.Body, 8<<20))
	s.record(r, body)
	path := r.URL.Path
	version := s.o.Version
	if s.o.VersionFromPath {
		m := versionPath.FindStringSubmatch(path)
		if m == nil {
			http.NotFound(w, r)
			return
		}
		version, path = m[1], m[2]
	}
	if s.o.PathSecret != "" {
		if !strings.HasPrefix(path, s.o.Prefix) {
			http.NotFound(w, r)
			return
		}
		rest := strings.TrimPrefix(r.URL.EscapedPath(), s.o.Prefix)
		seg, tail, _ := strings.Cut(rest, "/")
		dec, derr := url.PathUnescape(seg)
		if derr != nil || dec != s.o.PathSecret {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":{"code":"invalid_path_token","message":"bad token"}}`))
			return
		}
		if un, uerr := url.PathUnescape(tail); uerr == nil {
			path = "/" + un
		} else {
			path = "/" + tail
		}
	} else if s.o.Prefix != "" {
		if !strings.HasPrefix(path, s.o.Prefix) {
			http.NotFound(w, r)
			return
		}
		path = strings.TrimPrefix(path, s.o.Prefix)
	}
	switch {
	case s.o.StreamablePath != "" && path == s.o.StreamablePath:
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", "POST")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		s.serveStreamable(w, r, body, version)
	case s.o.SSEPath != "" && path == s.o.SSEPath:
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", "GET")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		s.serveSSE(w, r)
	case s.o.SSEPath != "" && path == s.o.MessagePath:
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		s.serveMessage(w, r, body, version)
	default:
		http.NotFound(w, r)
	}
}

func (s *srv) unauth(w http.ResponseWriter, r *http.Request, a AuthSpec) {
	switch a.Unauth {
	case "amap":
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"0","info":"INVALID_USER_KEY","infocode":"10001"}`))
	case "zhipu":
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"code":1001,"msg":"Header中未收到Authorization参数，无法进行身份验证。","success":false}`))
	case "dashscope":
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"code":"InvalidApiKey","message":"No API-key provided.","request_id":"req-1"}`))
	case "oauth":
		w.Header().Set("WWW-Authenticate", `Bearer realm="OAuth", resource_metadata="http://`+r.Host+`/.well-known/oauth-protected-resource/mcp/", scope="default"`)
		w.WriteHeader(http.StatusUnauthorized)
	case "jsonrpc401":
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("WWW-Authenticate", `Bearer realm="Zapier MCP", error="invalid_token"`)
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":null,"error":{"code":-31996,"message":"Unauthorized"}}`))
	default: // plain401
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte("bad request: missing required Authorization header"))
	}
}

func (s *srv) headersOK(w http.ResponseWriter, r *http.Request) bool {
	for k, v := range s.o.RequireHeaders {
		if r.Header.Get(k) != v {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"error":{"message":"` + k + ` header required"}}`))
			return false
		}
	}
	return true
}

type rpcReq struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
}

func (s *srv) toolDefs() []map[string]interface{} {
	mk := func(name, desc, param string) map[string]interface{} {
		return map[string]interface{}{
			"name": name, "description": desc,
			"inputSchema": map[string]interface{}{"type": "object", "properties": map[string]interface{}{param: map[string]interface{}{"type": "string"}}},
		}
	}
	return []map[string]interface{}{
		mk("echo", "回显文本", "text"),
		mk("get_weather", "查询城市天气", "city"),
		mk("delete_all", "清空全部数据", "path"),
	}
}

func rpcResult(id json.RawMessage, result interface{}) []byte {
	b, _ := json.Marshal(map[string]interface{}{"jsonrpc": "2.0", "id": id, "result": result})
	return b
}

func rpcError(id json.RawMessage, code int, msg string) []byte {
	b, _ := json.Marshal(map[string]interface{}{"jsonrpc": "2.0", "id": id, "error": map[string]interface{}{"code": code, "message": msg}})
	return b
}

func (s *srv) handleRPC(m rpcReq, version string) []byte {
	switch m.Method {
	case "initialize":
		return rpcResult(m.ID, map[string]interface{}{
			"protocolVersion": version,
			"capabilities":    map[string]interface{}{"tools": map[string]interface{}{}},
			"serverInfo":      map[string]interface{}{"name": s.o.Name, "version": "1"},
		})
	case "ping":
		return rpcResult(m.ID, map[string]interface{}{})
	case "tools/list":
		var p struct {
			Cursor string `json:"cursor"`
		}
		_ = json.Unmarshal(m.Params, &p)
		defs := s.toolDefs()
		if s.o.Pagination == "weird" {
			if p.Cursor == "" { // 空页但带 nextCursor
				return rpcResult(m.ID, map[string]interface{}{"tools": []interface{}{}, "nextCursor": "c1"})
			}
			// 忽略真实翻页：永远回同一个 nextCursor
			return rpcResult(m.ID, map[string]interface{}{"tools": defs[:2], "nextCursor": "c1"})
		}
		if p.Cursor == "" {
			return rpcResult(m.ID, map[string]interface{}{"tools": defs[:2], "nextCursor": "p2"})
		}
		return rpcResult(m.ID, map[string]interface{}{"tools": defs[2:]})
	case "tools/call":
		var p struct {
			Name      string                 `json:"name"`
			Arguments map[string]interface{} `json:"arguments"`
		}
		_ = json.Unmarshal(m.Params, &p)
		s.mu.Lock()
		s.toolCalls = append(s.toolCalls, p.Name)
		s.mu.Unlock()
		text := "ok:" + p.Name
		if p.Name == "echo" {
			text = fmt.Sprintf("echo: %v", p.Arguments["text"])
		}
		return rpcResult(m.ID, map[string]interface{}{"content": []interface{}{map[string]interface{}{"type": "text", "text": text}}})
	}
	if len(m.ID) == 0 {
		return nil
	}
	return rpcError(m.ID, -32601, "method not found")
}

func (s *srv) serveStreamable(w http.ResponseWriter, r *http.Request, body []byte, version string) {
	if !s.o.StreamAuth.ok(r) {
		s.unauth(w, r, s.o.StreamAuth)
		return
	}
	if !s.headersOK(w, r) {
		return
	}
	var m rpcReq
	if json.Unmarshal(body, &m) != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	if s.o.Mixed && m.Method != "initialize" && r.Header.Get("Mcp-Session-Id") == "" {
		http.Error(w, "missing session", http.StatusBadRequest)
		return
	}
	resp := s.handleRPC(m, version)
	if len(m.ID) == 0 { // 通知
		if s.o.Mixed {
			http.NotFound(w, r) // initialized 返回 404 不算失败
			return
		}
		w.WriteHeader(http.StatusAccepted)
		return
	}
	switch {
	case m.Method == "initialize" && s.o.Mixed:
		w.Header()["mcp-SESSION-id"] = []string{"sess-mixed-1"} // 大小写混用
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_, _ = w.Write(resp)
	case m.Method == "initialize":
		w.Header().Set("Mcp-Session-Id", "sess-1")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(resp)
	case s.o.Mixed && m.Method == "tools/call":
		w.Header().Set("Content-Type", "text/event-stream; charset=utf-8")
		_, _ = fmt.Fprintf(w, ": stream open\n\nevent: message\ndata: %s\n\n", resp)
	case s.o.Mixed && m.Method == "tools/list":
		var buf bytes.Buffer
		zw := gzip.NewWriter(&buf)
		_, _ = zw.Write(resp)
		_ = zw.Close()
		w.Header().Set("Content-Type", "Application/JSON; Charset=UTF-8")
		w.Header().Set("Content-Encoding", "gzip")
		_, _ = w.Write(buf.Bytes())
	default:
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(resp)
	}
}

func (s *srv) writeEvent(w http.ResponseWriter, name, data string) {
	nl := "\n"
	if s.o.Heartbeat {
		nl = "\r\n"
	}
	var b strings.Builder
	if name != "" {
		b.WriteString("event: " + name + nl)
	}
	if s.o.Heartbeat && name == "" {
		var pretty bytes.Buffer
		if json.Indent(&pretty, []byte(data), "", " ") == nil {
			data = pretty.String()
		}
	}
	for _, line := range strings.Split(data, "\n") {
		b.WriteString("data: " + line + nl)
	}
	b.WriteString(nl)
	_, _ = io.WriteString(w, b.String())
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}
}

func (s *srv) serveSSE(w http.ResponseWriter, r *http.Request) {
	if !s.o.SSEAuth.ok(r) {
		s.unauth(w, r, s.o.SSEAuth)
		return
	}
	if !s.headersOK(w, r) {
		return
	}
	s.mu.Lock()
	s.seq++
	sess := &sseSession{id: fmt.Sprintf("sid%d", s.seq), ch: make(chan []byte, 16), done: make(chan struct{})}
	s.sessions[sess.id] = sess
	s.mu.Unlock()
	atomic.AddInt32(&s.openStreams, 1)
	defer func() {
		atomic.AddInt32(&s.openStreams, -1)
		s.mu.Lock()
		delete(s.sessions, sess.id)
		s.mu.Unlock()
	}()

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.WriteHeader(http.StatusOK)
	if s.o.Heartbeat {
		_, _ = io.WriteString(w, ": welcome comment\r\n\r\n")
	}
	ep := s.o.Prefix + s.o.MessagePath + "?sessionId=" + sess.id
	if s.o.PathSecret != "" {
		ep = s.o.Prefix + url.PathEscape(s.o.PathSecret) + s.o.MessagePath + "?sessionId=" + sess.id
	}
	switch s.o.Endpoint {
	case "absolute":
		ep = "http://" + r.Host + ep
	case "crossorigin":
		ep = s.victimURL + ep
	}
	s.writeEvent(w, "endpoint", ep)

	var tick <-chan time.Time
	if s.o.Heartbeat || s.o.PingEvents {
		t := time.NewTicker(15 * time.Millisecond)
		defer t.Stop()
		tick = t.C
	}
	name := "message"
	if s.o.Heartbeat {
		name = ""
	}
	for {
		select {
		case msg := <-sess.ch:
			s.writeEvent(w, name, string(msg))
		case <-tick:
			if s.o.PingEvents {
				_, _ = io.WriteString(w, "event: ping\ndata: {}\n\n")
				if f, ok := w.(http.Flusher); ok {
					f.Flush()
				}
				continue
			}
			_, _ = io.WriteString(w, ": ping\r\n\r\nretry: 3000\r\n\r\n")
			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}
		case <-sess.done:
			return
		case <-r.Context().Done():
			return
		}
	}
}

func (s *srv) serveMessage(w http.ResponseWriter, r *http.Request, body []byte, version string) {
	if !s.o.SSEAuth.ok(r) {
		s.unauth(w, r, s.o.SSEAuth)
		return
	}
	if !s.headersOK(w, r) {
		return
	}
	s.mu.Lock()
	sess := s.sessions[r.URL.Query().Get("sessionId")]
	s.mu.Unlock()
	if sess == nil {
		http.Error(w, "Could not find session", http.StatusNotFound)
		return
	}
	if code := int(atomic.LoadInt32(&s.messageStatus)); code != 0 {
		http.Error(w, "forced status", code)
		return
	}
	var m rpcReq
	if json.Unmarshal(body, &m) != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	resp := s.handleRPC(m, version)
	if resp != nil && len(m.ID) > 0 {
		go func() {
			time.Sleep(5 * time.Millisecond)
			select {
			case sess.ch <- resp:
			case <-sess.done:
			}
		}()
	}
	w.WriteHeader(http.StatusAccepted)
	_, _ = w.Write([]byte("Accepted"))
}
