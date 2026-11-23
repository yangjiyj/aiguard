package mcpupstream

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/yangjiyj/aiguard/packages/shared-go/mcpprotocol"
)

// 工具分页护栏：最大页数与总量，由调用方（control-plane）按现有常量传入。
const DefaultMaxPages = 10

// Options 是 Connect 的参数。
type Options struct {
	// URL 是上游地址（建议不含密钥；存量行里可能带 query，会原样保留并与鉴权参数合并）。
	URL    *url.URL
	Config Config
	Secret string
	// Client 用于 Streamable POST；StreamClient 用于 SSE 长流（须无整体超时）。
	// 两者都必须是已绑定出站目标的客户端（safetarget.Client）。StreamClient 为空时退回 Client。
	Client          *http.Client
	StreamClient    *http.Client
	Limits          Limits
	EndpointTimeout time.Duration
	ClientName      string
	ClientVersion   string
	// SkipInitializedNotice=true 时握手后不发 notifications/initialized（连接测试只需 initialize）。
	SkipInitializedNotice bool
}

// Session 是一次已完成 initialize 握手的上游会话（Streamable 或旧 SSE）。
type Session struct {
	o Options

	// Transport 是实际使用的 transport：streamable_http / sse。
	Transport string
	// AutoDetected=true 表示配置为 auto，Transport 是探测结果。
	AutoDetected bool
	// FallbackNote 非空表示 auto 先试了 Streamable 失败后回退到旧 SSE（原因，已脱敏）。
	FallbackNote string
	Negotiated   mcpprotocol.Negotiated
	ServerInfo   map[string]interface{}
	// Warnings 是协商/分页过程中的非致命告警（前向兼容版本、重复 cursor 等）。
	Warnings []string

	mu        sync.Mutex
	sessionID string
	nextID    int
	sse       *SSEConn
}

func (o *Options) streamClient() *http.Client {
	if o.StreamClient != nil {
		return o.StreamClient
	}
	return o.Client
}

func (o *Options) clientInfo() map[string]interface{} {
	name, ver := o.ClientName, o.ClientVersion
	if name == "" {
		name = "jjdguard-mcp-gateway"
	}
	if ver == "" {
		ver = "1.0"
	}
	return map[string]interface{}{"name": name, "version": ver}
}

func (o *Options) secrets() []string { return []string{o.Secret} }

// Connect 按配置建立会话并完成 initialize：
//   - streamable_http：只走 Streamable，不回退；
//   - sse：只走旧 SSE；
//   - auto：已探测过则直接使用；路径以 /sse 结尾直接走旧 SSE；否则先试 Streamable，
//     遇到 400/404/405/406/415/501 或 text/html 等“明显不是 Streamable 端点”才回退旧 SSE。
func Connect(ctx context.Context, o Options) (*Session, error) {
	if o.URL == nil || o.Client == nil {
		return nil, Errorf(KindSSEEndpoint, "上游连接参数缺失")
	}
	transport := o.Config.EffectiveTransport()
	switch transport {
	case TransportStreamableHTTP:
		s, err, _ := connectStreamable(ctx, o)
		return s, err
	case TransportSSE:
		return connectSSE(ctx, o)
	}
	// auto 且未探测
	if PathEndsWithSSE(o.URL) {
		s, err := connectSSE(ctx, o)
		if s != nil {
			s.AutoDetected = true
		}
		return s, err
	}
	s, err, notStreamable := connectStreamable(ctx, o)
	if err == nil {
		s.AutoDetected = true
		return s, nil
	}
	if !notStreamable {
		return nil, err
	}
	sse, serr := connectSSE(ctx, o)
	if serr != nil {
		return nil, &Error{
			Kind: KindOf(serr),
			Message: fmt.Sprintf("自动探测传输方式失败：Streamable HTTP 方式——%s；回退旧版 SSE 方式——%s",
				err.Error(), serr.Error()),
			Cause: serr,
		}
	}
	sse.AutoDetected = true
	sse.FallbackNote = err.Error()
	return sse, nil
}

func (s *Session) newID() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.nextID++
	return s.nextID
}

func initPayload(id int, version string, info map[string]interface{}) []byte {
	b, _ := json.Marshal(map[string]interface{}{
		"jsonrpc": "2.0", "id": id, "method": "initialize",
		"params": map[string]interface{}{
			"protocolVersion": version,
			"capabilities":    map[string]interface{}{},
			"clientInfo":      info,
		},
	})
	return b
}

func (s *Session) applyInitResult(result json.RawMessage) error {
	var r struct {
		ProtocolVersion string                 `json:"protocolVersion"`
		ServerInfo      map[string]interface{} `json:"serverInfo"`
	}
	if err := json.Unmarshal(result, &r); err != nil {
		return Errorf(KindParse, "initialize 结果解析失败")
	}
	neg, err := mcpprotocol.Negotiate(r.ProtocolVersion)
	if err != nil {
		return &Error{Kind: KindProtocolVersion, Message: err.Error(), Cause: err}
	}
	if neg.Forward {
		s.Warnings = append(s.Warnings, fmt.Sprintf("上游返回的协议版本 %s 晚于网关已知的最新版本 %s，已前向兼容并按 %s 语义处理", neg.Raw, mcpprotocol.Latest, neg.Effective))
	}
	s.Negotiated = neg
	s.ServerInfo = r.ServerInfo
	return nil
}

// ---------- Streamable HTTP ----------

func connectStreamable(ctx context.Context, o Options) (*Session, error, bool) {
	s := &Session{o: o, Transport: TransportStreamableHTTP}
	id := s.newID()
	env, notStreamable, err := s.streamableExchange(ctx, initPayload(id, mcpprotocol.Latest, o.clientInfo()), id, true)
	if err != nil {
		return nil, wrapInit(err), notStreamable
	}
	if env.Error != nil {
		return nil, env.rpcError(o.secrets()...), false
	}
	if err := s.applyInitResult(env.Result); err != nil {
		return nil, err, false
	}
	if !o.SkipInitializedNotice {
		// 尽力而为：4xx / 404 / 202 都不算失败。
		_ = s.notifyStreamable(ctx, "notifications/initialized")
	}
	return s, nil, false
}

// wrapInit 给 initialize 阶段的非协议版本错误加上前缀（版本错误保持原文，与既有行为一致）。
func wrapInit(err error) error {
	if KindOf(err) == KindProtocolVersion {
		return err
	}
	if ue, ok := err.(*Error); ok {
		cp := *ue
		cp.Message = "initialize 握手失败: " + ue.Message
		return &cp
	}
	return fmt.Errorf("initialize 握手失败: %w", err)
}

func (s *Session) streamablePost(ctx context.Context, body []byte) (*http.Response, error) {
	u, uerr := RequestURL(s.o.URL, s.o.Config, s.o.Secret)
	if uerr != nil {
		return nil, uerr
	}
	StripCallerCredentials(u, s.o.Config)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), bytes.NewReader(body))
	if err != nil {
		return nil, newRequestError(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	ApplyCommon(req, s.o.Config)
	if err := ApplyAuth(req, s.o.Config, s.o.Secret); err != nil {
		return nil, err
	}
	s.mu.Lock()
	sid := s.sessionID
	s.mu.Unlock()
	if sid != "" {
		req.Header.Set("Mcp-Session-Id", sid)
	}
	if v := s.Negotiated.Effective; v != "" {
		req.Header.Set("MCP-Protocol-Version", v)
	}
	resp, err := s.o.Client.Do(req)
	if err != nil {
		return nil, ClassifyDial(err, s.o.secrets()...)
	}
	// Header.Get 对键名做规范化，因此大小写混用的 mcp-session-id / MCP-SESSION-ID 都能读到；
	// 上游没返回就保持无状态。
	if v := strings.TrimSpace(resp.Header.Get("Mcp-Session-Id")); v != "" {
		s.mu.Lock()
		s.sessionID = v
		s.mu.Unlock()
	}
	return resp, nil
}

// notStreamableStatus 判断 initialize 阶段的状态码是否“明显不是 Streamable 端点”。
func notStreamableStatus(status int) bool {
	switch status {
	case http.StatusBadRequest, http.StatusNotFound, http.StatusMethodNotAllowed,
		http.StatusNotAcceptable, http.StatusUnsupportedMediaType, http.StatusNotImplemented:
		return true
	}
	return false
}

func mediaTypeOf(resp *http.Response) string {
	raw := strings.TrimSpace(resp.Header.Get("Content-Type"))
	if raw == "" {
		return ""
	}
	mt, _, err := mime.ParseMediaType(raw)
	if err != nil {
		// 容忍畸形参数（如 "application/json;charset"）：取分号前的部分。
		mt, _, _ = strings.Cut(raw, ";")
		mt = strings.TrimSpace(mt)
	}
	return strings.ToLower(mt)
}

// streamableExchange 发一个请求并取回 id 匹配的响应。probe=true 表示 initialize 探测阶段，
// 此时“明显不是 Streamable”的响应会同时返回 notStreamable=true 供 auto 回退。
func (s *Session) streamableExchange(ctx context.Context, body []byte, id int, probe bool) (*Envelope, bool, error) {
	resp, err := s.streamablePost(ctx, body)
	if err != nil {
		return nil, false, err
	}
	defer resp.Body.Close()
	rc, err := decodedBody(resp)
	if err != nil {
		return nil, false, err
	}
	limits := s.o.Limits.withDefaults()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		sample, _ := io.ReadAll(io.LimitReader(rc, 4096))
		e := ClassifyHTTPFailure(resp.StatusCode, resp.Header, sample, s.o.secrets()...)
		return nil, probe && notStreamableStatus(resp.StatusCode), e
	}
	mt := mediaTypeOf(resp)
	switch mt {
	case "application/json", "text/json", "application/rpc", "application/jsonrequest":
		data, tooLarge, rerr := readLimited(rc, limits.MaxBodyBytes)
		if rerr != nil {
			return nil, false, ClassifyDial(rerr, s.o.secrets()...)
		}
		if tooLarge {
			return nil, false, Errorf(KindCapacity, "MCP 响应超过容量上限")
		}
		env, derr := DecodeResponse(data, id, resp.StatusCode, s.o.secrets()...)
		return env, false, derr
	case "text/event-stream":
		var found *Envelope
		perr := parseSSE(rc, limits.MaxEventBytes, limits.MaxStreamBytes, func(ev sseEvent) (bool, error) {
			if n := strings.ToLower(ev.Name); n != "" && n != "message" {
				return false, nil
			}
			var env Envelope
			if json.Unmarshal([]byte(ev.Data), &env) != nil || env.Method != "" {
				return false, nil
			}
			if len(env.Result) == 0 && env.Error == nil {
				return false, nil
			}
			if idMatchesInt(env.ID, id) || (env.Error != nil && IsNullID(env.ID)) {
				found = &env
				return true, nil
			}
			return false, nil
		})
		if perr != nil {
			if ue, ok := perr.(*Error); ok {
				return nil, false, ue
			}
			return nil, false, ClassifyDial(perr, s.o.secrets()...)
		}
		if found == nil {
			return nil, false, Errorf(KindParse, "MCP 事件流中未找到 id 匹配的响应")
		}
		return found, false, nil
	case "":
		// 无 Content-Type：按内容嗅探 JSON。
		data, tooLarge, rerr := readLimited(rc, limits.MaxBodyBytes)
		if rerr != nil || tooLarge {
			return nil, false, Errorf(KindParse, "MCP 响应无 Content-Type 且无法读取")
		}
		if t := bytes.TrimSpace(data); len(t) > 0 && (t[0] == '{' || t[0] == '[') {
			env, derr := DecodeResponse(data, id, resp.StatusCode, s.o.secrets()...)
			return env, false, derr
		}
		return nil, probe, NotJSONRPC(resp.StatusCode, data, s.o.secrets()...)
	default:
		sample, _ := io.ReadAll(io.LimitReader(rc, 4096))
		e := NotJSONRPC(resp.StatusCode, sample, s.o.secrets()...)
		if strings.HasPrefix(mt, "text/html") || strings.Contains(mt, "html") {
			e.Kind = KindNotStreamable
			e.Message = fmt.Sprintf("上游返回 HTML 页面（Content-Type=%s），不是 MCP 端点，响应摘要：%s", RedactText(mt), Summarize(sample, s.o.secrets()...))
			return nil, probe, e
		}
		return nil, false, e
	}
}

func (s *Session) notifyStreamable(ctx context.Context, method string) error {
	b, _ := json.Marshal(map[string]interface{}{"jsonrpc": "2.0", "method": method})
	resp, err := s.streamablePost(ctx, b)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	return nil
}

// ---------- 旧版 HTTP+SSE ----------

func connectSSE(ctx context.Context, o Options) (*Session, error) {
	s := &Session{o: o, Transport: TransportSSE}
	conn, err := DialSSE(ctx, SSEOptions{
		URL: o.URL, Config: o.Config, Secret: o.Secret, Client: o.streamClient(),
		Limits: o.Limits, EndpointTimeout: o.EndpointTimeout,
	})
	if err != nil {
		return nil, err
	}
	s.sse = conn
	hs, err := HandshakeSSE(ctx, conn, o.clientInfo(), o.SkipInitializedNotice, o.secrets()...)
	if err != nil {
		conn.Close()
		return nil, err
	}
	s.Negotiated, s.ServerInfo, s.Warnings = hs.Negotiated, hs.ServerInfo, hs.Warnings
	s.nextID = hs.UsedID
	return s, nil
}

// Handshake 是旧 SSE 连接上 initialize + notifications/initialized 的结果。
type Handshake struct {
	Negotiated mcpprotocol.Negotiated
	ServerInfo map[string]interface{}
	Warnings   []string
	UsedID     int
}

// HandshakeSSE 在已建立的旧 SSE 连接上完成 initialize（发我方最高版本）并按协商结果设置后续 POST 的
// MCP-Protocol-Version；skipInitialized=false 时再发 notifications/initialized（尽力而为）。
// 失败时不关闭连接，由调用方决定。网关为无会话请求创建临时上游会话时复用它。
func HandshakeSSE(ctx context.Context, conn *SSEConn, clientInfo map[string]interface{}, skipInitialized bool, secrets ...string) (*Handshake, error) {
	const id = 1
	raw, err := conn.Call(ctx, json.RawMessage(fmt.Sprint(id)), initPayload(id, mcpprotocol.Latest, clientInfo))
	if err != nil {
		return nil, wrapInit(err)
	}
	env, err := DecodeResponse(raw, id, 200, secrets...)
	if err != nil {
		return nil, wrapInit(err)
	}
	if env.Error != nil {
		return nil, env.rpcError(secrets...)
	}
	tmp := &Session{}
	if err := tmp.applyInitResult(env.Result); err != nil {
		return nil, err
	}
	conn.SetProtocolVersion(tmp.Negotiated.Effective)
	if !skipInitialized {
		nb, _ := json.Marshal(map[string]interface{}{"jsonrpc": "2.0", "method": "notifications/initialized"})
		_ = conn.Notify(ctx, nb)
	}
	return &Handshake{Negotiated: tmp.Negotiated, ServerInfo: tmp.ServerInfo, Warnings: tmp.Warnings, UsedID: id}, nil
}

// ---------- 通用调用 ----------

// Call 发送 JSON-RPC 请求并返回 result。上游返回的 JSON-RPC error（含 HTTP 200 + error）
// 以 *RPCError 原样返回，不吞掉。
func (s *Session) Call(ctx context.Context, method string, params interface{}) (json.RawMessage, error) {
	id := s.newID()
	payload := map[string]interface{}{"jsonrpc": "2.0", "id": id, "method": method}
	if params != nil {
		payload["params"] = params
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, Errorf(KindParse, "无法编码 JSON-RPC 请求")
	}
	var env *Envelope
	if s.sse != nil {
		raw, cerr := s.sse.Call(ctx, json.RawMessage(fmt.Sprint(id)), body)
		if cerr != nil {
			return nil, cerr
		}
		env, err = DecodeResponse(raw, id, 200, s.o.secrets()...)
	} else {
		env, _, err = s.streamableExchange(ctx, body, id, false)
	}
	if err != nil {
		return nil, err
	}
	if env.Error != nil {
		return nil, env.rpcError(s.o.secrets()...)
	}
	return env.Result, nil
}

// Close 释放会话：SSE 关闭长流；Streamable 不发 DELETE（无状态探测，不产生额外请求）。
func (s *Session) Close() {
	if s.sse != nil {
		s.sse.Close()
	}
}

// ListToolsResult 是分页拉取工具清单的结果。
type ListToolsResult struct {
	Tools []json.RawMessage
	// Truncated=true 表示达到总量上限被截断。
	Truncated bool
	// Warnings 记录重复 cursor、达到最大页数等情况。
	Warnings []string
}

// ListTools 拉取 tools/list（含 nextCursor 分页）。maxPages 限制页数，maxTools 限制总量；
// 检测重复 cursor（含上游忽略 cursor 一直返回同一个 nextCursor 的情况）并停止，不无限翻页。
func (s *Session) ListTools(ctx context.Context, maxPages, maxTools int) (*ListToolsResult, error) {
	if maxPages <= 0 {
		maxPages = DefaultMaxPages
	}
	res := &ListToolsResult{}
	seen := map[string]bool{}
	cursor := ""
	for page := 0; page < maxPages && !res.Truncated; page++ {
		var params interface{}
		if cursor != "" {
			params = map[string]interface{}{"cursor": cursor}
		}
		raw, err := s.Call(ctx, "tools/list", params)
		if err != nil {
			return nil, err
		}
		var lr struct {
			Tools      []json.RawMessage `json:"tools"`
			NextCursor string            `json:"nextCursor"`
		}
		if err := json.Unmarshal(raw, &lr); err != nil {
			return nil, Errorf(KindParse, "tools/list 响应解析失败: %v", err)
		}
		for _, t := range lr.Tools {
			if maxTools > 0 && len(res.Tools) >= maxTools {
				res.Truncated = true
				break
			}
			res.Tools = append(res.Tools, t)
		}
		if lr.NextCursor == "" {
			return res, nil
		}
		if seen[lr.NextCursor] || lr.NextCursor == cursor {
			res.Warnings = append(res.Warnings, "上游 tools/list 返回了重复的 nextCursor，已停止翻页（疑似忽略 cursor 参数）")
			return res, nil
		}
		seen[lr.NextCursor] = true
		cursor = lr.NextCursor
		if page == maxPages-1 {
			res.Warnings = append(res.Warnings, fmt.Sprintf("tools/list 达到最大页数 %d，已停止翻页", maxPages))
		}
	}
	return res, nil
}
