package mcpupstream

import (
	"bytes"
	"context"
	"encoding/json"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Limits 是上游读取的容量上限；零值取默认（与 gateway-core 现有常量一致）。
type Limits struct {
	MaxEventBytes  int
	MaxStreamBytes int64
	MaxBodyBytes   int64
}

func (l Limits) withDefaults() Limits {
	if l.MaxEventBytes <= 0 {
		l.MaxEventBytes = DefaultMaxEventBytes
	}
	if l.MaxStreamBytes <= 0 {
		l.MaxStreamBytes = DefaultMaxStreamBytes
	}
	if l.MaxBodyBytes <= 0 {
		l.MaxBodyBytes = DefaultMaxBodyBytes
	}
	return l
}

// DefaultEndpointTimeout 是等待 endpoint 事件的默认时长。
const DefaultEndpointTimeout = 10 * time.Second

// SSEOptions 是 DialSSE 的参数。
type SSEOptions struct {
	// URL 是 SSE GET 地址（不含密钥；密钥由 Config+Secret 注入）。
	URL    *url.URL
	Config Config
	Secret string
	// Client 必须是已绑定出站目标的客户端（safetarget.Client(..., streaming=true)），且 Timeout=0。
	Client          *http.Client
	Limits          Limits
	EndpointTimeout time.Duration
	// ProtocolVersion 非空时在 POST 上带 MCP-Protocol-Version 头。
	ProtocolVersion string
	// OnServerMessage 收到上游主动发来的消息（服务端通知/反向请求，即没有对应挂起请求的消息）时回调。
	// 回调在读取协程内同步执行，不得阻塞。
	OnServerMessage func(raw []byte)
}

// SSEConn 是一条旧版 HTTP+SSE transport 连接：一个 GET 长流 + 一个 POST endpoint。
// 响应按 JSON-RPC id 从流里关联回来。并发安全。
type SSEConn struct {
	cfg      Config
	secret   string
	client   *http.Client
	base     *url.URL
	endpoint *url.URL
	limits   Limits
	onServer func([]byte)

	protoVersion atomic.Value // string
	lastActive   atomic.Int64 // 任何收发（含上游事件），仅供观测
	clientActive atomic.Int64 // 仅下游发起的调用刷新；空闲回收只看它，上游心跳/事件无法续命

	cancel context.CancelFunc
	done   chan struct{}

	mu      sync.Mutex
	pending map[string]chan []byte
	err     error
}

type endpointResult struct {
	u   *url.URL
	err error
}

// DialSSE 建立 SSE 连接并等待 endpoint 事件。ctx 只约束建立阶段；连接建立后的生命周期由 Close 控制。
func DialSSE(ctx context.Context, o SSEOptions) (*SSEConn, error) {
	if o.URL == nil || o.Client == nil {
		return nil, Errorf(KindSSEEndpoint, "SSE 连接参数缺失")
	}
	limits := o.Limits.withDefaults()
	c := &SSEConn{
		cfg: o.Config, secret: o.Secret, client: o.Client, base: cloneURL(o.URL),
		limits: limits, onServer: o.OnServerMessage, done: make(chan struct{}),
		pending: map[string]chan []byte{},
	}
	c.protoVersion.Store(o.ProtocolVersion)
	c.touch()
	c.touchClient()

	streamCtx, cancel := context.WithCancel(context.Background())
	c.cancel = cancel
	// 建连阶段的 ctx 取消要能中止建立过程，但**成功建立之后**调用方取消 ctx（例如桥接里 defer cancel()）
	// 绝不能取消已建立的连接。做法：watcher 只在“建连窗口”内监听 ctx；成功路径上先通知 watcher 退出并等它
	// 真正退出，再把连接交给调用方——返回之后不再有任何 goroutine 会因调用方的 ctx 取消去关闭这条连接。
	// 仅依赖 select 的两个分支同时就绪时的随机选择是不可靠的。
	stopWatch := make(chan struct{})
	watcherDone := make(chan struct{})
	var ctxCancelled atomic.Bool
	go func() {
		defer close(watcherDone)
		select {
		case <-ctx.Done():
			ctxCancelled.Store(true)
			cancel()
		case <-stopWatch:
		}
	}()
	// handoff 在成功路径上调用：停掉 watcher 并等待其退出；若 ctx 恰好已先一步取消，则视为建连被取消。
	handoff := func() bool {
		close(stopWatch)
		<-watcherDone
		return !ctxCancelled.Load()
	}
	// 失败路径统一收尾（不需要等待 watcher）。
	var handedOff bool
	defer func() {
		if !handedOff {
			select {
			case <-stopWatch:
			default:
				close(stopWatch)
			}
		}
	}()

	// path 模式：用替换后的真实 URL 发 GET，并以它作为 endpoint 同源校验的基准（同源比较只看 scheme/host/port，
	// 不依赖路径里的密钥）；真实 URL 只存在于本函数与连接对象的内存里，绝不写入日志与错误。
	getURL, uerr := RequestURL(o.URL, o.Config, o.Secret)
	if uerr != nil {
		cancel()
		return nil, uerr
	}
	c.base = cloneURL(getURL)
	req, err := http.NewRequestWithContext(streamCtx, http.MethodGet, getURL.String(), nil)
	if err != nil {
		cancel()
		return nil, newRequestError(err)
	}
	req.Header.Set("Accept", "text/event-stream")
	req.Header.Set("Cache-Control", "no-cache")
	ApplyCommon(req, o.Config)
	StripCallerCredentials(req.URL, o.Config)
	if err := ApplyAuth(req, o.Config, o.Secret); err != nil {
		cancel()
		return nil, err
	}
	resp, err := o.Client.Do(req)
	if err != nil {
		cancel()
		if ctx.Err() != nil {
			return nil, ClassifyDial(ctx.Err(), o.Secret)
		}
		return nil, ClassifyDial(err, o.Secret)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		defer resp.Body.Close()
		cancel()
		return nil, ClassifyHTTPFailure(resp.StatusCode, resp.Header, peek(resp, 4096), o.Secret)
	}
	mt, _, _ := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if !strings.EqualFold(mt, "text/event-stream") {
		defer resp.Body.Close()
		cancel()
		sample := peek(resp, 4096)
		if mt == "" || strings.EqualFold(mt, "application/json") || strings.HasPrefix(strings.ToLower(mt), "text/") {
			return nil, NotJSONRPC(resp.StatusCode, sample, o.Secret)
		}
		return nil, Errorf(KindNotStreamable, "上游 GET 未返回 SSE 事件流（Content-Type=%s），不是旧版 SSE 端点", RedactText(mt))
	}
	body, derr := decodedBody(resp)
	if derr != nil {
		resp.Body.Close()
		cancel()
		return nil, derr
	}

	endpointCh := make(chan endpointResult, 1)
	go c.readLoop(body, endpointCh)

	timeout := o.EndpointTimeout
	if timeout <= 0 {
		timeout = DefaultEndpointTimeout
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case r := <-endpointCh:
		if r.err != nil {
			c.Close()
			return nil, r.err
		}
		c.endpoint = r.u
		if !handoff() {
			c.Close()
			return nil, ClassifyDial(ctx.Err(), o.Secret)
		}
		handedOff = true
		return c, nil
	case <-c.done:
		c.Close()
		if e := c.streamErr(); e != nil {
			return nil, e
		}
		return nil, Errorf(KindSSEEndpoint, "上游 SSE 连接在返回 endpoint 事件前已关闭")
	case <-timer.C:
		c.Close()
		return nil, Errorf(KindSSEEndpoint, "上游 SSE 在 %d 秒内未返回 endpoint 事件，不是有效的旧版 SSE 端点或鉴权未通过", int(timeout/time.Second))
	case <-ctx.Done():
		c.Close()
		return nil, ClassifyDial(ctx.Err(), o.Secret)
	}
}

func cloneURL(u *url.URL) *url.URL {
	c := *u
	if u.User != nil {
		ui := *u.User
		c.User = &ui
	}
	return &c
}

func (c *SSEConn) touch() { c.lastActive.Store(time.Now().UnixNano()) }

// touchClient 记录一次下游发起的活动（Call/Notify 入口）。
func (c *SSEConn) touchClient() { c.clientActive.Store(time.Now().UnixNano()) }

// LastClientActive 返回最近一次由下游发起的调用时间；上游事件不会刷新它。
// 空闲回收必须使用它，否则上游定时 ping 可以让空闲会话永不过期。
func (c *SSEConn) LastClientActive() time.Time { return time.Unix(0, c.clientActive.Load()) }

// LastActive 返回最近一次收发时间（会话空闲回收用）。
func (c *SSEConn) LastActive() time.Time { return time.Unix(0, c.lastActive.Load()) }

// SetProtocolVersion 设置后续 POST 携带的 MCP-Protocol-Version。
func (c *SSEConn) SetProtocolVersion(v string) { c.protoVersion.Store(v) }

// Done 在连接关闭（主动或上游断开）后关闭。
func (c *SSEConn) Done() <-chan struct{} { return c.done }

// Alive 报告连接是否仍可用。
func (c *SSEConn) Alive() bool {
	select {
	case <-c.done:
		return false
	default:
		return true
	}
}

func (c *SSEConn) streamErr() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.err
}

// Close 关闭连接并让所有挂起的 Call 立即失败。幂等。
func (c *SSEConn) Close() {
	c.fail(Errorf(KindStreamClosed, "上游 SSE 连接已关闭"))
	c.cancel()
}

func (c *SSEConn) fail(err error) {
	c.mu.Lock()
	if c.err == nil {
		c.err = err
	}
	select {
	case <-c.done:
	default:
		close(c.done)
	}
	c.mu.Unlock()
}

func (c *SSEConn) readLoop(body interface {
	Read([]byte) (int, error)
	Close() error
}, endpointCh chan<- endpointResult) {
	defer body.Close()
	gotEndpoint := false
	err := parseSSE(body, c.limits.MaxEventBytes, c.limits.MaxStreamBytes, func(ev sseEvent) (bool, error) {
		c.touch()
		switch strings.ToLower(ev.Name) {
		case "endpoint":
			if gotEndpoint {
				return false, nil
			}
			gotEndpoint = true
			u, err := ResolveEndpoint(c.base, ev.Data)
			endpointCh <- endpointResult{u: u, err: err}
			if err != nil {
				return true, err
			}
		case "", "message":
			c.dispatch([]byte(ev.Data))
		}
		return false, nil
	})
	switch {
	case err != nil:
		if ue, ok := err.(*Error); ok {
			c.fail(ue)
		} else {
			c.fail(ClassifyDial(err, c.secret))
		}
	default:
		c.fail(Errorf(KindStreamClosed, "上游 SSE 连接已断开"))
	}
	if !gotEndpoint {
		endpointCh <- endpointResult{err: c.streamErr()}
	}
}

func (c *SSEConn) dispatch(raw []byte) {
	var env Envelope
	if json.Unmarshal(bytes.TrimSpace(raw), &env) != nil {
		return // 非 JSON 事件数据（心跳文本等）忽略
	}
	isResponse := env.Method == "" && (len(env.Result) > 0 || env.Error != nil)
	if isResponse {
		if key, ok := IDKey(env.ID); ok {
			c.mu.Lock()
			ch := c.pending[key]
			c.mu.Unlock()
			if ch != nil {
				select {
				case ch <- append([]byte(nil), raw...):
				default:
				}
				return
			}
		}
	}
	if c.onServer != nil {
		c.onServer(append([]byte(nil), raw...))
	}
}

func (c *SSEConn) secrets() []string { return []string{c.secret} }

// Notify 发送不期待响应的消息（通知）。
func (c *SSEConn) Notify(ctx context.Context, body []byte) error {
	c.touchClient()
	_, err := c.post(ctx, body, "")
	return err
}

// Call 发送带 id 的请求并等待流里 id 相同的响应，返回响应原文（result 或 error 都原样返回，不吞）。
func (c *SSEConn) Call(ctx context.Context, id json.RawMessage, body []byte) ([]byte, error) {
	c.touchClient()
	key, ok := IDKey(id)
	if !ok {
		return nil, Errorf(KindParse, "SSE 请求缺少有效的 JSON-RPC id")
	}
	ch := make(chan []byte, 1)
	c.mu.Lock()
	if c.err != nil {
		err := c.err
		c.mu.Unlock()
		return nil, err
	}
	if _, dup := c.pending[key]; dup {
		c.mu.Unlock()
		return nil, Errorf(KindParse, "SSE 会话内存在重复的 JSON-RPC id")
	}
	c.pending[key] = ch
	c.mu.Unlock()
	defer func() {
		c.mu.Lock()
		delete(c.pending, key)
		c.mu.Unlock()
	}()

	direct, err := c.post(ctx, body, key)
	if err != nil {
		return nil, err
	}
	if direct != nil { // 非标准上游：POST 直接返回了响应
		return direct, nil
	}
	select {
	case resp := <-ch:
		c.touch()
		return resp, nil
	case <-c.done:
		if e := c.streamErr(); e != nil {
			return nil, e
		}
		return nil, Errorf(KindStreamClosed, "上游 SSE 连接已断开")
	case <-ctx.Done():
		return nil, ClassifyDial(ctx.Err(), c.secret)
	}
}

// post 把 JSON-RPC 载荷 POST 到 endpoint。wantKey 非空时，若 POST 直接带回了该 id 的响应则返回之。
func (c *SSEConn) post(ctx context.Context, body []byte, wantKey string) ([]byte, error) {
	if !c.Alive() {
		if e := c.streamErr(); e != nil {
			return nil, e
		}
		return nil, Errorf(KindStreamClosed, "上游 SSE 连接已断开")
	}
	target := cloneURL(c.endpoint)
	StripCallerCredentials(target, c.cfg)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target.String(), bytes.NewReader(body))
	if err != nil {
		return nil, newRequestError(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	if pv, _ := c.protoVersion.Load().(string); pv != "" {
		req.Header.Set("MCP-Protocol-Version", pv)
	}
	ApplyCommon(req, c.cfg)
	if err := ApplyAuth(req, c.cfg, c.secret); err != nil {
		return nil, err
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, ClassifyDial(err, c.secrets()...)
	}
	defer resp.Body.Close()
	c.touch()
	rc, derr := decodedBody(resp)
	if derr != nil {
		return nil, derr
	}
	payload, tooLarge, rerr := readLimited(rc, c.limits.MaxBodyBytes)
	if rerr != nil {
		return nil, ClassifyDial(rerr, c.secrets()...)
	}
	if tooLarge {
		return nil, Errorf(KindCapacity, "上游 POST 响应超过容量上限")
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, ClassifyHTTPFailure(resp.StatusCode, resp.Header, payload, c.secrets()...)
	}
	if wantKey != "" && len(bytes.TrimSpace(payload)) > 0 {
		var env Envelope
		if json.Unmarshal(bytes.TrimSpace(payload), &env) == nil && env.Method == "" && (len(env.Result) > 0 || env.Error != nil) {
			if key, ok := IDKey(env.ID); ok && key == wantKey {
				return payload, nil
			}
		}
	}
	return nil, nil
}

// NewClosedSSEConnForTest 返回一个已关闭的空连接，仅供其它包的单元测试构造会话表条目。
func NewClosedSSEConnForTest() *SSEConn {
	c := &SSEConn{done: make(chan struct{}), pending: map[string]chan []byte{}, cancel: func() {}}
	c.touch()
	c.touchClient()
	c.fail(Errorf(KindStreamClosed, "test"))
	return c
}
