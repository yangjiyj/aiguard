package handler

// 旧 HTTP+SSE 上游桥接。
//
// 下游（客户端）始终用 Streamable HTTP 与网关通信；当上游是旧 HTTP+SSE（transport=sse，或 auto 探测为 sse）时，
// 网关在“转发上游”这一步做协议转换，其余安全链路（六元组权限、红线、tools/call 拦截、HITL 确认、
// 审计、tools/list 过滤、工具结果检测）完全沿用原 HandlePost 流程，不做任何削弱。
//
// 会话模型：
//   - 下游 initialize：网关新建一条上游 SSE 连接，转发 initialize，并签发 Mcp-Session-Id（192 位随机）；
//   - 带 Mcp-Session-Id 的后续请求：按 (租户, serverID, 主体, 会话id) 取连接转发，会话不属于该主体一律按不存在（404）；
//   - 无会话且非 initialize 的请求（无状态调用、审批后重放）：建临时上游会话，握手→执行→立即关闭；
//   - 会话空闲超时回收、并发会话上限、上游断流映射为错误；下游 DELETE 关闭上游流。

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/auth"
	"github.com/yangjiyj/aiguard/packages/shared-go/mcpprotocol"
	"github.com/yangjiyj/aiguard/packages/shared-go/mcpupstream"
	"github.com/yangjiyj/aiguard/packages/shared-go/secrets"
	"golang.org/x/net/http/httpguts"
)

const (
	// mcpSSEBridgeMaxSessions 是单个网关进程内并发上游 SSE 会话（含临时会话）上限。
	mcpSSEBridgeMaxSessions = 256
	// mcpSSEBridgeMaxSessionsPerPrincipal 限制单个主体的并发会话，防止一个调用方占满全局额度。
	mcpSSEBridgeMaxSessionsPerPrincipal = 16
	// mcpSSEBridgeIdleTimeout 是会话空闲回收时间。
	mcpSSEBridgeIdleTimeout = 5 * time.Minute
	// mcpSSEBridgeReapInterval 是回收扫描间隔。
	mcpSSEBridgeReapInterval = 30 * time.Second
	// mcpSSEBridgeCallTimeout 是单次上游请求等待响应的时长上限（上游 SSE 流里取回结果）。
	mcpSSEBridgeCallTimeout = 120 * time.Second
	// mcpSSEBridgeMaxLifetime 是会话最大存活时长：即使下游持续有活动也会被回收，
	// 防止长期会话固化过期的鉴权配置，也给“上游状态漂移”设置上界。
	mcpSSEBridgeMaxLifetime = 30 * time.Minute
	// mcpSSEBridgeDialTimeout 是建立上游连接（GET 流 + endpoint 事件 + initialize）的时长上限。
	mcpSSEBridgeDialTimeout = 20 * time.Second
)

var (
	errMCPSSEBridgeCapacity = errors.New("MCP 旧版 SSE 桥接并发会话已达上限")
	errMCPSSESessionMissing = errors.New("MCP 会话不存在或已过期")
)

// mcpBridgeSession 是一条下游会话对应的上游 SSE 连接。
type mcpBridgeSession struct {
	id        string
	tenantID  string
	serverID  string
	principal string
	routeHash string // 创建时的 server 路由指纹；server 配置变更后旧会话作废
	conn      *mcpupstream.SSEConn
	// protocol 是网关生效的协议版本（Effective，恒在支持列表内）；protocolRaw 是上游原始声明。
	protocol    string
	protocolRaw string
	createdAt   time.Time
	// sem 串行化同一会话内的上游请求：旧 SSE 的响应靠 id 关联，串行可保持请求/响应顺序，
	// 也避免客户端并发请求耗尽上游。用带缓冲 channel 而不是 sync.Mutex，排队期间可响应 ctx 取消。
	sem     chan struct{}
	semOnce sync.Once
}

func (s *mcpBridgeSession) initSem() { s.semOnce.Do(func() { s.sem = make(chan struct{}, 1) }) }

// lock 获取会话调用锁；排队期间 ctx 取消会立即返回 false（不持有锁）。
func (s *mcpBridgeSession) lock(ctx context.Context) bool {
	s.initSem()
	select {
	case s.sem <- struct{}{}:
		return true
	case <-ctx.Done():
		return false
	}
}

func (s *mcpBridgeSession) unlock() { <-s.sem }

type mcpSSEBridge struct {
	mu       sync.Mutex
	sessions map[string]*mcpBridgeSession
	// temp 统计临时会话数（只占并发额度，不入表）。
	temp         int
	perPrincipal map[string]int
	maxSessions  int
	maxPerPrin   int
	idleTimeout  time.Duration
	maxLifetime  time.Duration
	stop         chan struct{}
	stopOnce     sync.Once
	reapOnce     sync.Once
}

func newMCPSSEBridge() *mcpSSEBridge {
	return &mcpSSEBridge{
		sessions: map[string]*mcpBridgeSession{}, perPrincipal: map[string]int{},
		maxSessions: mcpSSEBridgeMaxSessions, maxPerPrin: mcpSSEBridgeMaxSessionsPerPrincipal,
		idleTimeout: mcpSSEBridgeIdleTimeout, maxLifetime: mcpSSEBridgeMaxLifetime, stop: make(chan struct{}),
	}
}

// Close 关闭旧 SSE 桥接的全部上游会话并停止回收协程（进程优雅关停时调用）。
func (h *MCPProxyHandler) Close() {
	if h != nil {
		h.sseBridge.Close()
	}
}

// Close 关闭全部上游会话并停止回收协程（进程退出 / 测试清理用）。
func (b *mcpSSEBridge) Close() {
	if b == nil {
		return
	}
	b.stopOnce.Do(func() { close(b.stop) })
	b.mu.Lock()
	sessions := b.sessions
	b.sessions = map[string]*mcpBridgeSession{}
	b.perPrincipal = map[string]int{}
	b.mu.Unlock()
	for _, s := range sessions {
		s.conn.Close()
	}
}

// ensureReaper 懒启动空闲回收协程。
func (b *mcpSSEBridge) ensureReaper() {
	b.reapOnce.Do(func() {
		go func() {
			t := time.NewTicker(mcpSSEBridgeReapInterval)
			defer t.Stop()
			for {
				select {
				case <-t.C:
					b.reap(time.Now())
				case <-b.stop:
					return
				}
			}
		}()
	})
}

// reap 回收空闲超时或上游已断开的会话，返回回收数量。
func (b *mcpSSEBridge) reap(now time.Time) int {
	b.mu.Lock()
	var dead []*mcpBridgeSession
	for id, s := range b.sessions {
		// 空闲只看下游发起的活动（LastClientActive）；上游心跳/事件不能续命。
		if !s.conn.Alive() || now.Sub(s.conn.LastClientActive()) > b.idleTimeout ||
			(b.maxLifetime > 0 && now.Sub(s.createdAt) > b.maxLifetime) {
			dead = append(dead, s)
			delete(b.sessions, id)
			b.releasePrincipalLocked(s.principal)
		}
	}
	b.mu.Unlock()
	for _, s := range dead {
		s.conn.Close()
	}
	return len(dead)
}

func (b *mcpSSEBridge) releasePrincipalLocked(p string) {
	if b.perPrincipal[p] > 0 {
		b.perPrincipal[p]--
	}
	if b.perPrincipal[p] == 0 {
		delete(b.perPrincipal, p)
	}
}

// mcpQuotaToken 是预占的并发额度凭证，带状态，保证每一项额度只归还一次：
//   - 预占阶段：同时占用全局 temp 与 perPrincipal 各一项；Release 同时归还这两项；
//   - 转正（register）之后：额度由会话表持有，Release 变为空操作，改由 remove/reap/Close 归还。
type mcpQuotaToken struct {
	b         *mcpSSEBridge
	principal string
	mu        sync.Mutex
	state     int // 0=预占中 1=已转正 2=已归还
}

// Release 归还预占阶段的额度；已转正或已归还时无副作用（幂等）。
func (t *mcpQuotaToken) Release() {
	if t == nil {
		return
	}
	t.mu.Lock()
	if t.state != 0 {
		t.mu.Unlock()
		return
	}
	t.state = 2
	t.mu.Unlock()
	t.b.mu.Lock()
	t.b.temp--
	t.b.releasePrincipalLocked(t.principal)
	t.b.mu.Unlock()
}

// quotaInUse 返回正在占用的全局额度（预占中的临时会话 + 已登记会话）。
func (b *mcpSSEBridge) quotaInUse() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.temp + len(b.sessions)
}

// principalQuotaInUse 返回某主体占用的额度。
func (b *mcpSSEBridge) principalQuotaInUse(principal string) int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.perPrincipal[principal]
}

// reserve 预占一个并发额度；失败路径必须调用 token.Release()，成功建立会话后调用 register 转正。
func (b *mcpSSEBridge) reserve(principal string) (*mcpQuotaToken, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.sessions)+b.temp >= b.maxSessions || b.perPrincipal[principal] >= b.maxPerPrin {
		return nil, errMCPSSEBridgeCapacity
	}
	b.temp++
	b.perPrincipal[principal]++
	return &mcpQuotaToken{b: b, principal: principal}, nil
}

// register 把已建立的会话入表：额度由“预占”转为“会话表持有”（perPrincipal 不变，temp 减一），返回会话 id。
// 会话 id 生成失败时返回错误，额度保持预占状态，由调用方 Release。
func (b *mcpSSEBridge) register(s *mcpBridgeSession, tok *mcpQuotaToken) (string, error) {
	id, err := newMCPBridgeSessionID()
	if err != nil {
		return "", err
	}
	tok.mu.Lock()
	if tok.state != 0 {
		tok.mu.Unlock()
		return "", errors.New("MCP 额度凭证已失效")
	}
	tok.state = 1
	tok.mu.Unlock()
	b.mu.Lock()
	defer b.mu.Unlock()
	b.temp--
	s.id = id
	if s.createdAt.IsZero() {
		s.createdAt = time.Now()
	}
	b.sessions[id] = s
	return id, nil
}

// mcpBridgeRandRead 可在测试里替换，以验证随机数失败路径。
var mcpBridgeRandRead = rand.Read

func newMCPBridgeSessionID() (string, error) {
	raw := make([]byte, 24)
	if _, err := mcpBridgeRandRead(raw); err != nil {
		return "", fmt.Errorf("生成 MCP 会话 id 失败: %w", err)
	}
	return "mcpgw-" + base64.RawURLEncoding.EncodeToString(raw), nil
}

// lookup 取会话；租户、server、主体任一不匹配都按不存在处理（不泄露他人会话是否存在，也绝不据此关闭别人的会话）。
// 归属匹配但路由指纹已变化（管理员改了地址 / 密钥 / 鉴权配置）时，立即关闭该会话的上游连接并归还额度，
// 旧会话 id 此后一律按不存在处理——不等空闲回收，旧配置下建立的上游连接不再继续使用。
func (b *mcpSSEBridge) lookup(id, tenantID, serverID, principal, routeHash string) *mcpBridgeSession {
	b.mu.Lock()
	s := b.sessions[id]
	if s == nil || s.tenantID != tenantID || s.serverID != serverID || s.principal != principal {
		b.mu.Unlock()
		return nil
	}
	if s.routeHash != routeHash {
		delete(b.sessions, id)
		b.releasePrincipalLocked(s.principal)
		b.mu.Unlock()
		s.conn.Close()
		return nil
	}
	b.mu.Unlock()
	return s
}

// remove 关闭并移除会话；返回是否存在。
func (b *mcpSSEBridge) remove(id, tenantID, serverID, principal string) bool {
	b.mu.Lock()
	s := b.sessions[id]
	if s == nil || s.tenantID != tenantID || s.serverID != serverID || s.principal != principal {
		b.mu.Unlock()
		return false
	}
	delete(b.sessions, id)
	b.releasePrincipalLocked(s.principal)
	b.mu.Unlock()
	s.conn.Close()
	return true
}

// openSessions 返回当前会话数（测试与观测用）。
func (b *mcpSSEBridge) openSessions() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.sessions)
}

// mcpBridgePrincipal 把调用主体归一为会话归属键：同一把 key 的同一用户才能复用会话。
func mcpBridgePrincipal(info *auth.AuthInfo) string {
	if info == nil {
		return ""
	}
	return info.KeyID + "\x1f" + info.UserID + "\x1f" + info.ProjectID
}

// dialMCPSSEUpstream 为 server 建立一条已握手的上游 SSE 连接。密钥只在此处解密、注入，
// 不进入日志与错误。
func (h *MCPProxyHandler) dialMCPSSEUpstream(ctx context.Context, server *mcpServerRoute) (*mcpupstream.SSEConn, error) {
	cfg, err := server.upstreamConfig()
	if err != nil {
		return nil, errMCPUpstreamCredential
	}
	var secret string
	if strings.TrimSpace(server.AuthCiphertext) != "" {
		secret, err = secrets.DecryptProviderSecret(server.AuthCiphertext)
		if err != nil || secret == "" {
			return nil, errMCPUpstreamCredential
		}
	}
	client, target, err := h.resolveUpstreamClient(ctx, server, nil)
	if err != nil {
		return nil, fmt.Errorf("%s", mcpupstream.RedactText(err.Error(), secret))
	}
	dialCtx, cancel := context.WithTimeout(ctx, mcpSSEBridgeDialTimeout)
	defer cancel()
	conn, err := mcpupstream.DialSSE(dialCtx, mcpupstream.SSEOptions{
		URL: target, Config: cfg, Secret: secret, Client: client,
		EndpointTimeout: 10 * time.Second,
		Limits: mcpupstream.Limits{
			MaxEventBytes: maxMCPSSEEventBytes, MaxStreamBytes: maxMCPSSECumulativeBytes, MaxBodyBytes: maxMCPNonStreamingResponseBytes,
		},
	})
	if err != nil {
		return nil, err
	}
	return conn, nil
}

// mcpNotForwardedHeader 是历史上用来标记“未转发”的内部响应头名。标记现在不再放在 HTTP 头上
// （Streamable 上游可以伪造任何响应头）；这个常量只用于在入口剥掉上游响应里的同名头（纵深防御）。
const mcpNotForwardedHeader = "X-Jjd-Mcp-Not-Forwarded"

// mcpNotForwardedBody 把合成响应的 Body 包装成带私有类型的 ReadCloser：只有网关自己构造的“未转发”
// 合成响应才会带这个类型，上游无法伪造——它不是 HTTP 头，也不是任何网络上能传递的东西。
type mcpNotForwardedBody struct{ io.ReadCloser }

// mcpResponseNotForwarded 报告该响应是否是桥接合成的“未转发”响应（请求没有到达上游）。
func mcpResponseNotForwarded(resp *http.Response) bool {
	if resp == nil {
		return false
	}
	_, ok := resp.Body.(*mcpNotForwardedBody)
	return ok
}

// mcpStripInternalHeaders 删除内部标记头：写给下游前清理，并在 Streamable 入口清理上游响应里的同名头。
func mcpStripInternalHeaders(h http.Header) { h.Del(mcpNotForwardedHeader) }

// mcpSyntheticResponse 把上游 SSE 里取回的 JSON-RPC 响应包装成 Streamable 风格的 JSON 响应，
// 这样 HandlePost 之后的结果检测 / 改写 / 审计代码路径无需任何改动。
func mcpSyntheticResponse(status int, body []byte, sessionID string) *http.Response {
	h := http.Header{}
	h.Set("Content-Type", "application/json")
	if sessionID != "" {
		h.Set("Mcp-Session-Id", sessionID)
	}
	return &http.Response{
		StatusCode: status, Status: fmt.Sprintf("%d %s", status, http.StatusText(status)),
		Header: h, Body: io.NopCloser(bytes.NewReader(body)), ContentLength: int64(len(body)),
	}
}

// mcpNotificationFailureResponse 是桥接对「上游明确拒绝了通知」的合成响应。请求已到达上游（不是 not-forwarded），
// 所以不带未转发标记；审计按 failed 记录。
func mcpNotificationFailureResponse(status int, sessionID string) *http.Response {
	message := "MCP 上游拒绝了通知（通知无需响应体）"
	if status == http.StatusBadGateway {
		message = "MCP 通知投递失败（上游返回错误）"
	}
	body := `{"error":{"code":"mcp_notification_not_delivered","message":"` + message + `"}}`
	return mcpSyntheticResponse(status, []byte(body), sessionID)
}

// mcpNotForwardedResponse 构造“未转发”的合成错误响应（带内部标记）。
func mcpNotForwardedResponse(status int, body string) *http.Response {
	r := mcpSyntheticResponse(status, []byte(body), "")
	r.Body = &mcpNotForwardedBody{ReadCloser: r.Body}
	return r
}

func mcpEmptyResponse(status int, sessionID string) *http.Response {
	r := mcpSyntheticResponse(status, nil, sessionID)
	r.Header.Del("Content-Type")
	return r
}

// mcpNotForwardedResponseAfterForward 用于「请求其实已到达上游、但网关出于自身原因不能把结果交给客户端」的情形
// （例如会话登记表已满）。它仍用同一个私有 Body 类型标记，审计按 failed 记录。
func mcpNotForwardedResponseAfterForward(status int, body string) *http.Response {
	return mcpNotForwardedResponse(status, body)
}

func mcpNotForwardedEmpty(status int) *http.Response {
	r := mcpEmptyResponse(status, "")
	r.Body = &mcpNotForwardedBody{ReadCloser: r.Body}
	return r
}

const (
	mcpBridgeCapacityBody  = `{"error":{"code":"mcp_bridge_capacity","message":"MCP 旧版 SSE 桥接并发会话已达上限，请稍后重试"}}`
	mcpBridgeNoSessionBody = `{"error":{"code":"mcp_session_not_found","message":"MCP 会话不存在或已过期，请重新 initialize"}}`
)

// mcpReplayContextKey 标记“HITL 审批后重放”的转发：重放不复用下游会话，强制走临时上游会话，
// 额度按 replay 记录里的真实主体计，而不是空主体。
type mcpReplayContextKey struct{}

type mcpReplayPrincipal struct{ principal string }

func withMCPReplayPrincipal(ctx context.Context, principal string) context.Context {
	return context.WithValue(ctx, mcpReplayContextKey{}, mcpReplayPrincipal{principal: principal})
}

// mcpBridgePrincipalKey 由租户、key、用户、项目、agent 组成会话归属键。
func mcpBridgePrincipalKey(tenantID, keyID, userID, projectID string) string {
	return tenantID + "\x1f" + keyID + "\x1f" + userID + "\x1f" + projectID
}

// forwardMCPViaSSEBridge 是 forwardMCPUpstream 在旧 SSE 上游下的实现。
// 返回的 *http.Response 是合成的：成功时为 200 + application/json（或通知的 202）；
// 请求未到达上游的合成响应带 mcpNotForwardedHeader 标记。
func (h *MCPProxyHandler) forwardMCPViaSSEBridge(ctx context.Context, server *mcpServerRoute, r *http.Request, body []byte) (*http.Response, *url.URL, error) {
	if h.sseBridge == nil {
		return nil, nil, errors.New("MCP 旧版 SSE 桥接未初始化")
	}
	h.sseBridge.ensureReaper()
	info := auth.GetAuthInfo(r)
	principal := mcpBridgePrincipal(info)
	replay, isReplay := ctx.Value(mcpReplayContextKey{}).(mcpReplayPrincipal)
	if isReplay {
		principal = replay.principal
	}
	targetURL, _ := url.Parse(server.ServerURL)

	switch r.Method {
	case http.MethodGet:
		// 旧 SSE 没有“GET 长流承载服务端通知”的 Streamable 语义；明确按 405 告知下游。
		return mcpNotForwardedEmpty(http.StatusMethodNotAllowed), targetURL, nil
	case http.MethodDelete:
		return h.bridgeDelete(r, server, principal), targetURL, nil
	case http.MethodPost:
	default:
		return mcpNotForwardedEmpty(http.StatusMethodNotAllowed), targetURL, nil
	}

	var msg struct {
		ID     json.RawMessage `json:"id"`
		Method string          `json:"method"`
	}
	_ = json.Unmarshal(body, &msg)
	isRequest := len(bytes.TrimSpace(msg.ID)) > 0 && string(bytes.TrimSpace(msg.ID)) != "null"
	sessionID := strings.TrimSpace(r.Header.Get("Mcp-Session-Id"))
	if isReplay {
		sessionID = "" // 重放不复用下游会话：强制临时上游会话
	}

	switch {
	case msg.Method == "initialize":
		return h.bridgeInitialize(ctx, server, body, msg.ID, principal, targetURL)
	case sessionID != "":
		sess := h.sseBridge.lookup(sessionID, server.TenantID, server.ID, principal, server.RouteHash)
		if sess == nil {
			return mcpNotForwardedResponse(http.StatusNotFound, mcpBridgeNoSessionBody), targetURL, nil
		}
		return h.bridgeSend(ctx, sess, body, msg.ID, isRequest, sessionID, targetURL)
	default:
		return h.bridgeEphemeral(ctx, server, body, msg.ID, isRequest, principal, targetURL)
	}
}

// bridgeInitialize 为下游 initialize 新建上游会话。协议版本统一经 mcpprotocol.Negotiate：
// 返回给下游的 protocolVersion 改写为网关生效版本（Effective），原始值另存于会话。
func (h *MCPProxyHandler) bridgeInitialize(ctx context.Context, server *mcpServerRoute, body []byte, id json.RawMessage, principal string, targetURL *url.URL) (*http.Response, *url.URL, error) {
	tok, err := h.sseBridge.reserve(principal)
	if err != nil {
		return mcpNotForwardedResponse(http.StatusServiceUnavailable, mcpBridgeCapacityBody), targetURL, nil
	}
	// 任何失败路径都归还预占额度；register 成功后 Release 变为空操作。
	defer tok.Release()
	conn, err := h.dialMCPSSEUpstream(ctx, server)
	if err != nil {
		return nil, targetURL, err
	}
	sess := &mcpBridgeSession{tenantID: server.TenantID, serverID: server.ID, principal: principal, routeHash: server.RouteHash, conn: conn, createdAt: time.Now()}
	if !sess.lock(ctx) {
		conn.Close()
		return nil, targetURL, ctx.Err()
	}
	raw, callErr := h.bridgeCallLocked(ctx, sess, id, body)
	sess.unlock()
	if callErr != nil {
		conn.Close()
		return nil, targetURL, callErr
	}
	var env struct {
		Result map[string]json.RawMessage `json:"result"`
		Error  json.RawMessage            `json:"error"`
	}
	_ = json.Unmarshal(raw, &env)
	if len(env.Error) > 0 {
		// 上游对 initialize 回 JSON-RPC error：原样返回，不建会话。
		conn.Close()
		return mcpSyntheticResponse(http.StatusOK, raw, ""), targetURL, nil
	}
	var rawVersion string
	if v, ok := env.Result["protocolVersion"]; ok {
		_ = json.Unmarshal(v, &rawVersion)
	}
	neg, negErr := mcpprotocol.Negotiate(rawVersion)
	if negErr != nil {
		conn.Close()
		return nil, targetURL, &mcpupstream.Error{Kind: mcpupstream.KindProtocolVersion, Message: negErr.Error(), Cause: negErr}
	}
	if neg.Forward {
		log.Printf("MCP 桥接: 上游协议版本 %s 晚于已知最新版本，已前向兼容按 %s 处理 server=%s", neg.Raw, neg.Effective, server.ID)
		// 返回给下游的 protocolVersion 改写为生效版本，避免下游按未知版本协商。
		if rewritten := mcpRewriteInitializeVersion(raw, neg.Effective); rewritten != nil {
			raw = rewritten
		}
	}
	sess.protocol, sess.protocolRaw = neg.Effective, neg.Raw
	conn.SetProtocolVersion(neg.Effective)
	sessionID, regErr := h.sseBridge.register(sess, tok)
	if regErr != nil {
		conn.Close()
		return nil, targetURL, regErr
	}
	return mcpSyntheticResponse(http.StatusOK, raw, sessionID), targetURL, nil
}

// mcpRewriteInitializeVersion 把 initialize 结果里的 protocolVersion 改写为 version；失败返回 nil。
func mcpRewriteInitializeVersion(raw []byte, version string) []byte {
	var doc map[string]json.RawMessage
	if json.Unmarshal(raw, &doc) != nil {
		return nil
	}
	var result map[string]json.RawMessage
	if json.Unmarshal(doc["result"], &result) != nil {
		return nil
	}
	v, _ := json.Marshal(version)
	result["protocolVersion"] = v
	r, err := json.Marshal(result)
	if err != nil {
		return nil
	}
	doc["result"] = r
	out, err := json.Marshal(doc)
	if err != nil {
		return nil
	}
	return out
}

func (h *MCPProxyHandler) bridgeSend(ctx context.Context, sess *mcpBridgeSession, body []byte, id json.RawMessage, isRequest bool, sessionID string, targetURL *url.URL) (*http.Response, *url.URL, error) {
	if !sess.conn.Alive() {
		h.sseBridge.remove(sess.id, sess.tenantID, sess.serverID, sess.principal)
		return mcpNotForwardedResponse(http.StatusNotFound, `{"error":{"code":"mcp_session_not_found","message":"上游 SSE 连接已断开，会话已失效，请重新 initialize"}}`), targetURL, nil
	}
	// 排队等锁期间客户端断开要立即退出（不持有锁、不向上游发请求）。
	if !sess.lock(ctx) {
		return nil, targetURL, ctx.Err()
	}
	defer sess.unlock()
	if !isRequest { // 通知：POST 后返回 202
		callCtx, cancel := context.WithTimeout(ctx, mcpSSEBridgeCallTimeout)
		defer cancel()
		if err := sess.conn.Notify(callCtx, body); err != nil {
			// R2：通知投递失败不当作「上游不可达」的笼统错误：上游给了明确的 HTTP 状态就按通知规则映射（4xx 透传、
			// 5xx → 502），body 是固定的脱敏 JSON；传输层错误（断连、超时）仍走原有错误路径。
			var ue *mcpupstream.Error
			if errors.As(err, &ue) && ue.HTTPStatus >= 400 {
				return mcpNotificationFailureResponse(mcpNotificationDownstreamStatus(ue.HTTPStatus), sessionID), targetURL, nil
			}
			return nil, targetURL, err
		}
		return mcpEmptyResponse(http.StatusAccepted, sessionID), targetURL, nil
	}
	raw, err := h.bridgeCallLocked(ctx, sess, id, body)
	if err != nil {
		return nil, targetURL, err
	}
	return mcpSyntheticResponse(http.StatusOK, raw, sessionID), targetURL, nil
}

// bridgeEphemeral 处理无会话且非 initialize 的请求（含 HITL 重放）：临时建连、握手、执行、关闭。
func (h *MCPProxyHandler) bridgeEphemeral(ctx context.Context, server *mcpServerRoute, body []byte, id json.RawMessage, isRequest bool, principal string, targetURL *url.URL) (*http.Response, *url.URL, error) {
	tok, err := h.sseBridge.reserve(principal)
	if err != nil {
		return mcpNotForwardedResponse(http.StatusServiceUnavailable, mcpBridgeCapacityBody), targetURL, nil
	}
	defer tok.Release() // 临时会话永不转正，退出时一次性归还 temp 与 perPrincipal
	conn, err := h.dialMCPSSEUpstream(ctx, server)
	if err != nil {
		return nil, targetURL, err
	}
	defer conn.Close()
	hsCtx, cancel := context.WithTimeout(ctx, mcpSSEBridgeDialTimeout)
	defer cancel()
	if _, err := mcpupstream.HandshakeSSE(hsCtx, conn, map[string]interface{}{"name": "jjdguard-mcp-gateway", "version": "1.0"}, false); err != nil {
		return nil, targetURL, err
	}
	sess := &mcpBridgeSession{tenantID: server.TenantID, serverID: server.ID, principal: principal, conn: conn, createdAt: time.Now()}
	if !sess.lock(ctx) {
		return nil, targetURL, ctx.Err()
	}
	defer sess.unlock()
	if !isRequest {
		if err := conn.Notify(ctx, body); err != nil {
			return nil, targetURL, err
		}
		return mcpEmptyResponse(http.StatusAccepted, ""), targetURL, nil
	}
	raw, err := h.bridgeCallLocked(ctx, sess, id, body)
	if err != nil {
		return nil, targetURL, err
	}
	return mcpSyntheticResponse(http.StatusOK, raw, ""), targetURL, nil
}

func (h *MCPProxyHandler) bridgeCallLocked(ctx context.Context, sess *mcpBridgeSession, id json.RawMessage, body []byte) ([]byte, error) {
	callCtx, cancel := context.WithTimeout(ctx, mcpSSEBridgeCallTimeout)
	defer cancel()
	raw, err := sess.conn.Call(callCtx, id, body)
	if err != nil {
		return nil, err
	}
	// 上游响应走与 Streamable 非流式同一个容量与合法性校验。
	if int64(len(raw)) > maxMCPNonStreamingResponseBytes {
		return nil, errMCPResponseTooLarge
	}
	if err := validateMCPJSONResponse(raw); err != nil {
		return nil, err
	}
	return raw, nil
}

// bridgeDelete 关闭下游会话并同步关闭上游 SSE 流。
func (h *MCPProxyHandler) bridgeDelete(r *http.Request, server *mcpServerRoute, principal string) *http.Response {
	sessionID := strings.TrimSpace(r.Header.Get("Mcp-Session-Id"))
	if sessionID == "" || h.sseBridge.lookup(sessionID, server.TenantID, server.ID, principal, server.RouteHash) == nil {
		return mcpNotForwardedResponse(http.StatusNotFound, `{"error":{"code":"mcp_session_not_found","message":"MCP 会话不存在或已过期"}}`)
	}
	h.sseBridge.remove(sessionID, server.TenantID, server.ID, principal)
	return mcpEmptyResponse(http.StatusNoContent, "")
}

// mcpBridgeErrorMessage 把桥接过程中的上游错误映射为面向下游的中文提示（不含密钥与 URL query）。
func mcpBridgeErrorMessage(err error) string {
	var rpc *mcpupstream.RPCError
	switch {
	case errors.Is(err, errMCPUpstreamCredential):
		return "MCP 上游鉴权凭据不可用"
	case errors.As(err, &rpc):
		return "MCP 上游返回错误"
	}
	switch mcpupstream.KindOf(err) {
	case mcpupstream.KindStreamClosed:
		return "MCP 上游 SSE 连接已断开，请重新 initialize"
	case mcpupstream.KindTimeout:
		return "MCP 上游响应超时"
	case mcpupstream.KindCrossOrigin:
		return "MCP 上游消息端点与服务地址不同源，已按 SSRF 防护拒绝"
	case mcpupstream.KindCapacity:
		return "MCP 上游响应超过容量上限"
	case mcpupstream.KindHTTP429:
		return "MCP 上游限流，请稍后重试"
	case mcpupstream.KindHTTP401, mcpupstream.KindHTTP403:
		return "MCP 上游鉴权失败，请联系管理员检查该服务的鉴权配置"
	case mcpupstream.KindOAuth:
		return "MCP 上游要求 OAuth 授权，网关当前不支持"
	}
	return "MCP 上游服务不可达"
}

// writeMCPForwardError 把转发上游失败写给下游。仅对 mcpupstream 分类过的错误（旧 SSE 桥接路径）
// 给出更具体的中文原因，并透传限流的 Retry-After；其余（Streamable 直连）保持原有统一文案不变。
func writeMCPForwardError(w http.ResponseWriter, err error) {
	// 压缩编码问题：给出明确的中文原因，而不是笼统的“服务不可达”。
	if errors.Is(err, errMCPUnsupportedEncoding) {
		writeMCPHTTPError(w, http.StatusBadGateway, errMCPUnsupportedEncoding.Error())
		return
	}
	if errors.Is(err, errMCPDecodedTooLarge) {
		writeMCPHTTPError(w, http.StatusBadGateway, errMCPDecodedTooLarge.Error())
		return
	}
	var ue *mcpupstream.Error
	if !errors.As(err, &ue) && !errors.Is(err, errMCPUpstreamCredential) {
		writeMCPHTTPError(w, http.StatusBadGateway, "MCP 上游服务不可达")
		return
	}
	status := http.StatusBadGateway
	if ue != nil {
		switch ue.Kind {
		case mcpupstream.KindHTTP429:
			status = http.StatusTooManyRequests
			if ue.RetryAfter != "" && httpguts.ValidHeaderFieldValue(ue.RetryAfter) {
				w.Header().Set("Retry-After", ue.RetryAfter)
			}
		case mcpupstream.KindTimeout:
			status = http.StatusGatewayTimeout
		}
	}
	writeMCPHTTPError(w, status, mcpBridgeErrorMessage(err))
}
