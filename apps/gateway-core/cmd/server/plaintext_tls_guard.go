package main

import (
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

// 现场 P3-9：客户端把地址写成 https://主机:8080/v1，而 8080 是明文 HTTP 端口。
// 客户端发来的是 TLS ClientHello，Go 的 http.Server 会把它当成一个畸形的 HTTP 请求：
// 有时静默等到读头超时，有时回一个没有任何说明的 400；各语言的 TLS 库随后只会报
// “wrong version number”“record layer failure”之类用户看不懂的错误。
//
// 这里在明文监听口上识别 TLS ClientHello，立即回一个带中文改法的 400 并关闭连接，同时在
// 服务端日志留一条带来源地址的提示（按时间窗口限流，避免被扫描器刷屏）。
//
// 设计约束：
//   - 识别发生在每个连接自己的第一次 Read 里，Accept 路径不做任何阻塞读取，
//     沉默的连接只占用它自己的 goroutine；
//   - 偷看到的字节会原样回放，普通 HTTP 请求的字节流不被改变；
//   - 只检查连接的前 3 个字节；通过检查后每次 Read 只多一次互斥锁判断；
//   - 不解析、不记录握手内容，日志里没有任何握手字节。

const (
	tlsRecordTypeHandshake  = 0x16
	tlsHandshakeClientHello = 0x01

	plaintextTLSReplyBody = "检测到 TLS 握手数据，但当前端口是明文 HTTP 端口，不支持 HTTPS。\n" +
		"请把客户端地址里的 https:// 改成 http://（例如 http://主机:端口），或改用网关提供的 HTTPS 入口端口。\n" +
		"另外请注意：Anthropic 协议客户端（如 Claude Code）的地址不要带 /v1，OpenAI 协议客户端的地址只带一层 /v1。\n"

	plaintextTLSLogInterval = time.Minute
	plaintextTLSPeekBytes   = 512
)

// looksLikeTLSClientHello 判断数据开头是否是 TLS/SSL 握手记录：
// 记录类型 0x16（握手）、主版本 3、次版本 0 到 4；若已读到第 6 个字节，还要求握手类型是 ClientHello。
func looksLikeTLSClientHello(data []byte) bool {
	if len(data) < 3 {
		return false
	}
	if data[0] != tlsRecordTypeHandshake || data[1] != 0x03 || data[2] > 0x04 {
		return false
	}
	if len(data) >= 6 && data[5] != tlsHandshakeClientHello {
		return false
	}
	return true
}

type plaintextTLSGuard struct {
	logf     func(format string, args ...any)
	interval time.Duration
	now      func() time.Time

	mu         sync.Mutex
	lastLogged time.Time
	suppressed int
}

func newPlaintextTLSGuard(logf func(format string, args ...any)) *plaintextTLSGuard {
	if logf == nil {
		logf = log.Printf
	}
	return &plaintextTLSGuard{logf: logf, interval: plaintextTLSLogInterval, now: time.Now}
}

// Wrap 返回带 TLS 识别的监听器；Accept 本身不做任何网络读取。
func (g *plaintextTLSGuard) Wrap(listener net.Listener) net.Listener {
	return &plaintextTLSListener{Listener: listener, guard: g}
}

// report 记录一条提示；同一窗口内只记第一条，窗口结束后的下一条会带上被抑制的次数。
func (g *plaintextTLSGuard) report(conn net.Conn) {
	g.mu.Lock()
	now := g.now()
	if !g.lastLogged.IsZero() && now.Sub(g.lastLogged) < g.interval {
		g.suppressed++
		g.mu.Unlock()
		return
	}
	suppressed := g.suppressed
	g.suppressed = 0
	g.lastLogged = now
	g.mu.Unlock()

	remote, local := "未知来源", "未知端口"
	if addr := conn.RemoteAddr(); addr != nil {
		remote = addr.String()
	}
	if addr := conn.LocalAddr(); addr != nil {
		if _, port, err := net.SplitHostPort(addr.String()); err == nil {
			local = ":" + port
		} else {
			local = addr.String()
		}
	}
	line := fmt.Sprintf("[client-hint] 来自 %s 的连接发来了 TLS 握手数据，但监听端口 %s 是明文 HTTP 端口。"+
		"请让客户端把 https:// 改成 http://，或改用 HTTPS 入口端口；Base URL 也不要重复写 /v1。", remote, local)
	if suppressed > 0 {
		line += fmt.Sprintf("（上一提示窗口内已抑制同类提示 %d 次）", suppressed)
	}
	g.logf("%s", line)
}

type plaintextTLSListener struct {
	net.Listener
	guard *plaintextTLSGuard
}

func (l *plaintextTLSListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return &plaintextTLSConn{Conn: conn, guard: l.guard}, nil
}

type plaintextTLSConn struct {
	net.Conn
	guard *plaintextTLSGuard

	mu      sync.Mutex
	checked bool
	pending []byte
}

func (c *plaintextTLSConn) Read(p []byte) (int, error) {
	c.mu.Lock()
	if c.checked {
		if len(c.pending) > 0 {
			n := copy(p, c.pending)
			c.pending = c.pending[n:]
			if len(c.pending) == 0 {
				c.pending = nil
			}
			c.mu.Unlock()
			return n, nil
		}
		c.mu.Unlock()
		return c.Conn.Read(p)
	}
	defer c.mu.Unlock()

	// 首次读取：只要第一个字节不是 0x16 就一定不是 TLS，立即放行；
	// 是 0x16 时最多再等到 3 个字节（读超时由 http.Server 的 ReadHeaderTimeout 控制）。
	buf := make([]byte, plaintextTLSPeekBytes)
	n, err := c.Conn.Read(buf)
	for err == nil && n > 0 && n < 3 && buf[0] == tlsRecordTypeHandshake {
		var more int
		more, err = c.Conn.Read(buf[n:])
		n += more
	}
	if n > 0 && looksLikeTLSClientHello(buf[:n]) {
		c.checked = true
		c.replyAndClose()
		return 0, io.EOF
	}
	c.checked = true
	c.pending = buf[:n]
	if err != nil && n > 0 {
		// 把已读到的字节先交给调用方，错误留到下一次 Read 由底层连接重新报告。
		err = nil
	}
	if n == 0 {
		return 0, err
	}
	copied := copy(p, c.pending)
	c.pending = c.pending[copied:]
	if len(c.pending) == 0 {
		c.pending = nil
	}
	return copied, err
}

// CloseWrite 透传给底层 TCP 连接：http.Server 关闭连接时用它做优雅半关闭，
// 包装后若丢失该方法，普通连接的关闭行为会与改动前不同。
func (c *plaintextTLSConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}

func (c *plaintextTLSConn) replyAndClose() {
	c.guard.report(c.Conn)
	body := plaintextTLSReplyBody
	var reply strings.Builder
	reply.WriteString("HTTP/1.1 400 Bad Request\r\n")
	reply.WriteString("Content-Type: text/plain; charset=utf-8\r\n")
	reply.WriteString("Cache-Control: no-store\r\n")
	reply.WriteString("X-Content-Type-Options: nosniff\r\n")
	reply.WriteString("Connection: close\r\n")
	reply.WriteString("Content-Length: " + strconv.Itoa(len(body)) + "\r\n\r\n")
	reply.WriteString(body)

	_ = c.Conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
	_, _ = io.WriteString(c.Conn, reply.String())
	// 先半关闭写端再短暂排空对端剩余的握手字节，避免带着未读数据直接 close 触发 RST，
	// 把刚写出的回应从对端接收缓冲区里冲掉。
	if tcp, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		_ = tcp.CloseWrite()
	}
	_ = c.Conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	_, _ = io.Copy(io.Discard, io.LimitReader(c.Conn, 64<<10))
	_ = c.Conn.Close()
}

// listenGateway 创建网关模型 API 的明文监听器，并加上 TLS 握手识别。
func listenGateway(addr string) (net.Listener, error) {
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	return newPlaintextTLSGuard(log.Printf).Wrap(listener), nil
}
