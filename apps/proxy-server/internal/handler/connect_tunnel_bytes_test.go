package handler

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// 不解密的 CONNECT 隧道留痕：隧道结束时把上/下行字节数和持续时长回写到建隧道时那一行，
// 让“谁往哪个站点传了多少数据”可查。不新增行，异常断开同样回写。

// TestRelayTunnelCountsBothDirections 不依赖数据库，验证双向计数与对拷语义。
func TestRelayTunnelCountsBothDirections(t *testing.T) {
	clientSide, proxyClient := net.Pipe()
	proxyTarget, targetSide := net.Pipe()
	upPayload := strings.Repeat("u", 3000)
	downPayload := strings.Repeat("d", 5000)

	go func() {
		buf := make([]byte, len(upPayload))
		if _, err := io.ReadFull(targetSide, buf); err != nil {
			return
		}
		_, _ = targetSide.Write([]byte(downPayload))
		_ = targetSide.Close()
	}()
	go func() {
		_, _ = clientSide.Write([]byte(upPayload))
		_, _ = io.Copy(io.Discard, clientSide)
		_ = clientSide.Close()
	}()

	stats := relayTunnel(proxyClient, proxyTarget, 5*time.Second)
	if stats.UpBytes != int64(len(upPayload)) || stats.DownBytes != int64(len(downPayload)) {
		t.Fatalf("上行=%d 下行=%d，期望 %d/%d", stats.UpBytes, stats.DownBytes, len(upPayload), len(downPayload))
	}
	if stats.Duration <= 0 {
		t.Fatalf("时长必须为正: %v", stats.Duration)
	}
}

// TestRelayTunnelStopsAtMaxDuration 验证超时上限仍返回已计数字节，不会挂住。
func TestRelayTunnelStopsAtMaxDuration(t *testing.T) {
	clientSide, proxyClient := net.Pipe()
	proxyTarget, targetSide := net.Pipe()
	defer clientSide.Close()
	defer targetSide.Close()
	go func() { _, _ = io.Copy(io.Discard, targetSide) }()
	go func() { _, _ = clientSide.Write([]byte("hello")) }()
	started := time.Now()
	stats := relayTunnel(proxyClient, proxyTarget, 200*time.Millisecond)
	if time.Since(started) > 3*time.Second {
		t.Fatalf("超时上限后必须及时返回: %v", time.Since(started))
	}
	if stats.UpBytes != 5 {
		t.Fatalf("超时前已传字节必须计入: %d", stats.UpBytes)
	}
}

func tunnelBytesTestDB(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("C_WHITELIST_TEST_DATABASE_URL")
	if dsn == "" {
		t.Fatal("C_WHITELIST_TEST_DATABASE_URL is required: use disposable PostgreSQL")
	}
	db, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	return db
}

// startBlindTunnel 建一条走直通的 CONNECT 隧道，返回客户端连接。
func startBlindTunnel(t *testing.T, db *pgxpool.Pool, host string, upstream net.Listener) net.Conn {
	t.Helper()
	t.Setenv("SECURITY_AUDIT_ONLY", "false")
	checker := newCheckerWithRules([]WhitelistRule{{HostPattern: host, Port: 443, TenantID: "tenant_default", AuditEnabled: true}})
	h := NewProxyHandler(checker, nil, nil, NewAuditWriter(db), nil)
	h.egressGuard = redirectGuard(upstream.Addr().String())
	server := httptest.NewServer(http.HandlerFunc(h.Handle))
	t.Cleanup(server.Close)
	parsed, _ := url.Parse(server.URL)
	conn, err := net.DialTimeout("tcp", parsed.Host, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	fmt.Fprintf(conn, "CONNECT %s:443 HTTP/1.1\r\nHost: %s:443\r\n\r\n", host, host)
	reader := bufio.NewReader(conn)
	line, err := reader.ReadString('\n')
	if err != nil || line != "HTTP/1.1 200 Connection Established\r\n" {
		t.Fatalf("line=%q err=%v", line, err)
	}
	if blank, err := reader.ReadString('\n'); err != nil || blank != "\r\n" {
		t.Fatalf("blank=%q err=%v", blank, err)
	}
	return conn
}

type tunnelRow struct {
	rows       int
	up, down   int64
	durationMS int64
}

// waitTunnelRow 轮询直到该 host 的行出现非零时长（隧道结束回写完成）或超时。
func waitTunnelRow(t *testing.T, db *pgxpool.Pool, host string) tunnelRow {
	t.Helper()
	deadline := time.Now().Add(8 * time.Second)
	var got tunnelRow
	for {
		err := db.QueryRow(context.Background(), `
			SELECT count(*), COALESCE(max(proxy_request_bytes),0), COALESCE(max(proxy_response_bytes),0), COALESCE(max(proxy_tunnel_duration_ms),0)
			FROM request_logs WHERE tenant_id='tenant_default' AND proxy_target_host=$1 AND proxy_method='CONNECT'`, host).
			Scan(&got.rows, &got.up, &got.down, &got.durationMS)
		if err != nil {
			t.Fatal(err)
		}
		if got.durationMS > 0 {
			return got
		}
		if time.Now().After(deadline) {
			t.Fatalf("隧道结束后必须回写时长: %+v", got)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestCWhitelistDatabaseBlindTunnelRecordsBytesAndDuration(t *testing.T) {
	db := tunnelBytesTestDB(t)
	host := "bytes-" + uuid.NewString()[:8] + ".blob.core.windows.net"
	upPayload := strings.Repeat("a", 7000)
	downPayload := strings.Repeat("b", 12345)
	upstream, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer upstream.Close()
	go func() {
		conn, err := upstream.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, len(upPayload))
		if _, err := io.ReadFull(conn, buf); err != nil {
			return
		}
		time.Sleep(150 * time.Millisecond)
		_, _ = conn.Write([]byte(downPayload))
	}()
	conn := startBlindTunnel(t, db, host, upstream)
	if _, err := conn.Write([]byte(upPayload)); err != nil {
		t.Fatal(err)
	}
	got, _ := io.ReadAll(conn)
	if len(got) != len(downPayload) {
		t.Fatalf("隧道下行内容被改变: %d", len(got))
	}
	conn.Close()

	row := waitTunnelRow(t, db, host)
	if row.rows != 1 {
		t.Fatalf("隧道结束必须更新同一行，不得新增: rows=%d", row.rows)
	}
	if row.up != int64(len(upPayload)) || row.down != int64(len(downPayload)) {
		t.Fatalf("上行=%d 下行=%d，期望 %d/%d", row.up, row.down, len(upPayload), len(downPayload))
	}
	if row.durationMS < 150 {
		t.Fatalf("时长应覆盖上游等待: %dms", row.durationMS)
	}
}

func TestCWhitelistDatabaseBlindTunnelAbortStillRecords(t *testing.T) {
	db := tunnelBytesTestDB(t)
	host := "abort-" + uuid.NewString()[:8] + ".blob.core.windows.net"
	downPayload := strings.Repeat("c", 4096)
	upstream, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer upstream.Close()
	go func() {
		conn, err := upstream.Accept()
		if err != nil {
			return
		}
		buf := make([]byte, 10)
		_, _ = io.ReadFull(conn, buf)
		_, _ = conn.Write([]byte(downPayload))
		time.Sleep(50 * time.Millisecond)
		// 上游异常断开：RST 而不是正常 FIN。
		if tcp, ok := conn.(*net.TCPConn); ok {
			_ = tcp.SetLinger(0)
		}
		_ = conn.Close()
	}()
	conn := startBlindTunnel(t, db, host, upstream)
	if _, err := conn.Write([]byte("0123456789")); err != nil {
		t.Fatal(err)
	}
	_, _ = io.ReadAll(conn)

	row := waitTunnelRow(t, db, host)
	if row.rows != 1 {
		t.Fatalf("异常断开也只能更新同一行: rows=%d", row.rows)
	}
	if row.up != 10 || row.down != int64(len(downPayload)) {
		t.Fatalf("异常断开前已传字节必须入账: 上行=%d 下行=%d", row.up, row.down)
	}
}
