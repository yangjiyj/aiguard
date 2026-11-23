// Package errclass 把错误归为有限的、不含敏感信息的类别，供日志与指标使用。
//
// 背景：pgx/net/url 的错误文本会带连接串里的用户名、库名、主机，url.Error 还带完整 URL（含查询串）。
// 直接 %v 打日志既泄露信息，又让排障者只能看到 *errors.errorString 这类无用类型名。
// 这里只输出「类别 + SQLSTATE + HTTP 状态码」，不输出任何消息正文。
package errclass

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"strings"

	"github.com/jackc/pgx/v5/pgconn"
)

const (
	ClassNone           = "none"
	ClassTimeout        = "timeout"
	ClassCanceled       = "canceled"
	ClassTooManyClients = "too_many_clients"
	ClassDBUnavailable  = "db_unavailable"
	ClassSQLError       = "sql_error"
	ClassConnectionLost = "connection_lost"
	ClassConnectFailed  = "connect_failed"
	ClassDNS            = "dns"
	ClassHTTPStatus     = "http_status"
	ClassDecode         = "decode"
	ClassOther          = "other"
)

// HTTPStatusError 表示对端返回了非预期的 HTTP 状态码。它的 Error() 不含响应正文。
type HTTPStatusError struct {
	Op     string
	Status int
}

func (e *HTTPStatusError) Error() string {
	return fmt.Sprintf("%s returned status %d", e.Op, e.Status)
}

type timeouter interface{ Timeout() bool }

// Classify 返回错误类别。判定顺序有意义：先看超时/取消，再看数据库错误码，最后看网络层。
func Classify(err error) string {
	if err == nil {
		return ClassNone
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return ClassTimeout
	}
	if errors.Is(err, context.Canceled) {
		return ClassCanceled
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		switch {
		case pgErr.Code == "53300":
			return ClassTooManyClients
		case pgErr.Code == "57P01" || pgErr.Code == "57P02" || pgErr.Code == "57P03" || strings.HasPrefix(pgErr.Code, "08"):
			return ClassDBUnavailable
		default:
			return ClassSQLError
		}
	}
	var statusErr *HTTPStatusError
	if errors.As(err, &statusErr) {
		return ClassHTTPStatus
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return ClassDNS
	}
	var te timeouter
	if errors.As(err, &te) && te.Timeout() {
		return ClassTimeout
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return ClassConnectionLost
	}
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		if opErr.Op == "dial" {
			return ClassConnectFailed
		}
		return ClassConnectionLost
	}
	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		return ClassConnectFailed
	}
	if isDecodeError(err) {
		return ClassDecode
	}
	return ClassOther
}

func isDecodeError(err error) bool {
	type jsonErr interface{ Offset() int64 }
	var syn jsonErr
	if errors.As(err, &syn) {
		return true
	}
	text := err.Error()
	return strings.Contains(text, "invalid character") || strings.Contains(text, "unexpected end of JSON") ||
		strings.Contains(text, "cannot unmarshal")
}

// Summary 返回形如 "class=too_many_clients sqlstate=53300" 的摘要，可直接拼进日志行。
// 绝不包含错误消息正文、URL、主机、用户名或 SQL。
func Summary(err error) string {
	class := Classify(err)
	out := "class=" + class
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code != "" {
		out += " sqlstate=" + sanitizeToken(pgErr.Code)
	}
	var statusErr *HTTPStatusError
	if errors.As(err, &statusErr) {
		out += fmt.Sprintf(" http_status=%d", statusErr.Status)
	}
	return out
}

// sanitizeToken 只保留字母数字，防止异常值破坏日志行。
func sanitizeToken(s string) string {
	if len(s) > 8 {
		s = s[:8]
	}
	var b strings.Builder
	for _, r := range s {
		if r >= '0' && r <= '9' || r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' {
			b.WriteRune(r)
		}
	}
	return b.String()
}
