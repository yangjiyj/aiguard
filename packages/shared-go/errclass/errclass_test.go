package errclass

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestClassifyKnownCategories(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want string
	}{
		{"nil", nil, ClassNone},
		{"deadline", context.DeadlineExceeded, ClassTimeout},
		{"wrapped deadline", fmt.Errorf("query: %w", context.DeadlineExceeded), ClassTimeout},
		{"canceled", context.Canceled, ClassCanceled},
		{"too many clients", &pgconn.PgError{Code: "53300", Message: "sorry, too many clients already"}, ClassTooManyClients},
		{"wrapped too many clients", fmt.Errorf("failed to connect: %w", &pgconn.PgError{Code: "53300"}), ClassTooManyClients},
		{"server shutting down", &pgconn.PgError{Code: "57P01"}, ClassDBUnavailable},
		{"cannot connect now", &pgconn.PgError{Code: "57P03"}, ClassDBUnavailable},
		{"sql error", &pgconn.PgError{Code: "42P01", Message: "relation \"x\" does not exist"}, ClassSQLError},
		{"unexpected eof", io.ErrUnexpectedEOF, ClassConnectionLost},
		{"eof", fmt.Errorf("read: %w", io.EOF), ClassConnectionLost},
		{"net timeout", &net.OpError{Op: "read", Err: timeoutErr{}}, ClassTimeout},
		{"dial refused", &net.OpError{Op: "dial", Err: errors.New("connection refused")}, ClassConnectFailed},
		{"dns", &net.DNSError{Err: "no such host", Name: "internal.example"}, ClassDNS},
		{"http status", &HTTPStatusError{Op: "semantic config", Status: 503}, ClassHTTPStatus},
		{"json syntax", mustJSONError(t), ClassDecode},
		{"other", errors.New("something odd"), ClassOther},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := Classify(tc.err); got != tc.want {
				t.Fatalf("Classify(%v)=%q want %q", tc.err, got, tc.want)
			}
		})
	}
}

func TestClassifyURLErrorUsesCauseNotURL(t *testing.T) {
	inner := &url.Error{Op: "Get", URL: "http://cp.internal/x?token=sekret-token&user_id=u-1", Err: context.DeadlineExceeded}
	if got := Classify(inner); got != ClassTimeout {
		t.Fatalf("url.Error timeout classified as %q", got)
	}
	refused := &url.Error{Op: "Post", URL: "http://cp.internal/y?token=sekret-token", Err: &net.OpError{Op: "dial", Err: errors.New("connection refused")}}
	if got := Classify(refused); got != ClassConnectFailed {
		t.Fatalf("url.Error dial classified as %q", got)
	}
}

func TestSummaryNeverLeaksMessageOrURL(t *testing.T) {
	secrets := []string{"sekret-token", "p@ssw0rd", "cp.internal", "user_id=u-1", "db.internal", "tenant-secret"}
	errs := []error{
		&url.Error{Op: "Get", URL: "http://cp.internal/x?token=sekret-token&user_id=u-1", Err: context.DeadlineExceeded},
		&pgconn.PgError{Code: "28P01", Message: "password authentication failed for user p@ssw0rd", Detail: "host db.internal"},
		fmt.Errorf("failed to connect to `host=db.internal user=app password=p@ssw0rd`: %w", &pgconn.PgError{Code: "53300", Message: "tenant-secret"}),
		&HTTPStatusError{Op: "semantic config", Status: 502},
	}
	for _, err := range errs {
		summary := Summary(err)
		for _, secret := range secrets {
			if strings.Contains(summary, secret) {
				t.Fatalf("summary %q leaks %q", summary, secret)
			}
		}
		if !strings.Contains(summary, "class=") {
			t.Fatalf("summary %q has no class", summary)
		}
	}
}

func TestSummaryCarriesSQLStateAndStatus(t *testing.T) {
	if got := Summary(&pgconn.PgError{Code: "53300"}); !strings.Contains(got, "class=too_many_clients") || !strings.Contains(got, "sqlstate=53300") {
		t.Fatalf("pg summary = %q", got)
	}
	if got := Summary(&HTTPStatusError{Op: "x", Status: 503}); !strings.Contains(got, "class=http_status") || !strings.Contains(got, "http_status=503") {
		t.Fatalf("http summary = %q", got)
	}
	if got := Summary(nil); got != "class=none" {
		t.Fatalf("nil summary = %q", got)
	}
}

// 真实的连接失败（端口无人监听）必须被归为连接类，且摘要不含主机/用户。
func TestRealConnectFailureIsClassifiedWithoutLeakingDSN(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	pool, err := pgxpool.New(ctx, "postgres://leaky_user:leaky_pw@127.0.0.1:1/leaky_db?sslmode=disable&connect_timeout=2")
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	defer pool.Close()
	err = pool.Ping(ctx)
	if err == nil {
		t.Fatal("expected connection failure")
	}
	class := Classify(err)
	if class != ClassConnectFailed && class != ClassTimeout {
		t.Fatalf("class=%q for %v", class, err)
	}
	summary := Summary(err)
	for _, leaked := range []string{"leaky_user", "leaky_pw", "leaky_db", "127.0.0.1"} {
		if strings.Contains(summary, leaked) {
			t.Fatalf("summary %q leaks %q", summary, leaked)
		}
	}
}

type timeoutErr struct{}

func (timeoutErr) Error() string   { return "i/o timeout" }
func (timeoutErr) Timeout() bool   { return true }
func (timeoutErr) Temporary() bool { return true }

func mustJSONError(t *testing.T) error {
	t.Helper()
	var v map[string]any
	err := json.Unmarshal([]byte("{bad"), &v)
	if err == nil {
		t.Fatal("expected json error")
	}
	return err
}
