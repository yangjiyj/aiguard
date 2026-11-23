package handler

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestEmployeeForwardedIPRequiresTrustedServiceExit(t *testing.T) {
	t.Setenv("JJD_LOGIN_IP_FORWARD_SECRET", "fixture-ip-secret")
	t.Setenv("JJD_CHAT_LOGIN_TRUSTED_PROXY_IPS", "10.20.0.2")
	r := httptest.NewRequest("POST", "/admin/v1/employee-login", nil)
	r.RemoteAddr = "203.0.113.9:1234"
	reviewSignLoginIP(r, "198.51.100.18", time.Now())
	if ip := requestClientIP(r); ip != "203.0.113.9" {
		t.Fatalf("external XFF accepted: %s", ip)
	}
	r.RemoteAddr = "10.20.0.2:1234"
	if ip := requestClientIP(r); ip != "198.51.100.18" {
		t.Fatalf("trusted service source lost: %s", ip)
	}
}

func TestEmployeeAdministratorNeedsMFAAndAllowedIP(t *testing.T) {
	e, u, _ := chatLoginFixture(t)
	if _, err := e.pool.Exec(context.Background(), `UPDATE users SET role='platform_admin' WHERE id=$1`, u.ID); err != nil {
		t.Fatal(err)
	}
	response := e.employeeLogin(u.Username, u.Password, "192.0.2.10", nil)
	var payload map[string]json.RawMessage
	_ = json.Unmarshal(response.Body.Bytes(), &payload)
	if response.Code != 403 || len(payload["chat_ticket"]) > 0 {
		t.Fatalf("unbound admin status=%d ticket=%v", response.Code, len(payload["chat_ticket"]) > 0)
	}
}
func TestEmployeeAccountLockoutSurvivesClientIPChange(t *testing.T) {
	e, u, _ := chatLoginFixture(t)
	for i := 0; i < 8; i++ {
		e.employeeLogin(u.Username, "isolated-wrong-password", "192.0.2.10", nil)
	}
	response := e.employeeLogin(u.Username, u.Password, "192.0.2.11", nil)
	if response.Code != 401 {
		t.Fatalf("account lock bypassed by another IP: %d", response.Code)
	}
}

func TestEmployeeDirectoryFailuresDoNotEnumerateOrLock(t *testing.T) {
	e, u, _ := chatLoginFixture(t)
	ctx := context.Background()
	e.deps.UserIdentityLinkLookup = repository.NewUserIdentityLinkRepository(e.pool)
	if _, err := e.pool.Exec(ctx, "INSERT INTO user_identity_links(id,tenant_id,user_id,issuer,source_type,source_id,external_subject) VALUES($1,$2,$3,'https://directory.test','ldap','https://directory.test','directory-subject')", u.ID+"-ldap", e.tenantID, u.ID); err != nil {
		t.Fatal(err)
	}
	var baseline string
	for i := 0; i < 8; i++ {
		missing := e.employeeLogin("unknown-directory-test", "wrong-password", "192.0.2.15", nil)
		directory := e.employeeLogin(u.Username, u.Password, "192.0.2.15", nil)
		if i == 0 {
			baseline = missing.Body.String()
		}
		if missing.Code != 401 || directory.Code != 401 || missing.Body.String() != baseline || directory.Body.String() != baseline || directory.Header().Get("Retry-After") != "" {
			t.Fatalf("anonymous failures diverge: iteration=%d missing=%d directory=%d", i, missing.Code, directory.Code)
		}
		if !strings.Contains(baseline, "企业账号登录") {
			t.Fatal("generic enterprise-login hint missing")
		}
	}
	guardName := "employee:" + e.tenantID + "\x00" + u.Username
	if count := e.redis.Exists(ctx, loginFailAccountPrefix+normalizeLoginName(guardName), loginLockPrefix+normalizeLoginName(guardName)).Val(); count != 0 {
		t.Fatalf("directory failure counters=%d", count)
	}
	var attempts int
	if err := e.pool.QueryRow(ctx, "SELECT count(*) FROM user_login_history WHERE user_id=$1 AND failure_reason='enterprise_login_required'", u.ID).Scan(&attempts); err != nil || attempts != 8 {
		t.Fatalf("directory audits=%d err=%v", attempts, err)
	}
}

func TestEmployeeTrustedProxyServiceDNSResolvesExactPeer(t *testing.T) {
	t.Setenv("JJD_LOGIN_IP_FORWARD_SECRET", "fixture-ip-secret")
	t.Setenv("JJD_CHAT_LOGIN_TRUSTED_PROXY_IPS", "")
	t.Setenv("JJD_CHAT_LOGIN_TRUSTED_PROXY_HOSTS", "localhost")
	r := httptest.NewRequest("POST", "/admin/v1/employee-login", nil)
	r.RemoteAddr = "127.0.0.1:1234"
	reviewSignLoginIP(r, "198.51.100.19", time.Now())
	if ip := requestClientIP(r); ip != "198.51.100.19" {
		t.Fatalf("trusted service peer not resolved: %s", ip)
	}
	r.RemoteAddr = "203.0.113.9:1234"
	if ip := requestClientIP(r); ip != "203.0.113.9" {
		t.Fatal("DNS trust accepted unrelated peer")
	}
}

func TestReviewEmployeeDistributedLoginFailuresLockAccount(t *testing.T) {
	e, u, _ := chatLoginFixture(t)
	for i := 0; i < 8; i++ {
		e.employeeLogin(u.Username, "wrong-fixture-password", fmt.Sprintf("192.0.2.%d", i+1), nil)
	}
	if res := e.employeeLogin(u.Username, u.Password, "198.51.100.10", nil); res.Code != 401 {
		t.Fatalf("distributed lock bypass: %d", res.Code)
	}
}
func TestReviewEmployeePureIPLockAcrossAccounts(t *testing.T) {
	e, u, _ := chatLoginFixture(t)
	for i := 0; i < 60; i++ {
		e.employeeLogin(fmt.Sprintf("missing-%d", i), "wrong-fixture-password", "192.0.2.40", nil)
	}
	if res := e.employeeLogin(u.Username, u.Password, "192.0.2.40", nil); res.Code != 401 {
		t.Fatalf("IP lock bypass: %d", res.Code)
	}
}
func TestReviewAdminUnlockClearsEmployeeCounters(t *testing.T) {
	e, u, _ := chatLoginFixture(t)
	ctx := context.Background()
	g := newLoginGuard(e.redis, LoadConsoleLoginPolicy(ctx, e.deps.SystemRepo))
	name := "employee:" + e.tenantID + "\x00" + u.Username
	for i := 0; i < 8; i++ {
		if _, err := g.recordFailure(ctx, name, "192.0.2.10"); err != nil {
			t.Fatal(err)
		}
	}
	if err := g.Unlock(ctx, u.Username, e.tenantID); err != nil {
		t.Fatal(err)
	}
	if remaining, err := g.lockedFor(ctx, name); err != nil || remaining > 0 {
		t.Fatalf("employee lock survived unlock: %v %v", remaining, err)
	}
}
func TestReviewAllChatTicketEntrypointsEnforceAdminMFAAndIP(t *testing.T) {
	e, u, _ := chatLoginFixture(t)
	ctx := context.Background()
	if _, err := e.pool.Exec(ctx, "UPDATE users SET role='platform_admin' WHERE id=$1", u.ID); err != nil {
		t.Fatal(err)
	}
	user, err := e.deps.UserRepo.GetByID(ctx, u.ID)
	if err != nil {
		t.Fatal(err)
	}
	call := func() *httptest.ResponseRecorder {
		req := httptest.NewRequest("POST", "/admin/v1/me/chat-login", nil)
		req.RemoteAddr = "198.51.100.50:1234"
		req = req.WithContext(context.WithValue(req.Context(), auth.UserKey, user))
		w := httptest.NewRecorder()
		CreateChatLoginTicket(e.deps)(w, req)
		return w
	}
	if w := call(); w.Code != 403 {
		t.Errorf("unbound administrator signed ticket: %d", w.Code)
	}
	e.withConsoleSecurity()
	if err := e.deps.ConsoleSecurity.SetTOTP(ctx, u.ID, "fixture-encrypted-secret", true); err != nil {
		t.Fatal(err)
	}
	e.sys.Set(ctx, settingAdminIPAllowlist, "192.0.2.0/24")
	if w := call(); w.Code != 403 {
		t.Errorf("administrator outside allowed IP signed ticket: %d", w.Code)
	}
}

func TestReviewTrustedPeerRejectsUnsignedForwardedIP(t *testing.T) {
	t.Setenv("JJD_CHAT_LOGIN_TRUSTED_PROXY_IPS", "10.20.0.2")
	t.Setenv("JJD_LOGIN_IP_FORWARD_SECRET", "fixture-ip-secret")
	r := httptest.NewRequest("POST", "/admin/v1/employee-login", nil)
	r.RemoteAddr = "10.20.0.2:1000"
	r.Header.Set("X-Forwarded-For", "198.51.100.18")
	if got := requestClientIP(r); got != "10.20.0.2" {
		t.Fatalf("unsigned source trusted: %s", got)
	}
}
func TestReviewUnconfiguredProxyKeepsLegacyRealIP(t *testing.T) {
	t.Setenv("JJD_CHAT_LOGIN_TRUSTED_PROXY_IPS", "")
	t.Setenv("JJD_CHAT_LOGIN_TRUSTED_PROXY_HOSTS", "")
	t.Setenv("JJD_LOGIN_IP_FORWARD_SECRET", "")
	r := httptest.NewRequest("POST", "/admin/v1/login", nil)
	r.RemoteAddr = "198.51.100.18"
	r = r.WithContext(context.WithValue(r.Context(), loginTransportPeerKey{}, "10.20.0.2:1000"))
	if got := requestClientIP(r); got != "198.51.100.18" {
		t.Fatalf("legacy console attribution regressed: %s", got)
	}
}

func reviewSignLoginIP(r *http.Request, ip string, now time.Time) {
	stamp := strconv.FormatInt(now.Unix(), 10)
	mac := hmac.New(sha256.New, []byte("fixture-ip-secret"))
	mac.Write([]byte("v1\n" + ip + "\n" + stamp))
	r.Header.Set("X-Forwarded-For", ip)
	r.Header.Set("X-JJD-Client-IP-Time", stamp)
	r.Header.Set("X-JJD-Client-IP-Signature", hex.EncodeToString(mac.Sum(nil)))
}
func TestReviewSignedIPRejectsTamperingExpiryAndUntrustedPeer(t *testing.T) {
	t.Setenv("JJD_CHAT_LOGIN_TRUSTED_PROXY_IPS", "10.20.0.2")
	t.Setenv("JJD_LOGIN_IP_FORWARD_SECRET", "fixture-ip-secret")
	req := httptest.NewRequest("POST", "/admin/v1/employee-login", nil)
	req.RemoteAddr = "10.20.0.2:1234"
	reviewSignLoginIP(req, "198.51.100.18", time.Now())
	if ip := requestClientIP(req); ip != "198.51.100.18" {
		t.Fatalf("valid signature lost source: %s", ip)
	}
	req.Header.Set("X-Forwarded-For", "198.51.100.19")
	if ip := requestClientIP(req); ip != "10.20.0.2" {
		t.Fatal("tampered source accepted")
	}
	reviewSignLoginIP(req, "198.51.100.18", time.Now().Add(-2*time.Minute))
	if ip := requestClientIP(req); ip != "10.20.0.2" {
		t.Fatal("expired signature accepted")
	}
	reviewSignLoginIP(req, "198.51.100.18", time.Now())
	req.RemoteAddr = "203.0.113.9:1234"
	if ip := requestClientIP(req); ip != "203.0.113.9" {
		t.Fatal("signature accepted from unrelated peer")
	}
}
func TestReviewLoginProxyDNSHasTTLCache(t *testing.T) {
	original := loginProxyLookup
	calls := 0
	loginProxyLookup = func(context.Context, string) ([]net.IPAddr, error) {
		calls++
		return []net.IPAddr{{IP: net.ParseIP("10.20.0.2")}}, nil
	}
	t.Cleanup(func() { loginProxyLookup = original })
	for i := 0; i < 3; i++ {
		ips := cachedLoginProxyIPs(context.Background(), "review-cache.test")
		if len(ips) != 1 {
			t.Fatal("DNS projection missing")
		}
	}
	if calls != 1 {
		t.Fatalf("DNS resolved %d times", calls)
	}
}
