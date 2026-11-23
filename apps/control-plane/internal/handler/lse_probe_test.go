package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestProbeLSEHealth(t *testing.T) {
	t.Setenv("JJD_INTERNAL_API_SECRET", "shared-secret")

	// 真 LSE 握手端点：校验 Bearer 后返回 lse-api
	lse := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/integration/handshake" {
			http.NotFound(w, r)
			return
		}
		if r.Header.Get("Authorization") != "Bearer shared-secret" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("content-type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok","service":"lse-api","paired":true,"gateway_configured":true}`))
	}))
	defer lse.Close()
	t.Setenv("LSE_BASE_URL_ALLOWLIST", lse.URL)
	if ok, msg, _, service := probeLSEHealth(context.Background(), lse.URL); !ok || service != "lse-api" {
		t.Fatalf("带正确密钥应通过：ok=%v service=%q msg=%q", ok, service, msg)
	} else if msg != "网关到评估平台连接成功（评估平台已填写网关地址）" {
		t.Fatalf("单向探活不得宣称双方已互配：msg=%q", msg)
	}

	// 密钥不一致 → 401 → 失败（伪造/无密钥进不来）
	t.Setenv("JJD_INTERNAL_API_SECRET", "wrong-secret")
	if ok, _, _, _ := probeLSEHealth(context.Background(), lse.URL); ok {
		t.Fatalf("错误密钥应被 401 拒绝")
	}

	// 正确密钥但对面不是 lse-api → 身份校验拦截
	t.Setenv("JJD_INTERNAL_API_SECRET", "shared-secret")
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer shared-secret" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_, _ = w.Write([]byte(`{"service":"nginx"}`))
	}))
	defer other.Close()
	t.Setenv("LSE_BASE_URL_ALLOWLIST", other.URL)
	if ok, _, _, _ := probeLSEHealth(context.Background(), other.URL); ok {
		t.Fatalf("非 LSE 服务应被身份校验拦截")
	}

	// 网关未配置密钥 → 直接失败
	t.Setenv("JJD_INTERNAL_API_SECRET", "")
	t.Setenv("JJD_PROVIDER_SECRET_KEY", "")
	if ok, _, _, _ := probeLSEHealth(context.Background(), lse.URL); ok {
		t.Fatalf("网关无密钥应失败")
	}

	// 非法 scheme
	if ok, _, _, _ := probeLSEHealth(context.Background(), "ftp://x"); ok {
		t.Fatalf("非 http(s) 应拒绝")
	}

	// LSE 侧未配置网关地址(gateway_configured=false) → 联动未双向建立 → 失败
	noGw := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer shared-secret" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_, _ = w.Write([]byte(`{"status":"ok","service":"lse-api","gateway_configured":false}`))
	}))
	defer noGw.Close()
	t.Setenv("JJD_INTERNAL_API_SECRET", "shared-secret")
	t.Setenv("LSE_BASE_URL_ALLOWLIST", noGw.URL)
	if ok, _, _, _ := probeLSEHealth(context.Background(), noGw.URL); ok {
		t.Fatalf("对方未配置网关地址时不应通过(需双向)")
	}

	// nonce 回显一致 → 互证通过（证明配的就是发起方这台 LSE）
	t.Setenv("JJD_INTERNAL_API_SECRET", "shared-secret")
	t.Setenv("JJD_PROVIDER_SECRET_KEY", "")
	echo := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer shared-secret" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		n := r.URL.Query().Get("nonce")
		w.Header().Set("content-type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok","service":"lse-api","gateway_configured":true,"nonce":"` + n + `"}`))
	}))
	defer echo.Close()
	t.Setenv("LSE_BASE_URL_ALLOWLIST", echo.URL)
	if res := probeLSE(context.Background(), echo.URL, "abc12345", 0); !res.ok || res.nonceEchoed != "abc12345" {
		t.Fatalf("nonce 回显一致应通过：ok=%v echoed=%q reason=%q", res.ok, res.nonceEchoed, res.reason)
	}

	// nonce 回显不一致（网关被配去了另一台 LSE）→ 失败
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer shared-secret" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_, _ = w.Write([]byte(`{"status":"ok","service":"lse-api","gateway_configured":true,"nonce":"DIFFERENT"}`))
	}))
	defer bad.Close()
	t.Setenv("LSE_BASE_URL_ALLOWLIST", bad.URL)
	if res := probeLSE(context.Background(), bad.URL, "abc12345", 0); res.ok || res.reason != "peer_not_same_instance" {
		t.Fatalf("nonce 不一致应判 peer_not_same_instance：ok=%v reason=%q", res.ok, res.reason)
	}
}

func TestProbeLSERejectsEmptyAndNonAllowlistedTargets(t *testing.T) {
	t.Setenv("JJD_INTERNAL_API_SECRET", "shared-secret")
	lse := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer shared-secret" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_, _ = w.Write([]byte("{\"status\":\"ok\",\"service\":\"lse-api\",\"gateway_configured\":true}"))
	}))
	defer lse.Close()

	// Empty allowlist must fail closed even for a reachable private deployment.
	t.Setenv("LSE_BASE_URL_ALLOWLIST", "")
	if res := probeLSE(context.Background(), lse.URL, "", 0); res.ok || res.reason != "lse_addr_not_allowlisted" {
		t.Fatalf("empty allowlist must fail closed: ok=%v reason=%q", res.ok, res.reason)
	}

	// A non-matching explicit allowlist must also reject the destination.
	t.Setenv("LSE_BASE_URL_ALLOWLIST", "http://127.0.0.1:1")
	if res := probeLSE(context.Background(), lse.URL, "", 0); res.ok || res.reason != "lse_addr_not_allowlisted" {
		t.Fatalf("non-allowlisted target must fail closed: ok=%v reason=%q", res.ok, res.reason)
	}
}

func TestProbeLSENeverFollowsRedirect(t *testing.T) {
	t.Setenv("JJD_INTERNAL_API_SECRET", "shared-secret")
	var redirected bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/integration/handshake" {
			http.Redirect(w, r, "/redirected", http.StatusFound)
			return
		}
		redirected = true
		_, _ = w.Write([]byte("{\"status\":\"ok\",\"service\":\"lse-api\",\"gateway_configured\":true}"))
	}))
	defer server.Close()
	t.Setenv("LSE_BASE_URL_ALLOWLIST", server.URL)

	res := probeLSE(context.Background(), server.URL, "", 0)
	if res.ok {
		t.Fatalf("redirecting target must not be accepted: reason=%q", res.reason)
	}
	if redirected {
		t.Fatal("probe must not follow redirects")
	}
}
