package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
)

// lseProbeClient 探活 LSE /api/health。
// SSRF 取舍：放开内网（LSE 私有化部署常在内网，硬禁会误杀），靠克制护栏防滥用——
// 只 GET、只拼固定 /api/health 路径、禁跨主机重定向、10s 超时、限响应大小、身份校验。
var lseProbeClient = &http.Client{
	Timeout: 10 * time.Second,
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		// Keep the configured origin as the only destination; the probe uses a fixed endpoint.
		return http.ErrUseLastResponse
	},
}

type lseHealthBody struct {
	Status            string `json:"status"`
	Service           string `json:"service"`
	GatewayConfigured bool   `json:"gateway_configured"`
	Nonce             string `json:"nonce"`
}

// lseProbeResult 单次回连 LSE 的结果。reason 是内部码（供 LSE 侧映射中文），message 为中文兜底。
type lseProbeResult struct {
	ok          bool
	reason      string
	message     string
	latencyMs   int64
	service     string
	nonceEchoed string
}

// probeLSE 回连 base 的 /api/integration/handshake 并校验对面确实是 LSE。
// nonce 非空时附带 ?nonce= 并要求原样回显——证明"网关配的地址 == 发起校验的同一台 LSE"。
// timeout<=0 取 10s。
func probeLSE(ctx context.Context, base, nonce string, timeout time.Duration) lseProbeResult {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	u, err := url.Parse(bakeLSEBase(base))
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return lseProbeResult{reason: "lse_addr_invalid", message: "LSE 服务地址格式非法（需 http(s)://host[:port]）"}
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return lseProbeResult{reason: "lse_addr_invalid", message: "LSE 服务地址不能包含账号、查询参数或片段"}
	}
	allow := strings.TrimSpace(os.Getenv("LSE_BASE_URL_ALLOWLIST"))
	if allow == "" {
		return lseProbeResult{reason: "lse_addr_not_allowlisted", message: "未配置 LSE_BASE_URL_ALLOWLIST，已拒绝外呼"}
	}
	if !lseHostAllowed(u, allow) {
		return lseProbeResult{reason: "lse_addr_not_allowlisted", message: "LSE 服务地址不在 LSE_BASE_URL_ALLOWLIST 允许列表内"}
	}
	secret := lseIntegrationSecret()
	if secret == "" {
		return lseProbeResult{reason: "no_secret", message: "网关未配置集成密钥（JJD_INTERNAL_API_SECRET），无法发起带鉴权握手"}
	}
	handshakeURL := strings.TrimRight(u.Scheme+"://"+u.Host+u.Path, "/") + "/api/integration/handshake"
	if nonce != "" {
		handshakeURL += "?nonce=" + url.QueryEscape(nonce)
	}
	reqCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, handshakeURL, nil)
	if err != nil {
		return lseProbeResult{reason: "peer_unreachable", message: err.Error()}
	}
	req.Header.Set("accept", "application/json")
	// 自动携带本端集成密钥（不上界面）；对端校验，伪造无密钥者一律 401。
	req.Header.Set("authorization", "Bearer "+secret)
	start := time.Now()
	resp, err := lseProbeClient.Do(req)
	latency := time.Since(start).Milliseconds()
	if err != nil {
		return lseProbeResult{reason: "peer_unreachable", message: "无法连接 LSE：" + err.Error(), latencyMs: latency}
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
		// 继续身份校验
	case http.StatusUnauthorized:
		return lseProbeResult{reason: "token_mismatch", message: "握手被拒绝：双方集成密钥不一致，或 LSE 未配置集成密钥", latencyMs: latency}
	case http.StatusServiceUnavailable:
		return lseProbeResult{reason: "peer_no_secret", message: "LSE 未配置集成密钥（JJD_EVAL_INTEGRATION_TOKEN）", latencyMs: latency}
	default:
		return lseProbeResult{reason: "http_error", message: fmt.Sprintf("LSE 返回 HTTP %d（地址或服务异常）", resp.StatusCode), latencyMs: latency}
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	var h lseHealthBody
	if json.Unmarshal(body, &h) != nil || h.Service != "lse-api" {
		return lseProbeResult{reason: "peer_not_lse", message: "目标地址不是大模型安全评估平台", latencyMs: latency, service: h.Service}
	}
	if !h.GatewayConfigured {
		return lseProbeResult{reason: "peer_not_reciprocal", message: "LSE 已连通，但 LSE 侧尚未配置网关地址，联动未双向建立", latencyMs: latency, service: h.Service}
	}
	if nonce != "" && h.Nonce != nonce {
		return lseProbeResult{reason: "peer_not_same_instance", message: "回连到的并非发起校验的平台实例，请核对地址", latencyMs: latency, service: h.Service, nonceEchoed: h.Nonce}
	}
	message := "连接成功（双方已互配）"
	if nonce == "" {
		message = "网关到评估平台连接成功（评估平台已填写网关地址）"
	}
	return lseProbeResult{ok: true, reason: "ok", message: message, latencyMs: latency, service: h.Service, nonceEchoed: h.Nonce}
}

// probeLSEHealth 向后兼容旧调用（网关→LSE /system/lse/test）。
func probeLSEHealth(ctx context.Context, base string) (bool, string, int64, string) {
	r := probeLSE(ctx, base, "", 0)
	return r.ok, r.message, r.latencyMs, r.service
}

func lseHostAllowed(u *url.URL, allowlist string) bool {
	host := strings.ToLower(u.Host)
	hostname := strings.ToLower(u.Hostname())
	origin := strings.ToLower(u.Scheme + "://" + u.Host)
	for _, e := range strings.Split(allowlist, ",") {
		e = strings.ToLower(strings.TrimSpace(e))
		if e == "" {
			continue
		}
		if e == origin || e == host || (e == hostname && u.Port() == "") {
			return true
		}
	}
	return false
}

// lseIntegrationSecret 网关侧集成密钥（与 LSE 的 JJD_EVAL_INTEGRATION_TOKEN 同值）；不上界面，仅 env。
func lseIntegrationSecret() string {
	s := strings.TrimSpace(os.Getenv("JJD_INTERNAL_API_SECRET"))
	if s == "" {
		s = strings.TrimSpace(os.Getenv("JJD_PROVIDER_SECRET_KEY"))
	}
	return s
}

// bakeLSEBase 把"只填 IP/host"补全为 LSE 对外地址：<scheme>://<host>:<port>。
// 无 scheme→http；无端口→默认 8090（LSE web 对外口）；已带 scheme/端口则尊重。
func bakeLSEBase(input string) string {
	s := strings.TrimSpace(input)
	if s == "" {
		return ""
	}
	if !strings.Contains(s, "://") {
		s = "http://" + s
	}
	u, err := url.Parse(s)
	if err != nil || u.Host == "" {
		return strings.TrimRight(s, "/")
	}
	if u.Port() == "" {
		u.Host = u.Hostname() + ":8090"
	}
	return u.Scheme + "://" + u.Host + strings.TrimRight(u.Path, "/")
}

// TestLSEConnection 网关→LSE 探活端点：仅 platform_admin；探 lse_base_url + /api/health。
func TestLSEConnection(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil || user.Role != "platform_admin" {
			writeErrorWithStatus(w, http.StatusForbidden, "forbidden", "insufficient permissions")
			return
		}
		var req struct {
			LSEBaseURL string `json:"lse_base_url"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil && err != io.EOF {
			writeError(w, "invalid_request", "invalid JSON")
			return
		}
		base := strings.TrimRight(strings.TrimSpace(req.LSEBaseURL), "/")
		if base == "" && deps.SystemRepo != nil {
			if s, gerr := deps.SystemRepo.Get(r.Context(), "lse_base_url"); gerr == nil && s != nil {
				base = strings.TrimRight(strings.TrimSpace(s.Value), "/")
			}
		}
		if base == "" {
			writeJSON(w, map[string]interface{}{"ok": false, "message": "未填写 LSE 服务地址"})
			return
		}
		ok, msg, latency, service := probeLSEHealth(r.Context(), base)
		writeJSON(w, map[string]interface{}{"ok": ok, "message": msg, "latency_ms": latency, "service": service})
	}
}

// VerifyReciprocal 互证回连端点（共享密钥保护，供 LSE 触发）：
// 网关读自己配置的 lse_base_url，带 LSE 传来的 nonce 回连 LSE 的 handshake，要求 nonce 原样回显——
// 证明"网关侧配的 LSE 地址 == 发起校验的同一台 LSE 实例"。错填/打字错/连不通/配成另一台 LSE 都会失败，
// 杜绝旧逻辑"对端只要填了非空地址就算通"的假绿。本端点只回连 LSE 的被动 handshake，不再外呼，无递归。
func VerifyReciprocal(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		nonce := strings.TrimSpace(r.URL.Query().Get("nonce"))
		if !validReciprocalNonce(nonce) {
			writeJSON(w, map[string]interface{}{"reciprocal": false, "reason": "bad_nonce", "message": "缺少或非法的校验随机数"})
			return
		}
		base := ""
		if deps != nil && deps.SystemRepo != nil {
			if s, err := deps.SystemRepo.Get(r.Context(), "lse_base_url"); err == nil && s != nil {
				base = strings.TrimRight(strings.TrimSpace(s.Value), "/")
			}
		}
		if base == "" {
			writeJSON(w, map[string]interface{}{"reciprocal": false, "reason": "lse_not_configured", "message": "网关侧未配置本评估平台地址，联动尚未建立"})
			return
		}
		// 内层 6s，确保在 LSE 侧 10s 超时窗口内返回（避免超时链把成功也判成失败）。
		res := probeLSE(r.Context(), base, nonce, 6*time.Second)
		writeJSON(w, map[string]interface{}{
			"reciprocal":   res.ok,
			"reason":       res.reason,
			"message":      res.message,
			"nonce_echoed": res.nonceEchoed,
			"lse_service":  res.service,
			"latency_ms":   res.latencyMs,
		})
	}
}

// validReciprocalNonce 限定 nonce 为 8-64 位字母数字，挡掉空/超长/注入字符。
func validReciprocalNonce(s string) bool {
	if len(s) < 8 || len(s) > 64 {
		return false
	}
	for _, c := range s {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')) {
			return false
		}
	}
	return true
}
