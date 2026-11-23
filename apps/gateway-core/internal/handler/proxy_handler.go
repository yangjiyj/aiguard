package handler

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/yangjiyj/aiguard/packages/shared-go/egresspolicy"
	"github.com/yangjiyj/aiguard/packages/shared-go/proxywhitelist"
	"github.com/yangjiyj/aiguard/packages/shared-go/securityexit"
	"github.com/jackc/pgx/v5/pgxpool"
)

type ForwardProxyHandler struct {
	db                *pgxpool.Pool
	tenantID          string
	internalSecret    string
	whitelist         []whitelistEntry
	mu                sync.RWMutex
	lastReload        time.Time
	whitelistErr      error
	forwardProxyMode  string
	whitelistFailMode string
	auditRecorder     reverseProxyAuditRecorder
	reverseProxy      *ReverseProxyHandler
	// lookupIP 只给测试注入解析结果；nil 用系统解析器。
	lookupIP lookupIPAddrFunc
	// runtimeValues 返回控制台下发的正向代理设置（签名运行时投影里控制面发来的键）；
	// ok=false 表示还没拿到运行时配置。nil 时从反向代理的运行时配置客户端读。
	runtimeValues func(context.Context) (map[string]string, bool)
}

type whitelistEntry struct {
	pattern      string
	hasWildcard  bool
	wildcardHost string
	port         int
}

func NewForwardProxyHandler(db *pgxpool.Pool, tenantID, securityURL string) *ForwardProxyHandler {
	return NewForwardProxyHandlerWithSecret(db, tenantID, securityURL, "")
}

func NewForwardProxyHandlerWithSecret(db *pgxpool.Pool, tenantID, securityURL, internalSecret string) *ForwardProxyHandler {
	h := &ForwardProxyHandler{
		db:                db,
		tenantID:          proxywhitelist.Tenant(tenantID),
		internalSecret:    strings.TrimSpace(internalSecret),
		forwardProxyMode:  os.Getenv("GATEWAY_FORWARD_PROXY_MODE"),
		whitelistFailMode: os.Getenv("PROXY_WHITELIST_FAIL_MODE"),
		auditRecorder:     newReverseProxyDBAuditRecorder(db, os.Getenv("GATEWAY_ENVIRONMENT_SCOPE")),
	}
	h.reverseProxy = NewReverseProxyHandlerWithSecret(db, h.tenantID, securityURL, internalSecret)
	return h
}

func (h *ForwardProxyHandler) SetRuntimeConfigClient(client *ToolRiskClient, fallback bool) {
	if h == nil || h.reverseProxy == nil {
		return
	}
	h.reverseProxy.SetRuntimeConfigClient(client, fallback)
}

func (h *ForwardProxyHandler) reloadWhitelist() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	rules, err := (proxywhitelist.Store{DB: h.db}).ListRules(ctx, h.tenantID)
	var entries []whitelistEntry
	for _, rule := range rules {
		entries = append(entries, whitelistEntry{pattern: rule.HostPattern, port: rule.Port})
	}

	h.mu.Lock()
	h.whitelist = entries
	h.whitelistErr = err
	h.lastReload = time.Now()
	h.mu.Unlock()
	log.Printf("Proxy whitelist reloaded: %d entries", len(entries))
}

// ensureWhitelistLoaded refreshes whitelist if > 60 seconds since last load
func (h *ForwardProxyHandler) ensureWhitelistLoaded() {
	h.mu.RLock()
	needsReload := time.Since(h.lastReload) > 60*time.Second
	h.mu.RUnlock()
	if needsReload {
		h.reloadWhitelist()
	}
}

func (h *ForwardProxyHandler) isHostAllowed(host string, port int) bool {
	h.ensureWhitelistLoaded()
	h.mu.RLock()
	defer h.mu.RUnlock()
	if h.whitelistErr != nil {
		return false
	}
	for _, entry := range h.whitelist {
		if proxywhitelist.Matches(proxywhitelist.Rule{HostPattern: entry.pattern, Port: entry.port}, host, port) {
			return true
		}
	}
	return false
}

func (h *ForwardProxyHandler) SetForwardProxyMode(mode string) {
	h.forwardProxyMode = strings.TrimSpace(mode)
}

func (h *ForwardProxyHandler) SetWhitelistFailMode(mode string) {
	h.whitelistFailMode = strings.TrimSpace(mode)
}

// consoleValues 返回控制台下发的正向代理设置；没拿到运行时配置时为 nil（全部回落到部署
// 环境变量与默认值）。
func (h *ForwardProxyHandler) consoleValues(ctx context.Context) map[string]string {
	if h == nil {
		return nil
	}
	if h.runtimeValues != nil {
		if values, ok := h.runtimeValues(ctx); ok {
			return values
		}
		return nil
	}
	if h.reverseProxy != nil && h.reverseProxy.runtimeConfigClient != nil {
		if values, ok := h.reverseProxy.runtimeConfigClient.ForwardProxyValues(ctx); ok {
			return values
		}
	}
	return nil
}

// egressSettings 解析防跳板出站设置；库里某个键的值格式不对时只丢这个键（按默认拒绝），其余照常。
func (h *ForwardProxyHandler) egressSettings(ctx context.Context) egresspolicy.Settings {
	settings, err := egresspolicy.FromValues(h.consoleValues(ctx))
	if err != nil {
		log.Printf("Forward proxy egress settings partly invalid, the bad keys stay at their defaults: %v", err)
	}
	settings.Compat = egresspolicy.CompatGatewayProxy
	return settings
}

func (h *ForwardProxyHandler) whitelistOutcome(ctx context.Context, host string, port int) (securityexit.Outcome, string) {
	mode := h.runtimeForwardProxyMode(ctx)
	// 执行模式与其他出口同源（运行配置快照）：部署变量 SECURITY_AUDIT_ONLY=true 只在控制台没有
	// 显式执行模式时作初值（2.9.22 D7），不再与快照取或。
	auditOnly := h.reverseProxy.securityAuditOnly(ctx)
	exitMode := securityexit.ModeFromAuditOnly(auditOnly)
	if mode == "tunnel_audit" {
		return securityexit.DecideWithPolicy(exitMode, "audit", securityexit.DetectionFailure, securityexit.Policy{}), "forward_proxy_tunnel_audit"
	}
	allowed := h.isHostAllowed(host, port)
	h.mu.RLock()
	err := h.whitelistErr
	h.mu.RUnlock()
	if err != nil {
		return securityexit.DecideWithPolicy(exitMode, "block", securityexit.DetectionFailure, securityexit.Policy{FailClosedOnDetectionFailure: h.runtimeWhitelistFailMode(ctx) == egresspolicy.FailClosed}), "proxy_whitelist_unavailable"
	}
	if !allowed {
		return securityexit.DecideWithPolicy(exitMode, "block", securityexit.ToolPolicy, securityexit.Policy{}), "proxy_whitelist_unlisted"
	}
	return securityexit.DecideWithPolicy(exitMode, "allow", securityexit.ToolPolicy, securityexit.Policy{}), ""
}

// runtimeForwardProxyMode 是未登记目标的处置：控制台设置（forward_proxy_unlisted_action）
// 优先；库里没有该键时才用部署环境变量 GATEWAY_FORWARD_PROXY_MODE 作初值；默认拒绝。
func (h *ForwardProxyHandler) runtimeForwardProxyMode(ctx context.Context) string {
	mode := h.forwardProxyMode
	if mode == "" {
		mode = os.Getenv("GATEWAY_FORWARD_PROXY_MODE")
	}
	if egresspolicy.UnlistedAction(h.consoleValues(ctx), mode) == egresspolicy.UnlistedAllowAudit {
		return "tunnel_audit"
	}
	return "deny_unlisted"
}

// runtimeWhitelistFailMode 是白名单读取失败的处置：控制台设置（proxy_whitelist_fail_mode）
// 优先；库里没有该键时才用部署环境变量 PROXY_WHITELIST_FAIL_MODE 作初值；默认 closed。
func (h *ForwardProxyHandler) runtimeWhitelistFailMode(ctx context.Context) string {
	mode := h.whitelistFailMode
	if mode == "" {
		mode = os.Getenv("PROXY_WHITELIST_FAIL_MODE")
	}
	return egresspolicy.WhitelistFailMode(h.consoleValues(ctx), mode)
}

// guardEgress 按防跳板出站设置解析目标。拒绝时记安全事件并回 403（观察留痕也照拒）；
// 因设置放行内部地址时记一条放行事件。ok=false 表示已经写了响应。
func (h *ForwardProxyHandler) guardEgress(w http.ResponseWriter, r *http.Request, host string, port int) (resolvedEgressTarget, bool) {
	target, viaSetting, err := resolveForwardEgressTarget(r.Context(), host, port, h.egressSettings(r.Context()), h.lookupIP)
	if err != nil {
		log.Printf("Proxy: unsafe target %s:%d: %v", host, port, err)
		if errors.Is(err, errUnsafeEgressTarget) {
			h.recordForwardAudit(r, host, 0, 0, securityexit.Outcome{Enforce: true, Action: "block"}, egresspolicy.ReasonInternalEgressDenied)
		}
		http.Error(w, "Forbidden: unsafe proxy target", http.StatusForbidden)
		return resolvedEgressTarget{}, false
	}
	if viaSetting {
		h.recordForwardAudit(r, host, 0, 0, securityexit.Outcome{Action: "audit"}, egresspolicy.ReasonInternalEgressAllowed)
	}
	return target, true
}

func (h *ForwardProxyHandler) enforceWhitelist(w http.ResponseWriter, r *http.Request, host string, port int) bool {
	outcome, reason := h.whitelistOutcome(r.Context(), host, port)
	if outcome.Gap || reason != "" {
		h.recordForwardAudit(r, host, 0, 0, outcome, reason)
	}
	if outcome.Enforce {
		http.Error(w, "Forbidden: target not allowed by proxy whitelist", http.StatusForbidden)
		return false
	}
	return true
}

func (h *ForwardProxyHandler) recordForwardAudit(r *http.Request, host string, statusCode int, responseBytes int64, outcome securityexit.Outcome, reason string) {
	if h.auditRecorder == nil {
		return
	}
	record, err := newReverseProxyAuditRecord(forwardProxyAuditRequestID(r), proxywhitelist.Tenant(h.tenantID), host, r.URL, r, nil, nil, "in_progress", statusCode, responseBytes, 0)
	if err != nil {
		log.Printf("Forward proxy audit unavailable: %v", err)
		return
	}
	record.ProxyMode = "forward"
	record.TLSInspected, record.ContentRetained = false, false
	record.RetentionLevel = "summary"
	if statusCode > 0 {
		record.Status = "success"
	}
	if outcome.Enforce {
		record.Status, record.StatusCode = "blocked", http.StatusForbidden
	}
	if reason != "" {
		record.InputSemanticStatus, record.InputSemanticReason = "incomplete", reason
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 5*time.Second)
	defer cancel()
	h.auditRecorder.WriteReverseProxyAccess(ctx, record)
	if reason != "" {
		h.auditRecorder.WriteReverseProxySecurityEvent(ctx, record, "input", outcome.Action, nil)
	}
}

type forwardProxyAuditRequestIDKey struct{}

func forwardProxyAuditRequestID(r *http.Request) string {
	if requestID, ok := r.Context().Value(forwardProxyAuditRequestIDKey{}).(string); ok {
		return requestID
	}
	requestID := newReverseProxyRequestID()
	*r = *r.WithContext(context.WithValue(r.Context(), forwardProxyAuditRequestIDKey{}, requestID))
	return requestID
}

func (h *ForwardProxyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == "CONNECT" {
		h.handleConnect(w, r)
		return
	}
	if r.URL.IsAbs() && (r.URL.Scheme == "http" || r.URL.Scheme == "https") {
		h.handleHTTPProxy(w, r)
		return
	}
	if h.reverseProxy != nil && h.reverseProxy.ServeHTTP(w, r) {
		return
	}
	http.Error(w, "Proxy only supports CONNECT and absolute URI requests", http.StatusMethodNotAllowed)
}

// handleConnect handles HTTPS CONNECT tunneling
func (h *ForwardProxyHandler) handleConnect(w http.ResponseWriter, r *http.Request) {
	hostPort := r.Host
	if hostPort == "" {
		hostPort = r.URL.Host
	}

	host, portStr, err := net.SplitHostPort(hostPort)
	if err != nil {
		http.Error(w, "Bad request: invalid host:port", http.StatusBadRequest)
		return
	}

	port := 443
	if portStr != "" {
		if p, err := strconv.Atoi(portStr); err == nil {
			port = p
		}
	}
	if !h.enforceWhitelist(w, r, host, port) {
		return
	}

	target, ok := h.guardEgress(w, r, host, port)
	if !ok {
		return
	}

	destConn, err := dialResolvedEgress(r.Context(), target, 10*time.Second)
	if err != nil {
		log.Printf("Proxy: failed to connect to %s: %v", hostPort, err)
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return
	}

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		destConn.Close()
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}

	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		destConn.Close()
		http.Error(w, "Hijack failed", http.StatusInternalServerError)
		return
	}

	// Send 200 Connection Established
	clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
	h.recordForwardAudit(r, host, http.StatusOK, 0, securityexit.Outcome{Action: "audit", Gap: true}, "forward_proxy_tls_uninspected")

	// Bidirectional copy with stats tracking
	var bytesSent, bytesReceived int64
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		written, _ := io.Copy(destConn, clientConn)
		bytesSent = written
		destConn.Close()
	}()

	go func() {
		defer wg.Done()
		written, _ := io.Copy(clientConn, destConn)
		bytesReceived = written
		clientConn.Close()
	}()

	wg.Wait()

	// Record usage stats asynchronously.
	h.recordUsageAsync(context.WithoutCancel(r.Context()), host, port, bytesSent, bytesReceived)
}

// handleHTTPProxy handles plain HTTP forward proxy requests
func (h *ForwardProxyHandler) handleHTTPProxy(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Hostname()
	portStr := r.URL.Port()
	port := 80
	if r.URL.Scheme == "https" {
		port = 443
	}
	if portStr != "" {
		if p, err := strconv.Atoi(portStr); err == nil {
			port = p
		}
	}
	if !h.enforceWhitelist(w, r, host, port) {
		return
	}

	target, ok := h.guardEgress(w, r, host, port)
	if !ok {
		return
	}

	// Create outbound request
	outReq, err := http.NewRequestWithContext(r.Context(), r.Method, r.URL.String(), r.Body) // #nosec G107,G704 -- target host is allowed by policy, DNS validated, and the client dials the pinned safe IP.
	if err != nil {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	// Copy headers
	for k, vv := range r.Header {
		for _, v := range vv {
			outReq.Header.Add(k, v)
		}
	}
	// Remove proxy headers
	outReq.Header.Del("Proxy-Connection")

	// Send request
	client := httpClientForResolvedEgress(nil, target, 120*time.Second)
	resp, err := client.Do(outReq) // #nosec G107,G704 -- target host is allowed by policy, DNS validated, and the client dials the pinned safe IP.
	if err != nil {
		log.Printf("Proxy: failed to forward request to %s: %v", host, err)
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// Copy response headers
	for k, vv := range resp.Header {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)

	bytesSent := outReq.ContentLength
	if bytesSent < 0 {
		bytesSent = 0
	}
	bytesReceived, _ := io.Copy(w, resp.Body)
	h.recordForwardAudit(r, host, resp.StatusCode, bytesReceived, securityexit.Outcome{Action: "audit", Gap: true}, "forward_proxy_content_uninspected")

	// Record usage.
	h.recordUsageAsync(context.WithoutCancel(r.Context()), host, port, bytesSent, bytesReceived)
}

func (h *ForwardProxyHandler) recordUsageAsync(parent context.Context, host string, port int, bytesSent, bytesReceived int64) {
	if h.db == nil || (bytesSent == 0 && bytesReceived == 0) {
		return
	}
	go h.recordUsage(parent, host, port, bytesSent, bytesReceived)
}

// recordUsage inserts a proxy usage log entry.
func (h *ForwardProxyHandler) recordUsage(parent context.Context, host string, port int, bytesSent, bytesReceived int64) {
	ctx, cancel := context.WithTimeout(parent, 5*time.Second)
	defer cancel()

	_, err := h.db.Exec(ctx,
		`INSERT INTO proxy_usage_logs (tenant_id, host, port, bytes_sent, bytes_received)
		 VALUES ($1, $2, $3, $4, $5)`,
		h.tenantID, host, port, bytesSent, bytesReceived,
	)
	if err != nil {
		log.Printf("Failed to record proxy usage: %v", err)
	}
}

// GetWhitelistStats returns the current whitelist count and last reload time
func (h *ForwardProxyHandler) GetWhitelistStats() (count int, lastReload time.Time) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return len(h.whitelist), h.lastReload
}

// GetUsageSummary returns proxy usage aggregations
func (h *ForwardProxyHandler) GetUsageSummary(ctx context.Context) (map[string]interface{}, error) {
	type hostStat struct {
		Host           string `json:"host"`
		Port           int    `json:"port"`
		TotalBytesSent int64  `json:"total_bytes_sent"`
		TotalBytesRecv int64  `json:"total_bytes_received"`
		RequestCount   int    `json:"request_count"`
	}

	rows, err := h.db.Query(ctx,
		`SELECT host, port,
		         SUM(bytes_sent)::bigint,
		         SUM(bytes_received)::bigint,
		         COUNT(*)::int
		  FROM proxy_usage_logs
		  WHERE tenant_id = $1
		    AND started_at >= NOW() - INTERVAL '30 days'
		  GROUP BY host, port
		  ORDER BY SUM(bytes_sent + bytes_received) DESC
		  LIMIT 20`,
		h.tenantID,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to query proxy usage: %w", err)
	}
	defer rows.Close()

	var stats []hostStat
	for rows.Next() {
		var s hostStat
		if err := rows.Scan(&s.Host, &s.Port, &s.TotalBytesSent, &s.TotalBytesRecv, &s.RequestCount); err != nil {
			continue
		}
		stats = append(stats, s)
	}

	return map[string]interface{}{
		"hosts": stats,
	}, nil
}
