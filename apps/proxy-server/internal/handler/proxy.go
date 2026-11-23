package handler

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"github.com/google/uuid"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/yangjiyj/aiguard/packages/shared-go/headeraudit"
	"github.com/yangjiyj/aiguard/packages/shared-go/proxywhitelist"
	"github.com/yangjiyj/aiguard/packages/shared-go/securityexit"
)

// ProxyHandler handles HTTP proxy requests
type ProxyHandler struct {
	whitelistChecker *WhitelistChecker
	caManager        *CAManager
	securityClient   *SecurityClient
	auditWriter      *AuditWriter
	egressGuard      *EgressGuard
	transport        http.RoundTripper
	headerAudit      *headeraudit.Client

	// restrictedFilePolicy 是受限文件模式策略读取器（正向代理侧）。nil = 功能关闭。
	restrictedFilePolicy RestrictedFilePolicyReader

	// mitmKeepAliveOnce/mitmKeepAliveRT 懒初始化并缓存「MITM keep-alive 专用」上游 transport。
	// 必须缓存复用——否则每请求新建 transport = 无连接池 = keep-alive 改造失效。
	// 该 transport 强制 HTTP/1.1(对齐现网手拨上游路径,避免 h2 改变 SSE 时序/framing),
	// DialContext 仍走 guarded 拨号保 SSRF 防护。与共享 transport(handleHTTP 用的 h2 版)隔离。
	mitmKeepAliveOnce sync.Once
	mitmKeepAliveRT   http.RoundTripper
}

// NewProxyHandler requires the critical-audit client in every build. Tests
// that intentionally exercise unrelated or fail-closed paths pass nil explicitly.
// WithRestrictedFilePolicyReader 注入受限文件策略读取器（cmd/server 装配时调用）。
func (h *ProxyHandler) WithRestrictedFilePolicyReader(reader RestrictedFilePolicyReader) *ProxyHandler {
	h.restrictedFilePolicy = reader
	return h
}

func NewProxyHandler(whitelistChecker *WhitelistChecker, caManager *CAManager, securityClient *SecurityClient, auditWriter *AuditWriter, headerAudit *headeraudit.Client) *ProxyHandler {
	egressGuard := NewEgressGuard(nil, nil)
	h := &ProxyHandler{
		whitelistChecker: whitelistChecker,
		caManager:        caManager,
		securityClient:   securityClient,
		auditWriter:      auditWriter,
		egressGuard:      egressGuard,
		transport:        egressGuard.HTTPTransport(),
		headerAudit:      headerAudit,
	}
	h.recordMITMBypassEnvironmentConfiguration()
	return h
}

// Handle handles all incoming proxy requests
func (h *ProxyHandler) Handle(w http.ResponseWriter, r *http.Request) {
	if !h.preflightHeaderContract(w, r) {
		return
	}
	if r.Method == http.MethodConnect {
		h.handleConnect(w, r)
		return
	}
	h.handleHTTP(w, r)
}

// handleConnect handles HTTP CONNECT requests for HTTPS tunneling
func (h *ProxyHandler) handleConnect(w http.ResponseWriter, r *http.Request) {
	targetHost := r.Host
	host, port := proxywhitelist.Target(targetHost, 443)
	decision := h.whitelistChecker.decide(r.Context(), host, port, h.exitMode())
	if decision.Reason != "" {
		h.recordWhitelistAudit(r, targetHost, decision)
	}
	if decision.Outcome.Enforce {
		http.Error(w, "host not allowed by whitelist", http.StatusForbidden)
		return
	}
	if !h.guardEgressTarget(w, r, targetHost, 443, decision.TenantID) {
		return
	}

	// 存储/二进制类 host(对象存储/安装包/CDN)只承载非对话内容,MITM 它们既抽不出可审计内容,
	// 又会因 io.ReadAll 整段缓冲拖垮大文件下载(实证:CodeBuddy 自动更新包走 *.blob.core.windows.net
	// 经 MITM 缓冲后下载失败致客户端 500)。这类 host 改走 tunnelDirect 直通:客户端见真实证书、
	// 大文件边下边传。详见 shouldBypassMITM。
	if shouldBypassMITM(targetHost) {
		h.tunnelDirectWithTenant(w, r, targetHost, decision.TenantID)
		return
	}

	h.handleMITM(w, r, targetHost, decision.TenantID, decision.Audit)
}

func (h *ProxyHandler) recordWhitelistAudit(r *http.Request, targetHost string, d whitelistDecision) {
	if h.auditWriter == nil {
		return
	}
	record, err := NewProxyAuditRecord(forwardProxyAuditRequestID(r), d.TenantID, targetHost, r, detectLLMProvider(targetHost, r.URL.Path), false)
	if err != nil {
		log.Printf("Whitelist audit unavailable: %v", err)
		return
	}
	record.ContentRetained, record.RetentionLevel = false, "summary"
	record.InputSemanticStatus, record.InputSemanticReason = "incomplete", d.Reason
	record.InputAuditResult = map[string]interface{}{"action": d.Outcome.Action, "coverage_gap": d.Outcome.Gap, "would_block": d.Reason == "proxy_whitelist_unlisted" && !d.Outcome.Enforce}
	record.Status, record.StatusCode = "in_progress", 0
	if d.Reason == "forward_proxy_tls_uninspected" {
		record.Status, record.StatusCode = "success", http.StatusOK
	}
	if d.Outcome.Enforce {
		record.Status, record.StatusCode = "blocked", http.StatusForbidden
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 5*time.Second)
	defer cancel()
	h.auditWriter.WriteRequestLog(ctx, record)
	h.auditWriter.WriteSecurityEventForRecord(ctx, record, d.Outcome.Action, nil, "input")
}

type forwardProxyAuditRequestIDKey struct{}

func forwardProxyAuditRequestID(r *http.Request) string {
	if requestID, ok := r.Context().Value(forwardProxyAuditRequestIDKey{}).(string); ok {
		return requestID
	}
	requestID := uuid.NewString()
	*r = *r.WithContext(context.WithValue(r.Context(), forwardProxyAuditRequestIDKey{}, requestID))
	return requestID
}

// mitmBypassSuffixes 列出「不做 MITM、直接隧道直通」的 host 后缀。两类:
//
//	(1) 纯二进制/对象存储/CDN/更新域——只传安装包/静态资源/对象,无对话内容可审计,且 MITM 会因
//	    整段缓冲拖垮大文件下载;
//	(2) 「MITM 即破坏其可用性」的应用后端——MITM 后该应用经网关根本跑不起来(实测 CodeBuddy),
//	    留证无从谈起,只能直通让其可用(代价=该应用对话内容不被留证,需 keep-alive 改造才能两全)。
//
// ⚠️默认绝不要放普通 chat/LLM API 域(如 *.deepseek.com / doubao.com / copilot.tencent.com 等),
// 否则会无谓瞎掉其会话留证;只有(2)类「MITM 必坏」的 host 才作为例外加入,且必须注明代价。
// 后缀以前导点开头表示「该域及其子域」,前导点保证 evilblob.core.windows.net 不会误命中 .blob.core.windows.net。
var mitmBypassSuffixes = []string{
	".blob.core.windows.net", // (1) Azure Blob 对象存储(CodeBuddy 自动更新包/工作区产物等纯二进制)
	// 注:CodeBuddy(腾讯) 自有云后端 ride-3-live-webapp.azurewebsites.net 曾因 MITM 无 keep-alive
	// 致其几十个串行 /api/invoke 累计超时报 500 而临时直通(代价:对话不留证)。MITM keep-alive
	// 连接复用上线(env PROXY_MITM_KEEPALIVE)后已摘除该直通——CodeBuddy 重新走 MITM、对话恢复留证。
	// 若 keep-alive 关闭/回退,需把 .ride-3-live-webapp.azurewebsites.net 放回此名单兜底。
}

// mitmBypassSuffixesResolved 返回内置名单 + env PROXY_MITM_BYPASS_SUFFIXES(逗号分隔)扩展项,
// 便于运营按需新增更新/CDN 域而无需重建镜像。env 项统一小写、去空白、忽略空段。
func mitmBypassSuffixesResolved() []string {
	out := append([]string(nil), mitmBypassSuffixes...)
	return append(out, mitmBypassEnvironmentSuffixes()...)
}

// shouldBypassMITM 判断该 CONNECT 目标是否应跳过 MITM、直接隧道直通。
func shouldBypassMITM(targetHost string) bool {
	host := strings.ToLower(hostWithoutPort(targetHost))
	if host == "" {
		return false
	}
	for _, suf := range mitmBypassSuffixesResolved() {
		bare := strings.TrimPrefix(suf, ".")
		if host == bare || strings.HasSuffix(host, suf) {
			return true
		}
	}
	return false
}

// tunnelDirect establishes a direct tunnel without MITM
func (h *ProxyHandler) tunnelDirect(w http.ResponseWriter, r *http.Request, targetHost string) {
	tenantID := "tenant_default"
	if h.whitelistChecker != nil {
		tenantID = proxywhitelist.Tenant(h.whitelistChecker.tenantID)
	}
	h.tunnelDirectWithTenant(w, r, targetHost, tenantID)
}

func (h *ProxyHandler) tunnelDirectWithTenant(w http.ResponseWriter, r *http.Request, targetHost, tenantID string) {
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}

	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	defer clientConn.Close()

	// 双层代理下必须经上层出网代理建 CONNECT 隧道；未配置时与原来等价直拨。
	targetConn, err := h.currentEgressGuard().DialTunnelContext(r.Context(), "tcp", targetHost)
	if err != nil {
		clientConn.Write([]byte(fmt.Sprintf("HTTP/1.1 %d %s\r\n\r\n", http.StatusServiceUnavailable, err.Error())))
		return
	}
	defer targetConn.Close()

	clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
	d := whitelistDecision{TenantID: tenantID, Audit: true, Reason: "forward_proxy_tls_uninspected", Outcome: securityexit.DecideWithPolicy(h.exitMode(), "audit", securityexit.DetectionFailure, securityexit.Policy{})}
	h.recordWhitelistAudit(r, targetHost, d)

	stats := relayTunnel(clientConn, targetConn, blindTunnelMaxDuration)
	// 隧道结束（正常关闭、异常断开或到达时长上限）后回写同一行；失败只打日志，不影响隧道。
	h.recordTunnelTraffic(r, tenantID, stats)
}

// blindTunnelMaxDuration 与改造前一致：直通隧道最长保持 5 分钟。
const blindTunnelMaxDuration = 5 * time.Minute

// tunnelStats 是一条不解密隧道的流量摘要。UpBytes=客户端→目标，DownBytes=目标→客户端。
type tunnelStats struct {
	UpBytes   int64
	DownBytes int64
	Duration  time.Duration
}

// relayTunnel 双向对拷直到任一方向结束或到达 maxDuration，返回双向字节数与持续时长。
// 语义与原 copyData 一致：任一方向结束即关闭两端。字节数直接取 io.Copy 返回值（出错时也返回
// 已拷贝字节），不额外包装读写，保留 TCPConn 的 splice 零拷贝路径；两个方向各写各的原子计数器。
func relayTunnel(clientConn, targetConn net.Conn, maxDuration time.Duration) tunnelStats {
	started := time.Now()
	var up, down atomic.Int64
	done := make(chan struct{}, 2)
	closeBoth := func() {
		_ = clientConn.Close()
		_ = targetConn.Close()
	}
	go func() {
		defer func() { done <- struct{}{} }()
		n, _ := io.Copy(targetConn, clientConn)
		up.Store(n)
		closeBoth()
	}()
	go func() {
		defer func() { done <- struct{}{} }()
		n, _ := io.Copy(clientConn, targetConn)
		down.Store(n)
		closeBoth()
	}()

	timer := time.NewTimer(maxDuration)
	defer timer.Stop()
	select {
	case <-done:
	case <-timer.C:
		closeBoth()
		<-done
	}
	// 两端已关闭，另一方向的 io.Copy 会立即返回；等它把字节数落定。
	<-done
	return tunnelStats{UpBytes: up.Load(), DownBytes: down.Load(), Duration: time.Since(started)}
}

// recordTunnelTraffic 把隧道上/下行字节数与时长回写到建隧道时写入的那一行（同一 request_id），不新增行。
func (h *ProxyHandler) recordTunnelTraffic(r *http.Request, tenantID string, stats tunnelStats) {
	if h.auditWriter == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 5*time.Second)
	defer cancel()
	h.auditWriter.UpdateTunnelTraffic(ctx, forwardProxyAuditRequestID(r), tenantID, stats)
}

// handleMITM performs MITM decryption and inspection
func (h *ProxyHandler) handleMITM(w http.ResponseWriter, r *http.Request, targetHost, tenantID string, auditEnabled bool) {
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}

	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	defer clientConn.Close()

	cert, err := h.caManager.GetCertificate(targetHost)
	if err != nil {
		log.Printf("Failed to get certificate for %s: %v", targetHost, err)
		clientConn.Write([]byte("HTTP/1.1 500 Internal Server Error\r\n\r\n"))
		return
	}

	clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}
	tlsClientConn := tls.Server(clientConn, tlsConfig)

	if err := tlsClientConn.Handshake(); err != nil {
		log.Printf("TLS handshake failed for %s: %v", targetHost, err)
		return
	}
	defer tlsClientConn.Close()

	clientReader := bufio.NewReader(tlsClientConn)

	// 默认关(env PROXY_MITM_KEEPALIVE 未开):跑且仅跑一次 serveOneMITMRequest(useKeepAlive=false)
	// 后 return。内部上游恒走原 DialTLSContext 手拨 + clientReq.Write,与改造前逐字节等价。
	// 且默认关路径不设 read deadline——保持原阻塞读语义不变。这是「承重墙纪律」根基。
	if !keepAliveMITMEnabled() {
		h.serveOneMITMRequest(tlsClientConn, clientReader, r, targetHost, tenantID, auditEnabled, false)
		return
	}

	// 开启 keep-alive:同一 MITM 隧道上循环服务多个请求,直到客户端 Connection:close、
	// 空闲超时、或任一不可复用条件触发(serveOneMITMRequest 返回 false)。
	idle := mitmIdleTimeout()
	for {
		_ = tlsClientConn.SetReadDeadline(time.Now().Add(idle))
		if !h.serveOneMITMRequest(tlsClientConn, clientReader, r, targetHost, tenantID, auditEnabled, true) {
			return
		}
	}
}

// serveOneMITMRequest 在一条已建立的 MITM 隧道上服务一个 HTTP 请求轮次:读请求→detect→审计四件套
// (WriteRequestLog/CheckInput/CheckOutput/留证)→上游交互(双模)→回写。返回值 keepAlive 报告本隧道
// 是否应继续复用(仅 useKeepAlive 且客户端未声明 Connection:close 且本轮全程无异常时为 true)。
//
// 不变量:每轮新建 auditRecord(空 RequestID → audit.go 自动 uuid),审计四件套每轮都过——逐请求审计
// 不退化。audit-only 不可破:不新增任何 block 路径,sendBlockedResponse 仅在原 CheckInput/CheckOutput
// 受限文件的管理员显式拒绝是例外，见 mergeRestrictedFileOutput。
// action=block/reply 时触发(audit-only 下永不可达)。
func (h *ProxyHandler) serveOneMITMRequest(tlsClientConn *tls.Conn, clientReader *bufio.Reader, r *http.Request, targetHost, tenantID string, auditEnabled, useKeepAlive bool) (keepAlive bool) {
	clientReq, err := http.ReadRequest(clientReader)
	if err != nil {
		// 隧道正常结束:客户端关闭(EOF)或 keep-alive 空闲超时(net.Error.Timeout())——静默收尾。
		if err == io.EOF {
			return false
		}
		if ne, ok := err.(net.Error); ok && ne.Timeout() {
			return false
		}
		log.Printf("Failed to read request from %s: %v", targetHost, err)
		return false
	}

	// 读到请求头后立即清除 read deadline:循环顶设的 idle deadline 仅用于「等下一个请求头」的空闲
	// 等待,绝不能覆盖本轮的 body 读取 / 上游 RoundTrip / 回写——否则慢上游或长 SSE 一超 idle 就被
	// i/o timeout 掐断(还会被上面 ReadRequest 的 Timeout() 分支在下一轮静默吞掉)。下一轮循环顶会
	// 重新武装 deadline。默认关路径从不设 deadline,此清除对其为无害幂等(time.Time{} 表示无超时)。
	_ = tlsClientConn.SetReadDeadline(time.Time{})

	clientReq.RemoteAddr = r.RemoteAddr
	if status, code, message, conflict := h.headerContractDecision(clientReq); conflict {
		_ = writeMITMHeaderContractError(tlsClientConn, status, code, message)
		return false
	}
	providerMatch := detectLLMProvider(targetHost, clientReq.URL.Path)
	requestDecoder, responseDecoder := detectLLMDecoders(targetHost, clientReq.URL.Path)
	isLLMRequest := providerMatch.Known
	fileDLPBodyCandidate := auditEnabled && h.securityClient != nil &&
		h.securityClient.fileDLPEnabled(context.Background()) && requestHasBody(clientReq)
	// 遥测端点免送检:打点/计数类内容进 DLP/命令检测只会产出误报(Copilot telemetry
	// 曾刷出数千条 illegal_system_command)。仅跳过 CheckInput/CheckOutput,留证
	// (WriteRequestLog/WriteAccessContentLog)照常,不新增任何 block 路径。
	scanExempt := isScanExemptRequest(requestDecoder)
	auditRecord, auditErr := NewProxyAuditRecord("", tenantID, targetHost, clientReq, providerMatch, true)
	if auditErr != nil {
		_ = writeMITMHeaderContractError(tlsClientConn, http.StatusServiceUnavailable, "header_conflict_audit_unavailable", "security audit unavailable")
		return false
	}
	scanCtx := context.Background()
	// A full inspection queue is a coverage gap governed by the independent
	// capacity policy. Fail-open forwards without buffering; fail-closed rejects.
	capacityGap := false
	if auditEnabled && !scanExempt && h.securityClient != nil && h.securityClient.inspectionQueue != nil && (clientReq.ContentLength < 0 || clientReq.ContentLength > 8*1024*1024) {
		wait, cancel := context.WithTimeout(scanCtx, inspectionAdmissionWait)
		release, err := h.securityClient.inspectionQueue.admit(wait)
		cancel()
		if err != nil {
			capacityGap = true
		} else {
			defer release()
			scanCtx = context.WithValue(scanCtx, inspectionPermitKey{}, true)
		}
	}
	var requestBody []byte
	fileRequestCandidate := requestMayContainFile(clientReq)
	jsonRequestCandidate := requestMayContainJSON(clientReq)
	if (isLLMRequest || fileRequestCandidate || jsonRequestCandidate || fileDLPBodyCandidate) && auditEnabled && !capacityGap {
		var readErr error
		requestBody, readErr = readAndRestoreRequestBody(clientReq)
		if readErr != nil {
			log.Printf("Failed to read request body for access retention: %v", readErr)
			_ = writeMITMHeaderContractError(tlsClientConn, http.StatusBadRequest, "request_body_unavailable", "请求体未完整接收，未向上游转发")
			return false
		} else if !fileRequestCandidate && (jsonRequestCandidate || fileDLPBodyCandidate) {
			fileRequestCandidate = len(extractRequestContentWithDecoder(clientReq, requestBody, requestDecoder).Attachments) > 0
		}
	}
	// keep-alive 模式下非 LLM 请求也要能把 body 转发给上游(走 RoundTrip 需可重读 body)。
	// 若上面的 LLM 留证分支未读 body(非 LLM 或未开审计),这里兜底读出并复原,确保 requestBody 可用。
	// 注意:仅在 keep-alive 模式补读,绝不改变默认关路径(原条件)的行为。
	if useKeepAlive && requestBody == nil && !capacityGap {
		var readErr error
		requestBody, readErr = readAndRestoreRequestBody(clientReq)
		if readErr != nil {
			log.Printf("Failed to read request body for keep-alive forward: %v", readErr)
			return false
		}
	}
	if (auditRecord.AgentType == "" || auditRecord.AgentType == "main") && len(requestBody) > 0 {
		structuredRequest := extractRequestContentWithDecoder(clientReq, requestBody, requestDecoder)
		if inferred := inferStructuredAgentType(structuredRequest.Messages); inferred != "" {
			auditRecord.AgentType = inferred
		}
	}
	if auditRecord.AgentType == "workbuddy" && len(requestBody) > 0 {
		structuredRequest := extractRequestContentWithDecoder(clientReq, requestBody, requestDecoder)
		auditRecord.EvidenceRunID = workBuddyProxyTaskID(tenantID, structuredRequest.Messages)
	}
	// Task 3b: attribute the request to the upstream account / credential behind the
	// NAT address. Headers come from the client request, the Anthropic account from
	// the decoded body; only llm / ai_ide targets are considered.
	auditRecord = auditRecord.WithUpstreamPrincipal(tenantID, clientReq.Header, requestBody, providerMatch)
	if auditEnabled {
		h.auditWriter.WriteRequestLog(context.Background(), auditRecord)
	}

	if auditEnabled && capacityGap {
		gap := securityexit.DecideWithPolicy(h.exitMode(), "", securityexit.Capacity, h.securityClient.detectionPolicy())
		auditRecord = auditRecord.WithInputAudit(gap.Action, nil)
		auditRecord.InputSemanticStatus, auditRecord.InputSemanticReason = "incomplete", "inspection_admission_timeout"
		auditRecord.ScanMode = "durable_inspection"
		h.auditWriter.WriteRequestLog(context.Background(), auditRecord)
		h.auditWriter.WriteSecurityEventForRecord(context.Background(), auditRecord, gap.Action, nil, "input")
		if gap.Enforce {
			auditRecord.Status, auditRecord.StatusCode = "blocked", http.StatusServiceUnavailable
			h.auditWriter.WriteRequestLog(context.Background(), auditRecord)
			_ = writeMITMHeaderContractError(tlsClientConn, http.StatusServiceUnavailable, "inspection_capacity_unavailable", inspectionCapacityUnavailableMessage)
			return false
		}
	}
	if auditEnabled && !capacityGap && !scanExempt && h.securityClient != nil && (isLLMRequest || fileRequestCandidate) {
		action, findings, fpMeta := h.securityClient.CheckInput(scanCtx, tenantID, auditRecord.RequestID, clientReq)
		auditRecord = auditRecord.WithInputAudit(action, findings)
		if fpMeta != nil {
			auditRecord.InputSemanticStatus, auditRecord.InputSemanticReason = fpMeta.SemanticStatus, fpMeta.SemanticReason
			auditRecord.ScanMode = fpMeta.ScanMode
			auditRecord.FirstSeenRequestID = fpMeta.FirstSeenRequestID
		}

		blocked := securityexit.Blocks(action)
		// 任务 7.4：Codex 附件清单（# Files … by the user:）按受限文件模式拦截。
		// 命中合成 stage=input finding 并入 blocked 判定；审计模式下只记。
		if rfAction, rfFindings, rfBlocked := h.checkCodexMentionedFilesRestrictedInput(tenantID, auditRecord, clientReq, requestBody, requestDecoder); len(rfFindings) > 0 {
			findings = append(findings, rfFindings...)
			if inspectionActionRank(rfAction) > inspectionActionRank(action) {
				action = rfAction
			}
			auditRecord = auditRecord.WithInputAudit(action, findings)
			if rfBlocked {
				blocked = true
			}
		}
		if fileRequestCandidate && fileDLPActionBlocksExternalSend(action) {
			blocked = true
		}
		if blocked && !securityexit.Decide(h.exitMode(), "block", securityexit.RuleHit).Enforce {
			// 纵深防御：记录模式下任何安全原因都不中断请求，命中照常留痕为 audit。
			blocked = false
			action = securityexit.Clamp(securityexit.Record, action)
			auditRecord = auditRecord.WithInputAudit(action, findings)
		}
		if blocked {
			status, code := inputBlockResponse(fpMeta, findings)
			auditRecord.Status, auditRecord.StatusCode = "blocked", status
			h.auditWriter.WriteRequestLog(context.Background(), auditRecord)
			blockID := h.auditWriter.WriteSecurityEventForRecord(context.Background(), auditRecord, action, findings, "input")
			if code == "request_body_limit_exceeded" {
				_ = writeMITMHeaderContractError(tlsClientConn, status, code, "请求体超过安全检测上限，本次请求未转发")
			} else if status == http.StatusServiceUnavailable {
				_ = writeMITMHeaderContractError(tlsClientConn, status, code, inspectionUnavailableMessage(code))
			} else {
				h.sendBlockedResponse(tlsClientConn, auditRecord.RequestID, findings, blockID)
			}
			if auditRecord.ContentRetained {
				reqContent, respContent := resolveRetainedContents(tenantID, providerMatch.Provider, extractRequestContentWithDecoder(clientReq, requestBody, requestDecoder), ExtractedContent{})
				hydrateFileIDAttachments(context.Background(), clientReq, targetHost, providerMatch.Provider, &reqContent, &respContent)
				enrichAPIConversationKey(tenantID, auditRecord.AgentType, &reqContent, clientReq)
				h.auditWriter.WriteAccessContentLog(context.Background(), auditRecord, reqContent, respContent)
			}
			// block 后不复用本隧道。
			return false
		}
		h.auditWriter.WriteRequestLog(context.Background(), auditRecord)
		h.auditWriter.WriteSecurityEventForRecord(context.Background(), auditRecord, action, findings, "input")
	}

	// 上游交互双模:
	//  (A) keep-alive 且非 Upgrade(WebSocket 等):用缓存的 h1 transport.RoundTrip(连接池复用上游连接);
	//  (B) 默认关 / Upgrade 兜底:原 DialTLSContext 手拨 + clientReq.Write + ReadResponse,一字不改,
	//      与改造前字节级等价。
	var resp *http.Response
	if useKeepAlive && clientReq.Header.Get("Upgrade") == "" {
		outReq := buildUpstreamRequest(clientReq, targetHost, requestBody)
		if capacityGap {
			// 容量缺口路径未缓冲请求体：原样流式转发，不可重放。
			outReq.Body, outReq.ContentLength, outReq.GetBody = clientReq.Body, clientReq.ContentLength, nil
		}
		var rtErr error
		resp, rtErr = h.mitmKeepAliveTransport().RoundTrip(outReq)
		if rtErr != nil {
			log.Printf("Failed to roundtrip to %s: %v", targetHost, rtErr)
			return h.failMITMUpstream(tlsClientConn, auditEnabled, auditRecord)
		}
	} else {
		// 同理：配置了上层出网代理时先建隧道再握手，否则 ClientHello 会灌给代理。
		targetConn, derr := h.currentEgressGuard().DialTLSThroughTunnel(context.Background(), "tcp", targetHost, &tls.Config{ServerName: hostWithoutPort(targetHost), MinVersion: tls.VersionTLS12})
		if derr != nil {
			log.Printf("Failed to connect to target %s: %v", targetHost, derr)
			return h.failMITMUpstream(tlsClientConn, auditEnabled, auditRecord)
		}
		defer targetConn.Close()

		if werr := clientReq.Write(targetConn); werr != nil {
			log.Printf("Failed to forward request to %s: %v", targetHost, werr)
			return h.failMITMUpstream(tlsClientConn, auditEnabled, auditRecord)
		}

		targetReader := bufio.NewReader(targetConn)
		resp, err = http.ReadResponse(targetReader, clientReq)
		if err != nil {
			log.Printf("Failed to read response from %s: %v", targetHost, err)
			return h.failMITMUpstream(tlsClientConn, auditEnabled, auditRecord)
		}
	}

	// 流式回写分支（默认关闭，由运营经 env PROXY_STREAM_LLM_RESPONSES 显式开启）。
	// 背景：原 buffer 路径对响应体先 io.ReadAll 整段缓冲、扫完输出 DLP 才一次性回写浏览器；
	// 对豆包/Kimi 等 SSE/connect+json 流式 UI，浏览器在生成期间收不到任何增量、末尾才一次性
	// 收到整段 → 流式对话不渲染。本分支边流式回写浏览器边 tee 一份到 buf，流完用 buf 做
	// 非阻塞的输出审计 + 留证。
	// 安全前提：仅在 audit-only(CheckOutput 永不拦) 时启用——开关由运营声明。streamEligible
	// 含 auditEnabled 与 isModelReplyContentType，且 env 默认 false → 默认恒走下方原 buffer 路径，
	// 行为与现在逐字节一致（安全部署 + 一键回退的根基）。keep-alive 与 stream 两 flag 正交可叠加。
	streamEligible := streamLLMResponsesEnabled() && h.exitMode() == securityexit.Record && isLLMRequest && auditEnabled &&
		isModelReplyContentType(resp.Header.Get("Content-Type"))
	if streamEligible {
		contentEncoding := resp.Header.Get("Content-Encoding")
		respContentType := resp.Header.Get("Content-Type")

		// targetResp.Write 写完 header 后用 io.Copy 拷贝 Body（边读边写=流式）；把 Body 换成
		// TeeReader → Write 在向客户端逐字节回写的同时把同样的字节 tee 进 buf。tlsClientConn
		// 是裸 conn 无写缓冲，逐写即 flush。中间绝不再对 Body 做 io.ReadAll，保证不引入整段缓冲。
		var buf bytes.Buffer
		origBody := resp.Body
		resp.Body = io.NopCloser(io.TeeReader(origBody, &buf))
		writeErr := resp.Write(tlsClientConn)
		// 归池铁律:Write 内部 io.Copy 拖完 Body;writeErr(客户端断)时 Body 可能半读,
		// 显式拖尽 + Close 兜底,让 keep-alive 上游连接可被 Transport 安全归池。
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = origBody.Close()

		// Write 返回后 buf 即完整响应体（与原路径同样是压缩字节）；客户端断开导致 writeErr 时
		// buf 可能不全，留证尽力而为、状态记 client_write_error。
		respBody := buf.Bytes()
		inspectBody := decodeContentEncoding(respBody, contentEncoding)

		if isLLMRequest && auditEnabled {
			dumpRawExchange(providerMatch.Provider, targetHost, clientReq.URL.Path,
				clientReq.Header.Get("Content-Type"), respContentType,
				requestBody, inspectBody)
		}

		// 输出审计：流已发出，这里只记审计/安全事件，绝不 sendBlockedResponse（响应已回写无法拦）。
		// audit-only 下 CheckOutput 永远返回 audit；若 env 被误开在非 audit-only 环境而 action=block，
		// 也仅记日志告警，绝不改变已发送的响应。
		if isModelReplyContentType(respContentType) && !scanExempt {
			auditRecord.OutputAlreadySent = true
			action, findings, outputMeta := h.securityClient.CheckOutputDetailed(context.Background(), tenantID, providerMatch, inspectBody, respContentType)
			if fileDLPActionBlocksExternalSend(action) {
				action = "audit"
			}
			if outputMeta != nil {
				auditRecord.OutputSemanticStatus, auditRecord.OutputSemanticReason = outputMeta.SemanticStatus, outputMeta.SemanticReason
			}
			auditRecord = auditRecord.WithOutputAudit(action, findings)
			h.auditWriter.WriteSecurityEventForRecord(context.Background(), auditRecord, action, findings, "output")
			if action == "block" || action == "reply" {
				log.Printf("[stream] WARN: output action=%s 但响应已流式发出(audit-only 预期不应发生): host=%s", action, targetHost)
			}
		}

		if writeErr != nil {
			log.Printf("Failed to stream response to client: %v", writeErr)
		}

		if auditEnabled {
			auditRecord.Status = "success"
			if writeErr != nil {
				auditRecord.Status = "client_write_error"
			}
			auditRecord.StatusCode = resp.StatusCode
			auditRecord.ResponseBytes = int64(len(respBody))
			h.auditWriter.WriteRequestLog(context.Background(), auditRecord)
			if writeErr == nil {
			}
			if isLLMRequest && auditRecord.ContentRetained {
				reqContent, respContent := resolveRetainedContents(tenantID, providerMatch.Provider, extractRequestContentWithDecoder(clientReq, requestBody, requestDecoder), extractRetainableResponseContentWithDecoder(inspectBody, respContentType, responseDecoder))
				hydrateFileIDAttachments(context.Background(), clientReq, targetHost, providerMatch.Provider, &reqContent, &respContent)
				enrichAPIConversationKey(tenantID, auditRecord.AgentType, &reqContent, clientReq)
				h.auditWriter.WriteAccessContentLog(context.Background(), auditRecord, reqContent, respContent)
			}
		}
		// 客户端写出错 → 不复用本隧道(客户端已断);否则按客户端/上游 Connection:close 意图决定复用。
		if writeErr != nil {
			return false
		}
		return keepAliveDecision(useKeepAlive, clientReq.Close, resp.Close)
	}

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("Failed to read response body: %v", err)
		resp.Body.Close()
		return h.failMITMUpstream(tlsClientConn, auditEnabled, auditRecord)
	}
	resp.Body.Close()

	// 网页大模型响应几乎都带 Content-Encoding（br/gzip/zstd）。原始压缩字节照常回写客户端，
	// 但安全检测与访问留存抽取必须用解压后的明文，否则正文是乱码、敏感数据漏检、留存里全是编码。
	inspectBody := decodeContentEncoding(respBody, resp.Header.Get("Content-Encoding"))

	// 诊断开关（默认关闭，见 dumpRawExchange/rawDumpDir）开启时，把这次正向代理 LLM 交互的
	// 原始请求体与解压后的响应体原样落盘，供离线复现 content_extractor 的抽取缺口——线上不保留
	// 任何原始字节，只能在这唯一能看到 MITM 明文的进程里临时采集。
	if isLLMRequest && auditEnabled {
		dumpRawExchange(providerMatch.Provider, targetHost, clientReq.URL.Path,
			clientReq.Header.Get("Content-Type"), resp.Header.Get("Content-Type"),
			requestBody, inspectBody)
	}

	// 输出 DLP 只针对「模型回复正文」(JSON/SSE/纯文本等会话内容)。大模型网页版的
	// App 交付字节——导航 HTML 外壳、压缩 JS/CSS、图片/字体/二进制——是厂商公开前端
	// 代码，对其做密钥/敏感词检测语义上就是错的，且 secret_openai_key(sk-...) 必然在
	// 压缩 JS 词碎片上误报、403 拦死页面外壳/主包导致网页版打不开。故此类内容体跳过
	// 输出检测、原样回写；真会话回复(SSE/JSON/text)仍照常进 CheckOutput。
	if isLLMRequest && auditEnabled && !scanExempt && isModelReplyContentType(resp.Header.Get("Content-Type")) {
		action, findings, outputMeta := h.securityClient.CheckOutputDetailed(context.Background(), tenantID, providerMatch, inspectBody, resp.Header.Get("Content-Type"))
		if outputMeta != nil {
			auditRecord.OutputSemanticStatus, auditRecord.OutputSemanticReason = outputMeta.SemanticStatus, outputMeta.SemanticReason
		}
		// 受限文件模式：对本轮模型工具调用跑 filerestrict，命中合成 finding 并入判定。
		// 审计模式下一律只记；防护模式下配置 block 才拦。
		action, findings = h.mergeRestrictedFileOutput(tenantID, auditRecord, inspectBody, resp.Header.Get("Content-Type"), action, findings)
		auditRecord = auditRecord.WithOutputAudit(action, findings)

		if securityexit.Decide(h.exitMode(), action, securityexit.RuleHit).Enforce {
			status, code := inputBlockResponse(outputMeta, findings)
			auditRecord.Status, auditRecord.StatusCode = "blocked", status
			auditRecord.ResponseBytes = int64(len(respBody))
			h.auditWriter.WriteRequestLog(context.Background(), auditRecord)
			blockID := h.auditWriter.WriteSecurityEventForRecord(context.Background(), auditRecord, action, findings, "output")
			if status == http.StatusServiceUnavailable {
				_ = writeMITMHeaderContractError(tlsClientConn, status, code, inspectionUnavailableMessage(code))
			} else {
				h.sendBlockedResponse(tlsClientConn, auditRecord.RequestID, findings, blockID)
			}
			if auditRecord.ContentRetained {
				reqContent, respContent := resolveRetainedContents(tenantID, providerMatch.Provider, extractRequestContentWithDecoder(clientReq, requestBody, requestDecoder), extractRetainableResponseContentWithDecoder(inspectBody, resp.Header.Get("Content-Type"), responseDecoder))
				hydrateFileIDAttachments(context.Background(), clientReq, targetHost, providerMatch.Provider, &reqContent, &respContent)
				enrichAPIConversationKey(tenantID, auditRecord.AgentType, &reqContent, clientReq)
				h.auditWriter.WriteAccessContentLog(context.Background(), auditRecord, reqContent, respContent)
			}
			// block 后不复用本隧道。
			return false
		}

		h.auditWriter.WriteSecurityEventForRecord(context.Background(), auditRecord, action, findings, "output")
	}

	resp.Body = io.NopCloser(bytes.NewReader(respBody))
	resp.ContentLength = int64(len(respBody))

	writeErr := resp.Write(tlsClientConn)
	if writeErr != nil {
		log.Printf("Failed to send response to client: %v", writeErr)
	}

	if auditEnabled {
		auditRecord.Status = "success"
		auditRecord.StatusCode = resp.StatusCode
		auditRecord.ResponseBytes = int64(len(respBody))
		h.auditWriter.WriteRequestLog(context.Background(), auditRecord)
		if writeErr == nil {
		}
		if isLLMRequest && auditRecord.ContentRetained {
			reqContent, respContent := resolveRetainedContents(tenantID, providerMatch.Provider, extractRequestContentWithDecoder(clientReq, requestBody, requestDecoder), extractRetainableResponseContentWithDecoder(inspectBody, resp.Header.Get("Content-Type"), responseDecoder))
			hydrateFileIDAttachments(context.Background(), clientReq, targetHost, providerMatch.Provider, &reqContent, &respContent)
			enrichAPIConversationKey(tenantID, auditRecord.AgentType, &reqContent, clientReq)
			h.auditWriter.WriteAccessContentLog(context.Background(), auditRecord, reqContent, respContent)
		}
	}

	// 缓冲分支:Body 已 io.ReadAll 读尽(归池铁律满足)。writeErr → 客户端已断,不复用本隧道。
	if writeErr != nil {
		return false
	}
	return keepAliveDecision(useKeepAlive, clientReq.Close, resp.Close)
}

// keepAliveMITMEnabled 报告是否开启 MITM 隧道连接复用(keep-alive)。默认关闭:仅当
// PROXY_MITM_KEEPALIVE == "true" / "1"(大小写不敏感、去空白)时返回 true。默认 false 时每条
// MITM 隧道仍只处理一个请求,行为与开关引入前逐字节一致(安全部署 + 一键回退)。
func keepAliveMITMEnabled() bool {
	v := strings.ToLower(strings.TrimSpace(os.Getenv("PROXY_MITM_KEEPALIVE")))
	return v == "true" || v == "1"
}

// telemetryScanExemptEnabled 报告「遥测端点免送检」是否开启。默认开启:仅当
// PROXY_TELEMETRY_SCAN_EXEMPT 显式设为 "false" / "0"(大小写不敏感、去空白)时关闭,
// 作为误免检时的一键回退口。
func telemetryScanExemptEnabled() bool {
	v := strings.ToLower(strings.TrimSpace(os.Getenv("PROXY_TELEMETRY_SCAN_EXEMPT")))
	return v != "false" && v != "0"
}

// isScanExemptRequest 报告本次请求是否免于安全送检(CheckInput/CheckOutput)。
// 遥测类端点(catalog 中 request_decoder == "telemetry",如 Copilot telemetry 打点)
// 承载的是客户端计数/环境指纹,对其做 DLP/命令检测语义上就是错的,只会产出误报;
// 免检只跳过送检,留证不受影响,也不因此新增任何 block 路径。免检范围锚定 decoder
// 而非 host,对话/补全端点(copilot/chat 等 decoder)永不免检。
func isScanExemptRequest(requestDecoder string) bool {
	return requestDecoder == "telemetry" && telemetryScanExemptEnabled()
}

// mitmIdleTimeout 返回 keep-alive 模式下同隧道相邻请求之间的最大空闲等待(读超时)。读 env
// PROXY_MITM_IDLE_TIMEOUT(单位秒,正整数);空/非法/非正 → 默认 90s。
func mitmIdleTimeout() time.Duration {
	raw := strings.TrimSpace(os.Getenv("PROXY_MITM_IDLE_TIMEOUT"))
	if raw == "" {
		return 90 * time.Second
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n <= 0 {
		return 90 * time.Second
	}
	return time.Duration(n) * time.Second
}

// keepAliveDecision 判定一个成功完成的请求轮次后是否应继续复用本 MITM 客户端隧道:
// 仅当本轮以 keep-alive 模式服务、且客户端未声明 Connection:close、且上游也未声明 Connection:close
// 时为 true。上游 resp.Close 表示上游本次连接意图关闭——此时上游已无法在本逻辑连接上续答,客户端
// 隧道继续复用没有意义且易诱发不一致,故一并收尾(注意:这只影响「客户端隧道是否再服务下一个请求」,
// 上游物理连接是否归池仍由 Transport 按 Body 是否读尽独立自管)。
// inspectionAdmissionWait bounds how long a large request waits for an
// inspection slot before it is forwarded as a coverage gap. A variable so
// tests can shorten it.
var inspectionAdmissionWait = 45 * time.Second

func keepAliveDecision(useKeepAlive, clientReqClose, respClose bool) bool {
	return useKeepAlive && !clientReqClose && !respClose
}

// buildUpstreamRequest 把一个从客户端读到的 MITM 请求改写成可供 http.Client/Transport.RoundTrip
// 发往上游的请求:补全 https scheme + 目标 host、清空 RequestURI(client 模式必须)、用 requestBody
// 构造可重读 Body + GetBody、剥离逐跳头、解耦 Close。原 clientReq 不被改动(Clone)。
//
// GetBody(承重):让 Transport 在连接池里命中 stale(对端已半关)连接时,能安全重发这个已知 body
// 的幂等/可重试请求——否则 net/http 对带 body 的 POST 不敢重试,概率性返回 502 并断隧道。
// Close=false(解耦):Clone 会把 clientReq.Close 复制过来;客户端隧道 Connection:close 不应连累上游
// 连接用后即弃。客户端隧道复用与上游连接复用相互独立——客户端隧道收尾由 keepAliveDecision 决定,
// 上游复用由 Transport 按 Body 是否读尽自管。
func buildUpstreamRequest(clientReq *http.Request, targetHost string, requestBody []byte) *http.Request {
	outReq := clientReq.Clone(context.Background())
	outReq.URL.Scheme = "https"
	outReq.URL.Host = targetHost
	outReq.RequestURI = ""
	outReq.Body = io.NopCloser(bytes.NewReader(requestBody))
	outReq.ContentLength = int64(len(requestBody))
	outReq.GetBody = func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(requestBody)), nil
	}
	outReq.Close = false
	removeHopByHopHeaders(outReq.Header)
	return outReq
}

// removeHopByHopHeaders 删除逐跳头(RFC 7230 §6.1):Connection 头里逐条列出的字段,
// 加上固定的逐跳头集合。这些头属于单跳连接管理,不应转发给上游。
func removeHopByHopHeaders(header http.Header) {
	for _, listed := range header[http.CanonicalHeaderKey("Connection")] {
		for _, f := range strings.Split(listed, ",") {
			if name := strings.TrimSpace(f); name != "" {
				header.Del(name)
			}
		}
	}
	for _, hop := range []string{
		"Connection", "Proxy-Connection", "Keep-Alive",
		"Proxy-Authenticate", "Proxy-Authorization",
		"Te", "Trailer", "Transfer-Encoding", "Upgrade",
	} {
		header.Del(hop)
	}
}

// failMITMUpstream 收尾 MITM 上游失败（拨号、写请求、读响应头、读响应体）：给客户端回 502 并关隧道，
// 审计记 error/502。以前除 keep-alive RoundTrip 外都直接 return，request_logs 停在 in_progress。
// MITM 的上游 ctx 派生自 Background，这些失败不会是客户端断开导致的，按真实上游失败记。
func (h *ProxyHandler) failMITMUpstream(tlsClientConn net.Conn, auditEnabled bool, auditRecord ProxyAuditRecord) bool {
	_, _ = tlsClientConn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"))
	if auditEnabled {
		auditRecord.Status, auditRecord.StatusCode = "error", http.StatusBadGateway
		h.auditWriter.WriteRequestLog(context.Background(), auditRecord)
	}
	return false
}

// mitmKeepAliveTransport 懒初始化并缓存「MITM keep-alive 专用」上游 transport。基于 egressGuard
// 的 guarded DialContext 保 SSRF 防护;强制 HTTP/1.1(ForceAttemptHTTP2=false +
// TLSClientConfig.NextProtos=["http/1.1"]),对齐现网手拨上游路径,避免 h2 改变 SSE 时序/framing。
// 必须缓存复用(sync.Once)——否则每请求新建 transport=无连接池=keep-alive 改造失效。
// 不动共享 transport(handleHTTP 仍用 h2 版)。
//
// DisableCompression=true(承重):Go Transport 对「客户端未带 Accept-Encoding」的请求会自动注入
// Accept-Encoding:gzip 并对响应透明解压——剥掉 Content-Encoding 头、置 resp.Uncompressed=true、改写
// Content-Length。这会让 keep-alive 回写客户端的字节与手拨 ReadResponse 路径漂移;更危险的是流式
// gzip(非 chunked)解压后既无 Content-Length 也无 Transfer-Encoding → resp.Write 产出无定界响应 →
// 客户端挂起/读串包。设 DisableCompression=true 使其与手拨 ReadResponse 一样恒透传原始压缩字节。
// ResponseHeaderTimeout:上游建连后迟迟不回响应头时给个上界,避免无界阻塞占住隧道。
func (h *ProxyHandler) mitmKeepAliveTransport() http.RoundTripper {
	h.mitmKeepAliveOnce.Do(func() {
		tr := h.currentEgressGuard().HTTPTransport() // clone DefaultTransport + guarded DialContext
		// Proxy 每次请求现查，不在这里快照：这个 transport 是 sync.Once 懒初始化的,
		// 若它先于上层出网代理配置完成初始化,快照会永久是 nil,MITM keep-alive
		// 路径就静默直连出网(实测确认)。现查让顺序不再影响正确性。
		tr.Proxy = func(req *http.Request) (*url.URL, error) {
			if guard := h.currentEgressGuard(); guard != nil && guard.upstreamProxy != nil {
				return guard.upstreamProxy, nil
			}
			// 未配置时保持 DefaultTransport 原语义（含 NO_PROXY 判定），
			// 所以要把真实请求传进去，不能用合成请求。
			return http.ProxyFromEnvironment(req)
		}
		tr.ForceAttemptHTTP2 = false
		tr.DisableCompression = true
		tr.ResponseHeaderTimeout = 60 * time.Second
		if tr.TLSClientConfig == nil {
			tr.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
		} else {
			tr.TLSClientConfig = tr.TLSClientConfig.Clone()
		}
		tr.TLSClientConfig.NextProtos = []string{"http/1.1"}
		h.mitmKeepAliveRT = tr
	})
	return h.mitmKeepAliveRT
}

func extractRetainableResponseContent(body []byte, contentType string) ExtractedContent {
	return extractRetainableResponseContentWithDecoder(body, contentType, "")
}

func extractRetainableResponseContentWithDecoder(body []byte, contentType, decoderName string) ExtractedContent {
	if !isModelReplyContentType(contentType) {
		return ExtractedContent{}
	}
	return extractResponseContentWithDecoder(body, contentType, decoderName)
}

// isLLMRequest checks whether a host/path pair belongs to a supported LLM provider.
func (h *ProxyHandler) isLLMRequest(host, path string) bool {
	return detectLLMProvider(host, path).Known
}

func (h *ProxyHandler) currentEgressGuard() *EgressGuard {
	if h != nil && h.egressGuard != nil {
		return h.egressGuard
	}
	return NewEgressGuard(nil, nil)
}

func (h *ProxyHandler) currentTransport() http.RoundTripper {
	if h != nil && h.transport != nil {
		return h.transport
	}
	return h.currentEgressGuard().HTTPTransport()
}

// handleHTTP handles regular HTTP requests (non-CONNECT)
func (h *ProxyHandler) handleHTTP(w http.ResponseWriter, r *http.Request) {
	port := 80
	if r.URL.Scheme == "https" {
		port = 443
	}
	host, port := proxywhitelist.Target(r.URL.Host, port)
	decision := h.whitelistChecker.decide(r.Context(), host, port, h.exitMode())
	if decision.Reason != "" {
		h.recordWhitelistAudit(r, r.URL.Host, decision)
	}
	if decision.Outcome.Enforce {
		http.Error(w, "host not allowed by whitelist", http.StatusForbidden)
		return
	}
	if !h.guardEgressTarget(w, r, net.JoinHostPort(host, strconv.Itoa(port)), port, decision.TenantID) {
		return
	}
	tenantID := decision.TenantID
	var auditRecord *ProxyAuditRecord
	if h.auditWriter != nil {
		record, err := NewProxyAuditRecord(forwardProxyAuditRequestID(r), tenantID, r.Host, r, detectLLMProvider(r.Host, r.URL.Path), false)
		if err != nil {
			http.Error(w, "security audit unavailable", http.StatusServiceUnavailable)
			return
		}
		record = record.WithUpstreamPrincipal(tenantID, r.Header, nil, detectLLMProvider(r.Host, r.URL.Path))
		auditRecord = &record
		h.auditWriter.WriteRequestLog(r.Context(), record)
		defer func() { h.auditWriter.WriteRequestLog(context.Background(), *auditRecord) }()
	}
	requestDecoder, _ := detectLLMDecoders(r.Host, r.URL.Path)
	if h.securityClient != nil && requestHasBody(r) && !isScanExemptRequest(requestDecoder) {
		shouldCheck := requestMayContainFile(r) || (h.securityClient.inspectionQueue != nil && h.isLLMRequest(r.Host, r.URL.Path))
		if !shouldCheck && requestMayContainJSON(r) {
			body, oversized, err := readAndRestoreRequestBodyLimited(r, fileDLPRequestLimitBytes())
			if err != nil {
				http.Error(w, "failed to read request body", http.StatusBadRequest)
				return
			}
			shouldCheck = oversized || len(extractRequestContent(r, body).Attachments) > 0
		}
		if shouldCheck {
			requestID := uuid.NewString()
			if auditRecord != nil {
				requestID = auditRecord.RequestID
			}
			action, findings, meta := h.securityClient.CheckInput(r.Context(), tenantID, requestID, r)
			if meta != nil && meta.ClientGone {
				// 客户端在安全检测期间断开（Esc / 中断）：不是检测失败也不是拦截。不转发上游、不走 fail-closed、
				// 不写安全事件；审计不带这次失败的 input 结论，由 defer 收尾（脱离请求取消）记 cancelled/408。
				log.Printf("Forward proxy request cancelled during input security check (request=%s)", requestID)
				if auditRecord != nil {
					auditRecord.Status, auditRecord.StatusCode = "cancelled", http.StatusRequestTimeout
				}
				http.Error(w, "proxy request cancelled", http.StatusRequestTimeout)
				return
			}
			if auditRecord != nil {
				*auditRecord = auditRecord.WithInputAudit(action, findings)
				if meta != nil {
					auditRecord.InputSemanticStatus, auditRecord.InputSemanticReason, auditRecord.ScanMode = meta.SemanticStatus, meta.SemanticReason, meta.ScanMode
				}
			}
			if securityexit.Decide(h.exitMode(), action, securityexit.RuleHit).Enforce {
				if auditRecord != nil {
					auditRecord.Status, auditRecord.StatusCode = "blocked", http.StatusForbidden
				}

				status, code := inputBlockResponse(meta, findings)
				blockID := ""
				if auditRecord != nil {
					auditRecord.StatusCode = status
					h.auditWriter.WriteRequestLog(context.Background(), *auditRecord)
					blockID = h.auditWriter.WriteSecurityEventForRecord(context.Background(), *auditRecord, action, findings, "input")
				}
				if code == "request_body_limit_exceeded" {
					http.Error(w, "Request body exceeds the inspection limit; request was not forwarded", status)
				} else if status == http.StatusServiceUnavailable {
					http.Error(w, inspectionUnavailableMessage(code), status)
				} else {
					writeHTTPBlockedResponse(w, requestID, findings, blockID)
				}
				return
			}
			if auditRecord != nil {
				// 检测已出结论，客户端随后断开也要留证：写库脱离请求取消。
				h.auditWriter.WriteSecurityEventForRecord(context.WithoutCancel(r.Context()), *auditRecord, action, findings, "input")
			}
		}
	}
	resp, err := h.currentTransport().RoundTrip(r)
	if err != nil {
		if auditRecord != nil {
			auditRecord.Status, auditRecord.StatusCode = "error", http.StatusServiceUnavailable
		}
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	defer resp.Body.Close()

	for k, vv := range resp.Header {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}

	w.WriteHeader(resp.StatusCode)
	n, copyErr := io.Copy(w, resp.Body)
	if auditRecord != nil {
		auditRecord.Status, auditRecord.StatusCode, auditRecord.ResponseBytes = "success", resp.StatusCode, n
		if copyErr != nil {
			auditRecord.Status = "error"
		}
	}
}

func requestHasBody(r *http.Request) bool {
	if r == nil || r.Body == nil || r.Body == http.NoBody {
		return false
	}
	return r.ContentLength != 0 || r.Header.Get("Transfer-Encoding") != ""
}

func requestMayContainFile(r *http.Request) bool {
	if !requestHasBody(r) {
		return false
	}
	contentType := strings.ToLower(r.Header.Get("Content-Type"))
	if strings.HasPrefix(contentType, "multipart/") ||
		strings.HasPrefix(contentType, "image/") ||
		strings.HasPrefix(contentType, "audio/") ||
		strings.HasPrefix(contentType, "video/") ||
		strings.Contains(contentType, "application/pdf") ||
		strings.Contains(contentType, "application/zip") ||
		strings.Contains(contentType, "application/gzip") ||
		strings.Contains(contentType, "application/x-tar") ||
		strings.Contains(contentType, "application/x-7z") ||
		strings.Contains(contentType, "application/vnd.rar") ||
		strings.Contains(contentType, "octet-stream") ||
		strings.Contains(contentType, "officedocument") ||
		strings.Contains(contentType, "msword") ||
		strings.Contains(contentType, "msexcel") ||
		strings.Contains(contentType, "mspowerpoint") {
		return true
	}
	path := strings.ToLower(r.URL.Path)
	for _, fragment := range []string{"/upload", "/uploads", "/file", "/files", "/attachment", "/attachments", "/document", "/documents"} {
		if strings.Contains(path, fragment) {
			return true
		}
	}
	return false
}

func requestMayContainJSON(r *http.Request) bool {
	if !requestHasBody(r) {
		return false
	}
	contentType := strings.ToLower(r.Header.Get("Content-Type"))
	return strings.Contains(contentType, "json")
}

// Helper functions

func readAndRestoreRequestBody(req *http.Request) ([]byte, error) {
	if req == nil || req.Body == nil {
		return nil, nil
	}
	body, err := io.ReadAll(io.LimitReader(req.Body, inspectionTransportLimit+1))
	if int64(len(body)) > inspectionTransportLimit {
		return nil, fmt.Errorf("request body exceeds transport capacity")
	}
	if err != nil {
		return nil, err
	}
	_ = req.Body.Close()
	req.Body = io.NopCloser(bytes.NewReader(body))
	req.ContentLength = int64(len(body))
	return body, nil
}

// readAndRestoreRequestBodyLimited detects JSON file candidates without unbounded
// buffering. Oversized streams keep their unread suffix attached so audit-only mode
// can still forward the original request intact.
func readAndRestoreRequestBodyLimited(req *http.Request, limit int64) ([]byte, bool, error) {
	if req == nil || req.Body == nil {
		return nil, false, nil
	}
	if req.ContentLength > limit {
		return nil, true, nil
	}
	original := req.Body
	body, err := io.ReadAll(io.LimitReader(original, limit+1))
	if err != nil {
		return nil, false, err
	}
	if int64(len(body)) > limit {
		req.Body = &replayReadCloser{
			Reader: io.MultiReader(bytes.NewReader(body), original),
			closer: original,
		}
		req.ContentLength = -1
		return body, true, nil
	}
	_ = original.Close()
	req.Body = io.NopCloser(bytes.NewReader(body))
	req.ContentLength = int64(len(body))
	return body, false, nil
}

func hostWithoutPort(address string) string {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return strings.Trim(address, "[]")
	}
	return strings.Trim(host, "[]")
}

// mergeRestrictedFileOutput 对本轮模型工具调用跑受限文件模式，把命中合成 finding 并入
// 输出判定（inspectionActionRank 取强者）。审计模式下一律只记，防护模式下配置 block 才拦。
// 无策略 / 无命中时 action/findings 原样返回。
func (h *ProxyHandler) mergeRestrictedFileOutput(tenantID string, auditRecord ProxyAuditRecord, inspectBody []byte, contentType, action string, findings []map[string]interface{}) (string, []map[string]interface{}) {
	if h.restrictedFilePolicy == nil {
		return action, findings
	}
	extracted := extractResponseContentWithDecoder(inspectBody, contentType, "")
	if len(extracted.ToolInvocations) == 0 {
		return action, findings
	}
	agentType := auditRecord.AgentType
	policy := h.restrictedFilePolicy.Get(context.Background(), tenantID, agentType)
	rfFindings := evaluateRestrictedFileToolCalls(policy, extracted.ToolInvocations)
	if len(rfFindings) == 0 {
		return action, findings
	}

	// 执行模式以控制台为准：审计（record）模式最高优先级，配置 block 也只记；
	// 防护（protect）模式按策略阻断。record/alert_allow 始终只记（alert_allow 由告警桥另行告警）。
	rfAction := securityexit.Decide(h.exitMode(), policy.Action, securityexit.ToolPolicy).Action
	if rfAction != "block" {
		rfAction = "audit"
	}

	// 同步 finding 的 action 字段为最终处置（供告警桥/留证一致）；被例外放开的只记录。
	for _, f := range rfFindings {
		findingAction := rfAction
		if _, excepted := f["exception_id"]; excepted {
			findingAction = "audit"
		}
		f["action"] = findingAction
		if inspectionActionRank(findingAction) > inspectionActionRank(action) {
			action = findingAction
		}
	}
	findings = append(findings, rfFindings...)
	return action, findings
}

// Verified rule hits take precedence over operational failure responses.
func inputBlockResponse(meta *FingerprintScanMeta, findings []map[string]interface{}) (int, string) {
	for _, finding := range findings {
		if finding["counts_as_security_finding"] == false {
			continue
		}
		if fileDLPActionBlocksExternalSend(fmt.Sprint(finding["action"])) {
			return http.StatusForbidden, "security_blocked"
		}
	}
	if meta != nil && meta.CapacityRejected {
		return http.StatusServiceUnavailable, "inspection_capacity_unavailable"
	}
	if meta != nil && meta.DetectionRejected {
		return http.StatusServiceUnavailable, "inspection_unavailable"
	}
	if meta != nil && meta.SemanticReason == "request_body_limit_exceeded" {
		return http.StatusRequestEntityTooLarge, "request_body_limit_exceeded"
	}
	return http.StatusForbidden, "security_blocked"
}

const inspectionCapacityUnavailableMessage = "security inspection capacity is unavailable; the request was rejected by the capacity policy"

func inspectionUnavailableMessage(code string) string {
	if code == "inspection_capacity_unavailable" {
		return inspectionCapacityUnavailableMessage
	}
	return "security inspection is unavailable; the request was rejected by the fail-closed policy"
}

// blockedResponseBody is the JSON body shared by the MITM and plain-HTTP block
// paths, so both tell the client which rule stopped the request.
func blockedResponseBody(requestID string, findings []map[string]interface{}, blockIDs ...string) []byte {
	body, _ := json.Marshal(map[string]interface{}{"error": map[string]interface{}{
		"code":       "security_blocked",
		"type":       "security_error",
		"message":    proxyBlockNotice(requestID, findings, blockIDs...),
		"request_id": requestID,
		"block_id":   firstNonEmpty(blockIDs...),
	}})
	return body
}

func writeHTTPBlockedResponse(w http.ResponseWriter, requestID string, findings []map[string]interface{}, blockIDs ...string) {
	w.Header().Set("Content-Type", "application/json")
	if requestID != "" {
		w.Header().Set("X-JJDGuard-Request-ID", requestID)
	}
	if blockID := firstNonEmpty(blockIDs...); blockID != "" {
		w.Header().Set("X-JJDGuard-Block-ID", blockID)
	}
	w.WriteHeader(http.StatusForbidden)
	_, _ = w.Write(blockedResponseBody(requestID, findings, blockIDs...))
}

// sendBlockedResponse tells the client which configured rule stopped the
// request, on what (redacted) content, and the request number the console's
// 阻断记录 can look up.
func (h *ProxyHandler) sendBlockedResponse(conn net.Conn, requestID string, findings []map[string]interface{}, blockIDs ...string) {
	body := blockedResponseBody(requestID, findings, blockIDs...)
	header := make(http.Header)
	header.Set("Content-Type", "application/json")
	if requestID != "" {
		header.Set("X-JJDGuard-Request-ID", requestID)
	}
	if blockID := firstNonEmpty(blockIDs...); blockID != "" {
		header.Set("X-JJDGuard-Block-ID", blockID)
	}
	resp := &http.Response{
		StatusCode:    http.StatusForbidden,
		Status:        "403 Forbidden",
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        header,
		Body:          io.NopCloser(bytes.NewReader(body)),
		ContentLength: int64(len(body)),
	}
	resp.Write(conn)
}

func proxyBlockingFinding(findings []map[string]interface{}) map[string]interface{} {
	var chosen map[string]interface{}
	for _, finding := range findings {
		switch strings.ToLower(strings.TrimSpace(fmt.Sprint(finding["action"]))) {
		case "block", "reply", "deny", "quarantine":
			chosen = finding
		}
		if chosen != nil {
			break
		}
	}
	if chosen == nil && len(findings) > 0 {
		chosen = findings[0]
	}
	return chosen
}

func proxyBlockAttribution(requestID, blockID, stage string, findings []map[string]interface{}) map[string]interface{} {
	finding := proxyBlockingFinding(findings)
	reason := "输入内容命中安全规则"
	layer := "input_content"
	if stage == "output" {
		reason = "模型输出命中安全规则"
		layer = "output_content"
	}
	return map[string]interface{}{
		"block_id": blockID, "request_id": requestID, "reason": reason, "layer": layer,
		"rule_id":   firstNonEmpty(proxyFindingString(finding, "rule_id"), proxyFindingString(finding, "source_rule_id"), proxyFindingString(finding, "policy_code")),
		"rule_name": proxyFindingString(finding, "rule_name"),
		"detail":    redactValue(proxyFindingString(finding, "matched_text_preview")),
		"category":  proxyFindingString(finding, "category"), "severity": proxyFindingString(finding, "severity"),
	}
}

func proxyBlockNotice(requestID string, findings []map[string]interface{}, blockIDs ...string) string {
	chosen := proxyBlockingFinding(findings)
	text := func(key string) string {
		if chosen == nil || chosen[key] == nil {
			return ""
		}
		return strings.TrimSpace(fmt.Sprint(chosen[key]))
	}
	lines := []string{"【JJDGuard 安全网关】本次请求已被安全策略阻断。"}
	rule := text("rule_name")
	if id := text("rule_id"); id != "" && id != rule {
		if rule != "" {
			rule += "（" + id + "）"
		} else {
			rule = id
		}
	}
	if rule != "" {
		lines = append(lines, "命中规则："+rule)
	}
	if preview := redactValue(text("matched_text_preview")); preview != "" {
		lines = append(lines, "命中内容："+preview)
	}
	if blockID := firstNonEmpty(blockIDs...); blockID != "" {
		lines = append(lines, "阻断编号："+blockID)
	}
	if requestID != "" {
		lines = append(lines, "请求 ID："+requestID)
	}
	lines = append(lines, "如需核查，请联系管理员并提供阻断编号或请求 ID（管理后台「风险处理 → 阻断记录」可查）。")
	return strings.Join(lines, "\n")
}

// streamLLMResponsesEnabled 报告是否开启「响应流式回写」分支。默认关闭：仅当
// PROXY_STREAM_LLM_RESPONSES == "true" / "1"（大小写不敏感）时返回 true。
// 该分支边流式回写浏览器边 tee 做非阻塞审计，前提是运营声明自己处于 audit-only（输出永不拦）；
// 默认 false 时所有响应恒走原 buffer 路径，行为与开关引入前逐字节一致（安全部署 + 一键回退）。
func streamLLMResponsesEnabled() bool {
	v := strings.ToLower(strings.TrimSpace(os.Getenv("PROXY_STREAM_LLM_RESPONSES")))
	return v == "true" || v == "1"
}

// rawDumpSeq bounds plaintext capture when explicitly enabled.
var rawDumpSeq atomic.Int64

// Only an explicit environment setting can enable plaintext capture.
func rawDumpDir() string {
	return strings.TrimSpace(os.Getenv("PROXY_RAW_DUMP_DIR"))
}

func rawDumpMaxSamples() int64 {
	raw := strings.TrimSpace(os.Getenv("PROXY_RAW_DUMP_MAX_SAMPLES"))
	limit, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || limit < 1 || limit > 40 {
		return 40
	}
	return limit
}

// rawDumpPathOfInterest 判断该请求路径是否承载"真会话内容"，只有它们才值得诊断落盘。
// 网页大模型页面一次加载会打几十上百个非会话请求（遥测、challenge、静态资源、账号信息、
// Gemini 的 batchexecute 摘要总线等）——这些不是用户提问/模型回复的承载体，若一并落盘会把
// 有限的样本预算占满。这里只放行确属会话轮次的端点：
//   - Gemini 真对话轮次：StreamGenerate（bardfrontendservice 上的 streamgenerate）；
//   - ChatGPT 对话 POST：/backend-api/.../conversation（多模态用户文本/模型回复的承载体）；
//   - ChatGPT 上传 create：/backend-api/files（file_id/asset 元数据，定位含图对话所需）。
//   - GitHub Copilot 图片上传：/copilot/chat/attachments（uploads.github.com，承载用户图片字节 +
//     上传响应里的 attachment id，定位「对话引用↔上传字节」关联所需）。
func rawDumpPathOfInterest(path string) bool {
	lower := strings.ToLower(path)
	for _, frag := range []string{
		"streamgenerate",            // Gemini 真对话轮次响应
		"bardfrontendservice",       // Gemini StreamGenerate 所在 service
		"conversation",              // ChatGPT /backend-api/f/conversation 对话 POST
		"/backend-api/files",        // ChatGPT 上传 create（file_id/asset 元数据）
		"/api/invoke",               // WorkBuddy/CodeBuddy webapp 会话接口
		"/api/stream",               // WorkBuddy/CodeBuddy webapp 流式会话接口
		"/v2/chat/completions",      // WorkBuddy/CodeBuddy(copilot.tencent.com) OpenAI 兼容对话诊断
		"/api/v0/chat/completion",   // DeepSeek 网页版对话 POST（chat_session_id/parent_message_id 承载体）
		"/v1/responses",             // OpenAI Responses 兼容对话端点，承载 Codex 最终回答
		"/copilot/chat/attachments", // GitHub Copilot 图片上传（uploads.github.com，图片字节 + attachment id）
	} {
		if strings.Contains(lower, frag) {
			return true
		}
	}
	return false
}

// dumpRawExchange 在诊断开关开启时，把一次正向代理 LLM 交互的原始请求体与解压后的响应体原样
// 落盘（<seq>-<时间>-<provider>-<host>.{req,resp,meta}）。默认关闭；落盘的是明文，仅供临时排障，
// 采完即删。最多 rawDumpMaxSamples 个样本，超出即停，防止磁盘被占满。
func dumpRawExchange(provider, host, path, reqContentType, respContentType string, requestBody, responseBody []byte) {
	dir := rawDumpDir()
	if dir == "" {
		return
	}
	// 只采集"会话承载"端点——网页加载噪声（batchexecute 摘要总线、遥测、challenge、账号信息、
	// 静态资源）若也落盘，会把有限的样本预算耗尽，真正的会话响应反而采不到（线上实测 40 个样本
	// 全是噪声的根因）。故对不感兴趣的路径直接返回、不占用 seq 预算。
	if !rawDumpPathOfInterest(path) {
		return
	}
	seq := rawDumpSeq.Add(1)
	if seq > rawDumpMaxSamples() {
		return
	}
	stamp := time.Now().Format("20060102T150405.000")
	base := filepath.Join(dir, fmt.Sprintf("%03d-%s-%s-%s", seq, stamp, rawDumpSanitize(provider), rawDumpSanitize(host)))
	meta := fmt.Sprintf("provider=%s\nhost=%s\npath=%s\nrequest_content_type=%s\nresponse_content_type=%s\nrequest_len=%d\nresponse_len=%d\n",
		provider, host, path, reqContentType, respContentType, len(requestBody), len(responseBody))
	if err := os.WriteFile(base+".meta", []byte(meta), 0o600); err != nil {
		log.Printf("[raw-dump] write meta failed: %v", err)
		return
	}
	if len(requestBody) > 0 {
		_ = os.WriteFile(base+".req", requestBody, 0o600)
	}
	if len(responseBody) > 0 {
		_ = os.WriteFile(base+".resp", responseBody, 0o600)
	}
	log.Printf("[raw-dump] sample %d: %s %s (req=%dB resp=%dB) -> %s.*", seq, provider, host, len(requestBody), len(responseBody), base)
}

// rawDumpSanitize 把 provider/host 收敛成安全的文件名片段（仅保留字母数字和 -.，其余替换为 _）。
func rawDumpSanitize(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '.':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	out := b.String()
	if len(out) > 60 {
		out = out[:60]
	}
	return out
}
