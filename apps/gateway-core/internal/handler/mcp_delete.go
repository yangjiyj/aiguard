package handler

import (
	"context"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/auth"
)

// HandleDelete forwards Streamable HTTP session termination. A session and an
// explicit negotiated protocol version are required so a client cannot turn a
// stateless request into an ambiguous upstream teardown.
func (h *MCPProxyHandler) HandleDelete(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), reverseProxyStreamTimeout)
	defer cancel()
	startedAt := time.Now()
	info := auth.GetAuthInfo(r)
	ensureMCPRequestID(info)

	if strings.TrimSpace(r.Header.Get("Mcp-Session-Id")) == "" {
		writeMCPHTTPError(w, http.StatusBadRequest, "MCP DELETE requires MCP-Session-Id")
		return
	}
	if err := validateMCPProtocolVersion(r.Header.Get("MCP-Protocol-Version")); err != nil {
		writeMCPHTTPError(w, http.StatusBadRequest, "MCP DELETE requires a supported MCP-Protocol-Version")
		return
	}

	server := h.resolveMCPServer(ctx, w, r, info)
	if server == nil {
		return
	}
	resp, _, err := h.forwardMCPUpstream(ctx, server, r, nil)
	if err != nil {
		log.Printf("MCP DELETE upstream failed: server=%s err=%v", server.ID, err)
		h.writeMCPLightAudit(context.WithoutCancel(ctx), info, server, r, 0, 0, "failed", 0, time.Since(startedAt))
		writeMCPHTTPError(w, http.StatusBadGateway, "MCP upstream session termination failed")
		return
	}
	defer resp.Body.Close()

	// 复审 M-2：与 HandleGet / HandlePost 一致，显式处理「根本没到上游」的合成响应
	// （会话校验失败、重复头、桥接 404/405/503 等）：原样回给客户端，并按 failed 审计，
	// 绝不因为合成的 2xx/204 被记成「已转发成功」。
	if mcpResponseNotForwarded(resp) {
		notForwardedBody, _ := readMCPBoundedBody(resp.Body, maxMCPNonStreamingResponseBytes)
		copyMCPResponseHeaders(w.Header(), resp.Header)
		mcpStripInternalHeaders(w.Header())
		w.Header().Set("Connection", "close")
		w.WriteHeader(resp.StatusCode)
		_, _ = w.Write(notForwardedBody)
		h.writeMCPLightAudit(context.WithoutCancel(ctx), info, server, r, 0, int64(len(notForwardedBody)), "failed", resp.StatusCode, time.Since(startedAt))
		return
	}

	body, err := readMCPBoundedBody(resp.Body, maxMCPNonStreamingResponseBytes)
	if err != nil {
		h.writeMCPLightAudit(context.WithoutCancel(ctx), info, server, r, 0, 0, "failed", resp.StatusCode, time.Since(startedAt))
		writeMCPHTTPError(w, http.StatusBadGateway, "MCP DELETE upstream response exceeded the capacity limit")
		return
	}

	copyMCPResponseHeaders(w.Header(), resp.Header)
	mcpStripInternalHeaders(w.Header())
	w.Header().Set("Connection", "close")
	w.WriteHeader(resp.StatusCode)
	_, _ = w.Write(body)
	status := "success"
	if resp.StatusCode >= http.StatusBadRequest {
		status = "failed"
	}
	h.writeMCPLightAudit(context.WithoutCancel(ctx), info, server, r, 0, int64(len(body)), status, resp.StatusCode, time.Since(startedAt))
}
