package handler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/auth"
	"github.com/yangjiyj/aiguard/packages/shared-go/mcpupstream"
	"github.com/yangjiyj/aiguard/packages/shared-go/safetarget"
	"github.com/google/uuid"
)

// mcpUpstreamEgressDeniedReason 是 MCP 上游被防跳板出站拒绝时安全事件的原因码。
const mcpUpstreamEgressDeniedReason = "mcp_upstream_internal_egress_denied"

// errMCPUpstreamEgressDenied 标记上游地址被防跳板出站拒绝（内网、回环、链路本地、元数据、
// 内部主机名），区别于 DNS 失败等运行故障。
var errMCPUpstreamEgressDenied = errors.New("MCP upstream egress denied")

type mcpEgressDeniedError struct{ msg string }

func (e *mcpEgressDeniedError) Error() string        { return e.msg }
func (e *mcpEgressDeniedError) Is(target error) bool { return target == errMCPUpstreamEgressDenied }

// egressOptions 合成该服务的出站选项：原有的内网放行开关加上服务的 egress_overrides。
func (s *mcpServerRoute) egressOptions() safetarget.Options {
	if s == nil {
		return safetarget.Options{}
	}
	return s.EgressOverrides.Options(s.AllowPrivateEgress)
}

// resolveMCPUpstreamClientWithOptions 校验上游地址并返回钉住 IP 的客户端。默认（零值选项）
// 内网、回环、链路本地、元数据、内部主机名一律拒绝；全局观察留痕不改变这里的判定。
func resolveMCPUpstreamClientWithOptions(ctx context.Context, rawURL string, opts safetarget.Options, base *http.Client) (*http.Client, *url.URL, error) {
	target, err := safetarget.ResolveWithOptions(ctx, rawURL, opts, nil)
	if err != nil {
		// safetarget 的错误文本可能带出 URL 片段；路径密钥的占位 URL 本身不含密钥，但出于一致性仍只保留错误类别。
		msg := fmt.Sprintf("MCP 上游未通过出站安全校验: %s", mcpupstream.RedactText(err.Error()))
		if errors.Is(err, safetarget.ErrForbiddenAddress) || errors.Is(err, safetarget.ErrPrivateAddress) {
			return nil, nil, &mcpEgressDeniedError{msg: msg}
		}
		return nil, nil, errors.New(msg)
	}
	return safetarget.Client(base, target, true), target.URL, nil
}

// resolveUpstreamClient 是转发与 SSE 桥接共用的上游解析入口：测试注入的解析器优先，
// 否则按服务的出站选项解析。被防跳板出站拒绝时记一条安全事件。
func (h *MCPProxyHandler) resolveUpstreamClient(ctx context.Context, server *mcpServerRoute, r *http.Request) (*http.Client, *url.URL, error) {
	var (
		client    *http.Client
		targetURL *url.URL
		err       error
	)
	if h.targetClientResolver != nil {
		client, targetURL, err = h.targetClientResolver(ctx, server.ServerURL, server.AllowPrivateEgress, h.client)
	} else {
		client, targetURL, err = resolveMCPUpstreamClientWithOptions(ctx, server.ServerURL, server.egressOptions(), h.client)
	}
	if errors.Is(err, errMCPUpstreamEgressDenied) {
		h.recordMCPEgressDenied(ctx, server, r)
	}
	return client, targetURL, err
}

// recordMCPEgressDenied 把一次上游出站拒绝写成 request_logs 父行 + security_events 子行（同一事务）。
func (h *MCPProxyHandler) recordMCPEgressDenied(ctx context.Context, server *mcpServerRoute, r *http.Request) {
	if h == nil || h.auditRecorder == nil || h.auditRecorder.db == nil || r == nil {
		return
	}
	record := h.newMCPAuditRecord(auth.GetAuthInfo(r), server, r, 0, 0, "blocked", http.StatusForbidden, 0)
	if record.TenantID == "" || record.RequestID == "" {
		return
	}
	summary, _ := json.Marshal(map[string]interface{}{
		"source":      "gateway_mcp",
		"stage":       "upstream",
		"reason":      mcpUpstreamEgressDeniedReason,
		"server_id":   record.ServerID,
		"server_name": record.ServerName,
		"summary":     "MCP 上游地址未通过防跳板出站校验（内网、回环、链路本地、元数据或内部主机名）",
	})
	writeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	tx, err := h.auditRecorder.db.Begin(writeCtx)
	if err != nil {
		log.Printf("MCP 出站拒绝事件写入失败 (request_id=%s): %v", record.RequestID, err)
		return
	}
	defer func() { _ = tx.Rollback(writeCtx) }()
	if _, err := tx.Exec(writeCtx, mcpAccessUpsertSQL, mcpAccessUpsertArgs(record)...); err != nil {
		log.Printf("MCP 出站拒绝事件写 request_logs 失败 (request_id=%s): %v", record.RequestID, err)
		return
	}
	if _, err := tx.Exec(writeCtx, mcpSecurityEventSQL,
		"evt_"+strings.ReplaceAll(uuid.New().String(), "-", "")[:16],
		record.RequestID, record.TenantID, record.ProjectID,
		"mcp_upstream_egress_denied", "high", "", "block", summary,
		"request_logs:"+record.RequestID, mcpPrincipalKey(record),
	); err != nil {
		log.Printf("MCP 出站拒绝事件写 security_events 失败 (request_id=%s): %v", record.RequestID, err)
		return
	}
	if err := tx.Commit(writeCtx); err != nil {
		log.Printf("MCP 出站拒绝事件提交失败 (request_id=%s): %v", record.RequestID, err)
	}
}
