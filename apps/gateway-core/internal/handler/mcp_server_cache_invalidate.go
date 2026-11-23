package handler

import (
	"context"
	"log"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// W1 1.10：mcp_servers 行变更（禁用/删除/改路由）后主动失效网关路由缓存。
//
// 迁移 861 在 mcp_servers 上挂 AFTER UPDATE/DELETE 触发器，提交时
// pg_notify(mcpServerChangedChannel, tenant_id||chr(31)||id)，载荷与缓存键同构。
// 网关用一条独立连接（不占 pgxpool 连接，pool.Close 不会被阻塞）LISTEN，收到即删对应键。
// 连接断开期间可能漏通知，因此每次（重）连成功后整表清空缓存；未接线或 LISTEN
// 不可用时退回基线的 60s TTL 行为，不影响转发。

const (
	mcpServerChangedChannel         = "jjd_mcp_server_changed"
	mcpServerInvalidatorAppName     = "jjd-gateway-mcp-cache-invalidator"
	mcpServerInvalidatorRetryMin    = time.Second
	mcpServerInvalidatorRetryMax    = 30 * time.Second
	mcpServerInvalidatorWaitTimeout = time.Minute
)

// invalidate 删除单个缓存键。
func (c *mcpServerCache) invalidate(key string) {
	if c == nil || key == "" {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.entries, key)
}

// flush 清空全部缓存（LISTEN 重连后兜底漏掉的通知）。
func (c *mcpServerCache) flush() {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries = make(map[string]mcpServerCacheEntry)
}

// handleMCPServerChanged 处理一条通知载荷。载荷格式不符时整表清空（宁可多查一次库）。
func (h *MCPProxyHandler) handleMCPServerChanged(payload string) {
	if h == nil || h.serverCache == nil {
		return
	}
	tenantID, serverID, ok := strings.Cut(payload, "\x1f")
	if !ok || tenantID == "" || serverID == "" {
		h.serverCache.flush()
		return
	}
	h.serverCache.invalidate(tenantID + "\x1f" + serverID)
}

// StartServerCacheInvalidator 启动 LISTEN 协程，ctx 取消即退出。db 为 nil 时不做任何事。
// 由 main.go 在 NewMCPProxyHandler 之后调用：mcpProxy.StartServerCacheInvalidator(ctx)。
func (h *MCPProxyHandler) StartServerCacheInvalidator(ctx context.Context) {
	h.startServerCacheInvalidator(ctx, nil)
}

// startServerCacheInvalidator：ready 非 nil 时，每次 LISTEN 成功后非阻塞写入一次（供测试等待）。
func (h *MCPProxyHandler) startServerCacheInvalidator(ctx context.Context, ready chan<- struct{}) {
	if h == nil {
		return
	}
	h.cacheInvalidatorWired.Store(true)
	if h.db == nil {
		return
	}
	go h.runServerCacheInvalidator(ctx, ready)
}

func (h *MCPProxyHandler) runServerCacheInvalidator(ctx context.Context, ready chan<- struct{}) {
	backoff := mcpServerInvalidatorRetryMin
	for ctx.Err() == nil {
		err := h.listenServerChanges(ctx, ready, func() { backoff = mcpServerInvalidatorRetryMin })
		if ctx.Err() != nil {
			return
		}
		log.Printf("MCP server cache invalidator disconnected, fallback to TTL until reconnect: %v", err)
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		if backoff *= 2; backoff > mcpServerInvalidatorRetryMax {
			backoff = mcpServerInvalidatorRetryMax
		}
	}
}

// listenServerChanges 建独立连接并 LISTEN，直到出错或 ctx 取消。
func (h *MCPProxyHandler) listenServerChanges(ctx context.Context, ready chan<- struct{}, onListening func()) error {
	cfg := h.db.Config().ConnConfig.Copy()
	if cfg.RuntimeParams == nil {
		cfg.RuntimeParams = map[string]string{}
	}
	cfg.RuntimeParams["application_name"] = mcpServerInvalidatorAppName
	conn, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		return err
	}
	defer func() {
		closeCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = conn.Close(closeCtx)
	}()
	if _, err := conn.Exec(ctx, "LISTEN "+mcpServerChangedChannel); err != nil {
		return err
	}
	h.cacheInvalidatorRunning.Store(true)
	defer h.cacheInvalidatorRunning.Store(false)
	// 断线期间可能漏通知：LISTEN 生效后整表清空，之后的变更都能收到。
	h.serverCache.flush()
	onListening()
	if ready != nil {
		select {
		case ready <- struct{}{}:
		default:
		}
	}
	for {
		waitCtx, cancel := context.WithTimeout(ctx, mcpServerInvalidatorWaitTimeout)
		n, err := conn.WaitForNotification(waitCtx)
		cancel()
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if waitCtx.Err() != nil {
				// 空闲超时：探活一次，连接健在就继续等。
				if pingErr := conn.Ping(ctx); pingErr != nil {
					return pingErr
				}
				continue
			}
			return err
		}
		if n != nil && n.Channel == mcpServerChangedChannel {
			h.handleMCPServerChanged(n.Payload)
		}
	}
}
