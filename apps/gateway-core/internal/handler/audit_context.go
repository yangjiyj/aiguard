package handler

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// auditWriteTimeout 是单次审计/留证写入的整体时限。审计写入不随客户端断开而取消，
// 否则 request_logs 停在 received、安全事件与内容日志丢失、计费收尾丢失。
// 是 var 而非 const：仅测试会在 t.Cleanup 保护下临时调小。
var auditWriteTimeout = 10 * time.Second

// auditArtifactTimeout 是响应制品留存（对象存储上传 + 落库）的时限，最大单个制品 20MB，
// 比普通审计写入宽松；仍有界，避免存储挂死拖住请求收尾。
var auditArtifactTimeout = 60 * time.Second

// errClientGoneDuringSecurity 表示客户端在安全检测（输入扫描/输出扫描）期间已经断开
// （Claude Code 按 Esc、Codex 中断等）。它包装 context.Canceled，所以各调用方既有的
// client_canceled 分支（errors.Is(err, context.Canceled)）能直接认出来；同时它不是
// errGuardrailDetectionUnavailable，不会被当成 fail-closed 拒绝，也不是检测失败。
var errClientGoneDuringSecurity = fmt.Errorf("client disconnected during security check: %w", context.Canceled)

// clientGoneDuring 判断安全引擎调用返回的 err 是不是「客户端中途断开」造成的，
// 而不是引擎真的检测失败：err 是 context.Canceled，并且原始请求 ctx 确实已被取消。
//
// ctx 必须是原始请求 ctx（r.Context() 加 value 的那一份），不能是 syncCtx、
// inputSecurityCtx 这类带超时的派生 ctx：派生 ctx 到期后 Err() 也非 nil，但那是检测超时，
// 不是客户端断开。以下情况都不算客户端断开，行为保持原样（记检测失败，fail-closed 照常生效）：
//   - context.DeadlineExceeded 与 isSecurityScanTimeout 认作超时的错误；
//   - 引擎内部自己 cancel（err 是 Canceled，但请求 ctx 仍然存活）；
//   - 其他任何非 Canceled 的错误。
func clientGoneDuring(ctx context.Context, err error) bool {
	return err != nil && ctx != nil && errors.Is(err, context.Canceled) && ctx.Err() != nil
}

// detachAuditContext 返回脱离请求取消、带有界时限的审计 ctx，并保留 ctx 里的 value
// （租户、阻断台账等）。调用方必须 defer 返回的 cancel。每层重新计时：总耗时有界，
// 但嵌套时可能超过单次限时（WithoutCancel 会丢掉上层 deadline），所以已有更短限时的
// 调用点（如路由持久化的 3s）不要再包。
func detachAuditContext(ctx context.Context) (context.Context, context.CancelFunc) {
	return detachAuditContextFor(ctx, auditWriteTimeout)
}

// detachAuditContextFor 同 detachAuditContext，限时由调用方指定（如制品留存）。
func detachAuditContextFor(ctx context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(ctx), timeout)
}
