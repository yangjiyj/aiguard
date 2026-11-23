package nasexport

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"time"

	"github.com/yangjiyj/aiguard/packages/shared-go/eventbus"
	"github.com/yangjiyj/aiguard/packages/shared-go/outbox"
)

// Processor 实现 auditpipe.Processor：把安全事件转 ExportEvent 写到 NAS 挂载目录。
// 仅供文件内容 DLP 相关的安全事件（命中 file_content_* / 外发阻断类）；
// 其它事件类型直接返回 nil（由 auditpipe 链中的其它 Processor 处理）。
type Processor struct {
	rootDir string
	now     func() time.Time
}

// NewProcessor 构造 NAS 导出 Processor。rootDir 必须是管理员配置的绝对路径。
func NewProcessor(rootDir string) (*Processor, error) {
	if !filepath.IsAbs(rootDir) {
		return nil, errors.New("nasexport: root dir must be an absolute path configured by admin")
	}
	return &Processor{rootDir: filepath.Clean(rootDir), now: time.Now}, nil
}

// Process 处理单个 outbox 事件。安全事件 → 写 NAS；NAS 不可用返回 error 由 outbox 重试。
func (p *Processor) Process(ctx context.Context, event outbox.Event) error {
	if event.Type != eventbus.EventTypeAuditSecurityEventWrite {
		return nil // 非安全事件忽略
	}
	var payload eventbus.AuditSecurityEventPayload
	if err := json.Unmarshal(event.Payload, &payload); err != nil {
		return fmt.Errorf("nasexport: decode security event payload: %w", err)
	}
	// 严格白名单：只导出明确的文件内容 DLP 事件（设计§13）。其它安全事件
	// （prompt_injection / 常规 secret / 普通 PII 等）不导出 NAS，只留库内审计。
	if !isFileContentDLPEvent(payload) {
		return nil
	}
	eventID := payload.EventID
	if eventID == "" {
		eventID = event.ID
	}
	ev := ExportEvent{
		EventID:     eventID,
		EntryPoint:  payload.RequestLog.EndpointType,
		Subject:     payload.RequestLog.UserID,
		TargetAI:    payload.RequestLog.ModelID,
		HitTypes:    []string{payload.EventType},
		Action:      payload.ActionTaken,
		SampleHits:  redactSamples(payload.MatchedSummary),
		UpstreamGot: payload.ActionTaken != "block", // 阻断时上游未收到
		ExportedAt:  time.Now().UTC().Format(time.RFC3339),
	}
	return WriteEvent(p.rootDir, ev)
}

// fileContentDLPCategoryPrefixes 是文件内容 DLP 事件的 event_type / rule_id 前缀白名单。
// 只有命中这些前缀的事件才导出 NAS（避免把所有安全事件都外发到客户存储）。
var fileContentDLPCategoryPrefixes = []string{
	"file_content_",      // 文件内容 DLP 命中（phone/id/bank/secret in file）
	"file_id_verdict_",   // file_id 协议阻断
	"file-content-",      // 引擎 rule_id 风格（file-content-parse-failed 等）
	"file_policy_blocked",// 文件类型策略阻断（docx 被 blocked_types）
}

// isFileContentDLPEvent 严格判断是否文件内容 DLP 事件。
// 判据：event_type 或 rule_id 命中白名单前缀。
func isFileContentDLPEvent(payload eventbus.AuditSecurityEventPayload) bool {
	for _, prefix := range fileContentDLPCategoryPrefixes {
		if hasPrefix(payload.EventType, prefix) || hasPrefix(payload.RuleID, prefix) {
			return true
		}
	}
	return false
}

func hasPrefix(s, prefix string) bool {
	return len(s) >= len(prefix) && s[:len(prefix)] == prefix
}

// redactSamples 从 MatchedSummary 提取少量字符串值并兜底掩码（防完整 PII/密钥落 NAS）。
// 只取前若干个字符串值，每个经 sanitizeSamples（复用 nasexport 的掩码正则）。
func redactSamples(summary map[string]any) []string {
	if len(summary) == 0 {
		return nil
	}
	out := make([]string, 0, len(summary))
	for k, v := range summary {
		switch s := v.(type) {
		case string:
			out = append(out, k+":"+s)
		default:
			continue
		}
		if len(out) >= 5 {
			break
		}
	}
	return sanitizeSamples(out)
}
