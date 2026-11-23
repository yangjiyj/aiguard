package handler

import (
	"log"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/provider"
)

// 所有上游状态均保留定点遮盖后的响应错误原文，并另存中文解释；绝不写入请求内容。

const (
	upstreamRejectLogMinInterval = 10 * time.Second
	upstreamRejectLogMaxKeys     = 1024
)

var upstreamErrorTypePattern = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)

// upstreamRejectLogNow 让测试可以固定"现在"。
var upstreamRejectLogNow = time.Now

var upstreamRejectLogState = struct {
	sync.Mutex
	last       map[string]time.Time
	suppressed map[string]int64
}{last: map[string]time.Time{}, suppressed: map[string]int64{}}

// upstreamErrorTypeFromBody 只接受短类型标识，避免自由文本进入类型字段。
func upstreamErrorTypeFromBody(body []byte) string {
	value := parseUpstreamError(body).Type
	if upstreamErrorTypePattern.MatchString(value) {
		return value
	}
	return ""
}

// upstreamErrorAuditSummary 与客户端策略分离：不按状态码或业务敏感词丢弃整句。
func upstreamErrorAuditSummary(upstreamErr *provider.UpstreamHTTPError) (string, string) {
	if upstreamErr == nil {
		return "", ""
	}
	return upstreamErrorTypeFromBody(upstreamErr.Body), sanitizeClientUpstreamMessage(parseUpstreamError(upstreamErr.Body).Message)
}

// upstreamRejectionAuditResult 构造写入请求审计的结果，并按（模型、状态码、错误类型）限频记一行网关日志。
func upstreamRejectionAuditResult(envelope *modelrouter.RequestEnvelope, upstreamErr *provider.UpstreamHTTPError, stage string) *AuditResult {
	if upstreamErr == nil {
		return nil
	}
	errType, reason := upstreamErrorAuditSummary(upstreamErr)
	metadata := map[string]interface{}{
		"upstream_status_code": upstreamErr.StatusCode,
		"error_stage":          stage,
		"upstream_error_hint":  upstreamErrorHint(upstreamErr.StatusCode, parseUpstreamError(upstreamErr.Body)),
	}
	if code := sanitizeClientUpstreamMessage(parseUpstreamError(upstreamErr.Body).Code); code != "" {
		metadata["upstream_error_code"] = code
	}
	if errType != "" {
		metadata["upstream_error_type"] = errType
	}
	if reason != "" {
		metadata["error_message"] = reason
	} else {
		metadata["error_message"] = "上游返回 " + strconv.Itoa(upstreamErr.StatusCode) + "，上游未提供可解析的错误原因"
	}
	logUpstreamRejection(envelope, upstreamErr.StatusCode, errType, metadata["error_message"].(string), stage)
	return &AuditResult{ResponseMetadata: metadata}
}

func logUpstreamRejection(envelope *modelrouter.RequestEnvelope, status int, errType, reason, stage string) {
	requestID, model := "", ""
	if envelope != nil {
		requestID, model = envelope.RequestID, envelope.Model
	}
	key := strings.Join([]string{model, strconv.Itoa(status), errType}, "|")
	now := upstreamRejectLogNow()
	state := &upstreamRejectLogState
	state.Lock()
	if len(state.last) >= upstreamRejectLogMaxKeys {
		state.last = map[string]time.Time{}
		state.suppressed = map[string]int64{}
	}
	if last, seen := state.last[key]; seen && now.Sub(last) < upstreamRejectLogMinInterval {
		state.suppressed[key]++
		state.Unlock()
		return
	}
	suppressed := state.suppressed[key]
	state.last[key] = now
	state.suppressed[key] = 0
	state.Unlock()
	if reason == "" {
		reason = "(文案未留存)"
	}
	log.Printf("[upstream.reject] request_id=%s model=%s upstream_status=%d error_type=%s stage=%s reason=%q suppressed_since_last=%d",
		requestID, model, status, errType, stage, reason, suppressed)
}
