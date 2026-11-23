package handler

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

const (
	auditKeywordMaxRunes       = 128
	auditKeywordMaxWindow      = 180 * 24 * time.Hour
	auditKeywordQueryTimeout   = 5 * time.Second
	auditKeywordGlobalLimit    = 8
	auditKeywordPerTenantLimit = 2
)

var auditKeywordLimiter = struct {
	sync.Mutex
	global   chan struct{}
	byTenant map[string]int
}{global: make(chan struct{}, auditKeywordGlobalLimit), byTenant: map[string]int{}}

func validatedAuditKeyword(w http.ResponseWriter, raw string) (string, bool) {
	keyword := strings.TrimSpace(raw)
	if keyword == "" {
		return "", true
	}
	runes := utf8.RuneCountInString(keyword)
	minimum := 2
	if isASCII(keyword) {
		minimum = 3
	}
	if runes < minimum || runes > auditKeywordMaxRunes {
		writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "关键词长度不符合要求：中文至少 2 个字符、英文至少 3 个字符，最多 128 个字符")
		return "", false
	}
	return keyword, true
}

func isASCII(value string) bool {
	for _, r := range value {
		if r > 127 {
			return false
		}
	}
	return true
}

func validateAuditKeywordWindow(w http.ResponseWriter, keyword string, start, end time.Time) bool {
	if keyword == "" {
		return true
	}
	if start.IsZero() || end.IsZero() || !end.After(start) || end.Sub(start) > auditKeywordMaxWindow {
		writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "关键词检索时间范围必须在 180 天以内")
		return false
	}
	return true
}

func beginAuditKeywordSearch(w http.ResponseWriter, r *http.Request, tenantID, keyword string) (context.Context, func(), bool) {
	if keyword == "" {
		return r.Context(), func() {}, true
	}
	auditKeywordLimiter.Lock()
	if auditKeywordLimiter.byTenant[tenantID] >= auditKeywordPerTenantLimit {
		auditKeywordLimiter.Unlock()
		writeErrorWithStatus(w, http.StatusTooManyRequests, "search_busy", "当前租户关键词检索繁忙，请稍后重试")
		return nil, nil, false
	}
	select {
	case auditKeywordLimiter.global <- struct{}{}:
		auditKeywordLimiter.byTenant[tenantID]++
		auditKeywordLimiter.Unlock()
	default:
		auditKeywordLimiter.Unlock()
		writeErrorWithStatus(w, http.StatusTooManyRequests, "search_busy", "关键词检索繁忙，请稍后重试")
		return nil, nil, false
	}

	ctx, cancel := context.WithTimeout(r.Context(), auditKeywordQueryTimeout)
	return ctx, func() {
		cancel()
		auditKeywordLimiter.Lock()
		auditKeywordLimiter.byTenant[tenantID]--
		if auditKeywordLimiter.byTenant[tenantID] <= 0 {
			delete(auditKeywordLimiter.byTenant, tenantID)
		}
		<-auditKeywordLimiter.global
		auditKeywordLimiter.Unlock()
	}, true
}

func writeAuditKeywordQueryError(w http.ResponseWriter, err error, fallback string) {
	if errors.Is(err, context.DeadlineExceeded) {
		writeErrorWithStatus(w, http.StatusGatewayTimeout, "search_timeout", "检索超时，请缩小时间范围或使用更具体的关键词")
		return
	}
	writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", fallback)
}
