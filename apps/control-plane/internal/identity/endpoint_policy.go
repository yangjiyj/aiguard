package identity

import (
	"net/url"
	"strings"
)

// HTTPEndpointsExplicitlyAllowed 在发布时重新判定：给定端点里凡是 http 的，
// 都必须落在部署显式登记的私网（JJD_IDP_ALLOW_CIDRS）内，才允许以明文 http 写入身份运行态。
// 没有 http 端点时返回 false（无需例外）。任一 http 端点不满足 → false。
// 这里每次重新解析 DNS，防止「测试时指向私网、发布时改指公网」。
func HTTPEndpointsExplicitlyAllowed(endpoints ...string) bool {
	guard := NewSSRFGuard()
	sawHTTP := false
	for _, raw := range endpoints {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		parsed, err := url.Parse(raw)
		if err != nil {
			return false
		}
		if parsed.Scheme != "http" {
			continue
		}
		sawHTTP = true
		if _, _, err := guard.CheckRequestURL(raw); err != nil {
			return false
		}
	}
	return sawHTTP
}
