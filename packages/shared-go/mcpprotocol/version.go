// Package mcpprotocol 集中维护网关支持的 MCP 协议版本，control-plane 与 gateway-core 共用，
// 避免两侧版本集合漂移。
package mcpprotocol

import (
	"fmt"
	"strings"
	"time"
)

const (
	// Latest 是 initialize 时我方声明的版本。
	Latest = "2025-11-25"
	// DefaultAssumedWhenHeaderAbsent 是规范规定：请求缺少 MCP-Protocol-Version 头时服务端应假定的版本。
	DefaultAssumedWhenHeaderAbsent = "2025-03-26"
)

// supported 新版本在前。
var supported = []string{"2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"}

// SupportedVersions 返回支持列表副本（新的在前）。
func SupportedVersions() []string {
	return append([]string(nil), supported...)
}

// IsSupported 判断版本是否在支持列表内（忽略首尾空白）。
func IsSupported(version string) bool {
	version = strings.TrimSpace(version)
	for _, v := range supported {
		if v == version {
			return true
		}
	}
	return false
}

// AllowsBatch 仅 2025-03-26 规范允许 JSON-RPC batch。
func AllowsBatch(version string) bool {
	return strings.TrimSpace(version) == "2025-03-26"
}

// UnsupportedError 生成同时包含服务端返回版本与客户端支持列表的错误。
func UnsupportedError(serverVersion string) error {
	return fmt.Errorf("MCP 协议版本不受支持：服务端返回 %q，客户端支持 [%s]", strings.TrimSpace(serverVersion), strings.Join(supported, ", "))
}

// Negotiated 是对上游 initialize 返回版本的协商结果。
type Negotiated struct {
	// Effective 是网关据以处理语义、并写入后续 MCP-Protocol-Version 头的版本，恒在支持列表内。
	Effective string
	// Raw 是上游原样返回的版本（已去首尾空白）。
	Raw string
	// Forward=true 表示上游版本晚于我们已知的最新版本（前向兼容放行，按 Latest 语义处理）。
	Forward bool
}

// Negotiate 协商上游返回的协议版本：
//   - 在支持列表内：原样接受；
//   - 格式为合法 YYYY-MM-DD 且晚于 Latest：前向兼容接受，按 Latest 语义处理，调用方应记录 warning
//     并把 Raw 存进 capabilities 供展示；
//   - 其余（早于 2024-11-05 的未知版本、格式非法、空串）：返回 UnsupportedError（带双方版本）。
func Negotiate(serverVersion string) (Negotiated, error) {
	v := strings.TrimSpace(serverVersion)
	if IsSupported(v) {
		return Negotiated{Effective: v, Raw: v}, nil
	}
	if len(v) == 10 {
		if parsed, err := time.Parse("2006-01-02", v); err == nil {
			if latest, lerr := time.Parse("2006-01-02", Latest); lerr == nil && parsed.After(latest) {
				return Negotiated{Effective: Latest, Raw: v, Forward: true}, nil
			}
		}
	}
	return Negotiated{}, UnsupportedError(serverVersion)
}
