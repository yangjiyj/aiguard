package mcpupstream

import (
	"fmt"
	"net/url"
	"strings"
)

// 路径密钥（"密钥在 URL 路径中"）：server_url 里用占位符 {secret} 标出位置。
// 约束：
//   - path 模式下 URL 必须恰好含一个 {secret}，且只能出现在 URL 路径里（不能在主机、端口、query）；
//   - 请求时才把占位符替换成“路径段编码”后的真实密钥（斜杠、空格、百分号、井号、问号、中文都编码成一个段内字符）；
//   - 库里、展示、日志、审计、错误信息、同源校验的输入一律只出现占位形式或 ***；
//   - 非 path 模式的 URL 不得含 {secret}，避免被当作字面路径发往上游。

// PathSecretPlaceholder 是 server_url 里标出密钥位置的占位符。
const PathSecretPlaceholder = SecretPlaceholder

// 占位符在 URL 里可能以原样或百分号编码形式存在（url.Parse 后 Path 里是原样，EscapedPath 里是 %7Bsecret%7D）。
var encodedPlaceholder = strings.ToLower(url.PathEscape(PathSecretPlaceholder))

// ValidatePathSecretURL 校验 path 模式的 server_url：必须恰好含一个 {secret}，且只出现在路径中。
func ValidatePathSecretURL(raw string) error {
	if n := countPlaceholder(raw); n != 1 {
		return fmt.Errorf("鉴权位置为「URL 路径」时，服务地址必须恰好包含一个 {密钥} 占位（用来标出密钥所在的路径位置），当前包含 %d 个", n)
	}
	// 占位出现在 authority（主机 / 端口 / userinfo）里时，替换后 URL 往往无法解析：先按文本位置判定，给出准确提示。
	probe := strings.NewReplacer("{secret}", "SECRETPLACEHOLDER", "%7Bsecret%7D", "SECRETPLACEHOLDER", "%7bsecret%7d", "SECRETPLACEHOLDER").Replace(raw)
	if i := strings.Index(probe, "://"); i >= 0 {
		authority, _, _ := strings.Cut(strings.TrimLeft(probe[i+3:], "/"), "/")
		authority, _, _ = strings.Cut(authority, "?")
		authority, _, _ = strings.Cut(authority, "#")
		if strings.Contains(authority, "SECRETPLACEHOLDER") {
			return fmt.Errorf("{密钥} 占位只能出现在 URL 路径里，不能出现在主机、端口、参数或片段中")
		}
	}
	u, err := url.Parse(probe)
	if err != nil || u.Host == "" {
		return fmt.Errorf("服务地址格式非法（需 http(s)://host[:port][/path]）")
	}
	if strings.Contains(u.Host, "SECRETPLACEHOLDER") || strings.Contains(u.RawQuery, "SECRETPLACEHOLDER") || strings.Contains(u.Fragment, "SECRETPLACEHOLDER") || strings.Contains(u.User.String(), "SECRETPLACEHOLDER") {
		return fmt.Errorf("{密钥} 占位只能出现在 URL 路径里，不能出现在主机、端口、参数或片段中")
	}
	if !strings.Contains(u.Path, "SECRETPLACEHOLDER") {
		return fmt.Errorf("{密钥} 占位只能出现在 URL 路径里，不能出现在主机、端口、参数或片段中")
	}
	return nil
}

// ValidateNonPathURL 非 path 模式的 URL 里不允许出现 {secret} 占位。
func ValidateNonPathURL(raw string) error {
	if countPlaceholder(raw) > 0 {
		return fmt.Errorf("服务地址里出现了 {密钥} 占位，但鉴权位置不是「URL 路径」。请把鉴权位置改为「URL 路径」，或删除该占位")
	}
	return nil
}

func countPlaceholder(raw string) int {
	lower := strings.ToLower(raw)
	return strings.Count(lower, "{secret}") + strings.Count(lower, encodedPlaceholder)
}

// HasPathPlaceholder 判断 URL 是否含路径密钥占位。
func HasPathPlaceholder(raw string) bool { return countPlaceholder(raw) > 0 }

// SubstitutePathSecret 返回一个新 URL：把路径里的 {secret} 替换为密钥，替换值按“单个路径段”编码，
// 因此密钥里的 / ? # % 空格等不会改变路径结构，也不会漏进 query / fragment。不修改入参。
func SubstitutePathSecret(u *url.URL, secret string) (*url.URL, error) {
	if u == nil {
		return nil, fmt.Errorf("上游地址缺失")
	}
	if secret == "" || !safeSecret(secret) {
		return nil, ErrCredential
	}
	if err := ValidatePathSecretValue(secret); err != nil {
		return nil, Errorf(KindAuthConfig, "%s", err.Error())
	}
	cp := cloneURL(u)
	rawPath := cp.EscapedPath()
	lower := strings.ToLower(rawPath)
	var idx int
	var plen int
	switch {
	case strings.Contains(rawPath, PathSecretPlaceholder):
		idx, plen = strings.Index(rawPath, PathSecretPlaceholder), len(PathSecretPlaceholder)
	case strings.Contains(lower, encodedPlaceholder):
		idx, plen = strings.Index(lower, encodedPlaceholder), len(encodedPlaceholder)
	default:
		return nil, ErrCredential
	}
	escaped := rawPath[:idx] + url.PathEscape(secret) + rawPath[idx+plen:]
	decoded, err := url.PathUnescape(escaped)
	if err != nil {
		return nil, ErrCredential
	}
	cp.Path = decoded
	cp.RawPath = escaped
	return cp, nil
}

// ValidatePathSecretValue 校验密钥值能否安全地作为一个 URL 路径段：
// 单独的 "." 或 ".." 会被 URL 规范化当作当前 / 上级目录吃掉，改变路径结构（甚至跳出前缀），一律拒绝。
// 保存时与替换时都调用它。含点的普通密钥（如 "a.b"、".hidden"）不受影响。
func ValidatePathSecretValue(secret string) error {
	if secret == "." || secret == ".." {
		return fmt.Errorf("鉴权密钥的值不能是单独的 \".\" 或 \"..\"：它们作为 URL 路径段会被当作目录引用，无法作为路径中的密钥使用，请更换密钥")
	}
	return nil
}
