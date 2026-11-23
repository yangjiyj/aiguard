package agentguard

import (
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/yangjiyj/aiguard/packages/shared-go/egresspolicy"
	"github.com/yangjiyj/aiguard/packages/shared-go/filerestrict"
)

type TargetKind string

const (
	TargetUnknown TargetKind = "unknown"
	TargetURL     TargetKind = "url"
	TargetFile    TargetKind = "file"
)

const (
	targetReasonCloudMetadata     = "blocked_cloud_metadata"
	targetReasonLoopbackOrPrivate = "blocked_loopback_or_private_ip"
	targetReasonCloudCredential   = "blocked_cloud_credential_path"
	targetReasonSSHPrivateKey     = "blocked_ssh_private_key_path"
	targetReasonMetadataHostname  = "blocked_cloud_metadata_hostname"
	targetEvidenceRuleBlockedURL  = "blocked_target_url"
	targetEvidenceRuleBlockedFS   = "blocked_target_file"
)

// 2.9.22 起原“敏感本地文件”拆成五个防护项（任务 2.1）：前四个按文件名或完整路径判定，
// 其余靠名字猜的规则都落在 targetReasonSensitiveName。
const (
	targetReasonEnvFile            = "blocked_env_file"
	targetReasonSystemSecretFile   = "blocked_system_secret_file"
	targetReasonSecretMount        = "blocked_secret_mount_path"
	targetReasonGitCredentialsFile = "blocked_git_credentials_file"
	targetReasonSensitiveName      = "sensitive_name_hint"
)

// TargetAnalysis records normalized targets and sensitive-target matches. Hit
// only says the target is a protection item; the action comes from the
// tenant's protection settings.
type TargetAnalysis struct {
	Kind             TargetKind `json:"kind"`
	RawTarget        string     `json:"raw_target"`
	NormalizedTarget string     `json:"normalized_target"`
	Hit              bool       `json:"hit"`
	Reason           string     `json:"reason,omitempty"`
	Evidence         []Evidence `json:"evidence_json,omitempty"`
}

// AnalyzeTarget normalizes URL/file targets without DNS and flags sensitive targets.
func AnalyzeTarget(raw string) TargetAnalysis {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return TargetAnalysis{Kind: TargetUnknown, RawTarget: raw}
	}

	if parsed, err := url.Parse(trimmed); err == nil && parsed.Scheme != "" && parsed.Host != "" {
		return analyzeURLTarget(trimmed, parsed)
	}

	if looksLikeFileTarget(trimmed) {
		return analyzeFileTarget(trimmed)
	}

	return TargetAnalysis{Kind: TargetUnknown, RawTarget: raw, NormalizedTarget: trimmed}
}

func analyzeURLTarget(raw string, parsed *url.URL) TargetAnalysis {
	result := TargetAnalysis{Kind: TargetURL, RawTarget: raw}
	normalizedHost, parsedIP := normalizeURLHost(parsed.Hostname())
	port := parsed.Port()
	parsed.Host = formatURLHost(normalizedHost, port)
	result.NormalizedTarget = parsed.String()

	if isMetadataHostname(normalizedHost) {
		result.Hit = true
		result.Reason = targetReasonMetadataHostname
		result.Evidence = []Evidence{sanitizedEvidence(targetEvidenceRuleBlockedURL, "target", "url", raw)}
		return result
	}

	if isLoopbackOrPrivateHostname(normalizedHost) {
		result.Hit = true
		result.Reason = targetReasonLoopbackOrPrivate
		result.Evidence = []Evidence{sanitizedEvidence(targetEvidenceRuleBlockedURL, "target", "url", raw)}
		return result
	}

	if parsedIP != nil {
		ip := *parsedIP
		if isCloudMetadataIP(ip) {
			result.Hit = true
			result.Reason = targetReasonCloudMetadata
			result.Evidence = []Evidence{sanitizedEvidence(targetEvidenceRuleBlockedURL, "target", "url", raw)}
			return result
		}
		if isLoopbackPrivateOrLocal(ip) {
			result.Hit = true
			result.Reason = targetReasonLoopbackOrPrivate
			result.Evidence = []Evidence{sanitizedEvidence(targetEvidenceRuleBlockedURL, "target", "url", raw)}
			return result
		}
	}

	return result
}

// fileTargetEvidence 是文件类目标命中的证据：原词脱敏，另记字面写法（filerestrict.LiteralPath：
// 不解码、不折叠，截到 filerestrict.MaxLiteralPathBytes）。
func fileTargetEvidence(raw string) Evidence {
	evidence := sanitizedEvidence(targetEvidenceRuleBlockedFS, "target", "path", raw)
	evidence.LiteralPath = filerestrict.LiteralPath(raw)
	return evidence
}

func analyzeFileTarget(raw string) TargetAnalysis {
	normalized := normalizeFilePath(raw)
	result := TargetAnalysis{Kind: TargetFile, RawTarget: raw, NormalizedTarget: normalized}
	lower := strings.ToLower(normalized)

	if isSSHPrivateKeyPath(lower) {
		result.Hit = true
		result.Reason = targetReasonSSHPrivateKey
		result.Evidence = []Evidence{fileTargetEvidence(raw)}
		return result
	}
	if isCloudCredentialPath(lower) {
		result.Hit = true
		result.Reason = targetReasonCloudCredential
		result.Evidence = []Evidence{fileTargetEvidence(raw)}
		return result
	}
	if reason, ok := sensitiveLocalFileReason(lower); ok {
		result.Hit = true
		result.Reason = reason
		result.Evidence = []Evidence{fileTargetEvidence(raw)}
		return result
	}

	return result
}

func looksLikeFileTarget(value string) bool {
	trimmed := strings.TrimSpace(value)
	if isSensitiveBareFileName(strings.ToLower(trimmed)) {
		return true
	}
	return strings.HasPrefix(trimmed, "/") ||
		strings.HasPrefix(trimmed, "./") ||
		strings.HasPrefix(trimmed, "../") ||
		strings.HasPrefix(trimmed, "~/") ||
		strings.Contains(trimmed, "/") ||
		strings.Contains(trimmed, `\`)
}

func normalizeURLHost(host string) (string, *netip.Addr) {
	decoded, err := url.QueryUnescape(host)
	if err == nil {
		host = decoded
	}
	host = strings.Trim(strings.ToLower(host), "[]")
	if host == "" {
		return host, nil
	}

	if ip, ok := parseIPLiteral(host); ok {
		unmapped := ip.Unmap()
		return unmapped.String(), &unmapped
	}

	return host, nil
}

func formatURLHost(host string, port string) string {
	if port != "" {
		return net.JoinHostPort(host, port)
	}
	if strings.Contains(host, ":") {
		return "[" + host + "]"
	}
	return host
}

func parseIPLiteral(host string) (netip.Addr, bool) {
	if ip, err := netip.ParseAddr(host); err == nil {
		return ip, true
	}
	return parseIPv4InetAton(host)
}

func parseIPv4InetAton(host string) (netip.Addr, bool) {
	parts := strings.Split(host, ".")
	if len(parts) < 1 || len(parts) > 4 {
		return netip.Addr{}, false
	}
	values := make([]uint64, 0, len(parts))
	for _, part := range parts {
		if part == "" {
			return netip.Addr{}, false
		}
		value, err := strconv.ParseUint(part, 0, 32)
		if err != nil {
			return netip.Addr{}, false
		}
		values = append(values, value)
	}

	var packed uint64
	switch len(values) {
	case 1:
		if values[0] > 0xffffffff {
			return netip.Addr{}, false
		}
		packed = values[0]
	case 2:
		if values[0] > 0xff || values[1] > 0xffffff {
			return netip.Addr{}, false
		}
		packed = values[0]<<24 | values[1]
	case 3:
		if values[0] > 0xff || values[1] > 0xff || values[2] > 0xffff {
			return netip.Addr{}, false
		}
		packed = values[0]<<24 | values[1]<<16 | values[2]
	case 4:
		for _, value := range values {
			if value > 0xff {
				return netip.Addr{}, false
			}
		}
		packed = values[0]<<24 | values[1]<<16 | values[2]<<8 | values[3]
	}

	return netip.AddrFrom4([4]byte{
		byte(packed >> 24),
		byte(packed >> 16),
		byte(packed >> 8),
		byte(packed),
	}), true
}

func isCloudMetadataIP(ip netip.Addr) bool {
	if ip == (netip.Addr{}) {
		return false
	}
	unmapped := ip.Unmap()
	return unmapped == netip.MustParseAddr("169.254.169.254") ||
		unmapped == netip.MustParseAddr("169.254.170.2") ||
		unmapped == netip.MustParseAddr("100.100.100.200")
}

// isMetadataHostname 用全平台唯一的元数据主机名清单（egresspolicy）。
func isMetadataHostname(host string) bool {
	return egresspolicy.IsMetadataHostname(host)
}

func isLoopbackOrPrivateHostname(host string) bool {
	normalized := strings.TrimSuffix(strings.ToLower(host), ".")
	if normalized == "localhost" || normalized == "localhost.localdomain" {
		return true
	}
	privateSuffixes := []string{".localhost", ".local", ".internal", ".lan", ".home", ".home.arpa"}
	for _, suffix := range privateSuffixes {
		if strings.HasSuffix(normalized, suffix) {
			return true
		}
	}
	return false
}

func isLoopbackPrivateOrLocal(ip netip.Addr) bool {
	unmapped := ip.Unmap()
	return unmapped.IsLoopback() ||
		unmapped.IsPrivate() ||
		unmapped.IsLinkLocalUnicast() ||
		unmapped.IsUnspecified()
}

func normalizeFilePath(raw string) string {
	decoded, err := url.QueryUnescape(raw)
	if err == nil {
		raw = decoded
	}
	raw = strings.ReplaceAll(raw, `\`, "/")
	if strings.HasPrefix(raw, "~/") {
		return "~/" + filepath.ToSlash(filepath.Clean(strings.TrimPrefix(raw, "~/")))
	}
	return filepath.ToSlash(filepath.Clean(raw))
}

func isSSHPrivateKeyPath(path string) bool {
	base := filepath.Base(path)
	if !strings.Contains(path, "/.ssh/") && !strings.HasPrefix(path, ".ssh/") {
		return false
	}
	switch base {
	case "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", "identity":
		return true
	default:
		return strings.HasSuffix(base, ".pem")
	}
}

func isSensitiveBareFileName(value string) bool {
	base := filepath.Base(strings.ReplaceAll(value, `\`, "/"))
	if base == ".env" || base == "process.env" {
		return true
	}
	return strings.HasPrefix(base, ".env.") && !isEnvTemplateFileName(base)
}

// isEnvTemplateFileName: by dotenv convention a file whose last suffix is
// example/sample/template/tmpl/tpl/dist (.env.example, .env.production.sample)
// is the committed template that documents variable names, while real values
// live in .env, .env.local, .env.<stage>. Only the final suffix counts, so
// .env.example.local is a real file again. The name decides only whether the
// path alone is a secret; a template that does carry a real key is still
// caught by content detection on the tool result and on egress.
func isEnvTemplateFileName(base string) bool {
	switch strings.ToLower(base[strings.LastIndex(base, ".")+1:]) {
	case "example", "sample", "template", "tmpl", "tpl", "dist":
		return true
	default:
		return false
	}
}

// sensitiveLocalFileReason 给出私钥、云凭据以外的敏感本地文件属于哪个防护项。path 是
// 规范化并转小写后的路径。判定顺序即优先级：先按文件名或完整路径认四个精确类，
// 其余靠名字猜的都落在“名字像敏感文件”。
func sensitiveLocalFileReason(path string) (string, bool) {
	base := filepath.Base(path)
	switch {
	case isEnvFileName(base):
		return targetReasonEnvFile, true
	case isSystemSecretFilePath(path):
		return targetReasonSystemSecretFile, true
	case isSecretMountPath(path):
		return targetReasonSecretMount, true
	case isGitCredentialsFilePath(path, base):
		return targetReasonGitCredentialsFile, true
	case isSensitiveNameHint(path, base):
		return targetReasonSensitiveName, true
	}
	return "", false
}

// isEnvFileName：.env 或 .env.<非模板后缀>（.env.local、.env.production）。
func isEnvFileName(base string) bool {
	return base == ".env" || (strings.HasPrefix(base, ".env.") && !isEnvTemplateFileName(base))
}

// isSystemSecretFilePath 按完整路径认系统口令文件和进程环境：/etc/shadow、/etc/gshadow、
// /proc/self/environ、/proc/<数字>/environ。/etc/shadow.bak、/host/etc/shadow 这类只是
// 名字像，落在“名字像敏感文件”。
func isSystemSecretFilePath(path string) bool {
	switch path {
	case "/etc/shadow", "/etc/gshadow", "/proc/self/environ":
		return true
	}
	pid, ok := strings.CutPrefix(path, "/proc/")
	if !ok {
		return false
	}
	pid, ok = strings.CutSuffix(pid, "/environ")
	return ok && isDecimalDigits(pid)
}

// secretMountDirs 是容器编排挂载密钥的目录。
var secretMountDirs = []string{"/var/run/secrets", "/run/secrets", "/etc/secrets"}

// isSecretMountPath：密钥挂载目录本身或其下任何文件。
func isSecretMountPath(path string) bool {
	for _, dir := range secretMountDirs {
		if path == dir || strings.HasPrefix(path, dir+"/") {
			return true
		}
	}
	return false
}

// isGitCredentialsFilePath：git credential-store 的两个默认文件，~/.git-credentials 与
// $XDG_CONFIG_HOME/git/credentials（~/.config/git/credentials）。
func isGitCredentialsFilePath(path, base string) bool {
	return base == ".git-credentials" || path == "~/.config/git/credentials" || strings.HasSuffix(path, "/.config/git/credentials")
}

// sensitiveNameFragments 是 2.9.21 起按子串匹配的系统文件片段；完整路径命中精确类的
// 已在前面认走，这里只剩名字像的（/etc/shadow.bak、/host/etc/shadow、/etc/passwd 等）。
var sensitiveNameFragments = []string{
	"/etc/passwd",
	"/etc/shadow",
	"/proc/self/environ",
	"/proc/1/environ",
	"/var/run/docker.sock",
}

// isSensitiveNameHint 是全部名字启发式：process.env、系统文件片段、文件名等于 token 或
// 含 secret/credential、路径段叫 token(s)/secret(s)/credential(s)/api-key 等。
// 源码文件（keep_secrets.go、auth/credentials.py、internal/secrets/store.go）只是名字像，
// 文件名与路径段两条不算（2026-11-21 客户现场 wc -l internal/provider/keep_secrets.go）。
func isSensitiveNameHint(path, base string) bool {
	if base == "process.env" {
		return true
	}
	for _, fragment := range sensitiveNameFragments {
		if containsPathFragment(path, fragment) {
			return true
		}
	}
	if isSourceCodeFileName(base) {
		return false
	}
	return base == "token" || strings.Contains(base, "secret") || strings.Contains(base, "credential") || hasSensitivePathSegment(path)
}

// containsPathFragment：path 里出现 fragment，且其后是串尾或仍属同一个路径的字符
// （/etc/passwd、/etc/passwd-、/etc/shadow.bak、/host/etc/shadow/x）。后面紧跟引号、括号、
// 逗号、冒号、空白等时只是文本里提到这个名字（JSON 数据 {"tool":"../etc/passwd"} 被花括号
// 展开出的 "tool":"../etc/passwd"），不是这个文件（2026-11-21 客户现场 curl -d）。
func containsPathFragment(path, fragment string) bool {
	for offset := 0; offset < len(path); {
		at := strings.Index(path[offset:], fragment)
		if at < 0 {
			return false
		}
		end := offset + at + len(fragment)
		if end == len(path) || isPathNameByte(path[end]) {
			return true
		}
		offset += at + 1
	}
	return false
}

func isPathNameByte(b byte) bool {
	return b == '/' || b == '.' || b == '-' || b == '_' || b == '~' || b == '+' || b == '@' || b == '*' || b == '?' ||
		(b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9') || b >= 0x80
}

// sourceCodeExtensions 是程序源码的扩展名。脚本（.sh）、配置与数据文件（.json、.yaml、.env、
// .ini ...）不在其中：它们常常直接装着凭据。
var sourceCodeExtensions = map[string]bool{
	"go": true, "py": true, "js": true, "mjs": true, "cjs": true, "ts": true, "tsx": true, "jsx": true,
	"java": true, "kt": true, "kts": true, "scala": true, "groovy": true, "rs": true, "c": true, "h": true,
	"cc": true, "cpp": true, "cxx": true, "hpp": true, "hh": true, "cs": true, "fs": true, "rb": true,
	"php": true, "swift": true, "m": true, "mm": true, "dart": true, "lua": true, "pl": true, "pm": true,
	"ex": true, "exs": true, "erl": true, "clj": true, "vue": true, "svelte": true, "zig": true, "nim": true,
}

// isSourceCodeFileName：文件名以源码扩展名结尾（keep_secrets.go、credentials_test.py）。
func isSourceCodeFileName(base string) bool {
	dot := strings.LastIndexByte(base, '.')
	return dot > 0 && sourceCodeExtensions[base[dot+1:]]
}

func hasSensitivePathSegment(path string) bool {
	for _, segment := range strings.Split(path, "/") {
		segment = strings.TrimSpace(strings.ToLower(segment))
		switch segment {
		case "token", "tokens", "secret", "secrets", "credential", "credentials", "api-key", "api_keys", "private-key", "private_keys":
			return true
		}
	}
	return false
}

func isCloudCredentialPath(path string) bool {
	cloudCredentialFragments := []string{
		"/.aws/credentials",
		"/.aws/config",
		"/.azure/accessTokens.json",
		"/.config/gcloud/application_default_credentials.json",
		"/google_application_credentials.json",
		"/.docker/config.json",
		"/.kube/config",
	}
	for _, fragment := range cloudCredentialFragments {
		fragment = strings.ToLower(fragment)
		// A path relative to the home directory (".aws/credentials") names
		// the same file as "~/.aws/credentials".
		if strings.Contains(path, fragment) || strings.HasPrefix(path, strings.TrimPrefix(fragment, "/")) {
			return true
		}
	}
	return false
}

func (analysis TargetAnalysis) String() string {
	return fmt.Sprintf("%s %s hit=%t reason=%s", analysis.Kind, analysis.NormalizedTarget, analysis.Hit, analysis.Reason)
}
