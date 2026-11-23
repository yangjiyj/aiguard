package handler

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
	"github.com/yangjiyj/aiguard/packages/shared-go/mcpprotocol"
	"github.com/yangjiyj/aiguard/packages/shared-go/mcpupstream"
	"github.com/yangjiyj/aiguard/packages/shared-go/safetarget"
	"github.com/yangjiyj/aiguard/packages/shared-go/secrets"
)

// 容量常量沿用既有取值，并作为 mcpupstream 的读取上限传入（Streamable JSON / SSE 通用）。
const (
	mcpManifestMaxBody     = 4 << 20 // 4MB：单次响应体 / 单次同步内 SSE 累计上限
	mcpManifestMaxSSEEvent = 1 << 20 // 1MB：SSE 单事件上限
)

var mcpManifestLimits = mcpupstream.Limits{
	MaxEventBytes:  mcpManifestMaxSSEEvent,
	MaxStreamBytes: mcpManifestMaxBody,
	MaxBodyBytes:   mcpManifestMaxBody,
}

// 协议版本集合统一由 packages/shared-go/mcpprotocol 维护（与 gateway-core 同源）。
const mcpProtocolVersionLatest = mcpprotocol.Latest

// mcpManifestMaxPages tools/list 游标分页的页数上限（防恶意 server 无限翻页）。
const mcpManifestMaxPages = 10

// maxMCPToolsPerServer 单台服务器累积工具总数硬上限：恶意 server（rug-pull 威胁模型）
// 可在单页/多页塞入海量工具，无界 append 会打爆 control-plane 内存并撑爆 mcp_tools 表。
// 达到上限即停止翻页并截断（截断事实记日志），正常清单远小于此值不受影响。
const maxMCPToolsPerServer = 500

// 单字段长度上限：防恶意 server 用超长字段放大内存/DB 占用。name/description 超长即按
// UTF-8 边界截断保留前缀；inputSchema/annotations 以序列化字节数为准，超限时以合法的
// 截断哨兵替代（保证仍是合法 JSON，供 jsonb 存储与 manifest 哈希）。
const (
	mcpToolNameMaxLen          = 512
	mcpToolDescMaxLen          = 8192
	mcpToolInputSchemaMaxBytes = 65536
)

// mcpManifestTool 是 tools/list 返回的单个工具定义（MCP 协议字段名为 camelCase）。
type mcpManifestTool struct {
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	InputSchema map[string]interface{} `json:"inputSchema"`
	// Annotations 是 MCP 协议的工具行为提示（title/readOnlyHint/destructiveHint/
	// idempotentHint/openWorldHint 等）。纳入 manifest 指纹：恶意 server 偷改 annotations
	// （如把 destructiveHint 由 true 抹成 false）也要触发 changed=true，堵 rug-pull 漏报。
	Annotations map[string]interface{} `json:"annotations,omitempty"`
}

// mcpRiskTagRules 工具风险启发式标注规则表：对 tool_name+description（小写）做关键词
// 命中即打标。刻意写成包级表格，便于评审与后续扩展；标签枚举与前端中文字典保持一致：
// destructive（破坏性操作）/ network_egress（网络外联）/ data_export（数据外发）/
// cred_access（凭据访问）/ file_write（文件写入）。
var mcpRiskTagRules = []struct {
	Tag      string
	Keywords []string
}{
	{"destructive", []string{"delete", "remove", "drop ", "drop_", "truncate", "destroy", "destructive", "terminate", "kill", "rm -", "format", "wipe", "purge", "uninstall", "revoke", "shell", "exec", "bash", "spawn", "subprocess", "run_command", "run_shell", "system("}},
	{"network_egress", []string{"http", "fetch", "request", "url", "download", "webhook", "curl", "browse", "crawl", "scrape", "web_search", "websearch"}},
	{"data_export", []string{"export", "upload", "send", "share", "publish", "email", "mail", "transfer", "post_message", "sync_to"}},
	{"cred_access", []string{"credential", "secret", "token", "password", "passwd", "api_key", "apikey", "api key", "keychain", "private key", "private_key", "oauth", "session_cookie"}},
	{"file_write", []string{"write", "save", "create_file", "create file", "edit", "modify", "append", "chmod", "chown", "mkdir", "move_file", "rename"}},
}

// annotateMCPRiskTags 按规则表对 tool_name+description 做启发式风险标注，并叠加 MCP
// 协议 annotations 的权威信号（destructiveHint→destructive、openWorldHint→network_egress）。
// annotations 是 server 自声明的行为提示，优先级高于关键词猜测——命令执行类工具（如
// run_shell）描述常为中文/不含英文关键词，仅靠 destructiveHint 才不漏标。返回去重后的
// 标签列表（保持规则表顺序，annotation 补充的标签追加在后、同样去重）。
func annotateMCPRiskTags(name, description string, annotations map[string]interface{}) []string {
	haystack := strings.ToLower(name + " " + description)
	seen := map[string]bool{}
	tags := []string{}
	add := func(tag string) {
		if !seen[tag] {
			seen[tag] = true
			tags = append(tags, tag)
		}
	}
	for _, rule := range mcpRiskTagRules {
		for _, kw := range rule.Keywords {
			if strings.Contains(haystack, kw) {
				add(rule.Tag)
				break
			}
		}
	}
	// annotations 权威信号叠加（bool 或 "true" 字符串都认）。
	if annotationHintTrue(annotations, "destructiveHint") {
		add("destructive")
	}
	if annotationHintTrue(annotations, "openWorldHint") {
		add("network_egress")
	}
	return tags
}

// annotationHintTrue 读取 MCP annotations 里的布尔提示（兼容 bool 与 "true" 字符串）。
func annotationHintTrue(annotations map[string]interface{}, key string) bool {
	if annotations == nil {
		return false
	}
	switch v := annotations[key].(type) {
	case bool:
		return v
	case string:
		return strings.EqualFold(strings.TrimSpace(v), "true")
	default:
		return false
	}
}

// mcpToolSchemaHash 单工具指纹：sha256(description + 规范化 input_schema JSON)，
// 用于同名工具的定义偏离检测（description/schema 被悄悄改也算 rug-pull 的一种）。
func mcpToolSchemaHash(description string, inputSchema map[string]interface{}) string {
	schemaBytes, _ := json.Marshal(inputSchema) // Go map 序列化按 key 排序，天然规范化
	sum := sha256.Sum256(append([]byte(description+"\x00"), schemaBytes...))
	return hex.EncodeToString(sum[:])
}

// mcpManifestHash 能力清单指纹：对每个工具规范化为 JSON 对象后按「完整内容」排序再取 sha256。
// 「内容哈希即版本」：哈希变了 = 能力清单变了 = rug-pull 信号。
// 排序键取整条规范化内容（而非仅 name）：与服务端返回顺序无关，重名工具也不会因相邻顺序
// run-to-run 抖动导致 hash 翻转误报 changed——sort.SliceStable 仅稳定同键相对次序，服务端
// 若把两条重名工具乱序返回，只有内容级全序排序才能得到一致 hash。annotations 一并纳入规范化。
func mcpManifestHash(tools []mcpManifestTool) string {
	entries := make([]string, 0, len(tools))
	for _, t := range tools {
		// Go 的 encoding/json 对 map（含嵌套）按 key 字典序输出，天然规范化，与字段书写顺序无关。
		b, _ := json.Marshal(map[string]interface{}{
			"name":        t.Name,
			"description": t.Description,
			"inputSchema": t.InputSchema,
			"annotations": t.Annotations,
		})
		entries = append(entries, string(b))
	}
	sort.SliceStable(entries, func(i, j int) bool { return entries[i] < entries[j] })
	h := sha256.New()
	for _, e := range entries {
		h.Write([]byte(e))
		h.Write([]byte{0}) // 分隔符：避免相邻条目拼接产生歧义
	}
	return hex.EncodeToString(h.Sum(nil))
}

// normalizeMCPManifestTool 对单个工具做字段长度归一化：超长 name/description 按 UTF-8 边界截断，
// 超大 inputSchema/annotations 以合法截断哨兵替代。恶意 server（rug-pull）用超长字段放大占用的兜底。
func normalizeMCPManifestTool(t mcpManifestTool) mcpManifestTool {
	t.Name = truncateUTF8(t.Name, mcpToolNameMaxLen)
	t.Description = truncateUTF8(t.Description, mcpToolDescMaxLen)
	t.InputSchema = boundJSONObject(t.InputSchema, mcpToolInputSchemaMaxBytes)
	t.Annotations = boundJSONObject(t.Annotations, mcpToolInputSchemaMaxBytes)
	return t
}

// truncateUTF8 把字符串截断到不超过 maxBytes 字节，且不切断多字节 UTF-8 字符（中文工具名/描述常见）。
func truncateUTF8(s string, maxBytes int) string {
	if len(s) <= maxBytes {
		return s
	}
	cut := maxBytes
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut]
}

// boundJSONObject 限制一个 JSON 对象序列化后的字节数：超限或无法序列化时以合法的截断哨兵替代，
// 既堵住超大字段打爆内存/DB，又保证仍是合法 JSON（供 jsonb 存储与 manifest 哈希）。
func boundJSONObject(m map[string]interface{}, maxBytes int) map[string]interface{} {
	if len(m) == 0 {
		return m
	}
	b, err := json.Marshal(m)
	if err == nil && len(b) <= maxBytes {
		return m
	}
	return map[string]interface{}{"_truncated": true, "_original_bytes": len(b)}
}

// mcpUpstreamEndpoint 是一次上游访问所需的全部已解析信息：已绑定出站目标的 client、
// 不含密钥的 URL、解析后的连接配置与解密后的密钥。密钥只活在内存，不进日志与错误。
type mcpUpstreamEndpoint struct {
	url          *url.URL
	client       *http.Client
	streamClient *http.Client
	cfg          mcpupstream.Config
	secret       string
}

func (e *mcpUpstreamEndpoint) options() mcpupstream.Options {
	return mcpupstream.Options{
		URL: e.url, Config: e.cfg, Secret: e.secret,
		Client: e.client, StreamClient: e.streamClient,
		Limits: mcpManifestLimits, EndpointTimeout: 5 * time.Second,
	}
}

// mcpUpstreamClientFactory 构造出站 client。生产路径一律经 safetarget 校验并固定目标 IP
// （禁重定向与代理）；测试可替换为 loopback 实现，生产代码没有绕过它的入口。
var mcpUpstreamClientFactory = func(ctx context.Context, rawURL string, opts safetarget.Options) (*http.Client, *http.Client, *url.URL, error) {
	target, err := safetarget.ResolveWithOptions(ctx, rawURL, opts, nil)
	if err != nil {
		return nil, nil, nil, err
	}
	base := &http.Client{Timeout: 10 * time.Second}
	return safetarget.Client(base, target, false), safetarget.Client(nil, target, true), target.URL, nil
}

// newMCPUpstreamEndpointForServer 解密凭据、解析连接配置并建立出站 client。
// 返回的 kind 用于测试连接的错误归类（url / auth）。
func newMCPUpstreamEndpointForServer(ctx context.Context, server *repository.MCPServer) (*mcpUpstreamEndpoint, string, error) {
	if server == nil {
		return nil, "url", fmt.Errorf("MCP 服务器配置缺失")
	}
	// 路由（地址 + 密钥 + 传输）未经复核的服务，不使用库内密钥对外发请求：
	//   - 被撤销（revoked）：管理员已明确撤销其准入，一律不外呼；
	//   - 因路由变更被自动隔离（quarantine_reason=route_binding_changed）：新地址尚未批准，
	//     用旧密钥访问它等于把密钥送给未审批目标；
	//   - 因清单漂移 / 描述投毒 / 影子工具等被隔离且路由未变：仍需继续同步，供管理员复核新清单，照常外呼。
	// 管理员复核并重新批准后恢复。
	if status := strings.ToLower(strings.TrimSpace(server.AdmissionStatus)); status == "revoked" ||
		(status == "quarantined" && strings.EqualFold(strings.TrimSpace(server.QuarantineReason), "route_binding_changed")) {
		label := "「已撤销」"
		if status == "quarantined" {
			label = "「已隔离（上游地址或鉴权已变更）」"
		}
		return nil, "quarantined", fmt.Errorf("该服务当前处于%s状态，其上游地址与密钥尚未经过复核，已停止对外请求。请先在供应链准入中复核该服务并重新批准后再测试连接或同步", label)
	}
	secret, err := secrets.DecryptProviderSecret(server.AuthCiphertext)
	if err != nil {
		return nil, "auth", fmt.Errorf("解密 MCP 服务器鉴权凭据失败")
	}
	cfg, err := mcpupstream.ParseConfig(server.Transport, server.Capabilities)
	if err != nil {
		return nil, "auth", err
	}
	client, streamClient, target, err := mcpUpstreamClientFactory(ctx, server.ServerURL, server.EgressOverrides.Options(server.AllowPrivateEgress))
	if err != nil {
		return nil, "url", fmt.Errorf("MCP 服务地址未通过出站安全校验: %s", mcpupstream.RedactText(err.Error(), secret))
	}
	return &mcpUpstreamEndpoint{url: target, client: client, streamClient: streamClient, cfg: cfg, secret: secret}, "", nil
}

// fetchMCPManifestForServer 对一台已登记的 MCP 服务器拉取能力清单：
// 解密鉴权凭据 → 按 transport 配置（streamable_http / sse / auto 探测）建立会话并 initialize
// → notifications/initialized（尽力而为）→ tools/list（含游标分页，带最大页数与重复 cursor 检测）。
// 生产外呼统一经 safetarget 校验并固定目标 IP。协商结果（协议版本、auto 探测到的 transport、
// 前向兼容的原始版本）写入 server.Capabilities，由同步事务落库。
func fetchMCPManifestForServer(ctx context.Context, server *repository.MCPServer) ([]mcpManifestTool, error) {
	ep, _, err := newMCPUpstreamEndpointForServer(ctx, server)
	if err != nil {
		return nil, err
	}
	tools, sess, err := fetchMCPManifestWithEndpoint(ctx, ep)
	if err != nil {
		return nil, err
	}
	recordMCPNegotiation(server, ep.cfg, sess)
	return tools, nil
}

// recordMCPNegotiation 把协商结果写进内存里的 capabilities（同步事务随后落库）。
func recordMCPNegotiation(server *repository.MCPServer, cfg mcpupstream.Config, sess *mcpupstream.Session) {
	if server.Capabilities == nil {
		server.Capabilities = map[string]interface{}{}
	}
	server.Capabilities[mcpupstream.CapProtocolVersion] = sess.Negotiated.Effective
	delete(server.Capabilities, mcpupstream.CapProtocolVersionRaw)
	delete(server.Capabilities, mcpupstream.CapProtocolForward)
	if sess.Negotiated.Forward {
		server.Capabilities[mcpupstream.CapProtocolVersionRaw] = sess.Negotiated.Raw
		server.Capabilities[mcpupstream.CapProtocolForward] = true
		for _, w := range sess.Warnings {
			log.Printf("MCP 协议版本前向兼容: server=%s %s", server.ID, w)
		}
	}
	if cfg.Transport == mcpupstream.TransportAuto {
		server.Capabilities[mcpupstream.CapDetectedTransport] = sess.Transport
	}
}

// mcpSyncCapabilityPatch 取出同步事务需要持久化的协商产物。
func mcpSyncCapabilityPatch(server *repository.MCPServer) map[string]interface{} {
	patch := map[string]interface{}{}
	for _, key := range []string{mcpupstream.CapProtocolVersionRaw, mcpupstream.CapProtocolForward} {
		if v, ok := server.Capabilities[key]; ok {
			patch[key] = v
		}
	}
	if cfg, err := mcpupstream.ParseConfig(server.Transport, nil); err == nil && cfg.Transport == mcpupstream.TransportAuto {
		if v, ok := server.Capabilities[mcpupstream.CapDetectedTransport]; ok {
			patch[mcpupstream.CapDetectedTransport] = v
		}
	}
	return patch
}

// fetchMCPManifestWithEndpoint 是 fetchMCPManifestForServer 的可注入 endpoint 版本（便于测试）。
func fetchMCPManifestWithEndpoint(ctx context.Context, ep *mcpUpstreamEndpoint) ([]mcpManifestTool, *mcpupstream.Session, error) {
	sess, err := mcpupstream.Connect(ctx, ep.options())
	if err != nil {
		return nil, nil, err
	}
	defer sess.Close()

	// tools/list：带游标分页，页数设上限防恶意翻页；另设总条数硬上限 maxMCPToolsPerServer +
	// 单字段长度归一化——恶意 server 可在单页塞入海量工具或超长字段，无界累积会打爆内存/DB。
	list, err := sess.ListTools(ctx, mcpManifestMaxPages, maxMCPToolsPerServer)
	if err != nil {
		return nil, sess, fmt.Errorf("tools/list 拉取失败: %w", err)
	}
	tools := make([]mcpManifestTool, 0, len(list.Tools))
	for _, raw := range list.Tools {
		var t mcpManifestTool
		if err := json.Unmarshal(raw, &t); err != nil {
			return nil, sess, fmt.Errorf("tools/list 响应解析失败: %w", err)
		}
		tools = append(tools, normalizeMCPManifestTool(t))
	}
	if list.Truncated {
		log.Printf("MCP manifest 工具数超过上限 %d，已截断（防恶意清单放大）: endpoint=%s", maxMCPToolsPerServer, mcpupstream.RedactURL(ep.url.String()))
	}
	for _, w := range list.Warnings {
		log.Printf("MCP tools/list: %s endpoint=%s", w, mcpupstream.RedactURL(ep.url.String()))
	}
	return tools, sess, nil
}

// testMCPServerConnection 只做 initialize 探活（不落库、不 tools/list、不写工具表），
// 返回结构化的 server_info 与分类错误 kind（dns/timeout/tls/connect/http_401/http_403/http_429/
// http_5xx/http/not_jsonrpc/oauth_required/parse/url/auth/rpc_error/cross_origin 等）。
// 复用 manifest 拉取的护栏 client（SSRF 护栏、超时、限流）。
func testMCPServerConnection(ctx context.Context, server *repository.MCPServer) (map[string]interface{}, string, error) {
	ep, kind, err := newMCPUpstreamEndpointForServer(ctx, server)
	if err != nil {
		return nil, kind, err
	}
	return probeMCPInitialize(ctx, ep)
}

// probeMCPInitialize 对已构造好的 endpoint 做握手探测并解析结果（便于测试注入）。
func probeMCPInitialize(ctx context.Context, ep *mcpUpstreamEndpoint) (map[string]interface{}, string, error) {
	opts := ep.options()
	opts.SkipInitializedNotice = true
	sess, err := mcpupstream.Connect(ctx, opts)
	if err != nil {
		return nil, mcpTestErrorKind(err), err
	}
	defer sess.Close()
	info := map[string]interface{}{
		"protocol_version": sess.Negotiated.Effective,
		"transport":        sess.Transport,
		"auto_detected":    sess.AutoDetected,
	}
	if sess.Negotiated.Forward {
		info["protocol_version_raw"] = sess.Negotiated.Raw
		info["warnings"] = sess.Warnings
	}
	if sess.FallbackNote != "" {
		info["fallback_reason"] = sess.FallbackNote
	}
	if name, ok := sess.ServerInfo["name"].(string); ok && name != "" {
		info["name"] = name
	}
	if version, ok := sess.ServerInfo["version"].(string); ok && version != "" {
		info["version"] = version
	}
	return info, "", nil
}

// mcpTestErrorKind 把 mcpupstream 错误映射为测试连接的 error_kind。
// 协议版本类错误沿用既有 kind "parse"（前端与既有测试口径不变）。
func mcpTestErrorKind(err error) string {
	var rpc *mcpupstream.RPCError
	if errors.As(err, &rpc) {
		return "rpc_error"
	}
	switch k := mcpupstream.KindOf(err); k {
	case "":
		return "connect"
	case mcpupstream.KindProtocolVersion:
		return "parse"
	default:
		return k
	}
}

// validateMCPServerURL 校验登记的 MCP 服务器地址：只允许 http/https、必须有主机名、
// 禁内嵌账号与片段（查询串放行——部分 MCP 端点用签名查询参数；明文密钥由保存流程自动拆出）。
func validateMCPServerURL(serverURL string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(serverURL))
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return "", fmt.Errorf("MCP 服务地址格式非法（需 http(s)://host[:port][/path]）")
	}
	if u.User != nil || u.Fragment != "" {
		return "", fmt.Errorf("MCP 服务地址不能包含内嵌账号或片段")
	}
	return u.String(), nil
}
