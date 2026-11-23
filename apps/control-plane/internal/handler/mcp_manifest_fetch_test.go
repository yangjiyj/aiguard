package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/yangjiyj/aiguard/packages/shared-go/mcpupstream"
)

// testMCPEndpoint 构造测试专用的 loopback endpoint（不经 safetarget；生产代码没有绕过它的入口）。
func testMCPEndpoint(serverURL, authToken string) (*mcpUpstreamEndpoint, error) {
	endpoint, err := validateMCPServerURL(serverURL)
	if err != nil {
		return nil, err
	}
	u, err := url.Parse(endpoint)
	if err != nil {
		return nil, err
	}
	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	cfg, err := mcpupstream.ParseConfig("streamable_http", nil)
	if err != nil {
		return nil, err
	}
	return &mcpUpstreamEndpoint{url: u, client: client, streamClient: client, cfg: cfg, secret: authToken}, nil
}

// fetchMCPManifest 是测试专用入口：Streamable HTTP + Bearer 鉴权（存量默认配置）。
func fetchMCPManifest(ctx context.Context, serverURL, authToken string) ([]mcpManifestTool, error) {
	ep, err := testMCPEndpoint(serverURL, authToken)
	if err != nil {
		return nil, err
	}
	tools, _, err := fetchMCPManifestWithEndpoint(ctx, ep)
	return tools, err
}

// newMCPMockServer 起一个最小 MCP JSON-RPC 服务：initialize 回握手（签发 Mcp-Session-Id），
// tools/list 单页返回 toolsForPage 提供的工具清单（nextCursor 由其决定，用于覆盖截断/分页路径）。
func newMCPMockServer(t *testing.T, toolsForPage func() (tools []map[string]interface{}, nextCursor string)) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		w.Header().Set("Content-Type", "application/json")
		switch req.Method {
		case "initialize":
			w.Header().Set("Mcp-Session-Id", "sess-1")
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":` + string(req.ID) + `,"result":{"protocolVersion":"2025-11-25"}}`))
		case "notifications/initialized":
			w.WriteHeader(http.StatusAccepted)
		case "tools/list":
			tools, next := toolsForPage()
			result := map[string]interface{}{"tools": tools}
			if next != "" {
				result["nextCursor"] = next
			}
			resp, _ := json.Marshal(map[string]interface{}{
				"jsonrpc": "2.0",
				"id":      req.ID,
				"result":  result,
			})
			_, _ = w.Write(resp)
		default:
			http.Error(w, "unknown method", http.StatusBadRequest)
		}
	}))
}

// TestFetchMCPManifestCapsToolCount 恶意 server 单页塞入远超上限的工具，累积必须被截断到
// maxMCPToolsPerServer，且即便宣称还有 nextCursor 也不再翻页（防清单放大打爆内存/DB）。
func TestFetchMCPManifestCapsToolCount(t *testing.T) {
	srv := newMCPMockServer(t, func() ([]map[string]interface{}, string) {
		tools := make([]map[string]interface{}, 0, maxMCPToolsPerServer+100)
		for i := 0; i < maxMCPToolsPerServer+100; i++ {
			tools = append(tools, map[string]interface{}{"name": "tool_" + strconv.Itoa(i)})
		}
		return tools, "still-more" // 谎称还有下一页：截断后不应再翻页
	})
	defer srv.Close()

	got, err := fetchMCPManifest(context.Background(), srv.URL, "")
	if err != nil {
		t.Fatalf("fetchMCPManifest: %v", err)
	}
	if len(got) != maxMCPToolsPerServer {
		t.Fatalf("工具数应被截断到 %d，实得 %d", maxMCPToolsPerServer, len(got))
	}
}

// TestFetchMCPManifestTruncatesLongFields 超长 name/description/inputSchema 必须被截断/兜底，
// 避免恶意 server 用超长字段放大内存/DB 占用。
func TestFetchMCPManifestTruncatesLongFields(t *testing.T) {
	longName := strings.Repeat("N", mcpToolNameMaxLen+2000)
	longDesc := strings.Repeat("描", mcpToolDescMaxLen) // 每个中文 3 字节，远超字节上限
	longSchemaVal := strings.Repeat("x", mcpToolInputSchemaMaxBytes+1000)

	srv := newMCPMockServer(t, func() ([]map[string]interface{}, string) {
		return []map[string]interface{}{
			{
				"name":        longName,
				"description": longDesc,
				"inputSchema": map[string]interface{}{"blob": longSchemaVal},
			},
		}, ""
	})
	defer srv.Close()

	got, err := fetchMCPManifest(context.Background(), srv.URL, "")
	if err != nil {
		t.Fatalf("fetchMCPManifest: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("应返回 1 个工具，实得 %d", len(got))
	}
	tool := got[0]
	if len(tool.Name) > mcpToolNameMaxLen {
		t.Errorf("name 应截断到 <= %d 字节，实得 %d", mcpToolNameMaxLen, len(tool.Name))
	}
	if len(tool.Description) > mcpToolDescMaxLen {
		t.Errorf("description 应截断到 <= %d 字节，实得 %d", mcpToolDescMaxLen, len(tool.Description))
	}
	// 截断后的 description 必须仍是合法 UTF-8（不能切出半个中文字符）。
	if !utf8.ValidString(tool.Description) {
		t.Errorf("description 截断后不是合法 UTF-8")
	}
	// 超大 inputSchema 应被替换为合法的截断哨兵。
	if trunc, _ := tool.InputSchema["_truncated"].(bool); !trunc {
		t.Errorf("超大 inputSchema 应被替换为截断哨兵，实得 %+v", tool.InputSchema)
	}
}

// TestFetchMCPManifestNormalUnaffected 正常规模清单原样返回，字段与 annotations 均不被改动。
func TestFetchMCPManifestNormalUnaffected(t *testing.T) {
	srv := newMCPMockServer(t, func() ([]map[string]interface{}, string) {
		return []map[string]interface{}{
			{
				"name":        "fs.read_file",
				"description": "读取文件",
				"inputSchema": map[string]interface{}{"type": "object"},
				"annotations": map[string]interface{}{"readOnlyHint": true},
			},
			{"name": "net.fetch", "description": "拉取网页"},
		}, ""
	})
	defer srv.Close()

	got, err := fetchMCPManifest(context.Background(), srv.URL, "")
	if err != nil {
		t.Fatalf("fetchMCPManifest: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("应返回 2 个工具，实得 %d", len(got))
	}
	if got[0].Name != "fs.read_file" || got[0].Description != "读取文件" {
		t.Errorf("正常工具字段被改动: %+v", got[0])
	}
	if ro, _ := got[0].Annotations["readOnlyHint"].(bool); !ro {
		t.Errorf("annotations 应被原样保留: %+v", got[0].Annotations)
	}
}

// TestMCPManifestHashIncludesAnnotations annotations 变更（如 destructiveHint 被偷改）必须让
// manifest_hash 变化，才能触发 changed=true 堵 rug-pull 漏报。
func TestMCPManifestHashIncludesAnnotations(t *testing.T) {
	base := []mcpManifestTool{
		{Name: "rm", Description: "删除", Annotations: map[string]interface{}{"destructiveHint": true}},
	}
	tampered := []mcpManifestTool{
		{Name: "rm", Description: "删除", Annotations: map[string]interface{}{"destructiveHint": false}},
	}
	if mcpManifestHash(base) == mcpManifestHash(tampered) {
		t.Fatalf("annotations 变更应改变 manifest_hash")
	}
}

// TestMCPManifestHashOrderIndependent 内容相同、服务端返回顺序不同 → hash 不变（免误报 changed）。
func TestMCPManifestHashOrderIndependent(t *testing.T) {
	a := []mcpManifestTool{
		{Name: "a", Description: "A"},
		{Name: "b", Description: "B"},
		{Name: "c", Description: "C"},
	}
	b := []mcpManifestTool{
		{Name: "c", Description: "C"},
		{Name: "a", Description: "A"},
		{Name: "b", Description: "B"},
	}
	if mcpManifestHash(a) != mcpManifestHash(b) {
		t.Fatalf("工具顺序打乱但内容不变，hash 应一致")
	}
}

// TestMCPManifestHashDuplicateNamesStable 重名（畸形清单）工具在不同相邻顺序下 hash 稳定，
// 不因 run-to-run 排序抖动翻转导致误报 changed。
func TestMCPManifestHashDuplicateNamesStable(t *testing.T) {
	a := []mcpManifestTool{
		{Name: "dup", Description: "第一版"},
		{Name: "dup", Description: "第二版"},
	}
	b := []mcpManifestTool{
		{Name: "dup", Description: "第二版"},
		{Name: "dup", Description: "第一版"},
	}
	if mcpManifestHash(a) != mcpManifestHash(b) {
		t.Fatalf("重名工具相邻顺序不同但内容集合相同，hash 应一致")
	}
}

// TestAnnotateMCPRiskTagsShellAndAnnotations 回归（e2e 实测发现 run_shell 漏标）：
// ① 命令执行类工具靠新增 shell/exec 关键词命中 destructive；
// ② MCP annotations 的 destructiveHint/openWorldHint 作为权威信号叠加，
//
//	即便 description 是中文、无英文关键词也不漏标。
func TestAnnotateMCPRiskTagsShellAndAnnotations(t *testing.T) {
	has := func(tags []string, want string) bool {
		for _, x := range tags {
			if x == want {
				return true
			}
		}
		return false
	}

	// run_shell：名字含 shell 关键词 → destructive（此前中文描述漏标）
	tags := annotateMCPRiskTags("run_shell", "在服务器上执行 shell 命令（可删除文件）", nil)
	if !has(tags, "destructive") {
		t.Fatalf("run_shell 应标 destructive，得到 %v", tags)
	}

	// 仅靠 annotations.destructiveHint（名字/描述都无关键词）也要命中
	tags = annotateMCPRiskTags("do_thing", "执行某操作", map[string]interface{}{"destructiveHint": true})
	if !has(tags, "destructive") {
		t.Fatalf("destructiveHint=true 应标 destructive，得到 %v", tags)
	}

	// openWorldHint → network_egress；字符串 "true" 也认
	tags = annotateMCPRiskTags("connector", "连接外部系统", map[string]interface{}{"openWorldHint": "true"})
	if !has(tags, "network_egress") {
		t.Fatalf("openWorldHint 应标 network_egress，得到 %v", tags)
	}

	// 无害只读工具不误标
	tags = annotateMCPRiskTags("echo", "回显文本", map[string]interface{}{"readOnlyHint": true})
	if len(tags) != 0 {
		t.Fatalf("echo 不应有风险标签，得到 %v", tags)
	}
}
