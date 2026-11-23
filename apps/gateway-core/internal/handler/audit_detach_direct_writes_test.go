package handler

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/yangjiyj/aiguard/packages/shared-go/aimsg"
	"github.com/yangjiyj/aiguard/packages/shared-go/retentionartifact"
	"github.com/yangjiyj/aiguard/packages/shared-go/retentionstore"
)

// 补齐 audit_detach_all_writes_test.go 没有守护的三个直连审计写入和制品留存的限时：
// 它们不经 AuditWriter，回退任何一处脱离取消，这里的用例都必须失败。

// ctxRecordingTransport 记录出站请求的 ctx 状态（未取消、有限时、value 可读），再交给真实传输。
type ctxRecordingTransport struct {
	probe *ctxProbe
	next  http.RoundTripper
}

func (t *ctxRecordingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	t.probe.record("http.request", req.Context())
	return t.next.RoundTrip(req)
}

// newRecordingToolRiskClient 把记录 ctx 的传输装进 ToolRiskClient；服务端收到请求本身也证明
// 入口把 ctx 脱离了取消（已取消的 ctx 在发出前就会失败）。
func newRecordingToolRiskClient(url string, probe *ctxProbe) *ToolRiskClient {
	client := NewToolRiskClient(url, "internal")
	client.httpClient = &http.Client{
		Timeout:   client.httpClient.Timeout,
		Transport: &ctxRecordingTransport{probe: probe, next: http.DefaultTransport},
	}
	return client
}

// jsonServer 记录服务端收到的请求；handler 与测试线程并发访问，所以用锁保护。
type jsonServer struct {
	*httptest.Server
	mu      sync.Mutex
	arrived int
	path    string
}

func (s *jsonServer) received() (int, string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.arrived, s.path
}

func newJSONServer(t *testing.T, response string) *jsonServer {
	t.Helper()
	s := &jsonServer{}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		s.arrived++
		s.path = r.URL.Path
		s.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(response))
	}))
	t.Cleanup(s.Close)
	return s
}

func TestToolRiskClient_LogToolCallWithIDDetachesFromRequestCancel(t *testing.T) {
	probe := &ctxProbe{}
	server := newJSONServer(t, `{"id":"tc-detach"}`)
	client := newRecordingToolRiskClient(server.URL, probe)

	id, err := client.LogToolCallWithID(canceledRequestCtx(), detachTestEnvelope("req-tool-log"), ToolAuditLogPayload{
		ToolName: "shell", ToolType: "builtin", RiskLevel: "high", Status: "blocked",
	})

	if err != nil || id != "tc-detach" {
		t.Fatalf("客户端取消后工具调用审计应照常写入: id=%q err=%v", id, err)
	}
	if arrived, path := server.received(); arrived != 1 || path != "/admin/v1/internal/tools/logs" {
		t.Fatalf("控制面应收到 1 次工具审计请求: arrived=%d path=%q", arrived, path)
	}
	probe.require(t, "http.request")
}

func TestToolRiskClient_RecordSkillInvocationDetachesFromRequestCancel(t *testing.T) {
	probe := &ctxProbe{}
	server := newJSONServer(t, `{"invocation_id":"inv-detach"}`)
	client := newRecordingToolRiskClient(server.URL, probe)

	id, err := client.RecordSkillInvocation(canceledRequestCtx(), detachTestEnvelope("req-skill"), "call-1", skillInvocationRecord{
		CanonicalName: "pdf", Status: "proposed", RawDecision: "allow", EffectiveDecision: "allow",
	})

	if err != nil || id != "inv-detach" {
		t.Fatalf("客户端取消后技能调用记录应照常写入: id=%q err=%v", id, err)
	}
	if arrived, path := server.received(); arrived != 1 || path != skillInvocationPath {
		t.Fatalf("控制面应收到 1 次技能调用请求: arrived=%d path=%q", arrived, path)
	}
	probe.require(t, "http.request")
}

// ctxRecordingMCPAuditDB 记录 MCP 审计 db 收到的 ctx。
type ctxRecordingMCPAuditDB struct {
	probe *ctxProbe
}

func (d *ctxRecordingMCPAuditDB) Begin(ctx context.Context) (mcpAuditTx, error) {
	d.probe.record("mcp.begin", ctx)
	return &fakeMCPAuditTx{}, nil
}

func (d *ctxRecordingMCPAuditDB) Exec(ctx context.Context, _ string, _ ...any) (pgconn.CommandTag, error) {
	d.probe.record("mcp.exec", ctx)
	return pgconn.CommandTag{}, nil
}

func TestMCPAuditRecorder_WriteMCPAccessDetachesFromRequestCancel(t *testing.T) {
	probe := &ctxProbe{}
	rec := &mcpProxyAuditRecorder{db: &ctxRecordingMCPAuditDB{probe: probe}}

	rec.writeMCPAccess(canceledRequestCtx(), mcpBlockRecord())

	probe.require(t, "mcp.exec")
}

// ---- 制品留存：60 秒有界限时 ----

type ctxRecordingArtifactStore struct {
	probe *ctxProbe
	mu    sync.Mutex
	puts  int
	// remaining 是最近一次 PutObject 看到的剩余限时。
	remaining time.Duration
}

func (s *ctxRecordingArtifactStore) PutObject(ctx context.Context, in retentionstore.PutObjectInput) (retentionstore.ObjectMetadata, error) {
	s.probe.record("artifact.put", ctx)
	s.mu.Lock()
	s.puts++
	if deadline, ok := ctx.Deadline(); ok {
		s.remaining = time.Until(deadline)
	} else {
		s.remaining = 0
	}
	s.mu.Unlock()
	return retentionstore.ObjectMetadata{
		Key: "obj/" + in.Stage, TenantID: in.TenantID, RequestID: in.RequestID, ContentType: in.ContentType,
		Size: 1, SHA256: "sha", StorageBackend: retentionstore.StorageBackendLocal,
	}, nil
}

func (s *ctxRecordingArtifactStore) GetObject(context.Context, string, string) (retentionstore.Object, error) {
	return retentionstore.Object{}, retentionstore.ErrObjectNotFound
}
func (s *ctxRecordingArtifactStore) DeleteObject(context.Context, string, string) error { return nil }
func (s *ctxRecordingArtifactStore) ReapExpired(context.Context, time.Time) (int, error) {
	return 0, nil
}

// 一张 data URL 图片，经 aimsg 解析成带 Payload 的输出制品候选。
func responseImageCandidates(t *testing.T) []retentionartifact.Candidate {
	t.Helper()
	image := base64.StdEncoding.EncodeToString([]byte("\x89PNG\r\n\x1a\nfake-image-bytes"))
	body, err := json.Marshal(map[string]any{
		"model": "gpt-4",
		"choices": []map[string]any{{
			"index": 0, "finish_reason": "stop",
			"message": map[string]any{"role": "assistant", "content": []map[string]any{
				{"type": "text", "text": "图在这里"},
				{"type": "image_url", "image_url": map[string]any{"url": "data:image/png;base64," + image}},
			}},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	projection, ok := aimsg.ParseOpenAIChatResponse(body)
	if !ok || len(projection.Artifacts) != 1 || projection.Artifacts[0].Payload == nil {
		t.Fatalf("测试数据没有产出带 Payload 的制品候选: ok=%v artifacts=%d", ok, len(projection.Artifacts))
	}
	return projection.Artifacts
}

// 连不上的库：retentionDays 立即失败并回落默认值，不拖慢测试；artifact 落库失败只打日志。
func unreachablePool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	pool, err := pgxpool.New(context.Background(), "postgres://u:p@127.0.0.1:1/db?connect_timeout=1&sslmode=disable")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	return pool
}

// 制品存储没有自带超时：ctx 必须未取消，且限时在 (10s, 60s] —— 比普通审计写入宽松但仍有界。
func TestChatHandler_RetainResponseArtifactsUsesBoundedDetachedContext(t *testing.T) {
	probe := &ctxProbe{}
	store := &ctxRecordingArtifactStore{probe: probe}
	h := &ChatCompletionsHandler{db: unreachablePool(t), artifactStore: store}

	h.retainResponseArtifacts(canceledRequestCtx(), detachTestEnvelope("req-artifact"), responseImageCandidates(t))

	if store.puts == 0 {
		t.Fatal("响应制品没有走到存储 PutObject，用例没有覆盖到制品留存")
	}
	probe.require(t, "artifact.put")
	if store.remaining <= auditWriteTimeout || store.remaining > auditArtifactTimeout {
		t.Fatalf("制品留存限时应在 (%v, %v] 内: remaining=%v", auditWriteTimeout, auditArtifactTimeout, store.remaining)
	}
}
