package handler

// 2.9.22 任务 4.5：故障处理与检测执行里由网关执行的几项走签名投影、按请求读取；
// 控制面没下发（库里没存）时才用网关环境变量作初值。

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/agentguard"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/config"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/relay"
)

var signedRuntimeOptions = map[string]any{
	"security_capacity_fail_mode":      "closed",
	"mcp_policy_fail_mode":             "closed",
	"retention_failure_mode":           "closed",
	"output_security_mode":             "strict_buffered",
	"output_strict_max_bytes":          "2097152",
	"upload_inspection_failure_action": "block",
}

func runtimeOptionsClient(t *testing.T, extra map[string]any) *ToolRiskClient {
	t.Helper()
	payload := signedGatewaySemanticPayload(gatewaySemanticTestKey, true, true, true, false, false)
	for key, value := range extra {
		payload[key] = value
	}
	resignGatewayPayload(t, payload)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == semanticGatewayConfigPath {
			_ = json.NewEncoder(w).Encode(payload)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(server.Close)
	client := NewToolRiskClient(server.URL, gatewaySemanticInternalTestSecret, gatewaySemanticTestKey)
	if _, err := client.refreshSemanticRuntimeConfig(context.Background()); err != nil {
		t.Fatalf("signed runtime options rejected: %v", err)
	}
	return client
}

func TestGatewayRuntimeOptionsAreSignedDecodedAndBeatEnvironment(t *testing.T) {
	// 环境变量刻意与库里相反：签名下发的值生效。
	t.Setenv("SECURITY_CAPACITY_FAIL_CLOSED", "false")
	t.Setenv("MCP_POLICY_FAIL_MODE", "open")
	client := runtimeOptionsClient(t, signedRuntimeOptions)
	cfg := &config.Config{OutputSecurityMode: "stream_enforce", OutputStrictMaxBytes: 4 << 20, RetentionFailureMode: "open"}
	if !client.CapacityFailClosed() || !guardrailPolicy(context.Background(), client).FailClosedOnCapacity {
		t.Fatal("security_capacity_fail_mode=closed 未生效")
	}
	if client.currentMCPPolicyFailMode() != "closed" || !client.markMCPPolicyUnavailable(mcpSupplyChainUnavailablePolicy()).policyFailClosed {
		t.Fatal("mcp_policy_fail_mode=closed 未生效")
	}
	if client.RetentionFailureMode(cfg.RetentionFailureMode) != "close" {
		t.Fatal("retention_failure_mode=closed 未生效")
	}
	if effectiveOutputSecurityMode(client, cfg) != relay.OutputSecurityStrictBuffered || effectiveOutputStrictMaxBytes(client, cfg) != 2097152 {
		t.Fatal("输出检测方式与缓冲上限未按请求读取签名值")
	}
	if !client.UploadInspectionFailureBlocks() {
		t.Fatal("upload_inspection_failure_action=block 未生效")
	}
}

func TestGatewayRuntimeOptionsFallBackToEnvironmentWhenNotStored(t *testing.T) {
	client := runtimeOptionsClient(t, nil)
	cfg := &config.Config{OutputSecurityMode: "stream_audit", OutputStrictMaxBytes: 8192, RetentionFailureMode: "close"}
	for _, env := range []string{"true", "false"} {
		t.Setenv("SECURITY_CAPACITY_FAIL_CLOSED", env)
		if client.CapacityFailClosed() != (env == "true") {
			t.Fatalf("未下发时容量策略应取环境变量 %s", env)
		}
	}
	client.SetMCPPolicyFailMode("closed")
	if client.currentMCPPolicyFailMode() != "closed" {
		t.Fatal("未下发时 MCP 策略失败模式应取装配值")
	}
	if client.RetentionFailureMode(cfg.RetentionFailureMode) != "close" ||
		effectiveOutputSecurityMode(client, cfg) != relay.OutputSecurityStreamAudit ||
		effectiveOutputStrictMaxBytes(client, cfg) != 8192 || client.UploadInspectionFailureBlocks() {
		t.Fatal("未下发时应取网关启动配置与缺省")
	}
	var nilClient *ToolRiskClient
	if nilClient.UploadInspectionFailureBlocks() || effectiveOutputSecurityMode(nilClient, nil) != relay.OutputSecurityStreamEnforce {
		t.Fatal("没有客户端时取缺省")
	}
}

func TestGatewayRuntimeOptionsIgnoreUnknownValuesButRejectBadTypesOrSignature(t *testing.T) {
	// 代码质量审查（重要 2）：签名里某个键的取值网关不认识时，只把该键当未下发并记日志，
	// 其余配置照常生效；类型不对或签名不符仍整份拒收。
	for key, bad := range map[string]string{
		"security_capacity_fail_mode": "maybe", "retention_failure_mode": "close",
		"output_security_mode": "buffered", "output_strict_max_bytes": "12", "upload_inspection_failure_action": "allow",
	} {
		payload := signedGatewaySemanticPayload(gatewaySemanticTestKey, true, true, true, false, false)
		payload[key] = bad
		payload["mcp_policy_fail_mode"] = "closed"
		resignGatewayPayload(t, payload)
		config, err := fetchGatewayPayload(t, payload)
		if err != nil {
			t.Fatalf("%s=%q 不应让整份签名配置被拒：%v", key, bad, err)
		}
		if config.RuntimeOptions.MCPPolicyFailMode != "closed" {
			t.Fatalf("同一份配置里的其他键应照常生效：%+v", config.RuntimeOptions)
		}
		ignored := config.RuntimeOptions
		ignored.MCPPolicyFailMode = ""
		if ignored != (runtimeSecurityOptions{}) {
			t.Fatalf("%s=%q 应按未下发处理：%+v", key, bad, config.RuntimeOptions)
		}
	}
	nonString := signedGatewaySemanticPayload(gatewaySemanticTestKey, true, true, true, false, false)
	nonString["mcp_policy_fail_mode"] = true
	resignGatewayPayload(t, nonString)
	if _, err := fetchGatewayPayload(t, nonString); err == nil {
		t.Fatal("非字符串取值应整份拒收")
	}
	unsigned := signedGatewaySemanticPayload(gatewaySemanticTestKey, true, true, true, false, false)
	unsigned["security_capacity_fail_mode"] = "closed"
	if _, err := fetchGatewayPayload(t, unsigned); err == nil {
		t.Fatal("签名后追加的键必须被拒")
	}
}

func TestMCPPolicyFailureDecisionReadsRuntimeMode(t *testing.T) {
	client := runtimeOptionsClient(t, map[string]any{"mcp_policy_fail_mode": "closed"})
	policy := client.markMCPPolicyUnavailable(mcpSupplyChainUnavailablePolicy())
	decision := applyMCPPolicyFailureDecision(policy, agentguard.Decision{EffectiveDecision: agentguard.DecisionAllow}, agentguard.ModeStrict)
	if decision.EffectiveDecision != agentguard.DecisionBlock {
		t.Fatalf("控制台选 closed 时 MCP 策略不可用应拦：%+v", decision)
	}
	open := runtimeOptionsClient(t, map[string]any{"mcp_policy_fail_mode": "open"})
	t.Setenv("MCP_POLICY_FAIL_MODE", "closed")
	open.SetMCPPolicyFailMode("closed")
	policy = open.markMCPPolicyUnavailable(mcpSupplyChainUnavailablePolicy())
	decision = applyMCPPolicyFailureDecision(policy, agentguard.Decision{EffectiveDecision: agentguard.DecisionAllow}, agentguard.ModeStrict)
	if decision.EffectiveDecision == agentguard.DecisionBlock {
		t.Fatalf("控制台选 open 时放行（只记覆盖缺口）：%+v", decision)
	}
}

// 端到端：控制面真端点按库里设置产出的签名投影（control-plane 测试写入的夹具）→ 网关读取。
func TestGatewayReadsControlPlaneRuntimeFixture(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "semantic_gateway_runtime_config.json"))
	if err != nil {
		t.Skipf("缺夹具，先跑 control-plane 的 TestGetInternalSemanticGatewayConfigWritesRuntimeFixture：%v", err)
	}
	var payload map[string]any
	if err := json.Unmarshal(raw, &payload); err != nil {
		t.Fatal(err)
	}
	// 部署变量为 true 但库里是 protect：网关按防护执行（设计 D7）。
	t.Setenv("SECURITY_AUDIT_ONLY", "true")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == semanticGatewayConfigPath {
			_, _ = w.Write(raw)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	client := NewToolRiskClient(server.URL, gatewaySemanticInternalTestSecret, gatewaySemanticTestKey)
	if _, err := client.refreshSemanticRuntimeConfig(context.Background()); err != nil {
		t.Fatalf("控制面产出的签名投影被拒：%v", err)
	}
	if client.SecurityAuditOnly(context.Background(), true) {
		t.Fatal("库里 protect 时网关必须按防护执行，部署变量只作初值")
	}
	cfg := &config.Config{OutputSecurityMode: "stream_enforce", OutputStrictMaxBytes: 4 << 20}
	if !client.CapacityFailClosed() || client.currentMCPPolicyFailMode() != "closed" ||
		effectiveOutputSecurityMode(client, cfg) != relay.OutputSecurityStrictBuffered ||
		effectiveOutputStrictMaxBytes(client, cfg) != 2097152 || !client.UploadInspectionFailureBlocks() ||
		client.RetentionFailureMode("open") != "close" {
		t.Fatalf("控制面下发的故障处理与检测执行设置未生效：%+v", payload)
	}
}

// 上传时检测失败：缺省照现在转发并记告警；控制台选“禁止”时在防护模式下拦，观察留痕下仍只记录。
func TestFileUploadInspectionFailureFollowsConsoleAction(t *testing.T) {
	for _, tc := range []struct {
		name      string
		options   map[string]any
		auditOnly bool
		wantCode  int
		wantCalls int
	}{
		{"default_forwards", nil, false, http.StatusOK, 1},
		{"forward_alert_forwards", map[string]any{"upload_inspection_failure_action": "forward_alert"}, false, http.StatusOK, 1},
		// 审查第三轮第 5 项：只看上传处置，“检测服务不可用即拦”打开也照常转发并告警。
		{"forward_alert_ignores_detection_fail_closed", map[string]any{"upload_inspection_failure_action": "forward_alert", "guardrail_fail_closed_enabled": true}, false, http.StatusOK, 1},
		{"block_rejects_in_protect", map[string]any{"upload_inspection_failure_action": "block"}, false, http.StatusServiceUnavailable, 0},
		{"block_records_in_record_mode", map[string]any{"upload_inspection_failure_action": "block"}, true, http.StatusOK, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			payload := signedGatewaySemanticPayload(gatewaySemanticTestKey, true, true, true, tc.auditOnly, false)
			payload["security_execution_mode_managed"] = true
			for key, value := range tc.options {
				payload[key] = value
			}
			resignGatewayPayload(t, payload)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == semanticGatewayConfigPath {
					_ = json.NewEncoder(w).Encode(payload)
					return
				}
				w.WriteHeader(http.StatusOK)
			}))
			defer server.Close()
			client := NewToolRiskClient(server.URL, gatewaySemanticInternalTestSecret, gatewaySemanticTestKey)
			if _, err := client.refreshSemanticRuntimeConfig(context.Background()); err != nil {
				t.Fatal(err)
			}
			security := &fileUploadSecurityStub{err: errFileUploadInspectionTest}
			caller := &fileUploadCallerStub{body: []byte(`{"id":"file_upstream","object":"file"}`)}
			h := newFileUploadHandlerForTest(&config.Config{}, security, caller)
			h.toolRiskClient = client
			audit := &MockAuditWriter{}
			h.auditWriter = audit
			response := httptest.NewRecorder()
			h.Handler().ServeHTTP(response, newFileUploadRequest(t, []byte("%PDF-safe-sample")))
			if response.Code != tc.wantCode || caller.calls != tc.wantCalls {
				t.Fatalf("status=%d calls=%d body=%s", response.Code, caller.calls, response.Body.String())
			}
			if len(audit.SecurityEventWrites) == 0 {
				t.Fatal("检测失败必须记一条事件")
			}
		})
	}
}

var errFileUploadInspectionTest = errors.New("security engine unavailable")

// managedRuntimeClient：签名快照为控制台显式防护模式，并带上给定的运行选项。
func managedRuntimeClient(t *testing.T, options map[string]any) *ToolRiskClient {
	t.Helper()
	extra := map[string]any{"security_execution_mode_managed": true}
	for key, value := range options {
		extra[key] = value
	}
	return runtimeOptionsClient(t, extra)
}

// 审查第 6 项：非流式输出的“缓冲严格”与上限按请求读控制台值（chat_completions.go 读取点）。
func TestStrictBufferedOutputBudgetReadsConsolePerRequest(t *testing.T) {
	t.Setenv("SECURITY_AUDIT_ONLY", "")
	client := managedRuntimeClient(t, map[string]any{"output_security_mode": "strict_buffered", "output_strict_max_bytes": "1024"})
	h := &ChatCompletionsHandler{
		cfg:            &config.Config{OutputSecurityMode: "stream_enforce", OutputStrictMaxBytes: 4 << 20},
		toolRiskClient: client, securityClient: &MockSecurityChecker{}, auditWriter: &MockAuditWriter{},
	}
	body := []byte(`{"id":"x","object":"chat.completion","choices":[{"index":0,"message":{"role":"assistant","content":"` + strings.Repeat("a", 2048) + `"}}]}`)
	_, audit, err := h.applyOutputSecurityCore(context.Background(), &modelrouter.RequestEnvelope{RequestID: "strict-1"}, nil, body)
	if err == nil || audit == nil || audit.OutputAction != "block" || !strings.Contains(err.Error(), "1024-byte budget") {
		t.Fatalf("控制台选缓冲严格、上限 1024 时应按请求拦超限输出：audit=%+v err=%v", audit, err)
	}
	enforce := managedRuntimeClient(t, map[string]any{"output_security_mode": "stream_enforce"})
	h.cfg = &config.Config{OutputSecurityMode: "strict_buffered", OutputStrictMaxBytes: 1024}
	h.toolRiskClient = enforce
	if _, audit, err := h.applyOutputSecurityCore(context.Background(), &modelrouter.RequestEnvelope{RequestID: "strict-2"}, nil, body); err != nil || audit.OutputAction == "block" {
		t.Fatalf("控制台选流式执行时不按启动配置的缓冲严格拦：audit=%+v err=%v", audit, err)
	}
}

// 审查第 6 项：流式输出的执行方式按请求读控制台值（streaming_relay.go 读取点）。
func TestLiveChatStreamModeReadsConsolePerRequest(t *testing.T) {
	t.Setenv("SECURITY_AUDIT_ONLY", "")
	run := func(startup string, console string) string {
		caller := &liveRelayCaller{reader: &liveRelayReader{events: []relay.StreamEvent{
			{Type: relay.EventTextDelta, Delta: "credential-canary"},
			{Type: relay.EventMessageEnd, FinishReason: "stop"},
		}}}
		h := &ChatCompletionsHandler{
			cfg:            &config.Config{UpstreamStreaming: true, OutputSecurityMode: startup},
			toolRiskClient: managedRuntimeClient(t, map[string]any{"output_security_mode": console}),
			securityClient: &MockSecurityChecker{OutputAction: "block", OutputFindings: []SecurityFinding{{Type: "secret", Category: "openai_key", Action: "block", Severity: "high"}}},
			auditWriter:    &MockAuditWriter{},
		}
		recorder := httptest.NewRecorder()
		envelope := &modelrouter.RequestEnvelope{RequestID: "live-1", Model: "m", RequestStartedAt: time.Now()}
		if _, err := h.tryLiveChatStream(context.Background(), recorder, envelope, caller, []byte("{}"), time.Now(), "", &relay.CommitTracker{}); err != nil {
			t.Logf("stream err: %v", err)
		}
		return recorder.Body.String()
	}
	if body := run("stream_enforce", "stream_audit"); strings.Contains(body, "security_error") || !strings.Contains(body, "credential-canary") {
		t.Fatalf("控制台选只审计时流不应被打断：%s", body)
	}
	// 控制台选流式执行：命中阻断的增量先扣住不发、随后打断；启动配置的只审计会先原样发出。
	if body := run("stream_audit", "stream_enforce"); !strings.Contains(body, "security_error") || strings.Contains(body, "credential-canary") {
		t.Fatalf("控制台选流式执行时命中阻断的内容不应发出并打断流：%s", body)
	}
}

// 代码质量审查（严重）：反向代理流式缓冲也按请求读控制台的输出检测方式与缓冲上限。
// 启动配置是流式执行（待发上限 4MiB），控制台选缓冲严格、上限 1024：2KB 的输出超出上限，
// 开了“检测失败即拦”时必须安全收口，不能按启动配置原样放行。
func TestReverseProxyStreamHoldbackReadsConsolePerRequest(t *testing.T) {
	t.Setenv("SECURITY_AUDIT_ONLY", "")
	client := runtimeOptionsClient(t, map[string]any{
		"security_execution_mode_managed": true, "guardrail_fail_closed_enabled": true,
		"output_security_mode": "strict_buffered", "output_strict_max_bytes": "1024",
	})
	body := `data: {"choices":[{"delta":{"content":"` + strings.Repeat("safe ", 400) + `"}}]}` + "\n\ndata: [DONE]\n\n"
	h, route, _, _ := reverseHardeningFixture(t, "/v1/chat/completions", "text/event-stream", body, reverseHardeningEngine, client)
	h.SetOutputStreamConfig(&config.Config{OutputSecurityMode: "stream_enforce"})
	w := reverseHardeningForward(t, h, route, http.MethodGet, "")
	if strings.Contains(w.Body.String(), "safe safe") || !strings.Contains(w.Body.String(), guardrailDetectionUnavailableCode) {
		t.Fatalf("控制台选缓冲严格且上限 1024 时，超限输出应安全收口：%s", w.Body.String())
	}
}

// 复审第四轮：周期刷新时同一个不认识的取值只记一次日志，取值变化再记。
func TestGatewayRuntimeOptionsLogUnknownValueOnlyOnChange(t *testing.T) {
	var buf bytes.Buffer
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	client := runtimeOptionsClient(t, map[string]any{"security_capacity_fail_mode": "maybe"})
	for i := 0; i < 2; i++ {
		if _, err := client.refreshSemanticRuntimeConfig(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if n := strings.Count(buf.String(), "security_capacity_fail_mode"); n != 1 {
		t.Fatalf("同一个不认识的取值应只记一次，实际 %d 次：%s", n, buf.String())
	}
}
