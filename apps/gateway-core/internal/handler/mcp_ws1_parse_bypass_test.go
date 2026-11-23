package handler

// W1 1.1 / 1.2：解析差异绕过与非 tools/call 方法直通。全部用真实 JSON-RPC 请求体复现。

import (
	"encoding/json"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
)

// 1.1a 重复键：Go encoding/json 取最后一个 name，很多上游（JS 的 JSON.parse 也是后者，
// 但 Python json 默认后者、部分流式解析器取前者）——网关与上游看到的可能不是同一工具。
// 修复要求：重复键一律 -32600，且绝不触达上游。
func TestWS1DuplicateKeyToolNameRejected(t *testing.T) {
	env := newWS1Env(t, false, blockTool("delete_repo"))
	body := `{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"delete_repo","name":"read_file","arguments":{"repo":"demo"}}}`
	w := env.post(t, body)
	if code := rpcErrorCode(t, w.Body.String()); code != -32600 {
		t.Fatalf("重复键必须 -32600，got code=%d body=%s", code, w.Body.String())
	}
	if hits := atomic.LoadInt32(env.upstreamHits); hits != 0 {
		t.Fatalf("重复键载荷不得触达上游: hits=%d bodies=%v", hits, env.bodies())
	}
}

// 1.1b 顶层 method 重复键：网关看 tools/list（直通），上游若取第一个则执行 tools/call。
func TestWS1DuplicateMethodKeyRejected(t *testing.T) {
	env := newWS1Env(t, false, blockTool("delete_repo"))
	body := `{"jsonrpc":"2.0","id":9,"method":"tools/call","method":"tools/list","params":{"name":"delete_repo","arguments":{}}}`
	w := env.post(t, body)
	if code := rpcErrorCode(t, w.Body.String()); code != -32600 {
		t.Fatalf("method 重复键必须 -32600，got %d body=%s", code, w.Body.String())
	}
	if atomic.LoadInt32(env.upstreamHits) != 0 {
		t.Fatalf("不得触达上游: %v", env.bodies())
	}
}

// 1.1c 大小写：Go 把 "Name" 匹配到 Name 字段 → 网关判定 "Name" 的值；
// 区分大小写的上游只认 "name"。构造：name=read_file（上游执行？不，上游执行的是 name），
// 这里让 "name" 为被禁工具、"Name" 为无害工具；Go 后者覆盖 → 网关看 read_file 放行。
func TestWS1CaseVariantKeyDoesNotShadowName(t *testing.T) {
	env := newWS1Env(t, false, blockTool("delete_repo"))
	body := `{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"delete_repo","Name":"read_file","arguments":{"repo":"demo"}}}`
	w := env.post(t, body)
	if atomic.LoadInt32(env.upstreamHits) != 0 {
		t.Fatalf("大小写变体键绕过：上游收到了 delete_repo 调用 bodies=%v resp=%s", env.bodies(), w.Body.String())
	}
	if code := rpcErrorCode(t, w.Body.String()); code != -32000 && code != -32600 {
		t.Fatalf("应被策略拦截或按协议拒绝, got %d body=%s", code, w.Body.String())
	}
}

// 1.1d 顶层 "Method" 大小写变体：Go 取 Method 字段值 tools/list，上游只认 method。
func TestWS1CaseVariantMethodKeyNotTrusted(t *testing.T) {
	env := newWS1Env(t, false, blockTool("delete_repo"))
	body := `{"jsonrpc":"2.0","id":9,"method":"tools/call","Method":"tools/list","params":{"name":"delete_repo","arguments":{}}}`
	env.post(t, body)
	if atomic.LoadInt32(env.upstreamHits) != 0 {
		t.Fatalf("Method 大小写变体绕过：bodies=%v", env.bodies())
	}
}

// 1.1e 转发的是重新序列化后的规范载荷，而不是原始字节：未知的多余大小写键不会被带给上游。
func TestWS1ForwardsCanonicalReserializedBody(t *testing.T) {
	env := newWS1Env(t, false, blockTool("delete_repo"))
	body := `{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/tmp/a"}}}`
	w := env.post(t, body)
	if w.Code != http.StatusOK || atomic.LoadInt32(env.upstreamHits) != 1 {
		t.Fatalf("正常调用应转发: code=%d hits=%d body=%s", w.Code, atomic.LoadInt32(env.upstreamHits), w.Body.String())
	}
	var forwarded map[string]json.RawMessage
	if err := json.Unmarshal([]byte(env.bodies()[0]), &forwarded); err != nil {
		t.Fatalf("上游收到非法 JSON: %v", err)
	}
	for key := range forwarded {
		switch key {
		case "jsonrpc", "id", "method", "params":
		default:
			t.Fatalf("转发体含非规范顶层键 %q: %s", key, env.bodies()[0])
		}
	}
}

// 1.1f params 里 arguments 重复键：网关红线/参数判定用后者，上游可能取前者。
func TestWS1DuplicateArgumentsKeyRejected(t *testing.T) {
	env := newWS1Env(t, false, blockTool("never"))
	body := `{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"run_shell","arguments":{"command":"rm -rf /","command":"ls"}}}`
	w := env.post(t, body)
	if code := rpcErrorCode(t, w.Body.String()); code != -32600 {
		t.Fatalf("arguments 内重复键必须 -32600，got %d body=%s", code, w.Body.String())
	}
	if atomic.LoadInt32(env.upstreamHits) != 0 {
		t.Fatalf("不得触达上游: %v", env.bodies())
	}
}

// 1.2a resources/read 按 uri 查策略：管理员配了 block 的 uri 必须被拦。
func TestWS1ResourcesReadEntersPolicy(t *testing.T) {
	uri := "file:///etc/shadow"
	env := newWS1Env(t, false, func(name, kind string) MCPEffectivePolicy {
		if kind == "resource" && name == uri {
			return MCPEffectivePolicy{Matched: true, PolicyID: "mcppol_res", Mode: "strict", Action: "block"}
		}
		return MCPEffectivePolicy{Matched: false, Mode: "audit", Action: "audit"}
	})
	body := `{"jsonrpc":"2.0","id":5,"method":"resources/read","params":{"uri":"file:///etc/shadow"}}`
	w := env.post(t, body)
	if atomic.LoadInt32(env.upstreamHits) != 0 {
		t.Fatalf("resources/read 命中 block 仍直通: resp=%s targets=%v", w.Body.String(), env.targets())
	}
	if code := rpcErrorCode(t, w.Body.String()); code != -32000 {
		t.Fatalf("应返回策略阻断 -32000，got %d body=%s", code, w.Body.String())
	}
}

// 1.2b prompts/get 按 prompt 名查策略。
func TestWS1PromptsGetEntersPolicy(t *testing.T) {
	env := newWS1Env(t, false, func(name, kind string) MCPEffectivePolicy {
		if kind == "prompt" && name == "leak_secrets" {
			return MCPEffectivePolicy{Matched: true, PolicyID: "mcppol_prompt", Mode: "strict", Action: "block"}
		}
		return MCPEffectivePolicy{Matched: false, Mode: "audit", Action: "audit"}
	})
	body := `{"jsonrpc":"2.0","id":6,"method":"prompts/get","params":{"name":"leak_secrets","arguments":{}}}`
	w := env.post(t, body)
	if atomic.LoadInt32(env.upstreamHits) != 0 || rpcErrorCode(t, w.Body.String()) != -32000 {
		t.Fatalf("prompts/get 命中 block 必须拦: hits=%d resp=%s targets=%v", atomic.LoadInt32(env.upstreamHits), w.Body.String(), env.targets())
	}
}

// 1.2c 其他方法（completion/complete）按方法名查策略。
func TestWS1OtherMethodEntersPolicyByMethodName(t *testing.T) {
	env := newWS1Env(t, false, func(name, kind string) MCPEffectivePolicy {
		if kind == "method" && name == "completion/complete" {
			return MCPEffectivePolicy{Matched: true, PolicyID: "mcppol_method", Mode: "strict", Action: "block"}
		}
		return MCPEffectivePolicy{Matched: false, Mode: "audit", Action: "audit"}
	})
	body := `{"jsonrpc":"2.0","id":7,"method":"completion/complete","params":{"ref":{"type":"ref/prompt","name":"x"},"argument":{"name":"a","value":"b"}}}`
	w := env.post(t, body)
	if atomic.LoadInt32(env.upstreamHits) != 0 || rpcErrorCode(t, w.Body.String()) != -32000 {
		t.Fatalf("completion/complete 命中 block 必须拦: resp=%s targets=%v", w.Body.String(), env.targets())
	}
}

// Case variants must not bypass the tools/call policy target.
func TestWS1CaseVariantMethodUsesCanonicalToolPolicy(t *testing.T) {
	env := newWS1Env(t, false, blockTool("delete_repo"))
	body := `{"jsonrpc":"2.0","id":8,"method":"Tools/Call","params":{"name":"delete_repo","arguments":{}}}`
	w := env.post(t, body)
	found := false
	for _, target := range env.targets() {
		if target == "|delete_repo" {
			found = true
		}
	}
	if !found {
		t.Fatalf("case variant must use tools/call target: targets=%v", env.targets())
	}
	if atomic.LoadInt32(env.upstreamHits) != 0 || rpcErrorCode(t, w.Body.String()) != -32000 {
		t.Fatalf("case variant bypassed configured tool block: %s", w.Body.String())
	}
}

// 1.2e 未配策略的非 tools/call 方法：放行 + 记录（不新增默认拒绝）。
func TestWS1UnconfiguredMethodAllowedAndRecorded(t *testing.T) {
	env := newWS1Env(t, false, blockTool("delete_repo"))
	body := `{"jsonrpc":"2.0","id":5,"method":"resources/read","params":{"uri":"file:///tmp/readme"}}`
	w := env.post(t, body)
	if w.Code != http.StatusOK || atomic.LoadInt32(env.upstreamHits) != 1 {
		t.Fatalf("未配置 block 的方法应放行: code=%d hits=%d", w.Code, atomic.LoadInt32(env.upstreamHits))
	}
	recorded := false
	for _, log := range env.logs() {
		if name, _ := log["tool_name"].(string); strings.Contains(name, "file:///tmp/readme") {
			recorded = true
		}
	}
	if !recorded {
		t.Fatalf("放行的 resources/read 必须留痕: logs=%v", env.logs())
	}
}

// 1.2f 生命周期/通知方法（initialize、notifications/*、ping）不查策略，避免会话无法建立。
func TestWS1LifecycleMethodsSkipPolicy(t *testing.T) {
	env := newWS1Env(t, false, blockTool("delete_repo"))
	env.post(t, `{"jsonrpc":"2.0","id":1,"method":"ping"}`)
	env.post(t, `{"jsonrpc":"2.0","method":"notifications/initialized"}`)
	if n := atomic.LoadInt32(env.policyFetches); n != 0 {
		t.Fatalf("生命周期方法不应查策略: fetches=%d targets=%v", n, env.targets())
	}
}
