package agentdetect

import (
	"net/http"
	"strings"
	"testing"
)

func TestNormalizeAgentType(t *testing.T) {
	tests := map[string]string{
		"Claude Code":       "claude-code",
		"通义灵码":              "tongyi-lingma",
		"Tencent CodeBuddy": "codebuddy",
		"qwen coder":        "qwen-code",
	}
	for input, want := range tests {
		if got := NormalizeAgentType(input); got != want {
			t.Fatalf("NormalizeAgentType(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestInferFromTextCoversDomesticAndGlobalAgents(t *testing.T) {
	tests := map[string]string{
		"You are Claude Code, Anthropic's official CLI for Claude.": "claude-code",
		"使用智能体模式时，通义灵码可以自主规划并调用工具":                                  "tongyi-lingma",
		"Tencent Cloud CodeBuddy can run terminal commands":         "codebuddy",
		"CodeArts Snap 用户指南":                                        "codearts-snap",
		"Trae IDE is The Real AI Engineer":                          "trae",
		"百度研发编码助手 Comate":                                           "baidu-comate",
		"Amazon Q Developer CLI/1.2":                                "amazon-q-developer",
		"Gemini Code Assist extension":                              "gemini-code-assist",
		"CodeRabbit pull request review":                            "coderabbit",
		"AutoGPT autonomous agent":                                  "autogpt-babyagi",
		"LlamaIndex retrieval SDK":                                  "langchain-llamaindex",
		"Microsoft AutoGen multi-agent framework":                   "crewai-autogen",
		"Dify workflow platform":                                    "dify-coze",
	}
	for input, want := range tests {
		if got := InferFromText(input); got != want {
			t.Fatalf("InferFromText(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestInferFromTrustedTextUsesBoundariesAndSpecificIdentity(t *testing.T) {
	tests := map[string]string{
		"You must decline unsafe requests.":                                     "",
		"The decline policy mentions no coding client.":                         "",
		"You are Tencent Cloud CodeBuddy. Cline is another supported tool.":     "codebuddy",
		"You are WorkBuddy. It can edit projects opened in Visual Studio Code.": "workbuddy",
		"You are Cline. The CodeBuddy documentation is unrelated.":              "cline",
	}
	for input, want := range tests {
		if got := InferFromTrustedText(input); got != want {
			t.Fatalf("InferFromTrustedText(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestInferFromTrustedTextRejectsEqualStrengthConflict(t *testing.T) {
	if got := InferFromTrustedText("Cline WorkBuddy"); got != "workbuddy" {
		t.Fatalf("more specific product signal = %q, want workbuddy", got)
	}
	if got := InferFromTrustedText("You are Cline. You are Cursor."); got != "" {
		t.Fatalf("equal-strength identity conflict must fail closed, got %q", got)
	}
}

func TestInferFromHeadersPrefersExplicitAgentHeader(t *testing.T) {
	header := http.Header{}
	header.Set("X-NewAPI-Agent-Type", "Tongyi Lingma")
	header.Set("User-Agent", "curl/8.0")
	got, err := InferFromHeaders(header)
	if err != nil || got != "tongyi-lingma" {
		t.Fatalf("InferFromHeaders() = (%q, %v), want tongyi-lingma", got, err)
	}
}

func TestInferFromHeadersFallsBackToUserAgent(t *testing.T) {
	header := http.Header{}
	header.Set("User-Agent", "CodeBuddy-Code/1.0")
	got, err := InferFromHeaders(header)
	if err != nil || got != "codebuddy" {
		t.Fatalf("InferFromHeaders() = (%q, %v), want codebuddy", got, err)
	}
}

func TestInferFromHeadersRecognizesClaudeCodeCLI(t *testing.T) {
	tests := []http.Header{
		{"User-Agent": []string{"claude-cli/2.1.206"}},
		{"X-App-Name": []string{"claude-cli"}},
	}
	for _, header := range tests {
		got, err := InferFromHeaders(header)
		if err != nil || got != "claude-code" {
			t.Fatalf("InferFromHeaders(%v) = (%q, %v), want claude-code", header, got, err)
		}
	}
}

// 真实抓到的正向代理客户端 User-Agent（取自 home 库 request_logs.proxy_user_agent），
// 用于把这些桌面端 AI 客户端识别为智能体资产。空字符串表示「普通网页流量」，不应被打成智能体。
func TestInferFromTextRecognizesForwardProxyClients(t *testing.T) {
	tests := map[string]string{
		// WorkBuddy 桌面端（Electron），库里 204 次
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) WorkBuddy/5.0.3 Chrome/138.0.7204.251 Electron/37.10.3 Safari/537.36": "workbuddy",
		// VS Code 桌面端（Electron），库里 276 次
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Code/1.124.2 Chrome/148.0.7778.97 Electron/42.2.0 Safari/537.36": "vscode",
		// VS Code 扩展宿主精简 UA，库里 4 次
		"Code/1.124.2 Electron/42.2.0 Windows NT 10.0": "vscode",
		// Cursor 已被识别，确认不回归
		"Cursor/0.42 (cursor-agent)": "cursor",
		// Codex Desktop 通过正向代理访问 api.example-gateway.com 时的真实 UA
		"Codex Desktop/0.140.0-alpha.2 (Windows 10.0.26200; x86_64) unknown (Codex Desktop; 26.609.41114)": "openai-codex",
		// VS Code 里的 Copilot 必须仍判为 github-copilot，而非被宽泛的 vscode 规则吞掉
		"GitHubCopilotChat/0.52.0":                     "github-copilot",
		"copilot/1.0.57 (win32 v24.15.0) term/unknown": "github-copilot",
		// 普通浏览器网页流量：不打智能体标签（留给 Track5 网页解码器处理）
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36": "",
	}
	for input, want := range tests {
		if got := InferFromText(input); got != want {
			t.Fatalf("InferFromText(%q) = %q, want %q", input, got, want)
		}
	}
}

// Label 给智能体类型提供面向人的中文/品牌名，供 control-plane（访问留存、CSV 导出、
// 行为管控风险聚合）与前端共用同一套展示名，避免各处各写一份映射。
func TestLabelReturnsHumanReadableNames(t *testing.T) {
	tests := map[string]string{
		"workbuddy":       "WorkBuddy",
		"vscode":          "VS Code",
		"codebuddy":       "腾讯 CodeBuddy",
		"claude-code":     "Claude Code",
		"tongyi-lingma":   "通义灵码",
		"agent-tool-call": "待识别智能体请求",
	}
	for input, want := range tests {
		if got := Label(input); got != want {
			t.Fatalf("Label(%q) = %q, want %q", input, got, want)
		}
	}
	// 每条 Rule 都必须有展示名，否则前后端会露出原始 type。
	for _, rule := range Rules {
		if got := Label(rule.Type); got == "" || got == rule.Type {
			t.Fatalf("Label(%q) = %q, want a human-readable name", rule.Type, got)
		}
	}
	// 未知类型回退为原始输入（含空串）。
	if got := Label("totally-unknown-agent"); got != "totally-unknown-agent" {
		t.Fatalf("Label(unknown) = %q, want raw input", got)
	}
	if got := Label(""); got != "" {
		t.Fatalf("Label(\"\") = %q, want empty", got)
	}
}

func TestInferFromHeadersRecognizesWorkBuddyAndVSCode(t *testing.T) {
	cases := map[string]string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) WorkBuddy/5.0.3 Chrome/138.0.7204.251 Electron/37.10.3 Safari/537.36": "workbuddy",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Code/1.124.2 Chrome/148.0.7778.97 Electron/42.2.0 Safari/537.36":      "vscode",
	}
	for ua, want := range cases {
		header := http.Header{}
		header.Set("User-Agent", ua)
		got, err := InferFromHeaders(header)
		if err != nil || got != want {
			t.Fatalf("InferFromHeaders(UA=%q) = (%q, %v), want %q", ua, got, err, want)
		}
	}
}

func TestDetectFromHeadersSeparatesAgentProductAndClientRuntime(t *testing.T) {
	header := http.Header{}
	header.Set("User-Agent", "Code/1.124.2 Electron/42.2.0 Windows NT 10.0")

	got, err := DetectFromHeaders(header)
	if err != nil {
		t.Fatal(err)
	}
	if got.Product != "" {
		t.Fatalf("generic Code runtime must not be treated as the agent product: %+v", got)
	}
	if got.Runtime != "vscode" || got.Source != "user_agent_runtime" || got.Confidence >= 0.5 {
		t.Fatalf("runtime attribution = %+v, want vscode/weak runtime evidence", got)
	}
}

func TestDetectFromHeadersTreatsIDENameAsRuntimeOnly(t *testing.T) {
	header := http.Header{}
	header.Set("X-IDE-Name", "Visual Studio Code")

	got, err := DetectFromHeaders(header)
	if err != nil {
		t.Fatal(err)
	}
	if got.Product != "" || got.Runtime != "vscode" || got.Source != "user_agent_runtime" {
		t.Fatalf("IDE identity must remain runtime-only evidence: %+v", got)
	}
}

func TestDetectFromHeadersKeepsExplicitAgentProduct(t *testing.T) {
	header := http.Header{}
	header.Set("X-JJDGuard-Agent-Type", "OpenAI Codex")
	header.Set("User-Agent", "Code/1.124.2 Electron/42.2.0 Windows NT 10.0")

	got, err := DetectFromHeaders(header)
	if err != nil {
		t.Fatal(err)
	}
	if got.Product != "openai-codex" || got.Runtime != "vscode" || got.Source != "explicit_header" || got.Confidence != 1 {
		t.Fatalf("explicit attribution = %+v", got)
	}
}

func TestInferFromHeadersRejectsAgentTypeConflictWithoutValueLeak(t *testing.T) {
	header := http.Header{}
	header["X-JJDGuard-Agent-Type"] = []string{"agent-canary-new"}
	header["x-newapi-agent-type"] = []string{"agent-canary-old"}
	got, err := InferFromHeaders(header)
	if got != "" || err == nil {
		t.Fatalf("InferFromHeaders() = (%q, %v), want conflict", got, err)
	}
	if strings.Contains(err.Error(), "agent-canary-new") || strings.Contains(err.Error(), "agent-canary-old") {
		t.Fatal("error leaked header value")
	}
}

func TestCodexExecAndCLIUserAgents(t *testing.T) {
	for _, ua := range []string{
		"codex_exec/0.149.1 (Ubuntu 26.4.0; x86_64) unknown (codex_exec; 0.149.1)",
		"codex_cli/0.149.1 (Mac OS 26.0; arm64)",
	} {
		got, err := DetectFromHeaders(http.Header{"User-Agent": []string{ua}})
		if err != nil || got.Product != "openai-codex" || got.Source != "user_agent" {
			t.Fatalf("UA %q: %+v, %v", ua, got, err)
		}
	}
}

func TestDetectFromHeadersCallRoleIsNotProduct(t *testing.T) {
	const ua = "WorkBuddy/5.9.3 WorkBuddy/5.9.3 CLI/2.165.0"
	for _, role := range []string{"main", "auxiliary", "compaction", "subagent", "sub-agent", "title", "summary", "Sub_Agent", "default", "agent", "assistant", "unknown"} {
		t.Run(role, func(t *testing.T) {
			d, err := DetectFromHeaders(http.Header{"User-Agent": {ua}, "X-Agent-Type": {role}})
			if err != nil {
				t.Fatal(err)
			}
			if d.Product != "workbuddy" || d.Source != "user_agent" {
				t.Fatalf("product=%q source=%q", d.Product, d.Source)
			}
			if d.Role != NormalizeAgentType(role) {
				t.Fatalf("role=%q", d.Role)
			}
		})
	}
}

func TestDetectFromHeadersRoleWithoutKnownUserAgentYieldsNoProduct(t *testing.T) {
	d, err := DetectFromHeaders(http.Header{"User-Agent": {"Go-http-client/1.1"}, "X-Agent-Type": {"compaction"}})
	if err != nil {
		t.Fatal(err)
	}
	if d.Product != "" || d.Role != "compaction" {
		t.Fatalf("%+v", d)
	}
	if got, _ := InferFromHeaders(http.Header{"X-Agent-Type": {"auxiliary"}}); got != "" {
		t.Fatalf("legacy product=%q", got)
	}
}

func TestDetectFromHeadersRoleDoesNotMaskLaterProductHeader(t *testing.T) {
	d, _ := DetectFromHeaders(http.Header{"X-Agent-Type": {"main"}, "X-AI-Agent": {"cursor"}})
	if d.Product != "cursor" || d.Source != "client_header" || d.Role != "main" {
		t.Fatalf("%+v", d)
	}
}

func TestDetectFromHeadersExplicitHeaderStillWinsOverRole(t *testing.T) {
	d, _ := DetectFromHeaders(http.Header{"User-Agent": {"WorkBuddy/5.9.3"}, "X-JJDGuard-Agent-Type": {"cline"}, "X-Agent-Type": {"main"}})
	if d.Product != "cline" || d.Source != "explicit_header" {
		t.Fatalf("%+v", d)
	}
}

func TestDetectFromHeadersRealClientsUnchanged(t *testing.T) {
	for ua, want := range map[string]string{
		"claude-cli/2.1.316 (external, cli)":                              "claude-code",
		"claude-cli/2.1.311 (external, claude-vscode, agent-sdk/0.3.311)": "claude-code",
		"codex_exec/1.0": "openai-codex",
	} {
		d, _ := DetectFromHeaders(http.Header{"User-Agent": {ua}})
		if d.Product != want {
			t.Fatalf("%s -> %q", ua, d.Product)
		}
	}
	if d, _ := DetectFromHeaders(http.Header{"User-Agent": {"Go-http-client/2.0"}}); d.Product != "" {
		t.Fatalf("generic UA product=%q", d.Product)
	}
}

func TestIsGenericAgentIdentity(t *testing.T) {
	for _, v := range []string{"", "main", "Auxiliary", "compaction", "sub_agent", "title", "summary"} {
		if !IsGenericAgentIdentity(v) {
			t.Fatalf("%q should be generic", v)
		}
	}
	for _, v := range []string{"workbuddy", "claude-code", "openai-codex"} {
		if IsGenericAgentIdentity(v) {
			t.Fatalf("%q should not be generic", v)
		}
	}
}

func TestIdentityHeadersRecordsRole(t *testing.T) {
	got := IdentityHeaders(http.Header{"User-Agent": {"WorkBuddy/5.9.3"}, "X-Agent-Type": {"auxiliary"}})
	for _, want := range []string{`"declared_type":"auxiliary"`, `"header_role":"auxiliary"`, `"header_product":"workbuddy"`} {
		if !strings.Contains(got, want) {
			t.Fatalf("missing %s in %s", want, got)
		}
	}
}

func TestDetectFromHeadersRecognizesDeepSeekHarness(t *testing.T) {
	for _, ua := range []string{
		"deepseek-harness/0.1.0-rc.6 (+https://github.com/deepseek-ai/deepseek-harness)",
		"deepseek-harness/0.2.1-rc.2 (+https://github.com/deepseek-ai/deepseek-harness)",
	} {
		for _, role := range []string{"", "main"} {
			h := http.Header{"User-Agent": {ua}}
			if role != "" {
				h.Set("X-Agent-Type", role)
			}
			d, err := DetectFromHeaders(h)
			if err != nil {
				t.Fatal(err)
			}
			if d.Product != "deepseek-harness" || d.Source != "user_agent" {
				t.Fatalf("ua=%q role=%q product=%q source=%q", ua, role, d.Product, d.Source)
			}
		}
	}
	if got := Label("deepseek-harness"); got != "DeepSeek Harness" {
		t.Fatalf("label=%q", got)
	}
}

func TestInferFromContentRoleOnlyTrustsSystemAndDeveloper(t *testing.T) {
	const assertion = "You are Claude Code, Anthropic's official CLI for Claude."
	for _, role := range []string{"system", "developer", "SYSTEM", " Developer "} {
		if got := InferFromContentRole(role, assertion); got != "claude-code" {
			t.Fatalf("role=%q got %q, want claude-code", role, got)
		}
	}
	for _, role := range []string{"user", "assistant", "tool", "function", "", "unknown"} {
		for _, content := range []string{assertion, "帮我看看 dify 和 Codex 怎么选", "OpenAI Codex vs Cursor"} {
			if got := InferFromContentRole(role, content); got != "" {
				t.Fatalf("role=%q content=%q got %q, want empty", role, content, got)
			}
		}
	}
}

func TestGenericAgentIdentitiesMatchPredicate(t *testing.T) {
	names := GenericAgentIdentities()
	if len(names) == 0 {
		t.Fatal("generic list must not be empty")
	}
	for _, name := range names {
		if !IsGenericAgentIdentity(name) || NormalizeAgentType(name) != name {
			t.Fatalf("%q must be generic and already normalized (SQL mirrors compare normalized text)", name)
		}
	}
	for _, rule := range Rules {
		if IsGenericAgentIdentity(rule.Type) {
			t.Fatalf("registry product %q must not be generic", rule.Type)
		}
	}
}

// 锁定现状（有意保留，不是理想语义）：system / developer 角色里的非断言提及也会命中，
// 因为 InferFromTrustedText 只要求有边界的产品名，"You are X" 只是加分。
// 这与网关 inferAgentTypeFromProtocolMessages 对 system 的语义一致；
// 若以后要收窄成"只认断言"，必须两处一起改，并同步修改本测试。
func TestInferFromContentRoleLocksCurrentSystemMentionSemantics(t *testing.T) {
	if got := InferFromContentRole("system", "The user is using Windsurf today."); got != "windsurf" {
		t.Fatalf("system 非断言提及当前应返回 windsurf（锁定现状），got %q", got)
	}
	// 同一句话出现在非 system/developer 角色里仍然不算。
	if got := InferFromContentRole("user", "The user is using Windsurf today."); got != "" {
		t.Fatalf("user 角色不应命中，got %q", got)
	}
}

func TestUpgradeableRuntimeIdentities(t *testing.T) {
	names := UpgradeableRuntimeIdentities()
	want := map[string]bool{"vscode": true, "agent-tool-call": true}
	if len(names) != len(want) {
		t.Fatalf("names=%v", names)
	}
	for _, name := range names {
		if !want[name] || NormalizeAgentType(name) != name {
			t.Fatalf("unexpected or non-normalized upgradeable identity %q", name)
		}
		if !IsUpgradeableRuntimeIdentity(name) || IsGenericAgentIdentity(name) || IsConcreteAgentProduct(name) {
			t.Fatalf("%q must be upgradeable, not generic, not concrete", name)
		}
	}
	for _, v := range []string{" VSCode ", "Agent_Tool_Call"} {
		if !IsUpgradeableRuntimeIdentity(v) {
			t.Fatalf("%q should normalize to an upgradeable identity", v)
		}
	}
	for _, v := range []string{"", "main", "workbuddy", "cursor"} {
		if IsUpgradeableRuntimeIdentity(v) {
			t.Fatalf("%q must not be upgradeable", v)
		}
	}
}

func TestIsConcreteAgentProduct(t *testing.T) {
	for _, v := range []string{"workbuddy", "Claude_Code", "deepseek-harness"} {
		if !IsConcreteAgentProduct(v) {
			t.Fatalf("%q should be concrete", v)
		}
	}
	for _, v := range []string{"", "main", "Sub_Agent", "vscode", "agent-tool-call"} {
		if IsConcreteAgentProduct(v) {
			t.Fatalf("%q should not be concrete", v)
		}
	}
}

func TestSessionOverwritableIdentitiesCoversEmptyGenericAndUpgradeable(t *testing.T) {
	got := map[string]bool{}
	for _, name := range SessionOverwritableIdentities() {
		got[name] = true
	}
	if !got[""] {
		t.Fatal("empty string must be overwritable")
	}
	for _, name := range append(GenericAgentIdentities(), UpgradeableRuntimeIdentities()...) {
		if !got[name] {
			t.Fatalf("%q missing", name)
		}
	}
	if len(got) != 1+len(GenericAgentIdentities())+len(UpgradeableRuntimeIdentities()) {
		t.Fatalf("unexpected extra entries: %v", got)
	}
}
