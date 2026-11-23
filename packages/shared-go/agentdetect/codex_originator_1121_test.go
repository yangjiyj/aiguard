package agentdetect

import (
	"net/http"
	"testing"
)

// 客户现场 2.9.7 近 14 天的真实 UA：codex-tui / codex_vscode 识别不出产品，
// 内容兜底就把整批流量判成了 dify-coze，引擎也不按编程智能体分流。
// Codex 官方客户端的 UA 形如 "{originator}/{version} ({os} {ver}; {arch}) {terminal}"，
// originator 取值见 openai/codex codex-rs/login/src/auth/default_client.rs
// （DEFAULT_ORIGINATOR=codex_cli_rs、is_first_party_originator、is_first_party_chat_originator）、
// exec 的 codex_exec、TypeScript SDK 的 codex_sdk_ts、models-manager 的 codex_work_*。
func TestDetectFromHeadersRecognizesAllCodexFirstPartyOriginators(t *testing.T) {
	cases := []string{
		// 现场样本（原样）
		"codex-tui/0.155.0 (Windows 10.0.19045; x86_64) WindowsTerminal (codex-tui; 0.155.0)",
		"codex_vscode/0.164.0-alpha.11.1 (Windows 10.0.19045; x86_64) unknown (VS Code; 26.1021.22027)",
		"Codex Desktop/0.169.0-alpha.11.1 (Windows 10.0.19045; x86_64) unknown (Codex Desktop; 26.1111.21308)",
		"Codex Desktop/0.169.1 (Windows 10.0.19045; x86_64) unknown (Codex Desktop; 26.1111.71704)",
		"codex_exec/0.167.0-alpha.3.2 (Windows 10.0.19045; x86_64) unknown (codex_exec; 0.167.0-alpha.3.2)",
		// 其它官方 originator
		"codex_cli_rs/0.169.0 (Mac OS 26.0.0; arm64) iTerm.app/3.6.1",
		"codex_cli_rs/0.155.0 (Ubuntu 24.4.0; x86_64) xterm-256color",
		"codex_sdk_ts/0.168.0 (Linux 6.8.0; x86_64) unknown",
		"codex_atlas/0.169.0 (Mac OS 26.1.0; arm64) unknown",
		"codex_chatgpt_desktop/0.169.0 (Windows 10.0.26100; x86_64) unknown",
		"codex_work_desktop/0.170.0 (Windows 10.0.26100; x86_64) unknown",
		"codex-tui/0.170.0 (Mac OS 26.1.0; arm64) ghostty/1.2.0 (codex-tui; 0.170.0)",
	}
	for _, ua := range cases {
		got, err := DetectFromHeaders(http.Header{"User-Agent": {ua}})
		if err != nil {
			t.Fatalf("%q: %v", ua, err)
		}
		if got.Product != "openai-codex" || got.Source != "user_agent" {
			t.Errorf("%q: got product=%q source=%q, want openai-codex/user_agent", ua, got.Product, got.Source)
		}
	}
}

// Codex 同时发送 originator 头；UA 被代理改写时仍能凭它识别。
func TestDetectFromHeadersRecognizesCodexOriginatorHeader(t *testing.T) {
	for _, originator := range []string{"codex_cli_rs", "codex-tui", "codex_vscode", "codex_exec", "codex_sdk_ts", "Codex Desktop"} {
		got, _ := DetectFromHeaders(http.Header{"User-Agent": {"Go-http-client/2.0"}, "Originator": {originator}})
		if got.Product != "openai-codex" {
			t.Errorf("originator %q: product=%q, want openai-codex", originator, got.Product)
		}
	}
}

// 守门：名字里只是带 codex 字样的非官方客户端、普通浏览器、VS Code 本体不能被认成 Codex。
func TestDetectFromHeadersDoesNotOverMatchCodexOriginators(t *testing.T) {
	for ua, want := range map[string]string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) CherryStudio/1.9.6 Chrome/146.0 Electron/41.2.1 Safari/537.36": "",
		"node-fetch":                            "",
		"mycodex_tool/1.0":                      "",
		"codexify/2.0 (Linux)":                  "",
		"Code/1.106.0 (Windows NT 10.0) vscode": "",
	} {
		got, _ := DetectFromHeaders(http.Header{"User-Agent": {ua}})
		if got.Product != want {
			t.Errorf("%q: product=%q, want %q", ua, got.Product, want)
		}
	}
}

// 正文里出现 Codex 的 originator 字样只是话题，内容兜底（只看 system/developer）照旧；
// user 角色里提到不算。
func TestCodexOriginatorTokensInUserContentAreNotIdentity(t *testing.T) {
	if got := InferFromContentRole("user", "我在用 codex-tui 和 codex_vscode，也接了 Dify 和 Coze"); got != "" {
		t.Fatalf("user content must not assert identity, got %q", got)
	}
}
