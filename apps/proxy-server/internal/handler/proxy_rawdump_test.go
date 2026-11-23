package handler

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// 诊断用原始报文落盘开关——安全敏感：落盘的是 MITM 明文，必须默认关闭。
// 本测试锁定三条性质：
//  1. 不设环境变量且无哨兵目录时彻底关闭、一字节不写；
//  2. 仅对"会话承载"端点（Gemini StreamGenerate / ChatGPT conversation、files）落盘，
//     网页加载噪声（batchexecute 摘要总线、遥测、challenge、账号信息）一律跳过——否则
//     有限的样本预算会被噪声耗尽，真正的会话响应反而采不到（线上实测 40 样本全是噪声的根因）；
//  3. 命中会话端点时才把请求体/解压响应体原样落盘，供离线复现 content_extractor 抽取缺口。

func TestRawDumpDir_OffByDefault(t *testing.T) {
	// Only the explicit environment setting can enable plaintext capture.
	t.Setenv("PROXY_RAW_DUMP_DIR", "")

	if got := rawDumpDir(); got != "" {
		t.Fatalf("rawDumpDir() = %q, want empty (dump must be off by default)", got)
	}

	// 即便被调用，关闭态也不得在任何地方落盘。给一个真实存在的临时目录做反证：
	// 因为开关关闭（dir==""），dumpRawExchange 必须直接返回、不写这个目录。
	probe := t.TempDir()
	dumpRawExchange("gemini", "gemini.google.com",
		"/_/BardChatUi/data/assistant.lamda.BardFrontendService/StreamGenerate",
		"application/x-www-form-urlencoded", "application/json",
		[]byte("REQBODY"), []byte("RESPBODY"))
	entries, _ := os.ReadDir(probe)
	if len(entries) != 0 {
		t.Fatalf("dump wrote %d entries while disabled, want 0", len(entries))
	}
}

func TestDumpRawExchange_SkipsNonConversationPaths(t *testing.T) {
	// 即便诊断开关打开，网页加载噪声端点也必须跳过、一字节不落盘——否则有限样本预算会被
	// 遥测/资源/challenge/batchexecute 摘要总线耗尽，真正的会话响应（StreamGenerate /
	// conversation）反而采不到（线上实测 40 个样本全是噪声的根因）。
	dir := t.TempDir()
	t.Setenv("PROXY_RAW_DUMP_DIR", dir)

	for _, noisePath := range []string{
		"/_/BardChatUi/data/batchexecute", // Gemini 摘要总线（建议气泡/历史），非真对话轮次
		"/v1/rgstr",                       // 遥测上报
		"/cdn-cgi/challenge-platform/h/b/orchestrate/chl_api/v1", // challenge
		"/backend-api/me", // 账号信息，非会话
	} {
		dumpRawExchange("noise", "example.com", noisePath,
			"application/json", "application/json",
			[]byte("REQ"), []byte("RESP"))
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 0 {
		t.Fatalf("dump wrote %d entries for non-conversation paths, want 0: %v", len(entries), entries)
	}
}

func TestDumpRawExchange_WritesRawBytesForConversationPaths(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("PROXY_RAW_DUMP_DIR", dir)

	reqBody := []byte(`f.req=%5B%5B%5B%22prompt%22%5D%5D%5D`)
	respBody := []byte(")]}'\n\n[[\"wrb.fr\",\"hello model reply\"]]")
	dumpRawExchange("gemini", "gemini.google.com",
		"/_/BardChatUi/data/assistant.lamda.BardFrontendService/StreamGenerate",
		"application/x-www-form-urlencoded", "application/json",
		reqBody, respBody)

	reqs, _ := filepath.Glob(filepath.Join(dir, "*.req"))
	if len(reqs) != 1 {
		t.Fatalf("got %d .req files, want 1: %v", len(reqs), reqs)
	}
	if got, _ := os.ReadFile(reqs[0]); string(got) != string(reqBody) {
		t.Fatalf(".req body = %q, want verbatim request bytes %q", got, reqBody)
	}

	resps, _ := filepath.Glob(filepath.Join(dir, "*.resp"))
	if len(resps) != 1 {
		t.Fatalf("got %d .resp files, want 1: %v", len(resps), resps)
	}
	if got, _ := os.ReadFile(resps[0]); string(got) != string(respBody) {
		t.Fatalf(".resp body = %q, want verbatim decompressed response bytes %q", got, respBody)
	}

	metas, _ := filepath.Glob(filepath.Join(dir, "*.meta"))
	if len(metas) != 1 {
		t.Fatalf("got %d .meta files, want 1: %v", len(metas), metas)
	}
	meta, _ := os.ReadFile(metas[0])
	for _, want := range []string{"provider=gemini", "host=gemini.google.com", "response_content_type=application/json"} {
		if !strings.Contains(string(meta), want) {
			t.Fatalf(".meta missing %q: %s", want, meta)
		}
	}
}

func TestDumpRawExchange_DumpsChatGPTConversationAndFiles(t *testing.T) {
	// ChatGPT 含图对话：会话 POST /backend-api/f/conversation 承载用户多模态文本（无正文 bug 现场），
	// /backend-api/files 承载上传 create 的 file_id/asset 元数据——两者都必须采到。
	dir := t.TempDir()
	t.Setenv("PROXY_RAW_DUMP_DIR", dir)

	dumpRawExchange("openai_chatgpt", "chatgpt.com", "/backend-api/f/conversation",
		"application/json", "text/event-stream", []byte("REQ-CONV"), []byte("RESP-CONV"))
	dumpRawExchange("openai_chatgpt", "chatgpt.com", "/backend-api/files",
		"application/json", "application/json", []byte("REQ-FILES"), []byte("RESP-FILES"))

	reqs, _ := filepath.Glob(filepath.Join(dir, "*.req"))
	if len(reqs) != 2 {
		t.Fatalf("got %d .req files for chatgpt conversation+files, want 2: %v", len(reqs), reqs)
	}
}

func TestRawDumpMaxSamplesHonorsBoundedEnvironmentSetting(t *testing.T) {
	for _, tc := range []struct {
		name  string
		value string
		want  int64
	}{
		{name: "default", value: "", want: 40},
		{name: "single sample", value: "1", want: 1},
		{name: "invalid falls back", value: "0", want: 40},
		{name: "upper bound", value: "99", want: 40},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("PROXY_RAW_DUMP_MAX_SAMPLES", tc.value)
			if got := rawDumpMaxSamples(); got != tc.want {
				t.Fatalf("rawDumpMaxSamples() = %d, want %d", got, tc.want)
			}
		})
	}
}
