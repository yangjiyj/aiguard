package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/types"
)

// nilAccessContentRepo 模拟 access_content_logs 里没有该请求（主链路只写 content_logs）。
type nilAccessContentRepo struct{}

func (r *nilAccessContentRepo) GetAccessContentLog(ctx context.Context, tenantID, requestID string) (*repository.AccessContentLog, error) {
	return nil, nil
}
func (r *nilAccessContentRepo) GetAccessContentLogs(ctx context.Context, tenantID string, requestIDs []string) ([]repository.AccessContentLog, error) {
	return nil, nil
}
func (r *nilAccessContentRepo) ResolveUploadedFileBytes(ctx context.Context, tenantID string, referenceIDs []string) (map[string]repository.ResolvedUploadedFile, error) {
	return map[string]repository.ResolvedUploadedFile{}, nil
}

// fallbackContentLogReader 是 content_logs 的假桩，记录被调用的租户/请求范围。
type fallbackContentLogReader struct {
	gotTenantID  string
	gotRequestID string
	logs         []repository.ContentLog
}

func (f *fallbackContentLogReader) ListByRequest(ctx context.Context, tenantID, requestID string) ([]repository.ContentLog, error) {
	f.gotTenantID = tenantID
	f.gotRequestID = requestID
	return f.logs, nil
}

type perRequestContentLogReader map[string][]repository.ContentLog

func (f perRequestContentLogReader) ListByRequest(_ context.Context, _, requestID string) ([]repository.ContentLog, error) {
	return f[requestID], nil
}

type orderedBatchContentLogReader struct {
	logs []repository.ContentLog
}

func (f orderedBatchContentLogReader) ListByRequest(_ context.Context, _, requestID string) ([]repository.ContentLog, error) {
	var out []repository.ContentLog
	for _, item := range f.logs {
		if item.RequestID == requestID {
			out = append(out, item)
		}
	}
	return out, nil
}

func (f orderedBatchContentLogReader) ListByRequests(_ context.Context, _ string, _ []string) ([]repository.ContentLog, error) {
	return f.logs, nil
}

func assertCustomerRetentionResponseHasNoLegacyFields(t *testing.T, payload []byte) {
	t.Helper()
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(payload, &fields); err != nil {
		t.Fatalf("decode response fields: %v", err)
	}
	for _, key := range []string{"request_content", "response_content", "file_metadata"} {
		if _, ok := fields[key]; ok {
			t.Fatalf("customer response must not include legacy raw field %q: %s", key, payload)
		}
	}
}

func TestBuildAccessRetentionMessagesDeduplicatesReplayAndKeepsEachCurrentModelOutput(t *testing.T) {
	logs := perRequestContentLogReader{
		"req-1": {
			{ID: "1-system", Role: "system", Content: "machine instructions"},
			{ID: "1-user", Role: "user", Content: "修复状态判断"},
			{ID: "1-assistant", Role: "assistant", Content: "我先检查实现。"},
		},
		"req-2": {
			{ID: "2-system", Role: "system", Content: "machine instructions"},
			{ID: "2-user", Role: "user", Content: "修复状态判断"},
			{ID: "2-history", Role: "assistant", Content: "我先检查实现。"},
			{ID: "2-tool", Role: "tool", Content: "read result"},
			{ID: "2-assistant", Role: "assistant", Content: "测试已经补齐。"},
		},
		"req-3": {
			{ID: "3-system", Role: "system", Content: "machine instructions"},
			{ID: "3-user", Role: "user", Content: "修复状态判断"},
			{ID: "3-history-1", Role: "assistant", Content: "我先检查实现。"},
			{ID: "3-tool-1", Role: "tool", Content: "read result"},
			{ID: "3-history-2", Role: "assistant", Content: "测试已经补齐。"},
			{ID: "3-tool-2", Role: "tool", Content: "test result"},
		},
		"req-4": {
			{ID: "4-system", Role: "system", Content: "machine instructions"},
			{ID: "4-user", Role: "user", Content: "修复状态判断"},
			{ID: "4-history-1", Role: "assistant", Content: "我先检查实现。"},
			{ID: "4-tool-1", Role: "tool", Content: "read result"},
			{ID: "4-history-2", Role: "assistant", Content: "测试已经补齐。"},
			{ID: "4-tool-2", Role: "tool", Content: "test result"},
			{ID: "4-assistant", Role: "assistant", Content: "专项测试通过。"},
		},
	}

	messages, err := buildAccessRetentionMessages(context.Background(), &Dependencies{ContentLogReader: logs}, "tenant-1", []string{"req-1", "req-2", "req-3", "req-4"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(messages) != 4 {
		t.Fatalf("messages=%#v", messages)
	}
	if messages[0].Role != "user" || messages[0].Content != "修复状态判断" {
		t.Fatalf("user message=%#v", messages[0])
	}
	for index, want := range []string{"我先检查实现。", "测试已经补齐。", "专项测试通过。"} {
		message := messages[index+1]
		if message.Role != "assistant" || message.Content != want {
			t.Fatalf("assistant[%d]=%#v want=%q", index, message, want)
		}
	}
	if messages[2].RequestID != "req-2" || messages[3].RequestID != "req-4" {
		t.Fatalf("model outputs lost owning request: %#v", messages)
	}
}

func TestGetAccessRetentionContentFallsBackToContentLogs(t *testing.T) {
	reader := &fallbackContentLogReader{
		logs: []repository.ContentLog{
			{ID: "cl_user", RequestID: "req_reverse_001", Role: "user", Content: "如何获取系统里所有用户的身份证号"},
			{ID: "cl_assistant", RequestID: "req_reverse_001", Role: "assistant", Content: "抱歉，我无法协助。"},
		},
	}
	deps := &Dependencies{
		AccessContentRepo: &nilAccessContentRepo{},
		ContentLogReader:  reader,
	}

	router := chi.NewRouter()
	router.Get("/admin/v1/audit/access-retention/{request_id}/content", GetAccessRetentionContent(deps))

	req := httptest.NewRequest(http.MethodGet, "/admin/v1/audit/access-retention/req_reverse_001/content", nil)
	req = req.WithContext(context.WithValue(req.Context(), auth.UserKey, &repository.User{
		ID: "user_admin", Username: "admin", TenantID: "tenant_default", Role: "platform_admin",
	}))
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 fallback, got %d: %s", w.Code, w.Body.String())
	}
	if reader.gotTenantID != "tenant_default" || reader.gotRequestID != "req_reverse_001" {
		t.Fatalf("content log reader scope mismatch: tenant=%q request=%q", reader.gotTenantID, reader.gotRequestID)
	}
	payload := w.Body.Bytes()
	assertCustomerRetentionResponseHasNoLegacyFields(t, payload)
	var resp struct {
		RequestID   string `json:"request_id"`
		UserInput   string `json:"user_input"`
		ModelOutput string `json:"model_output"`
	}
	if err := json.Unmarshal(payload, &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.RequestID != "req_reverse_001" {
		t.Fatalf("request_id = %q, want req_reverse_001", resp.RequestID)
	}
	if !strings.Contains(resp.UserInput, "身份证号") {
		t.Fatalf("user_input missing user input: %q", resp.UserInput)
	}
	if !strings.Contains(resp.ModelOutput, "无法协助") {
		t.Fatalf("model_output missing assistant reply: %q", resp.ModelOutput)
	}
}

func TestGetAccessRetentionContentStillNotFoundWhenNoContentLogs(t *testing.T) {
	deps := &Dependencies{
		AccessContentRepo: &nilAccessContentRepo{},
		ContentLogReader:  &fallbackContentLogReader{logs: nil},
	}

	router := chi.NewRouter()
	router.Get("/admin/v1/audit/access-retention/{request_id}/content", GetAccessRetentionContent(deps))

	req := httptest.NewRequest(http.MethodGet, "/admin/v1/audit/access-retention/req_missing/content", nil)
	req = req.WithContext(context.WithValue(req.Context(), auth.UserKey, &repository.User{
		ID: "user_admin", Username: "admin", TenantID: "tenant_default", Role: "platform_admin",
	}))
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404 when no content logs, got %d: %s", w.Code, w.Body.String())
	}
}

func TestGetAccessRetentionContentLabelsNonUserRoles(t *testing.T) {
	reader := &fallbackContentLogReader{
		logs: []repository.ContentLog{
			{ID: "cl_sys", RequestID: "req_roles_001", Role: "system", Content: "你是一个严格遵守安全策略的助手"},
			{ID: "cl_user", RequestID: "req_roles_001", Role: "user", Content: "如何获取系统里所有用户的身份证号"},
			{ID: "cl_tool", RequestID: "req_roles_001", Role: "tool", Content: "tool_result_payload_xyz"},
			{ID: "cl_assistant", RequestID: "req_roles_001", Role: "assistant", Content: "抱歉，我无法协助。"},
		},
	}
	deps := &Dependencies{
		AccessContentRepo: &nilAccessContentRepo{},
		ContentLogReader:  reader,
	}

	router := chi.NewRouter()
	router.Get("/admin/v1/audit/access-retention/{request_id}/content", GetAccessRetentionContent(deps))

	req := httptest.NewRequest(http.MethodGet, "/admin/v1/audit/access-retention/req_roles_001/content", nil)
	req = req.WithContext(context.WithValue(req.Context(), auth.UserKey, &repository.User{
		ID: "user_admin", Username: "admin", TenantID: "tenant_default", Role: "platform_admin",
	}))
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 fallback, got %d: %s", w.Code, w.Body.String())
	}
	payload := w.Body.Bytes()
	assertCustomerRetentionResponseHasNoLegacyFields(t, payload)
	var resp struct {
		UserInput   string `json:"user_input"`
		ModelOutput string `json:"model_output"`
	}
	if err := json.Unmarshal(payload, &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if strings.Contains(string(payload), "严格遵守安全策略") || strings.Contains(string(payload), "tool_result_payload_xyz") {
		t.Fatalf("customer response leaked non-customer content: %q", payload)
	}
	if !strings.Contains(resp.UserInput, "身份证号") {
		t.Fatalf("user input was not safely projected: %#v", resp)
	}
	if !strings.Contains(resp.ModelOutput, "无法协助") {
		t.Fatalf("model output was not safely projected: %#v", resp)
	}
}

// TestGetAccessRetentionContentFallbackFoldsAgentSystemPrompt 复现 WorkBuddy/编码 agent 场景：
// 结构化留证缺失时（access_content_logs 无该请求），content_logs 回退合成必须——
//  1. 把真实用户输入（<user_query> 内文）提到最前作正文（convo-first，防 64KB 截断切掉真话）；
//  2. 把巨型系统提示词内部空行归并成单段并整段打【role】前缀，使前端 collapseSystemSections
//     能整块折叠（否则系统提示词按 \n\n 裂成多段、只有首段带前缀、其余当正文展开＝满屏噪音）。
//
// 这是 proxy 侧 messagesToRetentionText 早已修好、回退路径漏抄的坑。
func TestGetAccessRetentionContentFallbackFoldsAgentSystemPrompt(t *testing.T) {
	systemContent := "This conversation is powered by glm-5.2\n\n" +
		"Your main goal is to follow the USER's instructions.\n\n" +
		"<task_management>\nuse the todo tool.\n</task_management>\n\n" +
		"<asking_questions>\nask clearly.\n</asking_questions>"
	userContent := "<system-reminder><current-working-directory>/Users/yj</current-working-directory></system-reminder>\n\n" +
		"<user_query>shi sha</user_query>"

	reader := &fallbackContentLogReader{
		logs: []repository.ContentLog{
			{ID: "cl_sys", RequestID: "log_wb", Role: "system", Content: systemContent},
			{ID: "cl_user", RequestID: "log_wb", Role: "user", Content: userContent},
			{ID: "cl_asst", RequestID: "log_wb", Role: "assistant", Content: "嘿，看起来你在测试一下连接？"},
		},
	}
	deps := &Dependencies{AccessContentRepo: &nilAccessContentRepo{}, ContentLogReader: reader}

	router := chi.NewRouter()
	router.Get("/admin/v1/audit/access-retention/{request_id}/content", GetAccessRetentionContent(deps))
	req := httptest.NewRequest(http.MethodGet, "/admin/v1/audit/access-retention/log_wb/content", nil)
	req = req.WithContext(context.WithValue(req.Context(), auth.UserKey, &repository.User{
		ID: "user_admin", Username: "admin", TenantID: "tenant_default", Role: "platform_admin",
	}))
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	payload := w.Body.Bytes()
	assertCustomerRetentionResponseHasNoLegacyFields(t, payload)
	var resp struct {
		UserInput   string `json:"user_input"`
		ModelOutput string `json:"model_output"`
	}
	if err := json.Unmarshal(payload, &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}

	if strings.TrimSpace(resp.UserInput) != "shi sha" {
		t.Fatalf("expected only real user input, got %q", resp.UserInput)
	}
	if strings.Contains(string(payload), "task_management") || strings.Contains(string(payload), "current-working-directory") {
		t.Fatalf("customer response leaked agent system prompt: %q", payload)
	}
	if !strings.Contains(resp.ModelOutput, "看起来你在测试") {
		t.Fatalf("model_output missing assistant reply: %q", resp.ModelOutput)
	}
}

func TestSafeRetentionProjectionExcludesRuntimeContextToolsAndRecaps(t *testing.T) {
	runtimePayloads := []string{
		"<environment_context>workspace=/srv/customer</environment_context>",
		"<skills_instructions>internal skill catalog</skills_instructions>",
		"<tool_call name=\"shell_command\">private command output</tool_call>",
		"internal recap: the user stepped away and is coming back",
		"You are Codex. # Skills\ninternal operating instructions",
		"Analyze this rollout and produce JSON with `raw_memory`, `rollout_summary`, and `rollout_slug`.\n\nrollout_context:\n- rollout_path: /Users/example/.codex/sessions/private.jsonl\n\nrendered conversation (pre-rendered from rollout):\n[{\"type\":\"message\"}]",
	}
	for _, raw := range runtimePayloads {
		if text, status := safeRetentionUserInput(raw); text != "" || status != "evidence_gap" {
			t.Fatalf("runtime user content leaked as %q with status %q for %q", text, status, raw)
		}
		if text := safeRetentionModelOutput(raw); text != "" {
			t.Fatalf("runtime model content leaked as %q for %q", text, raw)
		}
	}

	projection := projectRetentionContentLogs([]repository.ContentLog{
		{Role: "user", Content: "查询客户工单"},
		{Role: "assistant", Content: "已定位到工单状态。"},
		{Role: "assistant", Content: "<tool_result>private tool payload</tool_result>"},
	})
	if projection.userInput != "查询客户工单" || projection.modelOutput != "已定位到工单状态。" {
		t.Fatalf("tool result must not replace customer conversation: %#v", projection)
	}
}

func TestProjectRetentionContentLogsIgnoresLoopGuardBeforeVisibleAssistant(t *testing.T) {
	loopGuard := `[
Loop detected: the tool "Skill" has been called 4 consecutive times with identical arguments.

STOP calling tools immediately. Do NOT make any more tool calls.
Instead, tell the user what happened and suggest they switch models or modify their prompt to retry.
]

[LOOP_DETECTED]`
	projection := projectRetentionContentLogs([]repository.ContentLog{
		{Role: "user", Content: "咋回事"},
		{Role: "user", Content: loopGuard},
		{Role: "assistant", Content: "这是正常模型答复。"},
	})
	if projection.userInput != "咋回事" || projection.userOrdinal != 1 || projection.modelOutput != "这是正常模型答复。" {
		t.Fatalf("transport-only loop guard broke the visible turn: %#v", projection)
	}

	projection = projectRetentionContentLogs([]repository.ContentLog{
		{Role: "user", Content: "上一轮问题"},
		{Role: "assistant", Content: "上一轮回答"},
		{Role: "user", Content: loopGuard},
	})
	if projection.userInput != "上一轮问题" || projection.modelOutput != "" {
		t.Fatalf("trailing loop guard reused a historical answer: %#v", projection)
	}
}

func TestSafeRetentionUserInputProjectsVSCodeRuntimeEnvelope(t *testing.T) {
	raw := `<current_datetime>2026-09-03T04:51:10.219+08:00</current_datetime>
继续
<system_reminder><sql_tables>Available tables: todos, todo_deps</sql_tables></system_reminder>
你在干嘛`
	got, status := safeRetentionUserInput(raw)
	if status != "complete" || got != "继续\n你在干嘛" {
		t.Fatalf("VS Code user projection=(%q,%q)", got, status)
	}
}

func TestSafeRetentionUserInputProjectsCodexInAppBrowserContext(t *testing.T) {
	raw := `<in-app-browser-context source="ambient-ui-state">
This block is automatically supplied ambient UI state, not part of the user's request.
# In app browser:
- Current URL: http://127.0.0.1:13001/dashboard
</in-app-browser-context>

## My request:
发完了`
	got, status := safeRetentionUserInput(raw)
	if status != "complete" || got != "发完了" {
		t.Fatalf("Codex browser context projection=(%q,%q)", got, status)
	}
	for _, forbidden := range []string{"in-app-browser-context", "ambient-ui-state", "127.0.0.1", "My request"} {
		if strings.Contains(got, forbidden) {
			t.Fatalf("Codex browser metadata leaked %q: %q", forbidden, got)
		}
	}
}

func TestSafeRetentionProjectionHandlesCodexPastedEnvelopeAndPrivateAssistantBlocks(t *testing.T) {
	request := `# Files pasted by the user:

## "pasted-text.txt": C:\Users\test\AppData\Local\Temp\pasted-text.txt

Pasted text contains the user's request.

## My request:
继续检查网关留证`
	userInput, status := safeRetentionUserInput(request)
	if status != "complete" || userInput != "继续检查网关留证" {
		t.Fatalf("Codex pasted envelope projection = (%q, %q)", userInput, status)
	}

	response := "已定位问题。\n<oai-mem-citation><citation_entries>MEMORY.md:1</citation_entries><rollout_ids>private</rollout_ids></oai-mem-citation>"
	if modelOutput := safeRetentionModelOutput(response); modelOutput != "已定位问题。" {
		t.Fatalf("private assistant block leaked: %q", modelOutput)
	}

	toolDocumentation := "已完成检查。\n\nWaits on a yielded `exec` cell and returns new output or completion.\nTools for spawning and managing sub-agents."
	if got := safeRetentionModelOutput(toolDocumentation); got != "已完成检查。" {
		t.Fatalf("tool runtime documentation leaked: %q", got)
	}

	privateTransport := "已完成检查。\n[tool_use:Bash] command=cat /private/path\n<tool_call name=\"shell\">secret arguments</tool_call>"
	if got := safeRetentionModelOutput(privateTransport); got != "已完成检查。" {
		t.Fatalf("assistant tool transport leaked: %q", got)
	}

	fencedExample := "示例：\n```xml\n<tool_call name=\"demo\">visible example</tool_call>\n```"
	if got := safeRetentionModelOutput(fencedExample); got != fencedExample {
		t.Fatalf("fenced customer-visible XML was removed: %q", got)
	}

	unterminatedFence := "Customer-visible answer.\n```xml\n<tool_call name=\"private\">secret arguments</tool_call>"
	if got := safeRetentionModelOutput(unterminatedFence); got != "Customer-visible answer.\n```xml" {
		t.Fatalf("unterminated fence leaked private tool transport: %q", got)
	}
}

func TestSafeRetentionModelOutputHidesAdditionalRuntimeToolDocumentation(t *testing.T) {
	runtimeLines := []string{
		"Output token budget for this wait call. Defaults to 10000 tokens.",
		"True stops the running exec cell; false or omitted waits for output.",
		"Wait before yielding more output. Defaults to 10000 ms.",
	}
	for _, runtimeLine := range runtimeLines {
		if got, status := safeRetentionUserInput(runtimeLine); got != runtimeLine || status != "complete" {
			t.Errorf("real user input matching runtime documentation was removed for %q: (%q, %q)", runtimeLine, got, status)
		}
		if got := safeRetentionModelOutput(runtimeLine); got != "" {
			t.Errorf("standalone runtime documentation leaked for %q: %q", runtimeLine, got)
		}
		mixed := "Customer-visible answer.\n" + runtimeLine + "\nPrivate runtime suffix."
		if got := safeRetentionModelOutput(mixed); got != "Customer-visible answer." {
			t.Errorf("mixed runtime documentation leaked for %q: %q", runtimeLine, got)
		}
	}
}

func TestSafeRetentionModelOutputKeepsRuntimePhraseMentionsAndFencedExamples(t *testing.T) {
	for _, visible := range []string{
		"Output token budget for this wait call can be documented for administrators.",
		"True stops the running exec cell only after a separate confirmation.",
		"Wait before yielding more output when the downstream service is busy.",
	} {
		if got := safeRetentionModelOutput(visible); got != visible {
			t.Errorf("ordinary phrase mention was removed for %q: %q", visible, got)
		}
	}

	fencedExample := "Example:\n```text\nOutput token budget for this wait call. Defaults to 10000 tokens.\nTrue stops the running exec cell; false or omitted waits for output.\nWait before yielding more output. Defaults to 10000 ms.\n```"
	if got := safeRetentionModelOutput(fencedExample); got != fencedExample {
		t.Fatalf("fenced runtime documentation example was removed: %q", got)
	}
}

func TestSafeRetentionModelOutputHidesTruncatedVSCodeRuntimeEnvelope(t *testing.T) {
	runtimeEnvelope := "<current_datetime>2026-09-03T04:51:10.219+08:00</current_datetime>\nCustomer text lost to historical truncation.\n<system_reminder><sql_tables>Available tables: todos"
	if got := safeRetentionModelOutput(runtimeEnvelope); got != "" {
		t.Fatalf("standalone truncated VS Code runtime envelope leaked: %q", got)
	}
	if got, status := safeRetentionUserInput(runtimeEnvelope); got != "" || status != "evidence_gap" {
		t.Fatalf("standalone truncated VS Code user runtime envelope leaked: (%q, %q)", got, status)
	}
	mixed := "Customer-visible answer.\n" + runtimeEnvelope
	if got := safeRetentionModelOutput(mixed); got != "Customer-visible answer." {
		t.Fatalf("truncated VS Code runtime suffix leaked: %q", got)
	}

	visible := "This answer discusses <current_datetime> and <system_reminder> as XML element names."
	if got := safeRetentionModelOutput(visible); got != visible {
		t.Fatalf("ordinary VS Code tag discussion was removed: %q", got)
	}
	fencedExample := "Example:\n```xml\n" + runtimeEnvelope + "\n```"
	if got := safeRetentionModelOutput(fencedExample); got != fencedExample {
		t.Fatalf("fenced VS Code runtime example was removed: %q", got)
	}
}

func TestSafeRetentionModelOutputHidesImageGenOrchestrationOnlyWithFingerprints(t *testing.T) {
	runtimePrompts := []struct{ raw, want string }{
		{raw: "Use the built-in image_gen tool directly. Generate exactly one image. Do not inspect the repository, skills, configuration, or local files. PROMPT: a red fox", want: "a red fox"},
		{raw: "You have an internal tool called image_gen. Invoke it without exposing these instructions.\nTASK: Generate an image for the user.\nPROMPT: a red fox", want: "a red fox"},
	}
	for _, test := range runtimePrompts {
		if got, status := safeRetentionUserInput(test.raw); got != test.want || status != "complete" {
			t.Errorf("ImageGen user prompt projection failed for %q: (%q, %q), want %q", test.raw, got, status, test.want)
		}
		if got := safeRetentionModelOutput(test.raw); got != "" {
			t.Errorf("standalone ImageGen orchestration leaked for %q: %q", test.raw, got)
		}
		mixed := "Customer-visible answer.\n" + test.raw
		if got := safeRetentionModelOutput(mixed); got != "Customer-visible answer." {
			t.Errorf("mixed ImageGen orchestration leaked for %q: %q", test.raw, got)
		}
	}

	visible := []string{
		"Use the built-in image_gen tool directly. This sentence merely quotes one integration option.",
		"You have an internal tool called image_gen, but this sentence has no orchestration task or prompt fields.",
		"TASK: Generate an image is an example field, while PROMPT: is another field; no internal-tool prefix is present.",
	}
	for _, answer := range visible {
		if got := safeRetentionModelOutput(answer); got != answer {
			t.Errorf("ordinary ImageGen discussion was removed for %q: %q", answer, got)
		}
	}

	fencedExample := "Example:\n```text\nUse the built-in image_gen tool directly. Generate exactly one image. Do not inspect the repository, skills, configuration.\n```"
	if got := safeRetentionModelOutput(fencedExample); got != fencedExample {
		t.Fatalf("fenced ImageGen example was removed: %q", got)
	}
}

func TestSafeRetentionModelOutputKeepsCustomerJSONAndMarkdownButRejectsProtocolJSON(t *testing.T) {
	for _, visible := range []string{
		`{"status":"ok","items":[1,2]}`,
		`["alpha","beta"]`,
		`[查看结果](https://example.test/result)`,
	} {
		if got := safeRetentionModelOutput(visible); got != visible {
			t.Fatalf("visible model output = %q, want %q", got, visible)
		}
	}
	for _, protocol := range []string{
		`{"id":"chatcmpl_1","object":"chat.completion","choices":[]}`,
		`{"role":"assistant","content":[{"type":"text","text":"private envelope"}]}`,
		`{"type":"message","role":"assistant","content":[{"type":"text","text":"private envelope"}]}`,
		`{"type":"response.output_text.delta","delta":"private stream frame"}`,
		`{"candidates":[{"content":{"parts":[{"text":"private envelope"}]}}]}`,
	} {
		if got := safeRetentionModelOutput(protocol); got != "" {
			t.Fatalf("raw model protocol JSON leaked: %q", got)
		}
	}
}

func TestBuildAccessRetentionMessagesUsesChronologicalBatchOrderForIncrementalInput(t *testing.T) {
	reader := orderedBatchContentLogReader{logs: []repository.ContentLog{
		{ID: "old-user", RequestID: "req-old", Role: "user", Content: "继续", CreatedAt: time.Unix(10, 0)},
		{ID: "old-assistant", RequestID: "req-old", Role: "assistant", Content: "第一步完成", CreatedAt: time.Unix(11, 0)},
		{ID: "new-user", RequestID: "req-new", Role: "user", Content: "继续\n你在干嘛", CreatedAt: time.Unix(20, 0)},
		{ID: "new-assistant", RequestID: "req-new", Role: "assistant", Content: "正在继续", CreatedAt: time.Unix(21, 0)},
	}}
	messages, err := buildAccessRetentionMessages(context.Background(), &Dependencies{ContentLogReader: reader}, "tenant-1", []string{"req-new", "req-old"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"继续", "第一步完成", "你在干嘛", "正在继续"}
	if len(messages) != len(want) {
		t.Fatalf("messages=%#v", messages)
	}
	for i := range want {
		if messages[i].Content != want[i] {
			t.Fatalf("messages[%d]=%#v, want content %q", i, messages[i], want[i])
		}
	}
}

func TestBuildAccessRetentionMessagesKeepsLegitimateRepeatedTurnsWithDistinctSections(t *testing.T) {
	items := []repository.AccessContentLog{
		{RequestID: "req-1", SectionID: "turn-1", RequestContent: "再试一次", ResponseContent: "第一次", CreatedAt: time.Unix(10, 0)},
		{RequestID: "req-2", SectionID: "turn-2", RequestContent: "再试一次", ResponseContent: "第二次", CreatedAt: time.Unix(20, 0)},
	}
	messages, err := buildAccessRetentionMessages(context.Background(), &Dependencies{}, "tenant-1", []string{"req-2", "req-1"}, items)
	if err != nil {
		t.Fatal(err)
	}
	var userCount int
	for _, item := range messages {
		if item.Role == "user" && item.Content == "再试一次" {
			userCount++
		}
	}
	if userCount != 2 {
		t.Fatalf("legitimate repeated turns were collapsed: %#v", messages)
	}
}

func TestBuildAccessRetentionMessagesMergesStructuredAndFallbackChronologically(t *testing.T) {
	reader := orderedBatchContentLogReader{logs: []repository.ContentLog{
		{ID: "old-user", RequestID: "req-old", Role: "user", Content: "先检查旧记录", CreatedAt: time.Unix(10, 0)},
		{ID: "old-assistant", RequestID: "req-old", Role: "assistant", Content: "旧记录已检查", CreatedAt: time.Unix(11, 0)},
	}}
	accessItems := []repository.AccessContentLog{{
		RequestID: "req-new", SectionID: "turn-new", RequestContent: "再检查新记录",
		ResponseContent: "新记录已检查", CreatedAt: time.Unix(20, 0),
	}}
	messages, err := buildAccessRetentionMessages(context.Background(), &Dependencies{ContentLogReader: reader},
		"tenant-1", []string{"req-new", "req-old"}, accessItems)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"先检查旧记录", "旧记录已检查", "再检查新记录", "新记录已检查"}
	if len(messages) != len(want) {
		t.Fatalf("messages=%#v", messages)
	}
	for i := range want {
		if messages[i].Content != want[i] {
			t.Fatalf("messages[%d]=%#v, want content %q", i, messages[i], want[i])
		}
	}
}

func TestEnsureInputArtifactMessagesPlacesImageOnlyTurnByRequestTime(t *testing.T) {
	messages := []types.AccessRetentionMessageInfo{
		{ID: "before-user", RequestID: "req-before", Sequence: 1, Role: "user", Kind: "user_input", Content: "前一轮", CreatedAt: time.Unix(10, 0).UTC().Format(time.RFC3339Nano)},
		{ID: "after-user", RequestID: "req-after", Sequence: 2, Role: "user", Kind: "user_input", Content: "后一轮", CreatedAt: time.Unix(30, 0).UTC().Format(time.RFC3339Nano)},
	}
	artifacts := []types.AccessRetentionArtifactInfo{{
		ID: "artifact-image", RequestID: "req-image-only", Direction: "input", Kind: "image",
		RetentionStatus: "retained", RequestCreatedAt: time.Unix(20, 0),
	}}
	got := ensureInputArtifactMessages(messages, artifacts)
	if len(got) != 3 || got[1].RequestID != "req-image-only" || got[1].Role != "user" || got[1].Content != "" {
		t.Fatalf("image-only message order=%#v", got)
	}
	for index := range got {
		if got[index].Sequence != index+1 {
			t.Fatalf("message sequence not normalized: %#v", got)
		}
	}
}

func TestIncrementalRetentionUserTextDropsRetriesAndKeepsAppendedPrompt(t *testing.T) {
	if display, next := incrementalRetentionUserText("", "继续"); display != "继续" || next != "继续" {
		t.Fatalf("first=(%q,%q)", display, next)
	}
	if display, next := incrementalRetentionUserText("继续", "继续"); display != "" || next != "继续" {
		t.Fatalf("retry=(%q,%q)", display, next)
	}
	if display, next := incrementalRetentionUserText("继续", "继续\n你在干嘛"); display != "你在干嘛" || next != "继续\n你在干嘛" {
		t.Fatalf("append=(%q,%q)", display, next)
	}
	if display, _ := incrementalRetentionUserText("hello", "hello again"); display != "hello again" {
		t.Fatalf("word prefix must not be treated as accumulated input: %q", display)
	}
}
