package aimsg

import (
	"os"
	"strings"
	"testing"
)

func readEnvelopeFixture(t *testing.T, name string) string {
	t.Helper()
	body, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

func TestAgentEnvelopeCodexExtractsOnlyHumanRequest(t *testing.T) {
	text, status, matched := NormalizeAgentEnvelope(
		readEnvelopeFixture(t, "agent-envelope-codex.txt"),
	)
	if !matched || status != ParseComplete || text != "Implement retained artifact evidence." {
		t.Fatalf("normalized = (%q, %q, %v)", text, status, matched)
	}
	for _, forbidden := range []string{"AGENTS.md", "environment_context", "tool schema", "checkpoint"} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("human projection leaked %q: %q", forbidden, text)
		}
	}
}

func TestAgentEnvelopeWorkBuddyAndClaudeExtractUserQuery(t *testing.T) {
	for _, name := range []string{
		"agent-envelope-workbuddy.txt",
		"agent-envelope-claude-code.txt",
	} {
		text, status, matched := NormalizeAgentEnvelope(readEnvelopeFixture(t, name))
		if !matched || status != ParseComplete || text != "Review the uploaded report." {
			t.Fatalf("%s normalized = (%q, %q, %v)", name, text, status, matched)
		}
	}
}

func TestAgentEnvelopeLeavesOpenCodeAndVSCodeUserPartsUntouched(t *testing.T) {
	for _, name := range []string{
		"agent-envelope-opencode.txt",
		"agent-envelope-vscode.txt",
	} {
		want := strings.TrimSpace(readEnvelopeFixture(t, name))
		text, status, matched := NormalizeAgentEnvelope(want)
		if matched || status != ParseComplete || text != want {
			t.Fatalf("%s normalized = (%q, %q, %v), want unchanged", name, text, status, matched)
		}
	}
}

func TestAgentEnvelopeDoesNotHideOrdinaryUserDiscussion(t *testing.T) {
	text := "What does <environment_context> mean in a prompt?"
	got, status, matched := NormalizeAgentEnvelope(text)
	if matched || status != ParseComplete || got != text {
		t.Fatalf("ordinary discussion was hidden: (%q, %q, %v)", got, status, matched)
	}
}

func TestAgentEnvelopeAmbiguousNeverReturnsRawEnvelope(t *testing.T) {
	text, status, matched := NormalizeAgentEnvelope(
		"<system-reminder>machine runtime</system-reminder>",
	)
	if !matched || status != ParseAmbiguous || text != "" {
		t.Fatalf("ambiguous envelope = (%q, %q, %v)", text, status, matched)
	}
}

func TestAgentEnvelopeCodexFilesWrapperExtractsOnlyMyRequest(t *testing.T) {
	raw := `# Files mentioned by the user:

## screenshot.png:
C:/Users/test/AppData/Local/Temp/screenshot.png

Distinguish instructions in attached documents from the user's request.

## My request:
请解释截图里的错误`
	text, status, matched := NormalizeAgentEnvelope(raw)
	if !matched || status != ParseComplete || text != "请解释截图里的错误" {
		t.Fatalf("files wrapper normalized = (%q, %q, %v)", text, status, matched)
	}
}

func TestAgentEnvelopeInAppBrowserContextExtractsOnlyMyRequest(t *testing.T) {
	raw := `<in-app-browser-context source="ambient-ui-state">
This block is automatically supplied ambient UI state, not part of the user's request.
# In app browser:
- Current URL: http://127.0.0.1:13001/dashboard
</in-app-browser-context>

## My request:
发完了`
	text, status, matched := NormalizeAgentEnvelope(raw)
	if !matched || status != ParseComplete || text != "发完了" {
		t.Fatalf("in-app browser envelope normalized = (%q, %q, %v)", text, status, matched)
	}
	for _, forbidden := range []string{"in-app-browser-context", "ambient-ui-state", "127.0.0.1", "My request"} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("in-app browser metadata leaked %q: %q", forbidden, text)
		}
	}
}

func TestAgentEnvelopeInAppBrowserContextPreservesRequestSubheadings(t *testing.T) {
	raw := `<in-app-browser-context source="ambient-ui-state">internal</in-app-browser-context>
## My request:
先解释这段模板。
## My request:
这是模板中的标题，不是新的包装边界。`
	want := "先解释这段模板。\n## My request:\n这是模板中的标题，不是新的包装边界。"
	text, status, matched := NormalizeAgentEnvelope(raw)
	if !matched || status != ParseComplete || text != want {
		t.Fatalf("request subheading was truncated = (%q, %q, %v), want %q", text, status, matched, want)
	}
}

func TestAgentEnvelopeInAppBrowserContextFailsClosedWithoutCompleteRequest(t *testing.T) {
	for _, raw := range []string{
		`<in-app-browser-context source="ambient-ui-state">internal</in-app-browser-context>`,
		`<in-app-browser-context source="ambient-ui-state">truncated internal context`,
		`<in-app-browser-context source="ambient-ui-state">internal</in-app-browser-context>
## My request:`,
	} {
		text, status, matched := NormalizeAgentEnvelope(raw)
		if !matched || status != ParseAmbiguous || text != "" {
			t.Fatalf("incomplete in-app browser envelope = (%q, %q, %v) for %q", text, status, matched, raw)
		}
	}

	ordinary := "What does <in-app-browser-context> mean?"
	if text, status, matched := NormalizeAgentEnvelope(ordinary); matched || status != ParseComplete || text != ordinary {
		t.Fatalf("ordinary tag discussion changed = (%q, %q, %v)", text, status, matched)
	}
	userXML := `<in-app-browser-context>customer-authored XML</in-app-browser-context>
## My request:
请解释这个示例`
	if text, status, matched := NormalizeAgentEnvelope(userXML); matched || status != ParseComplete || text != userXML {
		t.Fatalf("untrusted same-name XML changed = (%q, %q, %v)", text, status, matched)
	}
}

func TestAgentEnvelopeWorkBuddyImageRemovesTransportPath(t *testing.T) {
	raw := "@image#1:Clipboard_Screenshot.png 这个是什么意思\n" +
		"<image_local_path>C:/Users/test/.workbuddy/clipboard-images/private.png</image_local_path>"
	text, status, matched := NormalizeAgentEnvelope(raw)
	if !matched || status != ParseComplete || text != "这个是什么意思" {
		t.Fatalf("workbuddy image normalized = (%q, %q, %v)", text, status, matched)
	}
	for _, forbidden := range []string{"@image#", "image_local_path", ".workbuddy"} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("workbuddy transport metadata leaked %q: %q", forbidden, text)
		}
	}
}

func TestAgentEnvelopeWorkBuddyImageSessionExtractsHumanText(t *testing.T) {
	raw := `<session>
@image#1:Clipboard_Screenshot.png 这个是什么意思
</session>`
	text, status, matched := NormalizeAgentEnvelope(raw)
	if !matched || status != ParseComplete || text != "这个是什么意思" {
		t.Fatalf("WorkBuddy image session normalized = (%q, %q, %v)", text, status, matched)
	}

	truncated := `<session>
@image#1:Clipboard_Screenshot.png 这个是什么意思`
	text, status, matched = NormalizeAgentEnvelope(truncated)
	if !matched || status != ParseAmbiguous || text != "" {
		t.Fatalf("truncated WorkBuddy image session = (%q, %q, %v)", text, status, matched)
	}
}

func TestAgentEnvelopeDoesNotGeneralizeWorkBuddySessionXML(t *testing.T) {
	for _, raw := range []string{
		"<session> 是什么",
		"<session>ordinary XML</session>",
		"<session>\npure text\n</session>",
	} {
		text, status, matched := NormalizeAgentEnvelope(raw)
		if matched || status != ParseComplete || text != raw {
			t.Fatalf("ordinary session XML changed = (%q, %q, %v), want %q", text, status, matched, raw)
		}
	}
}

func TestAgentEnvelopeClineTaskProgressExtractsOnlyTask(t *testing.T) {
	raw := `<task> 可以啊 </task>

# task_progress RECOMMENDED
When starting a new task, it is recommended to include a todo list using the task_progress parameter.
1. Include a todo list using the task_progress parameter in your next tool call
<environment_details>
# Detected CLI Tools
git, npm, curl
# Current Mode
ACT MODE
</environment_details>`
	text, status, matched := NormalizeAgentEnvelope(raw)
	if !matched || status != ParseComplete || text != "可以啊" {
		t.Fatalf("Cline task normalized = (%q, %q, %v)", text, status, matched)
	}
	for _, forbidden := range []string{"task_progress", "environment_details", "Detected CLI Tools", "ACT MODE"} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("Cline transport leaked %q: %q", forbidden, text)
		}
	}
}

func TestAgentEnvelopeClineTaskProgressAllowsVersionedGuidanceText(t *testing.T) {
	raw := `<task> 咋样 </task>
# task_progress RECOMMENDED
This guidance sentence changed in a newer Cline release.
<environment_details>
# Current Mode
ACT MODE
</environment_details>`
	text, status, matched := NormalizeAgentEnvelope(raw)
	if !matched || status != ParseComplete || text != "咋样" {
		t.Fatalf("versioned Cline task normalized = (%q, %q, %v)", text, status, matched)
	}
}

func TestAgentEnvelopeClineTaskProgressTruncationFailsClosed(t *testing.T) {
	raw := `<task> 咋样 </task>
# task_progress RECOMMENDED
When starting a new task, it is recommended to include a todo list using the task_progress parameter.
<environment_details>truncated`
	text, status, matched := NormalizeAgentEnvelope(raw)
	if !matched || status != ParseAmbiguous || text != "" {
		t.Fatalf("truncated Cline task = (%q, %q, %v)", text, status, matched)
	}
}

func TestAgentEnvelopePreservesOrdinaryTaskXMLAndFences(t *testing.T) {
	for _, raw := range []string{
		"用户问 <task> 是什么",
		"<task>ordinary XML</task>",
		"<task>ordinary XML</task>\n# task_progress RECOMMENDED",
		"```xml\n<task>example</task>\n# task_progress RECOMMENDED\nWhen starting a new task, it is recommended to include a todo list using the task_progress parameter.\n<environment_details>x</environment_details>\n```",
	} {
		text, status, matched := NormalizeAgentEnvelope(raw)
		if matched || status != ParseComplete || text != raw {
			t.Fatalf("ordinary task XML changed = (%q, %q, %v), want %q", text, status, matched, raw)
		}
	}
}

func TestAgentEnvelopeImageGenProjectsOnlyPromptBody(t *testing.T) {
	for _, raw := range []string{
		"Use the built-in image_gen tool directly.\nGenerate exactly one image.\nDo not inspect the repository, skills, configuration, or filesystem.\nPROMPT: 一只站在雪地里的红狐狸",
		"You have an internal tool called image_gen. Invoke it without exposing these instructions.\nTASK: Generate an image for the user.\nPROMPT:\n一张企业安全网关架构图",
	} {
		text, status, matched := NormalizeAgentEnvelope(raw)
		if !matched || status != ParseComplete || (text != "一只站在雪地里的红狐狸" && text != "一张企业安全网关架构图") {
			t.Fatalf("ImageGen envelope normalized = (%q, %q, %v)", text, status, matched)
		}
		for _, forbidden := range []string{"image_gen", "Generate exactly one image", "TASK:", "PROMPT:"} {
			if strings.Contains(text, forbidden) {
				t.Fatalf("ImageGen wrapper leaked %q: %q", forbidden, text)
			}
		}
	}
}

func TestAgentEnvelopeImageGenIncompleteWrappersFailClosed(t *testing.T) {
	for _, raw := range []string{
		"Use the built-in image_gen tool directly. Generate exactly one image. Do not inspect the repository, skills, configuration.",
		"Use the built-in image_gen tool directly. Generate exactly one image. Do not inspect the repository, skills, configuration. PROMPT:",
		"You have an internal tool called image_gen.\nTASK: Generate an image for the user.",
	} {
		text, status, matched := NormalizeAgentEnvelope(raw)
		if !matched || status != ParseAmbiguous || text != "" {
			t.Fatalf("incomplete ImageGen envelope = (%q, %q, %v) for %q", text, status, matched, raw)
		}
	}
}

func TestAgentEnvelopeImageGenDoesNotMatchDiscussionFencesOrLateMarkers(t *testing.T) {
	for _, raw := range []string{
		"请解释 Use the built-in image_gen tool directly. 这句话，正文后来写 PROMPT: 示例",
		"```text\nUse the built-in image_gen tool directly.\nGenerate exactly one image.\nDo not inspect the repository, skills, configuration.\nPROMPT: fenced example\n```",
		"Use the built-in image_gen tool directly. PROMPT: 用户先写正文，后来讨论 Generate exactly one image 和 Do not inspect the repository, skills, configuration",
		"You have an internal tool called image_gen, but this is only a product discussion. PROMPT: example",
	} {
		text, status, matched := NormalizeAgentEnvelope(raw)
		if matched || status != ParseComplete || text != raw {
			t.Fatalf("ordinary ImageGen text changed = (%q, %q, %v), want %q", text, status, matched, raw)
		}
	}
}

func TestAgentEnvelopeWorkBuddyAttributedReminderExtractsUserQuery(t *testing.T) {
	raw := `<system-reminder data-role="user-context"><memory>internal</memory></system-reminder>
<user_query data-source="desktop">来，你操作</user_query>`
	text, status, matched := NormalizeAgentEnvelope(raw)
	if !matched || status != ParseComplete || text != "来，你操作" {
		t.Fatalf("attributed WorkBuddy envelope normalized = (%q, %q, %v)", text, status, matched)
	}
}

func TestAgentEnvelopeWorkBuddyAttributedContextWithoutUserQueryIsAmbiguous(t *testing.T) {
	raw := `<system-reminder data-role="user-context">
<user_info>
OS Version: darwin
Shell: /bin/zsh
Workspace Folder: /Users/yj/WorkBuddy/task
</user_info>
</system-reminder>`
	text, status, matched := NormalizeAgentEnvelope(raw)
	if !matched || status != ParseAmbiguous || text != "" {
		t.Fatalf("attributed WorkBuddy context normalized = (%q, %q, %v)", text, status, matched)
	}
	if !IsWorkBuddyUserContextEnvelope(raw) {
		t.Fatal("complete attributed WorkBuddy context must be recognized")
	}
	if IsWorkBuddyUserContextEnvelope(raw + "\nordinary user text") {
		t.Fatal("text appended after the WorkBuddy wrapper must remain user input")
	}
}

func TestNormalizeRetainedAssistantTextDropsPrivateReasoningAndMemoryCitation(t *testing.T) {
	raw := `[reasoning] internal chain of thought
正在检查代码。
<oai-mem-citation>
<citation_entries>MEMORY.md:1-2</citation_entries>
<rollout_ids>private-rollout-id</rollout_ids>
</oai-mem-citation>
修复已经完成。`
	want := "正在检查代码。\n修复已经完成。"
	if got := NormalizeRetainedAssistantText(raw); got != want {
		t.Fatalf("assistant normalized = %q, want %q", got, want)
	}
}

func TestNormalizeRetainedAssistantTextReasoningOnlyBecomesEmpty(t *testing.T) {
	if got := NormalizeRetainedAssistantText("[reasoning] internal only\n[reasoning] second line"); got != "" {
		t.Fatalf("reasoning-only output must not enter customer retention: %q", got)
	}
}

func TestNormalizeRetainedAssistantTextDropsHistoricalToolPayload(t *testing.T) {
	toolOnly := `{"file_path":"C:/private/memory.md","new_string":"internal state"}`
	if got := NormalizeLegacyRetainedAssistantText(toolOnly); got != "" {
		t.Fatalf("tool-only payload must not enter customer retention: %q", got)
	}
	mixed := "正在检查配置。" + `{"command":"Get-Content C:/private/config"}`
	if got := NormalizeLegacyRetainedAssistantText(mixed); got != "正在检查配置。" {
		t.Fatalf("tool suffix must be removed from visible commentary: %q", got)
	}
}

func TestNormalizeRetainedAssistantTextPreservesVisibleJSONAnswer(t *testing.T) {
	raw := `{"command":"echo this is the requested answer"}`
	if got := NormalizeRetainedAssistantText(raw); got != raw {
		t.Fatalf("new protocol projections must preserve visible JSON answers: %q", got)
	}
}

func TestAgentEnvelopeGitHubCopilotPromptExtractsHumanText(t *testing.T) {
	raw := "<prompt>\nGWRETENTION-VSCODE 请只回复：VSCODE-OK\n</prompt>"
	text, status, matched := NormalizeAgentEnvelope(raw)
	if !matched || status != ParseComplete || text != "GWRETENTION-VSCODE 请只回复：VSCODE-OK" {
		t.Fatalf("Copilot prompt normalized = (%q, %q, %v)", text, status, matched)
	}
}

func TestAgentEnvelopeStandaloneEnvironmentContextHasNoUserTurn(t *testing.T) {
	raw := `<environment_context>
  <current_date>2026-08-29</current_date>
  <timezone>Asia/Shanghai</timezone>
  <filesystem><workspace_roots><root>C:\Users\test\project</root></workspace_roots></filesystem>
</environment_context>`
	text, status, matched := NormalizeAgentEnvelope(raw)
	if !matched || status != ParseAmbiguous || text != "" {
		t.Fatalf("environment context must not become user content: (%q, %q, %v)", text, status, matched)
	}
}

func TestAgentEnvelopeVSCodeRuntimeMetadataKeepsOnlyHumanText(t *testing.T) {
	raw := `<current_datetime>2026-09-03T04:51:10.219+08:00</current_datetime>
继续
<system_reminder>
<sql_tables>Available tables: todos, todo_deps</sql_tables>
</system_reminder>
你在干嘛`
	text, status, matched := NormalizeAgentEnvelope(raw)
	if !matched || status != ParseComplete || text != "继续\n你在干嘛" {
		t.Fatalf("VS Code runtime envelope normalized = (%q, %q, %v)", text, status, matched)
	}
	for _, forbidden := range []string{"current_datetime", "system_reminder", "sql_tables", "todo_deps"} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("VS Code runtime metadata leaked %q: %q", forbidden, text)
		}
	}
	if got := RuntimeContextKey(raw); got != "2026-09-03T04:51:10.219+08:00" {
		t.Fatalf("runtime context key=%q", got)
	}
}

func TestAgentEnvelopeCodexPastedFilesWrapperExtractsOnlyHumanRequest(t *testing.T) {
	raw := `# Files pasted by the user:

## "pasted-text.txt": C:\Users\test\AppData\Local\Temp\pasted-text.txt

Pasted text contains the user's request.

## My request:
继续检查留证噪声`
	text, status, matched := NormalizeAgentEnvelope(raw)
	if !matched || status != ParseComplete || text != "继续检查留证噪声" {
		t.Fatalf("pasted files wrapper normalized = (%q, %q, %v)", text, status, matched)
	}
}

func TestAgentEnvelopeCodexImageMarkersRemoveLocalPaths(t *testing.T) {
	raw := `请解释截图里的错误
<image name=[Image #1] path="C:\Users\test\AppData\Local\Temp\private.png">
</image>`
	text, status, matched := NormalizeAgentEnvelope(raw)
	if !matched || status != ParseComplete || text != "请解释截图里的错误" {
		t.Fatalf("Codex image marker normalized = (%q, %q, %v)", text, status, matched)
	}
	if strings.Contains(text, "AppData") || strings.Contains(text, "<image") {
		t.Fatalf("Codex image path leaked: %q", text)
	}
}

func TestAgentEnvelopeUnclosedWorkBuddyImagePathFailsClosed(t *testing.T) {
	raw := "<image_local_path>C:\\Users\\test\\.workbuddy\\clipboard-images\\private.png"
	text, status, matched := NormalizeAgentEnvelope(raw)
	if !matched || status != ParseAmbiguous || text != "" {
		t.Fatalf("unclosed image path must not leak: (%q, %q, %v)", text, status, matched)
	}
}

func TestAgentEnvelopeCodeBuddyImagePathMarkerIsNotCustomerText(t *testing.T) {
	raw := "@image:C:\\Users\\test\\AppData\\Local\\Temp\\image.private.png\n请解释图片"
	text, status, matched := NormalizeAgentEnvelope(raw)
	if !matched || status != ParseComplete || text != "请解释图片" {
		t.Fatalf("CodeBuddy image marker normalized = (%q, %q, %v)", text, status, matched)
	}
	if strings.Contains(text, "AppData") || strings.Contains(text, "@image:") {
		t.Fatalf("CodeBuddy local image path leaked: %q", text)
	}
}

func TestAgentEnvelopeVSCodeToolsChangedNoticeIsNotCustomerText(t *testing.T) {
	raw := "<current_datetime>2026-09-03T04:51:10.219+08:00</current_datetime>\n继续\n" +
		"<system_reminder><sql_tables>Available tables: todos</sql_tables></system_reminder>\n" +
		"<tools_changed_notice>Tools no longer available: grep</tools_changed_notice>\n你在干嘛"
	text, status, matched := NormalizeAgentEnvelope(raw)
	if !matched || status != ParseComplete || text != "继续\n你在干嘛" {
		t.Fatalf("VS Code tool-change notice normalized = (%q, %q, %v)", text, status, matched)
	}
}

func TestAgentEnvelopeVSCodeRuntimeMetadataPreservesFencedXMLExamples(t *testing.T) {
	raw := "<current_datetime>2026-09-03T04:51:10.219+08:00</current_datetime>\n继续\n" +
		"<system_reminder><sql_tables>Available tables: todos</sql_tables></system_reminder>\n" +
		"```xml\n<system_reminder>visible example</system_reminder>\n" +
		"<tools_changed_notice>Tools no longer available: demo</tools_changed_notice>\n```"
	want := "继续\n```xml\n<system_reminder>visible example</system_reminder>\n" +
		"<tools_changed_notice>Tools no longer available: demo</tools_changed_notice>\n```"
	text, status, matched := NormalizeAgentEnvelope(raw)
	if !matched || status != ParseComplete || text != want {
		t.Fatalf("VS Code runtime fenced example normalized = (%q, %q, %v), want %q", text, status, matched, want)
	}
}

func TestAgentEnvelopeStandaloneToolsChangedNoticeIsNotCustomerText(t *testing.T) {
	raw := "继续\n你在干嘛\n<tools_changed_notice>Tools no longer available: grep</tools_changed_notice>"
	text, status, matched := NormalizeAgentEnvelope(raw)
	if !matched || status != ParseComplete || text != "继续\n你在干嘛" {
		t.Fatalf("standalone VS Code tool-change notice normalized = (%q, %q, %v)", text, status, matched)
	}
}

func TestAgentEnvelopeTruncatedToolsNoticeAndVSCodeLocalImagePathAreNotCustomerText(t *testing.T) {
	raw := "继续\n<tools_changed_notice>\nTools no longer available: grep\nImportant: truncated transport"
	text, status, matched := NormalizeAgentEnvelope(raw)
	if !matched || status != ParseComplete || text != "继续" {
		t.Fatalf("truncated tool-change notice normalized = (%q, %q, %v)", text, status, matched)
	}

	raw = "请解释图片\nImage file at path C:\\Users\\test\\agentSessionData\\private\\Pasted Image.png"
	text, status, matched = NormalizeAgentEnvelope(raw)
	if !matched || status != ParseComplete || text != "请解释图片" {
		t.Fatalf("VS Code local image path normalized = (%q, %q, %v)", text, status, matched)
	}

	fenced := "```text\nImage file at path C:\\Users\\test\\visible-example.png\n```"
	text, status, matched = NormalizeAgentEnvelope(fenced)
	if matched || status != ParseComplete || text != fenced {
		t.Fatalf("fenced VS Code path example changed = (%q, %q, %v)", text, status, matched)
	}
}

func TestAgentEnvelopeToolsChangedNoticeOnlyStripsOutsideSupportedCodeFences(t *testing.T) {
	fenced := "请解释这个示例：\n```xml\n<tools_changed_notice>Tools no longer available: demo</tools_changed_notice>\n```"
	text, status, matched := NormalizeAgentEnvelope(fenced)
	if matched || status != ParseComplete || text != fenced {
		t.Fatalf("fenced tool-change example must remain visible: (%q, %q, %v)", text, status, matched)
	}

	for _, unsupported := range []string{
		"````xml\n<tools_changed_notice>private</tools_changed_notice>\n````",
		"~~~xml\n<tools_changed_notice>private</tools_changed_notice>\n~~~",
		"```xml\n<tools_changed_notice>private</tools_changed_notice>",
	} {
		text, status, matched = NormalizeAgentEnvelope(unsupported)
		if !matched || status != ParseComplete || strings.Contains(text, "tools_changed_notice") || strings.Contains(text, "private") {
			t.Fatalf("unsupported fence must not exempt tool notice: (%q, %q, %v)", text, status, matched)
		}
	}
}

func TestAgentEnvelopeFenceAwareCleaningPreservesOrdinaryMarkdownSpacing(t *testing.T) {
	raw := "正文\n\n```json\n{\"status\":\"visible\"}\n```\n\n  后文保留缩进"
	text, status, matched := NormalizeAgentEnvelope(raw)
	if matched || status != ParseComplete || text != raw {
		t.Fatalf("ordinary fenced Markdown changed = (%q, %q, %v), want %q", text, status, matched, raw)
	}
}

func TestAgentEnvelopeWorkBuddyLoopGuardHasNoUserTurn(t *testing.T) {
	raw := `[
Loop detected: the tool "Skill" has been called 4 consecutive times with identical arguments.

STOP calling tools immediately. Do NOT make any more tool calls.
Instead, tell the user what happened and suggest they switch models or modify their prompt to retry.
]

[LOOP_DETECTED]`
	text, status, matched := NormalizeAgentEnvelope(raw)
	if !matched || status != ParseAmbiguous || text != "" {
		t.Fatalf("WorkBuddy loop guard must not become user content: (%q, %q, %v)", text, status, matched)
	}
	if !IsRetainedUserTransportOnly(raw) {
		t.Fatal("complete WorkBuddy loop guard must be classified as transport-only")
	}
	if IsRetainedUserTransportOnly("用户在询问 LOOP_DETECTED 是什么意思") {
		t.Fatal("ordinary user text must not be classified as transport-only")
	}
}

func TestNormalizeRetainedAssistantTextDropsPrivateToolAndThinkingBlocks(t *testing.T) {
	raw := "可见结论。\n[thinking] private chain\n<tool_call>private arguments</tool_call>\n最终答复。"
	if got := NormalizeLegacyRetainedAssistantText(raw); got != "可见结论。\n最终答复。" {
		t.Fatalf("private assistant content leaked: %q", got)
	}
	truncated := "已完成检查。\n<oai-mem-citation><rollout_ids>private"
	if got := NormalizeLegacyRetainedAssistantText(truncated); got != "已完成检查。" {
		t.Fatalf("truncated private block leaked: %q", got)
	}
}

func TestNormalizeRetainedAssistantTextPreservesVisibleXMLExample(t *testing.T) {
	raw := "示例：<tool_call>echo hello</tool_call>"
	if got := NormalizeRetainedAssistantText(raw); got != raw {
		t.Fatalf("structured visible output was over-cleaned: %q", got)
	}
}

func TestNormalizeLegacyRetainedAssistantTextProtectsFencedExamplesOnly(t *testing.T) {
	raw := "示例：\n```xml\n<tool_call name=\"demo\">visible example</tool_call>\n```\n" +
		"[tool_use:Bash] command=cat /private/path"
	want := "示例：\n```xml\n<tool_call name=\"demo\">visible example</tool_call>\n```"
	if got := NormalizeLegacyRetainedAssistantText(raw); got != want {
		t.Fatalf("legacy fence-aware projection = %q, want %q", got, want)
	}

	truncatedFence := "可见结论\n```xml\n<tool_call>private arguments"
	if got := NormalizeLegacyRetainedAssistantText(truncatedFence); got != "可见结论\n```xml" {
		t.Fatalf("unterminated fence must not expose private transport: %q", got)
	}

	for _, unsupported := range []string{
		"~~~~xml\n<tool_call>private</tool_call>\n~~~~",
		"````xml\n<tool_call>private</tool_call>\n````",
		" ```xml\n<tool_call>private</tool_call>\n ```",
	} {
		if got := NormalizeLegacyRetainedAssistantText(unsupported); strings.Contains(got, "private") {
			t.Fatalf("unsupported fence created a privacy exemption: %q", got)
		}
	}
}

func TestAgentEnvelopeDoesNotStripOrdinaryRuntimeTagDiscussion(t *testing.T) {
	raw := "What does <current_datetime>foo</current_datetime> mean?"
	text, status, matched := NormalizeAgentEnvelope(raw)
	if matched || status != ParseComplete || text != raw {
		t.Fatalf("ordinary runtime-tag discussion was hidden: (%q, %q, %v)", text, status, matched)
	}
}

func TestAgentEnvelopeCodexFilesHeaderVariantsUseSameExtractor(t *testing.T) {
	raw := "# Files pasted by the user:\n\n## note.txt: C:\\Temp\\note.txt\n\n## My request for codex :\n保留真实请求"
	text, status, matched := NormalizeAgentEnvelope(raw)
	if !matched || status != ParseComplete || text != "保留真实请求" {
		t.Fatalf("variant files envelope normalized = (%q, %q, %v)", text, status, matched)
	}
}

func TestCompleteClientMetadataDoesNotBecomeHumanInput(t *testing.T) {
	for _, content := range []string{"<system-reminder>workspace context</system-reminder>", "<environment_details>\n# VSCode Visible Files\nmain.go\n</environment_details>"} {
		text, status, _ := NormalizeAgentEnvelope(content)
		if text != "" || status != ParseAmbiguous || !IsRetainedUserTransportOnly(content) {
			t.Fatal("metadata became a human question")
		}
	}
	for _, content := range []string{"解释 <system-reminder> 的用途", "<system-reminder>context</system-reminder>\n<user_query>继续</user_query>", "<system-reminder>incomplete"} {
		if IsRetainedUserTransportOnly(content) {
			t.Fatalf("human or incomplete input discarded: %q", content)
		}
	}
	text, status, _ := NormalizeAgentEnvelope("<system-reminder><user_query>继续</user_query></system-reminder>")
	if text != "继续" || status != ParseComplete {
		t.Fatal("explicit human input lost")
	}
}
