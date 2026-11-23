package retentionfmt

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func TestWorkBuddyWorkspaceFolder(t *testing.T) {
	content := "<system-reminder>\r\n<user_info>\r\nWorkspace Folder: /Users/yj/WorkBuddy/task-42\r\n</user_info>\r\n</system-reminder>"
	if got := WorkBuddyWorkspaceFolder(content); got != "/Users/yj/WorkBuddy/task-42" {
		t.Fatalf("workspace folder=%q", got)
	}
	if got := WorkBuddyWorkspaceFolder("用户正文提到 Workspace Folder: /tmp/not-a-field"); got != "" {
		t.Fatalf("inline user text must not be treated as workspace identity: %q", got)
	}
}

func TestSplitUserQuery(t *testing.T) {
	q, rest := SplitUserQuery("<system-reminder>ctx</system-reminder>\n<user_query>行</user_query>")
	if q != "行" {
		t.Fatalf("query = %q, want 行", q)
	}
	if !strings.Contains(rest, "<system-reminder>") || strings.Contains(rest, "<user_query>") {
		t.Fatalf("rest should keep system-reminder and drop user_query, got %q", rest)
	}

	q2, _ := SplitUserQuery("<user_query>问一</user_query>中间\n<user_query>问二</user_query>")
	if q2 != "问一\n问二" {
		t.Fatalf("multi user_query joined wrong: %q", q2)
	}

	if q3, _ := SplitUserQuery("just a normal message"); q3 != "" {
		t.Fatalf("no tag should yield empty query, got %q", q3)
	}

	if q4, _ := SplitUserQuery(`<user_query data-x="1">带属性</user_query>`); q4 != "带属性" {
		t.Fatalf("attributed user_query not extracted: %q", q4)
	}
}

func TestProjectAgentTaskTitleUnwrapsWorkBuddySession(t *testing.T) {
	raw := "<session>\r\n@image#1:Clipboard_Screenshot.png 这个是什么意思\r\n</session>"
	got, matched := ProjectAgentTaskTitle("WorkBuddy", raw, false)
	if !matched || got != "@image#1:Clipboard_Screenshot.png 这个是什么意思" {
		t.Fatalf("WorkBuddy title=(%q,%v)", got, matched)
	}

	prefix := "<session>\n"
	truncated := prefix + strings.Repeat("任", 160-len([]rune(prefix)))
	got, matched = ProjectAgentTaskTitle("workbuddy", truncated, utf8.RuneCountInString(truncated) == 160)
	if !matched || got != strings.Repeat("任", 160-len([]rune(prefix))) {
		t.Fatalf("truncated WorkBuddy title=(%q,%v)", got, matched)
	}

	crlfPrefix := "<session>\r\n历史标题"
	crlfTruncated := crlfPrefix + strings.Repeat("任", 160-utf8.RuneCountInString(crlfPrefix)-1) + " "
	got, matched = ProjectAgentTaskTitle("workbuddy", crlfTruncated, utf8.RuneCountInString(crlfTruncated) == 160)
	if !matched || !strings.HasPrefix(got, "历史标题") || strings.HasPrefix(got, "<session>") {
		t.Fatalf("CRLF/space-truncated WorkBuddy title=(%q,%v)", got, matched)
	}
	if got, matched = ProjectAgentTaskTitle("workbuddy", truncated, false); matched || got != truncated {
		t.Fatalf("caller without database truncation evidence changed prefix text: (%q,%v)", got, matched)
	}
}

func TestProjectAgentTaskTitlePreservesOrdinarySessionXML(t *testing.T) {
	for _, test := range []struct {
		agent string
		raw   string
	}{
		{agent: "workbuddy", raw: "<session> 是什么"},
		{agent: "workbuddy", raw: "<session>ordinary XML</session>"},
		{agent: "workbuddy", raw: "  <session>ordinary XML</session>\r\n"},
		{agent: "cline", raw: "<session>\nordinary XML\n</session>"},
		{agent: "workbuddy", raw: "```xml\n<session>\nexample\n</session>\n```"},
		{agent: "workbuddy", raw: "<session>\nshort incomplete wrapper"},
	} {
		got, matched := ProjectAgentTaskTitle(test.agent, test.raw, false)
		if matched || got != test.raw {
			t.Fatalf("ordinary XML changed for %s: (%q,%v), want %q", test.agent, got, matched, test.raw)
		}
	}
}

func TestProjectAgentTaskTitleUnwrapsStrictClineTaskProgressEnvelope(t *testing.T) {
	raw := "<task> 可以啊 </task>\n\n# task_progress RECOMMENDED\n" +
		"When starting a new task, include a todo list.\n<environment_details>private</environment_details>"
	got, matched := ProjectAgentTaskTitle("cline", raw, false)
	if !matched || got != "可以啊" {
		t.Fatalf("Cline title=(%q,%v)", got, matched)
	}
}

func TestProjectAgentTaskTitlePreservesOrdinaryTaskMarkup(t *testing.T) {
	for _, raw := range []string{
		"用户问 <task> 是什么",
		"<task>ordinary XML</task>",
		"<task>ordinary XML</task>\n# task_progress OPTIONAL",
		"```xml\n<task>example</task>\n# task_progress RECOMMENDED\n```",
	} {
		got, matched := ProjectAgentTaskTitle("cline", raw, false)
		if matched || got != raw {
			t.Fatalf("ordinary task markup changed: (%q,%v), want %q", got, matched, raw)
		}
	}
}

func TestIsAgentMetaContent(t *testing.T) {
	if IsAgentMetaContent("行啊") {
		t.Fatal("short real input must not be treated as agent meta")
	}
	longReal := strings.Repeat("这是一段很长的真实中文提问但不含 agent 特征串。", 40)
	if IsAgentMetaContent(longReal) {
		t.Fatal("long real content without markers must not be folded")
	}
	if !IsAgentMetaContent("You are Claude Code. " + strings.Repeat("x ", 300)) {
		t.Fatal("agent system prompt must be detected as meta")
	}
}

func TestIsAgentMetaContentMatchesAttributedSystemReminder(t *testing.T) {
	content := `<system-reminder data-role="user-context">
<user_info>
OS Version: darwin
Shell: /bin/zsh
Workspace Folder: /Users/yj/WorkBuddy/task
</user_info>
` + strings.Repeat("internal runtime context ", 30) + `
</system-reminder>`
	if !IsAgentMetaContent(content) {
		t.Fatal("attributed WorkBuddy user-context must be treated as agent metadata")
	}
}

func TestCollapseBlankLines(t *testing.T) {
	// 内部空行（含 CRLF）压平成单换行——整段可作为一个 paragraph 被前端折叠。
	in := "a\r\n\r\nb\n\n\nc\nd"
	got := CollapseBlankLines(in)
	if strings.Contains(got, "\n\n") {
		t.Fatalf("blank lines not collapsed: %q", got)
	}
	if got != "a\nb\nc\nd" {
		t.Fatalf("collapse result = %q, want a\\nb\\nc\\nd", got)
	}
}
