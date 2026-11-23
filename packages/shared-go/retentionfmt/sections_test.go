package retentionfmt

import (
	"strings"
	"testing"
)

func TestToolSectionPrefixesAndCollapsesBlankLines(t *testing.T) {
	got := ToolSection("#!/bin/bash\n\n\necho hi\r\n\r\nls -la\n")
	want := "【工具】#!/bin/bash\necho hi\nls -la"
	if got != want {
		t.Fatalf("ToolSection = %q, want %q", got, want)
	}
}

func TestToolSectionEmptyContentRendersEmpty(t *testing.T) {
	for _, content := range []string{"", "   ", "\r\n\r\n", " \n \t "} {
		if got := ToolSection(content); got != "" {
			t.Fatalf("ToolSection(%q) = %q, want empty", content, got)
		}
	}
}

func TestToolSectionKeepsEvidenceContent(t *testing.T) {
	got := ToolSection("127.0.0.1 localhost")
	if got != "【工具】127.0.0.1 localhost" {
		t.Fatalf("ToolSection lost evidence content: %q", got)
	}
	if ToolSection("secret-token-value") == "" {
		t.Fatal("ToolSection must not drop non-empty content")
	}
}

func TestSplitRetainedSectionsRestoresRolesAndGluesDefaultParagraphs(t *testing.T) {
	text := strings.Join([]string{
		"第一段用户话",
		"",
		"第二段用户话",
		"",
		ToolSection("#!/bin/bash\necho hi"),
	}, "\n\n")
	got := SplitRetainedSections(text, "user")
	if len(got) != 2 {
		t.Fatalf("sections = %#v", got)
	}
	// 用户正文本身含空行，拆开后必须原样拼回去（不能显示成两段）。
	if got[0].Role != "user" || got[0].Content != "第一段用户话\n\n第二段用户话" {
		t.Fatalf("user section = %#v", got[0])
	}
	if got[1].Role != "tool" || got[1].Content != "#!/bin/bash\necho hi" {
		t.Fatalf("tool section = %#v", got[1])
	}
}

func TestSplitRetainedSectionsMapsEveryInternalRoleTag(t *testing.T) {
	text := strings.Join([]string{
		"客户可见的问题",
		"【系统】internal system prompt",
		"【system】english system prompt",
		"【developer】developer instructions",
		"【工具】tool payload",
		"【tool】english tool payload",
		"【其它】other bucket",
		"答复正文",
	}, "\n\n")
	got := SplitRetainedSections(text, "assistant")
	wantRoles := []string{"assistant", "system", "system", "system", "tool", "tool", "other", "assistant"}
	if len(got) != len(wantRoles) {
		t.Fatalf("sections = %#v", got)
	}
	for index, want := range wantRoles {
		if got[index].Role != want {
			t.Fatalf("sections[%d].Role = %q, want %q (%#v)", index, got[index].Role, want, got)
		}
	}
	// 标签必须从内容里剥掉，否则前端会把它当正文再显示一遍。
	for _, section := range got {
		if strings.HasPrefix(section.Content, "【") {
			t.Fatalf("role tag leaked into content: %#v", section)
		}
	}
	if got[1].Content != "internal system prompt" {
		t.Fatalf("system section content = %q", got[1].Content)
	}
}

func TestSplitRetainedSectionsEmptyText(t *testing.T) {
	if got := SplitRetainedSections("   \n\n  \n", "user"); len(got) != 0 {
		t.Fatalf("blank text must produce no sections: %#v", got)
	}
	if got := SplitRetainedSections("只是普通一句话", "user"); len(got) != 1 || got[0].Role != "user" {
		t.Fatalf("plain text = %#v", got)
	}
}
