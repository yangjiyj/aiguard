package handler

import "testing"

// 受限文件模式在 .. 写法下照样认出（filerestrict 按 path.Clean 折叠 . 与 ..）：
// 目录型模式 /vault/ 下 /tmp/../vault/x 就是 /vault/x，/vault/../tmp/x 是 /tmp/x 不算受限。
// 2.9.22 批次 2B 起文件类工具（Read 的 file_path）也按路径精确匹配，目录型模式认得出。
func TestEvaluateRestrictedFileToolCallsFoldsDotDot(t *testing.T) {
	policy := RestrictedFilePolicy{Patterns: []string{"/vault/"}, Action: "block"}
	if f := evaluateRestrictedFileToolCalls(policy, readInvocation("/tmp/../vault/x.txt")); len(f) != 1 || f[0]["action"] != "block" {
		t.Fatalf("Read /tmp/../vault/x.txt is under /vault/: %+v", f)
	}
	if f := evaluateRestrictedFileToolCalls(policy, []ToolInvocation{{Name: "Bash", Arguments: `{"command":"cat /tmp/../vault/x.txt"}`}}); len(f) != 1 || f[0]["action"] != "block" {
		t.Fatalf("/tmp/../vault/x.txt is under /vault/: %+v", f)
	}
	if f := evaluateRestrictedFileToolCalls(policy, []ToolInvocation{{Name: "Bash", Arguments: `{"command":"cat /vault/../tmp/x.txt"}`}}); len(f) != 0 {
		t.Fatalf("/vault/../tmp/x.txt is /tmp/x.txt: %+v", f)
	}
}

func TestProxyCodexMentionedFileFoldsDotDot(t *testing.T) {
	h := newRFInputProxyHandler(false, RestrictedFilePolicy{Patterns: []string{"/vault/"}, Action: "block"})
	if action, _, blocked := callInput(h, codexResponsesRequest("/tmp/../vault/x.txt")); !blocked || action != "block" {
		t.Fatalf("a mentioned /tmp/../vault/x.txt must be blocked, action=%q blocked=%v", action, blocked)
	}
	if action, findings, blocked := callInput(h, codexResponsesRequest("/vault/../tmp/x.txt")); blocked || len(findings) != 0 {
		t.Fatalf("a mentioned /vault/../tmp/x.txt is not restricted, action=%q findings=%+v", action, findings)
	}
}
