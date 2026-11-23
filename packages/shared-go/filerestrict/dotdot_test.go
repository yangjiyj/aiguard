package filerestrict

import "testing"

// “..” 按 path.Clean 语义折叠后再匹配：/tmp/../vault/secret.txt 就是 /vault/secret.txt，
// 2.9.21 起目录型模式 /vault/ 认不出它。
func TestMatchPathFoldsDotDotSegments(t *testing.T) {
	m, err := Compile([]string{"/vault/", "C:/vault/", "*.docx", "/srv/**/payroll.csv"})
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{
		"/tmp/../vault/secret.txt",
		`C:\tmp\..\vault\secret.txt`,
		"/vault/./a/../secret.txt",
		"/srv/x/../hr/payroll.csv",
	} {
		hit, ok := m.MatchPath(p)
		if !ok {
			t.Fatalf("%s must match after folding ..", p)
		}
		if hit.Target != p {
			t.Fatalf("Target must stay the original candidate, got %q", hit.Target)
		}
	}
	for _, p := range []string{"/vault/../tmp/x.txt", "/vault", "/vault/"} {
		if _, ok := m.MatchPath(p); ok {
			t.Fatalf("%s must not match", p)
		}
	}
	if got := normalizePath("/vault/"); got != "/vault/" {
		t.Fatalf("directory patterns keep their trailing slash, got %q", got)
	}
}
