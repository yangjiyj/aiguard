package agentguard

import (
	"sort"
	"strings"
	"testing"
)

// 代码质量复审：超限兜底原来按原始文字直接切词，不去引号，比 2.9.21 宽（~/.ss''h/id_rsa 切成两段认
// 不出）；前瞻扫描的递归又把同一段字节记了多遍，329 字节的命令就会转入兜底。现在兜底先用关掉前瞻
// 扫描的分词器（去引号、转义、$'…' 照常）逐词按读判定，再并上原始切词；递归只在最外层记一次账。

func TestShellFallbackJudgesUnquotedWords2922(t *testing.T) {
	short := "cat ~/.ss''h/id_rsa; echo \"" + strings.Repeat("$(\"", 100) + ")\""
	if len(short) != 329 {
		t.Fatalf("length %d", len(short))
	}
	if _, _, work := analyzeShellCommandTargetsWork(short); work.fellBack {
		t.Errorf("a 329-byte command must not need the fallback (work %d)", work.spent)
	}
	for _, command := range []string{
		short,
		"cat ~/.ss''h/id_rsa; echo " + strings.Repeat("${", 20000) + "}",
		"cat ~/.ss\"\"h/id_rs\\a; echo " + strings.Repeat("${", 20000) + "}",
		"cat $'\\x7e/.ssh/id_rsa'; echo " + strings.Repeat("${", 20000) + "}",
	} {
		decision, found := analyzeShellCommandTargets(command)
		if !found || decision.Reason != targetReasonSSHPrivateKey {
			t.Errorf("%.40q…: found=%v reason=%s", command, found, decision.Reason)
		}
	}
}

func withShellWorkLimit(t *testing.T, limit int) {
	t.Helper()
	saved := shellWorkLimitOverride
	shellWorkLimitOverride = limit
	t.Cleanup(func() { shellWorkLimitOverride = saved })
}

func hitReasons(decision Decision) []string {
	seen := map[string]bool{decision.Reason: true}
	for _, hit := range decision.ProtectionHits {
		seen[hit.Reason] = true
	}
	var out []string
	for reason := range seen {
		if reason != "" {
			out = append(out, reason)
		}
	}
	sort.Strings(out)
	return out
}

// 本包与 handler 包测试文件里所有在精确模式下命中的字符串字面量（各条拦截用例、语料），把上限设成 0
// 强制走兜底，精确模式命中的每个原因码都还要命中。
func TestShellFallbackKeepsPreciseReasons2922(t *testing.T) {
	type precise struct {
		command string
		reasons []string
	}
	var hits []precise
	for _, command := range testStringLiterals(t, ".", "../handler") {
		if decision, found := analyzeShellCommandTargets(command); found {
			hits = append(hits, precise{command, hitReasons(decision)})
		}
	}
	if len(hits) < 500 {
		t.Fatalf("only %d literals hit in precise mode", len(hits))
	}
	withShellWorkLimit(t, 0)
	for _, item := range hits {
		decision, found, work := analyzeShellCommandTargetsWork(item.command)
		if !work.fellBack {
			t.Fatalf("limit 0 must force the fallback: %.60q", item.command)
		}
		got := map[string]bool{}
		for _, reason := range hitReasons(decision) {
			got[reason] = true
		}
		for _, reason := range item.reasons {
			if !found || !got[reason] {
				t.Errorf("%.80q: precise %v, fallback %v", item.command, item.reasons, hitReasons(decision))
				break
			}
		}
	}
}

// 第三轮复审：兜底对 heredoc 正文、含空白/引号/$(/反引号的词，也要用关前瞻的分词器当命令行重新切
// （嵌套不超过 maxShellNesting 层）再逐词按读判。这些写法基线都拦；前面垫一段 20000 个 "${" 强制
// 走兜底后也要拦。
var fallbackNestedCommandLines2922 = []string{
	"bash <<E\ncat ~/.ss''h/id_rsa\nE",
	"cat <<E | sh\ncat ~/.ss''h/id_rsa\nE",
	"sh -c \"cat ~/.ss''h/id_rsa\"",
	"bash -c 'cat ~/.ss\"\"h/id_rsa'",
	"ssh h \"cat ~/.ss''h/id_rsa\"",
	"kubectl exec p -- sh -c \"cat ~/.ss''h/id_rsa\"",
	"sh -c \"sh -c 'cat ~/.ss\\\"\\\"h/id_rsa'\"",
	"echo \"$(cat ~/.ss''h/id_rsa)\"",
	"echo \"`cat ~/.ss''h/id_rsa`\"",
}

func TestShellFallbackReSplitsNestedCommandLines2922(t *testing.T) {
	pad := "echo " + strings.Repeat("${", 20000) + "}\n"
	for _, command := range fallbackNestedCommandLines2922 {
		if decision, found := analyzeShellCommandTargets(command); !found || decision.Reason != targetReasonSSHPrivateKey {
			t.Errorf("%q: precise found=%v reason=%s", command, found, decision.Reason)
		}
		decision, found, work := analyzeShellCommandTargetsWork(pad + command)
		if !work.fellBack {
			t.Fatalf("%q: the padding must force the fallback", command)
		}
		if !found || !strings.Contains(strings.Join(hitReasons(decision), " "), targetReasonSSHPrivateKey) {
			t.Errorf("%q under the fallback: found=%v reasons=%v", command, found, hitReasons(decision))
		}
	}
}
