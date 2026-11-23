package agentguard

import (
	"testing"
	"time"

	"github.com/yangjiyj/aiguard/packages/shared-go/protection"
)

// 批次 1 审查留下的例外比对收尾项。

// 相对路径折叠后才变成 ~/ 开头（或等于 ~）的，原始写法里的 ~ 只是当前目录下一个叫 ~ 的
// 目录，不是家目录：落不到确定文件，例外比对用的原始路径置空。
func TestFileExceptionTargetTildeOnlyFromLiteralPrefix2922(t *testing.T) {
	// 路径规范化的表驱动用例在 shared-go filerestrict（TestExceptionTargetTildeIsHomeOnlyAsLiteralPrefix），这里只留端到端。
	evaluate := func(path string) Decision {
		return analyzeMatrix(ToolCallAnalysisInput{ToolName: "Read", ToolType: ToolTypeFile, Mode: ModeStrict,
			Arguments: map[string]any{"file_path": path},
			Policy: policyWith(blockingProtections(protection.GroupAgentTarget), nil,
				[]PolicyException{{ID: "e-home", RuleID: "agent.ssh_private_key", TargetPattern: "~/.ssh/id_rsa", Decision: DecisionAudit, ExpiresAt: time.Now().Add(time.Hour)}})})
	}
	if d := evaluate("~/.ssh/id_rsa"); d.EffectiveDecision != DecisionAudit {
		t.Fatalf("an exception for ~/.ssh/id_rsa must release that file, got %s", d.EffectiveDecision)
	}
	if d := evaluate("x/../~/.ssh/id_rsa"); d.EffectiveDecision != DecisionBlock {
		t.Fatalf("x/../~/.ssh/id_rsa is ./~/.ssh/id_rsa, not the home key: the exception must not apply, got %s", d.EffectiveDecision)
	}
}

// 目录型例外（/ 结尾）也匹配“路径正好等于该目录”：例外 ~/.ssh/ 放开打包整个 ~/.ssh。
func TestDirectoryExceptionMatchesTheDirectoryItself2922(t *testing.T) {
	// 比对的表驱动用例在 shared-go filerestrict（TestExceptionTargetMatchesDirectoryItself），这里只留端到端。
	evaluate := func(exceptions []PolicyException) Decision {
		in := siteBash("tar czf k.tgz ~/.ssh")
		in.Policy = policyWith(blockingProtections(protection.GroupAgentTarget), nil, exceptions)
		return analyzeMatrix(in)
	}
	if d := evaluate(nil); d.EffectiveDecision != DecisionBlock {
		t.Fatalf("archiving ~/.ssh must block when configured, got %s", d.EffectiveDecision)
	}
	dir := []PolicyException{{ID: "e-dir", RuleID: "agent.ssh_private_key", TargetPattern: "~/.ssh/", Decision: DecisionAudit, ExpiresAt: time.Now().Add(time.Hour)}}
	if d := evaluate(dir); d.EffectiveDecision != DecisionAudit || len(d.ProtectionExceptionIDs()) != 1 {
		t.Fatalf("a ~/.ssh/ exception must release archiving ~/.ssh, got %s exceptions=%v", d.EffectiveDecision, d.ProtectionExceptionIDs())
	}
}

// 证据里另记未经 URL 解码的字面写法：审计显示的规范化路径是解码后的，与内核实际读的不一致。
func TestTargetEvidenceKeepsLiteralPath2922(t *testing.T) {
	literalOf := func(d Decision) string {
		for _, e := range d.Evidence {
			if e.RuleID == targetEvidenceRuleBlockedFS && e.LiteralPath != "" {
				return e.LiteralPath
			}
		}
		return ""
	}
	read := analyzeSiteRead(t, "/srv/app/%2e%2e/.env")
	if read.NormalizedTarget != "/srv/.env" || literalOf(read) != "/srv/app/%2e%2e/.env" {
		t.Fatalf("Read: normalized=%q literal=%q", read.NormalizedTarget, literalOf(read))
	}
	shell := analyzeSiteBash(t, "cat /srv/app/a%2fb/../.env")
	if literalOf(shell) != "/srv/app/a%2fb/../.env" {
		t.Fatalf("Bash: literal=%q evidence=%+v", literalOf(shell), shell.Evidence)
	}
	if target := AnalyzeTarget("/srv/app/%2e%2e/.env"); len(target.Evidence) == 0 || target.Evidence[0].LiteralPath != "/srv/app/%2e%2e/.env" {
		t.Fatalf("AnalyzeTarget evidence must carry the literal path: %+v", target.Evidence)
	}
}
