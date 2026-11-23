package agentguard

import (
	"context"
	"testing"
	"time"

	"github.com/yangjiyj/aiguard/packages/shared-go/protection"
)

// 受限文件例外只放开它点名的那个文件：同一次调用里还有别的受限文件，或被例外的文件名
// 只出现在注释、参数字符串里时，照样按受限文件动作处理。
func restrictedDocxPolicy(exceptionPattern string) *EffectivePolicy {
	return &EffectivePolicy{Mode: ModeStrict,
		RestrictedFiles: &RestrictedFilePolicy{Patterns: []string{"*.docx"}, Action: "block"},
		Exceptions:      []PolicyException{{ID: "e-plan", RuleID: restrictedFileReason, TargetPattern: exceptionPattern, Decision: DecisionAudit, ExpiresAt: time.Now().Add(time.Hour)}},
	}
}

func TestRestrictedFileExceptionReleasesOnlyTheNamedFile(t *testing.T) {
	patch := "*** Begin Patch\n*** Update File: docs/plan.docx\n@@\n*** Update File: docs/budget.docx\n@@\n*** End Patch"
	for _, tc := range []struct {
		name     string
		toolName string
		toolType string
		args     map[string]any
	}{
		{"two files in one command", "Bash", "system", map[string]any{"command": "cat /x/plan.docx /x/budget.docx"}},
		{"excepted name only in a shell comment", "Bash", "system", map[string]any{"command": "cat /x/budget.docx # plan.docx"}},
		{"excepted name inside an argument string", "upload", "", map[string]any{"note": "/x/budget.docx plan.docx"}},
		{"apply_patch touching two files", "apply_patch", ToolTypeFile, map[string]any{"patch": patch}},
		{"two files whose redacted forms collide", "Bash", "system", map[string]any{"command": "cat /x/plan.docx /x/pxyz.docx"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := AnalyzeToolCall(context.Background(), ToolCallAnalysisInput{
				ToolName: tc.toolName, ToolType: tc.toolType, Arguments: tc.args, Mode: ModeStrict,
				Policy: restrictedDocxPolicy("plan.docx"),
			})
			if got.EffectiveDecision != DecisionBlock || got.ProtectionItem != "agent.restricted_file" {
				t.Fatalf("an exception for plan.docx must not release other restricted files: %+v", got)
			}
		})
	}
	single := AnalyzeToolCall(context.Background(), ToolCallAnalysisInput{
		ToolName: "Bash", ToolType: "system", Arguments: map[string]any{"command": "cat /x/plan.docx"}, Mode: ModeStrict,
		Policy: restrictedDocxPolicy("plan.docx"),
	})
	if single.EffectiveDecision != DecisionAudit {
		t.Fatalf("the named file alone must be released: %+v", single)
	}
}

func restrictedPolicyWith(patterns []string, exceptionPattern string) *EffectivePolicy {
	return &EffectivePolicy{Mode: ModeStrict,
		RestrictedFiles: &RestrictedFilePolicy{Patterns: patterns, Action: "block"},
		Exceptions:      []PolicyException{{ID: "e", RuleID: restrictedFileReason, TargetPattern: exceptionPattern, Decision: DecisionAudit, ExpiresAt: time.Now().Add(time.Hour)}},
	}
}

func readFile(path string, policy *EffectivePolicy) Decision {
	return AnalyzeToolCall(context.Background(), ToolCallAnalysisInput{ToolName: "Read", ToolType: ToolTypeFile,
		Arguments: map[string]any{"file_path": path}, Mode: ModeStrict, Policy: policy})
}

// 文件类防护项的例外按路径层级匹配：不含 / 只比文件名，含 / 比完整路径或以 / 为界的
// 后缀，以 / 结尾比目录前缀；路径先折叠 ..。
func TestFileProtectionExceptionsMatchPathLevels(t *testing.T) {
	docx := []string{"*.docx"}
	for _, tc := range []struct {
		name, pattern, path string
		released            bool
	}{
		{"traversal through the excepted name", "plan.docx", "/tmp/plan.docx/../../x/budget.docx", false},
		{"directory named like the excepted file", "plan.docx", "/x/plan.docx.d/budget.docx", false},
		{"longer file name", "plan.docx", "/x/myplan.docx", false},
		{"relative path leaving the root", "plan.docx", "../x/plan.docx", false},
		{"file name", "plan.docx", "/data/x/plan.docx", true},
		{"file name after folding ..", "plan.docx", "/data/y/../x/plan.docx", true},
		{"suffix with /", "x/plan.docx", "/data/x/plan.docx", true},
		{"suffix must stop at a segment", "x/plan.docx", "/data/xx/plan.docx", false},
		{"full path", "/data/x/plan.docx", "/data/x/plan.docx", true},
		{"directory prefix", "/data/x/", "/data/x/plan.docx", true},
		{"directory prefix stops at a segment", "/data/x/", "/data/xy/plan.docx", false},
		{"relative directory prefix", "x/", "/data/x/plan.docx", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := readFile(tc.path, restrictedPolicyWith(docx, tc.pattern))
			if released := got.EffectiveDecision == DecisionAudit; released != tc.released || got.ProtectionItem != "agent.restricted_file" {
				t.Fatalf("pattern %q path %q: released=%t want %t: %+v", tc.pattern, tc.path, released, tc.released, got)
			}
		})
	}
	bash := AnalyzeToolCall(context.Background(), ToolCallAnalysisInput{ToolName: "Bash", ToolType: "system", Mode: ModeStrict,
		Arguments: map[string]any{"command": "cat /tmp/plan.docx/../../x/budget.docx"}, Policy: restrictedPolicyWith(docx, "plan.docx")})
	if bash.EffectiveDecision != DecisionBlock {
		t.Fatalf("shell traversal through the excepted name must stay blocked: %+v", bash)
	}
}

// 目录型受限模式在 .. 写法下照样认出（2.9.21 起就漏的问题）。
func TestRestrictedDirectoryPatternFoldsDotDot(t *testing.T) {
	got := readFile("/tmp/../vault/secret.txt", restrictedPolicyWith([]string{"/vault/"}, "unrelated.txt"))
	if got.EffectiveDecision != DecisionBlock || got.ProtectionItem != "agent.restricted_file" {
		t.Fatalf("/tmp/../vault/secret.txt is /vault/secret.txt: %+v", got)
	}
}

// SSH 私钥例外写 id_rsa 时只放开名为 id_rsa 的私钥；~/.ssh/id_rsa_backup.pem 这类名字里
// 含 id_rsa 的其他私钥照拦（id_rsa_backup 本身不在私钥清单里，不构成命中）。
func TestSSHKeyExceptionMatchesTheFileNameExactly(t *testing.T) {
	policy := func() *EffectivePolicy {
		return policyWith(protection.Settings{"agent.ssh_private_key": {Action: protection.ActionBlock}}, nil,
			[]PolicyException{{ID: "e", RuleID: "agent.ssh_private_key", TargetPattern: "id_rsa", Decision: DecisionAudit, ExpiresAt: time.Now().Add(time.Hour)}})
	}
	bash := func(command string) Decision {
		return AnalyzeToolCall(context.Background(), ToolCallAnalysisInput{ToolName: "Bash", ToolType: "system", Mode: ModeStrict,
			Arguments: map[string]any{"command": command}, Policy: policy()})
	}
	for _, d := range []Decision{bash("cat ~/.ssh/id_rsa_backup.pem"), readFile("/home/u/.ssh/id_rsa_backup.pem", policy())} {
		if d.EffectiveDecision != DecisionBlock || d.ProtectionItem != "agent.ssh_private_key" {
			t.Fatalf("an exception for id_rsa must not release id_rsa_backup.pem: %+v", d)
		}
	}
	for _, d := range []Decision{bash("cat ~/.ssh/id_rsa"), readFile("/home/u/.ssh/id_rsa", policy())} {
		if d.EffectiveDecision != DecisionAudit || d.ProtectionAction != string(protection.ActionRecord) {
			t.Fatalf("an exception for id_rsa releases id_rsa: %+v", d)
		}
	}
	if d := readFile("/home/u/.ssh/id_rsa_backup", policy()); len(d.ProtectionHits) != 0 {
		t.Fatalf("id_rsa_backup is not on the private-key list: %+v", d.ProtectionHits)
	}
}

// URL 类目标（元数据、内网、密钥外发）保持子串口径。
func TestURLProtectionExceptionsKeepSubstringMatching(t *testing.T) {
	d := AnalyzeToolCall(context.Background(), ToolCallAnalysisInput{ToolName: "fetch", ToolType: "network", Mode: ModeStrict,
		Arguments: map[string]any{"url": "http://169.254.169.254/latest/meta-data"},
		Policy: policyWith(protection.Settings{"agent.cloud_metadata": {Action: protection.ActionBlock}}, nil,
			[]PolicyException{{ID: "e", RuleID: "agent.cloud_metadata", TargetPattern: "169.254.169.254", Decision: DecisionAudit, ExpiresAt: time.Now().Add(time.Hour)}})})
	if d.EffectiveDecision != DecisionAudit {
		t.Fatalf("URL targets keep substring matching: %+v", d)
	}
}

// 例外比对不做 URL 解码：shell 和内核按字面读路径，/srv/deploy/a%2fb%2fc/../../../home/u/.ssh/id_rsa
// 实际读的是 /home/u/.ssh/id_rsa。原始路径含 % 的落不到确定文件，只有不限目标的例外能放开。
func TestFileProtectionExceptionsDoNotURLDecodePaths(t *testing.T) {
	const encoded = "a%2fb%2fc/../../../"
	future := time.Now().Add(time.Hour)
	for _, tc := range []struct {
		name     string
		settings protection.Settings
		restrict []string
		ruleID   string
		dir      string
		file     string
	}{
		{"ssh private key", protection.Settings{"agent.ssh_private_key": {Action: protection.ActionBlock}}, nil, "agent.ssh_private_key", "/srv/deploy/", "home/u/.ssh/id_rsa"},
		{"cloud credential", protection.Settings{"agent.cloud_credential": {Action: protection.ActionBlock}}, nil, "agent.cloud_credential", "/srv/ci/", "home/u/.aws/credentials"},
		{"restricted file", nil, []string{"*.docx"}, restrictedFileReason, "/x/allowed/", "x/budget.docx"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			policy := func() *EffectivePolicy {
				p := policyWith(tc.settings, nil, []PolicyException{{ID: "e", RuleID: tc.ruleID, TargetPattern: tc.dir, Decision: DecisionAudit, ExpiresAt: future}})
				if tc.restrict != nil {
					p.RestrictedFiles = &RestrictedFilePolicy{Patterns: tc.restrict, Action: "block"}
				}
				return p
			}
			bypass := tc.dir + encoded + tc.file
			for _, d := range []Decision{
				readFile(bypass, policy()),
				AnalyzeToolCall(context.Background(), ToolCallAnalysisInput{ToolName: "Bash", ToolType: "system", Mode: ModeStrict,
					Arguments: map[string]any{"command": "cat " + bypass}, Policy: policy()}),
			} {
				if d.EffectiveDecision != DecisionBlock {
					t.Fatalf("%s: a directory exception must not release an encoded traversal: %+v", bypass, d)
				}
			}
			if d := readFile(tc.dir+"sub/"+tc.file, policy()); d.EffectiveDecision != DecisionAudit {
				t.Fatalf("a file really under %s is released: %+v", tc.dir, d)
			}
		})
	}
	if d := readFile("/x/budget.docx%2f..%2fplan.docx", restrictedPolicyWith([]string{"*.docx"}, "plan.docx")); d.EffectiveDecision != DecisionBlock {
		t.Fatalf("an exception for plan.docx must not release the literal name budget.docx%%2f..%%2fplan.docx: %+v", d)
	}
}

// 文件类防护项例外区分大小写（Linux 上 Plan.docx 与 plan.docx 是两个文件）；URL 类不变。
func TestFileProtectionExceptionsAreCaseSensitive(t *testing.T) {
	docx := []string{"*.docx"}
	if d := readFile("/x/Plan.docx", restrictedPolicyWith(docx, "plan.docx")); d.EffectiveDecision != DecisionBlock {
		t.Fatalf("plan.docx must not release Plan.docx: %+v", d)
	}
	if d := readFile("/x/Plan.docx", restrictedPolicyWith(docx, "Plan.docx")); d.EffectiveDecision != DecisionAudit {
		t.Fatalf("Plan.docx releases Plan.docx: %+v", d)
	}
	if d := readFile("/data/x/plan.docx", restrictedPolicyWith(docx, "/Data/x/")); d.EffectiveDecision != DecisionBlock {
		t.Fatalf("/Data/x/ must not release /data/x/plan.docx: %+v", d)
	}
	url := AnalyzeToolCall(context.Background(), ToolCallAnalysisInput{ToolName: "fetch", ToolType: "network", Mode: ModeStrict,
		Arguments: map[string]any{"url": "http://Metadata.Google.Internal/computeMetadata/v1/"},
		Policy: policyWith(protection.Settings{"agent.cloud_metadata": {Action: protection.ActionBlock}}, nil,
			[]PolicyException{{ID: "e", RuleID: "agent.cloud_metadata", TargetPattern: "METADATA.google", Decision: DecisionAudit, ExpiresAt: time.Now().Add(time.Hour)}})})
	if url.EffectiveDecision != DecisionAudit {
		t.Fatalf("URL targets keep case-insensitive substring matching: %+v", url)
	}
}
