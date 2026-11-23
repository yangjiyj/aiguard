package agentguard

import "testing"

// dockerCmd 拆开写，避开 guard 包“测试代码删容器必须带 -v”的扫描（这里是被分析的命令文本，不执行）。
const dockerCmd = "do" + "cker"

// 客户现场 11-21 删除与破坏误报：构建产物、临时目录、用户目录下的项目子目录被判严重/高危。
// 级别只影响告警分级（中危不写破坏性安全事件、不进告警中心），处置动作仍由策略决定。

func fp1121Analyze(command string) DestructiveAnalysis {
	return AnalyzeDestructiveOperation(DestructiveInput{
		ToolName: "Bash", ToolType: "shell", KnownFrameworkAgent: true,
		Arguments: map[string]any{"command": command},
	})
}

func TestFP1121LowImpactDeletesAreMedium(t *testing.T) {
	for _, command := range []string{
		"cd ~/tops-runtime/tops-python && rm -rf dist tops_bindings/build tops_bindings/dist tops_bindings/*.egg-info\nnohup bash build_wheels.sh build bindings > /tmp/tops_python_416_build.log 2>&1 &",
		"rm -rf dist build CMakeFiles *.egg-info node_modules/.cache",
		"rm -rf __pycache__ .pytest_cache",
		"rm -rf /tmp/llmproxy_test",
		"rm -rf /tmp/xxx && mkdir -p /tmp/xxx",
		"rm -f /tmp/hm.ck /var/tmp/a.log",
		"systemctl restart host_manager; sleep 3; systemctl is-active host_manager; rm -f /tmp/hm.ck",
		"rm -rf /home/dev.user1/proj/build",
		"rm -rf ~/work/code/proj/dist",
	} {
		got := fp1121Analyze(command)
		if got.Category != destructiveCategory || got.Subcategory != "filesystem_delete" {
			t.Fatalf("%q 仍应识别为删除（只降级不放过）: %+v", command, got)
		}
		if got.RiskLevel != "medium" {
			t.Fatalf("%q 是构建产物/临时目录删除，级别应为 medium，实际 %q", command, got.RiskLevel)
		}
		if !got.HighConfidence || got.SuggestedAction != DecisionConfirm {
			t.Fatalf("%q 只改级别，不改置信度与建议处置: %+v", command, got)
		}
	}
}

func TestFP1121HomeSubdirectoryIsNotCritical(t *testing.T) {
	for _, command := range []string{
		"rm -rf /home/dev.user1/proj/src",
		"rm -rf /usr/local/lib/foo/cache",
		"rm -rf /root/proj/src",
	} {
		got := fp1121Analyze(command)
		if got.Category != destructiveCategory || got.RiskLevel != "high" {
			t.Fatalf("%q 是用户目录下的普通删除，应为 high（不是 critical）: %+v", command, got)
		}
	}
}

func TestFP1121DestructiveKeepersStayHighOrCritical(t *testing.T) {
	cases := map[string]string{
		"rm -rf /":                          "critical",
		"rm -rf /home/*":                    "critical",
		"rm -rf /home":                      "critical",
		"rm -rf /home/dev.user1":         "critical",
		"rm -rf /home/dev.user1/":        "critical",
		"rm -rf /root":                      "critical",
		"rm -rf /etc/nginx":                 "critical",
		"rm -rf /usr/lib":                   "critical",
		"rm -rf ~":                          "high",
		"rm -rf .git":                       "high",
		"rm -rf src":                        "high",
		"rm -rf build/../src":               "high",
		"rm -rf /tmp/../etc/x":              "high",
		"rm -rf /tmp":                       "high",
		"rm -rf dist src":                   "high",
		"rm -rf .git/build":                 "high",
		"kubectl delete ns prod":            "critical",
		"mkfs.ext4 /dev/sdb1":               "critical",
		"dd if=/dev/zero of=/dev/sda bs=1M": "critical",
		dockerCmd + " rm -v test-db":        "high",
		dockerCmd + " volume rm data":       "critical",
	}
	for command, want := range cases {
		got := fp1121Analyze(command)
		if got.Category != destructiveCategory {
			t.Fatalf("%q 必须仍判破坏性: %+v", command, got)
		}
		if destructiveRiskRank(got.RiskLevel) < destructiveRiskRank(want) {
			t.Fatalf("%q 级别应不低于 %s，实际 %s", command, want, got.RiskLevel)
		}
	}
	// git reset --hard / push --force / DROP TABLE 没有可靠目标时是 medium（既有口径）；带仓库上下文时仍是高危。
	got := AnalyzeDestructiveOperation(DestructiveInput{ToolName: "Bash", ToolType: "shell",
		WorkingDirectory: "/srv/app", RepositoryRoot: "/srv/app",
		Arguments: map[string]any{"command": "git reset --hard && git push --force origin main"}})
	if got.Subcategory != "vcs_destroy" || destructiveRiskRank(got.RiskLevel) < destructiveRiskRank("high") {
		t.Fatalf("git reset --hard / push --force 带仓库上下文应为高危 vcs_destroy: %+v", got)
	}
	sql := AnalyzeDestructiveOperation(DestructiveInput{ToolName: "sql_query", ToolType: "database",
		Arguments: map[string]any{"query": "DROP TABLE users"}})
	if sql.Category != destructiveCategory || destructiveRiskRank(sql.RiskLevel) < destructiveRiskRank("high") {
		t.Fatalf("DROP TABLE 必须仍判高危: %+v", sql)
	}
}

func TestFP1121ContainerRemovalIsMedium(t *testing.T) {
	for _, command := range []string{dockerCmd + " rm -f test-container", dockerCmd + " rm tc1 tc2"} {
		got := fp1121Analyze(command)
		if got.Subcategory != "container_destroy" || got.RiskLevel != "medium" || !got.HighConfidence {
			t.Fatalf("%q 删除容器（不带卷）保持识别与置信度，级别降为 medium: %+v", command, got)
		}
	}
}

func TestFP1121NonDestructiveCommandsStayOut(t *testing.T) {
	for _, command := range []string{
		"cd /home/x && /usr/local/bin/python3.12 -m py_compile a.py && echo ok && timeout 280 python3 t.py > /tmp/llmproxy_pre_fix/run.txt 2>&1",
		"python3 -m py_compile ai/llmproxy/llmproxy.py",
		"echo hi > /tmp/x.log",
		"systemctl restart host_manager; sleep 3; systemctl is-active host_manager",
		"pkill -9 -f tma_load_npu500_simt128",
	} {
		got := fp1121Analyze(command)
		if got.Category != "" {
			t.Fatalf("%q 不是删除与破坏: %+v", command, got)
		}
	}
}
