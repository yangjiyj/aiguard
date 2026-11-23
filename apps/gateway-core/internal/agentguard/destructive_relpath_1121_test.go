package agentguard

import "testing"

// 客户A 11-21 仍高危的 5 条：删工作目录里的相对路径，用户拍板降中危。
func TestFP1121WorkdirRelativeDeletesAreMedium(t *testing.T) {
	for _, command := range []string{
		"rm -rf lp3_cycle_mpirun_logs",
		"rm -f inject_err; rm -f cnt",
		"rm -f .commit_msg.txt",
		"rm -f efml_lib/usr/include/efml",
		"rm -rf opt/tops _deps/topsgraph-src",
		"rm -rf ./out/run1",
		"rm -rf src/generated",
	} {
		got := fp1121Analyze(command)
		if got.Category != destructiveCategory || got.RiskLevel != "medium" {
			t.Fatalf("%q 是工作目录相对路径删除，应为 medium: %+v", command, got)
		}
	}
}

func TestFP1121WorkdirRelativeDeletesKeepHigh(t *testing.T) {
	for _, command := range []string{
		"rm -rf src", "rm -rf ./lib", "rm -rf tests/", "rm -rf .", "rm -rf ./", "rm -rf *",
		"rm -rf ./*", "rm -rf logs/*", "rm -rf ../other", "rm -rf .git", "rm -rf deploy migrations",
	} {
		got := fp1121Analyze(command)
		if got.Category != destructiveCategory || destructiveRiskRank(got.RiskLevel) < destructiveRiskRank("high") {
			t.Fatalf("%q 应不低于 high: %+v", command, got)
		}
	}
}

// 同一条命令里赋成临时目录的变量：rm -rf $T 按 /tmp 删除降中危；重复赋值、读入、越界仍高危。
func TestFP1121TmpVariableDeletes(t *testing.T) {
	medium := []string{
		"T=$(ls -d /tmp/tmp.UiMgqdoXRm); export T PATH=$T/bin:$PATH; cd $T; rm -f inject_err; rm -rf lp3_cycle_mpirun_logs\nrm -f cnt; rm -rf $T",
		"T=/tmp/work1; rm -rf $T",
		"D=$(mktemp -d); cp a.txt \"$D\"/; rm -rf \"$D\"",
		"T=/tmp/work1; rm -rf ${T}/out",
	}
	for _, command := range medium {
		got := fp1121Analyze(command)
		if got.Category != destructiveCategory || got.RiskLevel != "medium" {
			t.Fatalf("%q 应为 medium: %+v", command, got)
		}
	}
	// 来源不可信的变量不展开：保持原有"目标不完整"口径（与未改前一致）。
	for _, command := range []string{
		"T=/tmp/work1; T=/etc; rm -rf $T",
		"read T; rm -rf $T",
		"rm -rf $HOME/proj",
		"T=/tmp/work1; rm -rf $T $U",
	} {
		got := fp1121Analyze(command)
		if got.Category != destructiveCategory || got.Reason != "destructive_target_incomplete" {
			t.Fatalf("%q 不应展开变量: %+v", command, got)
		}
	}
	// 展开后越出临时目录的仍高危。
	for _, command := range []string{
		"T=$(mktemp -d); rm -rf $T/../../etc",
		"T=/tmp/work1; rm -rf $T/*/../..",
	} {
		got := fp1121Analyze(command)
		if got.Category != destructiveCategory || destructiveRiskRank(got.RiskLevel) < destructiveRiskRank("high") {
			t.Fatalf("%q 应不低于 high: %+v", command, got)
		}
	}
}
