package agentguard

import "testing"

func analyzeShell(command string) DestructiveAnalysis {
	return AnalyzeDestructiveOperation(DestructiveInput{ToolName: "shell", Arguments: map[string]any{"command": command}})
}

func TestRedirectsThatDoNotOverwriteUserFilesAreNotDestructive(t *testing.T) {
	for _, command := range []string{
		"make build >> build.log",
		"go test ./... 2>/dev/null",
		"npm run lint &>/dev/null",
		"ls -la > /tmp/listing.txt",
		"ls missing 2>&1",
		"echo done >&2",
		"cat a.txt > /dev/stdout",
		"pytest -q > /var/tmp/report.txt 2>&1",
	} {
		if got := analyzeShell(command); got.Category != "" {
			t.Fatalf("%q must not be destructive: %+v", command, got)
		}
	}
}

func TestRedirectOverwritingAProjectFileIsMediumRisk(t *testing.T) {
	got := analyzeShell("cat template.txt > config.yaml")
	if got.Subcategory != "filesystem_overwrite" || got.RiskLevel != "medium" {
		t.Fatalf("overwrite of a regular file: %+v", got)
	}
	if got.TargetSummary != "filesystem_overwrite:1-targets" {
		t.Fatalf("target count: %+v", got)
	}
}

func TestRedirectOverwritingSystemPathStaysCritical(t *testing.T) {
	got := analyzeShell("printf x > /etc/app.conf")
	if got.Subcategory != "filesystem_overwrite" || got.RiskLevel != "critical" {
		t.Fatalf("system path overwrite must stay critical: %+v", got)
	}
}

func TestRedirectTargetRisk(t *testing.T) {
	type want struct {
		risk string
		keep bool
	}
	cases := []struct {
		target     string
		appendMode bool
		want       want
	}{
		{"/dev/null", false, want{"", false}}, {"/dev/stderr", false, want{"", false}},
		{"/dev/fd/3", false, want{"", false}}, {"/dev/tty", true, want{"", false}},
		{"NUL", false, want{"", false}}, {"$null", false, want{"", false}},
		{"/tmp/x.log", false, want{"", false}}, {"/var/tmp/y", true, want{"", false}},
		{"\"/tmp/z\"", false, want{"", false}}, {"/private/tmp/x", false, want{"", false}},
		{"/tmp/../etc/passwd", false, want{"critical", true}},
		{"/etc/hosts", false, want{"critical", true}}, {"/private/etc/hosts", false, want{"critical", true}}, {"/etc/sudoers", true, want{"critical", true}},
		{"/usr/local/bin/x", false, want{"critical", true}}, {"/boot/grub.cfg", true, want{"critical", true}},
		{"/var/log/audit/audit.log", true, want{"critical", true}},
		{"~/.ssh/authorized_keys", true, want{"high", true}},
		{"/home/u/.ssh/config", false, want{"high", true}},
		{"~/.bashrc", false, want{"high", true}}, {"~/.zshrc", true, want{"high", true}},
		{"/root/.profile", true, want{"high", true}}, {"/var/spool/cron/root", true, want{"high", true}},
		{"config.yaml", false, want{"medium", true}}, {"config.yaml", true, want{"", false}},
		{"build.log", true, want{"", false}}, {"../x/out.txt", false, want{"medium", true}},
		{"", false, want{"medium", true}},
	}
	for _, c := range cases {
		risk, keep := redirectTargetRisk(c.target, c.appendMode)
		if risk != c.want.risk || keep != c.want.keep {
			t.Fatalf("redirectTargetRisk(%q, append=%v)=(%q,%v) want (%q,%v)", c.target, c.appendMode, risk, keep, c.want.risk, c.want.keep)
		}
	}
}

func TestRedirectRiskBySensitivity(t *testing.T) {
	cases := []struct{ command, risk string }{
		{"echo 'u ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers", "critical"},
		{"echo key >> ~/.ssh/authorized_keys", "high"},
		{"echo x > ~/.bashrc", "high"},
		{"echo x > /tmp/../etc/passwd", "critical"},
		{"echo x >> /root/.profile", "high"},
		{"echo x >> build.log", ""},
		{"echo x > config.yaml", "medium"},
		{"echo x &>> /dev/null", ""},
		{"echo x &>> build.log", ""},
		{"echo x &> config.yaml", "medium"},
	}
	for _, c := range cases {
		for name, input := range map[string]DestructiveInput{
			"shell":      {ToolName: "shell", Arguments: map[string]any{"command": c.command}},
			"production": {ToolName: "Bash", ToolType: "shell", Arguments: map[string]any{"command": c.command}},
		} {
			got := AnalyzeDestructiveOperation(input)
			if got.RiskLevel != c.risk || (c.risk == "" && got.Category != "") {
				t.Fatalf("%s %q: risk=%q category=%q want %q", name, c.command, got.RiskLevel, got.Category, c.risk)
			}
		}
	}
}

func TestProductionShapedBashRedirects(t *testing.T) {
	run := func(command string) DestructiveAnalysis {
		return AnalyzeDestructiveOperation(DestructiveInput{ToolName: "Bash", ToolType: "shell", Arguments: map[string]any{"command": command}})
	}
	if got := run("make build >> build.log"); got.Category != "" {
		t.Fatalf("append to log must not report: %+v", got)
	}
	if got := run("cat a > config.yaml"); got.RiskLevel != "medium" || got.Subcategory != "filesystem_overwrite" {
		t.Fatalf("overwrite: %+v", got)
	}
	if got := run("echo x >> /etc/sudoers"); got.RiskLevel != "critical" {
		t.Fatalf("sudoers append: %+v", got)
	}
}

func TestSameSubcategoryMergeKeepsHigherRisk(t *testing.T) {
	for _, command := range []string{
		"cat a > config.yaml; truncate -s 0 b.txt",
		"truncate -s 0 b.txt; cat a > config.yaml",
		"cat a > config.yaml && truncate -s 0 b.txt",
	} {
		got := analyzeShell(command)
		if got.Subcategory != "filesystem_overwrite" || got.RiskLevel != "high" || !got.HighConfidence || got.SuggestedAction != DecisionConfirm {
			t.Fatalf("%q must stay high: %+v", command, got)
		}
	}
	for _, command := range []string{
		"echo x > d.txt; Clear-Content b.txt",
		"Clear-Content b.txt; echo x > d.txt",
	} {
		got := analyzeLexerShell(command)
		if got.Subcategory != "filesystem_overwrite" || got.RiskLevel != "high" {
			t.Fatalf("lexer %q must stay high: %+v", command, got)
		}
	}
	// Codex 自由格式：两条 exec_command 走多段 executable 合并。
	got := AnalyzeDestructiveOperation(DestructiveInput{ToolName: "shell", Arguments: map[string]any{
		"input": `await tools.exec_command({cmd: "cat a > config.yaml"}); await tools.exec_command({cmd: "truncate -s 0 b.txt"})`}})
	if got.RiskLevel != "high" {
		t.Fatalf("multi-executable merge must stay high: %+v", got)
	}
}

func TestLexerAppendTargetsAreKept(t *testing.T) {
	if got := analyzeLexerShell("echo x >> /etc/sudoers"); got.RiskLevel != "critical" {
		t.Fatalf("lexer append to sudoers: %+v", got)
	}
	if got := analyzeLexerShell("echo x >> ~/.ssh/authorized_keys"); got.RiskLevel != "high" {
		t.Fatalf("lexer append to authorized_keys: %+v", got)
	}
}

func analyzeLexerShell(command string) DestructiveAnalysis {
	// cmd 工具不走 POSIX 解析器，命令会进入 destructive_lexer.go 的词法兜底。
	return AnalyzeDestructiveOperation(DestructiveInput{ToolName: "cmd", Arguments: map[string]any{"command": command}})
}

func TestLexerFallbackRedirects(t *testing.T) {
	for _, command := range []string{
		"make build >> build.log",
		"ls missing 2>&1",
		"echo done >&2",
		"go test ./... 2>/dev/null",
		"pytest -q > /var/tmp/report.txt 2>&1",
	} {
		if got := analyzeLexerShell(command); got.Category != "" {
			t.Fatalf("%q must not be destructive in lexer fallback: %+v", command, got)
		}
	}
	got := analyzeLexerShell("cat template.txt > config.yaml")
	if got.Subcategory != "filesystem_overwrite" || got.RiskLevel != "medium" {
		t.Fatalf("lexer overwrite of a regular file: %+v", got)
	}
}

func TestLexerSegmentsDropDescriptorTokens(t *testing.T) {
	segments, _ := parseShellCommand("cmd arg 2>err.log 2>&1 >> out.log")
	if len(segments) != 1 {
		t.Fatalf("segments: %+v", segments)
	}
	segment := segments[0]
	if len(segment.Words) != 2 || segment.Words[0] != "cmd" || segment.Words[1] != "arg" {
		t.Fatalf("descriptor digits leaked into words: %+v", segment.Words)
	}
	if len(segment.Redirects) != 1 || segment.Redirects[0] != "err.log" || !segment.Redirect ||
		len(segment.AppendRedirects) != 1 || segment.AppendRedirects[0] != "out.log" {
		t.Fatalf("only the 2> target should remain: %+v", segment)
	}
}

func productionShell(command string) DestructiveAnalysis {
	return AnalyzeDestructiveOperation(DestructiveInput{ToolName: "Bash", ToolType: "shell", Arguments: map[string]any{"command": command}})
}

func TestDynamicAppendTargetsOnlyAlertWhenSensitive(t *testing.T) {
	for _, command := range []string{`echo x >> "$LOG"`, `echo k=v >> "$GITHUB_OUTPUT"`, `echo x &>> "${OUT_DIR}/run.log"`} {
		for name, got := range map[string]DestructiveAnalysis{"shell": analyzeShell(command), "production": productionShell(command)} {
			if got.Category != "" || got.ParseRejected {
				t.Fatalf("%s %q: dynamic append to a log must be ignored: %+v", name, command, got)
			}
		}
	}
	// 敏感片段：维持原兜底（ParseRejected），不是 high 发现。
	for _, command := range []string{`cat k >> "$HOME/.ssh/authorized_keys"`, `echo x >> "$HOME/.bashrc"`, `echo x >> "$ROOT/etc/sudoers"`} {
		got := productionShell(command)
		if !got.ParseRejected {
			t.Fatalf("%q: sensitive dynamic append must keep the fail-safe: %+v", command, got)
		}
	}
	// 动态覆盖写维持原兜底。
	if got := productionShell(`echo x > "$OUT"`); !got.ParseRejected {
		t.Fatalf("dynamic overwrite keeps the fail-safe: %+v", got)
	}
}

func TestLexerDynamicAppendTargets(t *testing.T) {
	for _, command := range []string{"echo x >> $LOG", "echo k=v >> ${GITHUB_OUTPUT}"} {
		if got := analyzeLexerShell(command); got.Category != "" {
			t.Fatalf("lexer %q must be ignored: %+v", command, got)
		}
	}
	if got := analyzeLexerShell("echo k >> $HOME/.ssh/authorized_keys"); got.RiskLevel != "high" {
		t.Fatalf("lexer sensitive dynamic append: %+v", got)
	}
}

func TestMergeTakesHighestRiskAcrossSubcategories(t *testing.T) {
	solo := analyzeShell("rm -rf ./x")
	if solo.Category == "" {
		t.Fatalf("rm -rf must be destructive: %+v", solo)
	}
	got := analyzeShell(`rm -rf ./x; echo y >> "/etc/sudoers"`)
	if got.RiskLevel != "critical" {
		t.Fatalf("critical append must lift the merged level: %+v", got)
	}
	if got := analyzeShell("rm -rf ./x; cat a > config.yaml"); got.RiskLevel != solo.RiskLevel || got.Subcategory != solo.Subcategory {
		t.Fatalf("medium overwrite must not change rm: got %+v solo %+v", got, solo)
	}
	got = AnalyzeDestructiveOperation(DestructiveInput{ToolName: "shell", Arguments: map[string]any{
		"input": `await tools.exec_command({cmd: "rm -rf ./x"}); await tools.exec_command({cmd: "echo y >> /etc/sudoers"})`}})
	if got.RiskLevel != "critical" {
		t.Fatalf("multi-executable merge must take the highest level: %+v", got)
	}
}

// 动态部分不是简单 $VAR / ${VAR} 的追加目标必须回到兜底告警。
var dynamicAppendFailSafeCommands = []string{
	`echo x >> "$(printf /%s/sudo%s etc ers)"`,
	`echo k >> "$(printf %s/.ss%s ~ h)/authorized_keys"`,
	`echo x >> "${X:-/etc/sudoers}"`,
	`echo x >> >(sudo tee /etc/sudoers)`,
	`echo x >> "${X:-/tmp/a.log}"`,
	`echo x >> "$((1+2)).log"`,
	`echo x >> "${X//a/b}"`,
	`echo x >> "${!X}"`,
}

func TestComplexDynamicAppendKeepsFailSafe(t *testing.T) {
	for _, command := range dynamicAppendFailSafeCommands {
		for name, got := range map[string]DestructiveAnalysis{"shell": analyzeShell(command), "production": productionShell(command)} {
			if !got.ParseRejected {
				t.Fatalf("%s %q must keep the fail-safe: %+v", name, command, got)
			}
		}
	}
	for _, command := range []string{`echo x >> $HOME/x.log`, `echo x >> "${OUT_DIR}/run.log"`, `echo x >> "$LOG"`} {
		if got := productionShell(command); got.ParseRejected || got.Category != "" {
			t.Fatalf("%q must stay ignored: %+v", command, got)
		}
	}
}

// 动态追加写的放行只覆盖“外部环境变量或本命令内纯字面赋值”的简单展开，其余回到兜底或按代入值定级。
var dynamicAppendIgnoredCommands = []string{
	`echo x >> /tmp/$$.log`,
	`echo x >> "$LOG"`,
	`LOG=build.log; make >> "$LOG"`,
	`LOG=/tmp/build.log; make >> "$LOG"`,
	`OUT_DIR=/tmp/o; cmd >> "${OUT_DIR}/run.log"`,
}

var dynamicAppendFailSafeEscapes = []string{
	`echo k >> $HOME$'/\x2essh/authorized_keys'`,
	`f(){ echo x >> "$1"; }; f /etc/sudoers`,
	`echo x >> "$@"`,
	`echo x >> "$*"`,
	`echo x >> "${10}"`,
	`for f in a b; do echo >> "$f"; done`,
	`read X; echo >> "$X"`,
	`read -r -p prompt X; echo >> "$X"`,
	`mapfile X; echo >> "$X"`,
	`mapfile -t -C 'X=/etc/sudoers; :' -c 1 A <<< a; echo >> "$X"`,
	`printf -v X %s /etc/sudoers; echo >> "$X"`,
	`X=$Y; echo >> "$X"`,
	`X=$(cmd); echo >> "$X"`,
	`((X=1)); echo >> "$X"`,
	`eval "X=/etc/sudoers"; echo >> "$X"`,
	`X=a; X=$(cmd); echo >> "$X"`,
}

var dynamicAppendResolvedRisks = []struct{ command, risk string }{
	{`X=/etc/sudoers; echo x >> "$X"`, "critical"},
	{`X=~/.bashrc; echo >> "$X"`, "high"},
	{`X=/etc/sudoers; f(){ echo >> "$X"; }; f`, "critical"},
	{`export X=/etc/sudoers; echo >> "$X"`, "critical"},
	{`declare X=/etc/sudoers; echo >> "$X"`, "critical"},
	{`X=a; X=/etc/sudoers; echo >> "$X"`, "critical"},
	{`D=/etc; echo >> "$D/sudoers"`, "critical"},
}

func TestDynamicAppendAssignmentTracking(t *testing.T) {
	for _, command := range dynamicAppendIgnoredCommands {
		for name, got := range map[string]DestructiveAnalysis{"shell": analyzeShell(command), "production": productionShell(command)} {
			if got.Category != "" || got.ParseRejected {
				t.Fatalf("%s %q must be ignored: %+v", name, command, got)
			}
		}
	}
	for _, command := range dynamicAppendFailSafeEscapes {
		for name, got := range map[string]DestructiveAnalysis{"shell": analyzeShell(command), "production": productionShell(command)} {
			if !got.ParseRejected {
				t.Fatalf("%s %q must keep the fail-safe: %+v", name, command, got)
			}
		}
	}
	for _, c := range dynamicAppendResolvedRisks {
		for name, got := range map[string]DestructiveAnalysis{"shell": analyzeShell(c.command), "production": productionShell(c.command)} {
			if got.Category == "" || got.RiskLevel != c.risk || got.ParseRejected {
				t.Fatalf("%s %q must be %s: %+v", name, c.command, c.risk, got)
			}
		}
	}
}

func TestNestedShellInheritsAssignments(t *testing.T) {
	got := productionShell(`X=/etc/sudoers bash -c 'echo x >> "$X"'`)
	if got.Category == "" || got.RiskLevel != "critical" {
		t.Fatalf("nested shell must see the inherited assignment and report critical: %+v", got)
	}
}
