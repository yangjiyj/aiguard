package agentguard

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

func repeatedCDs(count int) string {
	var builder strings.Builder
	for i := 1; i <= count; i++ {
		fmt.Fprintf(&builder, "cd d%d; ", i)
	}
	return builder.String()
}

// 第三轮回归：相对目标按敏感文件名定级、cd 解析、运行时赋值漏网、/dev 收窄、引号转义等。
var redirectRegressionCases3 = []redirectRegressionCase{
	// NC1
	{`cd "$(git rev-parse --show-toplevel)" && make >> build.log`, "none", ""},
	{`cd /tmp/x && echo x >> hosts`, "high", ""},
	{`echo x >> passwd`, "high", ""},
	{`echo x > resolv.conf`, "high", ""},
	{`echo x >> fstab`, "high", ""},
	{`X=/etc; cd "$X" && echo x >> foo`, "critical", ""},
	{`cd /var/spool && cd cron/crontabs && echo x >> root`, "high", ""},
	{`echo x >> ~+/hosts`, "high", ""},
	{`cd /etc && echo x >> ~+/foo`, "critical", ""},
	{`HOME=/etc; cd; echo x >> foo`, "critical", ""},
	{repeatedCDs(17) + `echo x >> out.log`, "failsafe", ""},
	{repeatedCDs(16) + `echo x >> out.log`, "none", ""},
	// NC2
	{`c=eval; $c "X=/etc/sudoers"; echo >> "$LOG"`, "failsafe", ""},
	{`$'eval' "X=/etc/sudoers"; echo >> "$LOG"`, "failsafe", ""},
	{`"$(echo eval)" "X=/etc/sudoers"; echo >> "$LOG"`, "failsafe", ""},
	{`$c /etc; echo x >> "$LOG"`, "none", ""}, // 外部变量作命令词：信任外部环境
	{`read -r "$n" X; echo >> "$LOG"`, "failsafe", ""},
	{`printf -vX %s /etc/sudoers; echo >> "$X"`, "failsafe", ""},
	{`alias cd=x; echo >> "$LOG"`, "failsafe", ""},
	{`command alias cd=x; echo >> "$LOG"`, "failsafe", ""},
	{`X=/et?/hosts; echo >> $X`, "failsafe", ""},
	{`command -v git; echo >> "$LOG"`, "none", ""},
	{`printf '%s' "$x"; echo >> "$LOG"`, "none", ""},
	// 含字面 / 的动态命令词一定是外部程序路径，不改 shell 状态
	{`"$VENV/bin/python" x.py >> "$LOG"`, "none", ""},
	{`$HOME/bin/tool x >> "$LOG"`, "none", ""},
	{`"$ROOT"/scripts/run.sh >> "$LOG"`, "none", ""},
	{`c=eval; $c 'X=/etc/sudoers'; echo >> "$X"`, "failsafe", ""},
	{`$c /etc; echo >> hosts`, "high", ""},
	// NI1
	{`echo x > /dev/tcp/127.0.0.1/5432`, "none", ""},
	{`(echo > /dev/tcp/127.0.0.1/5432) >/dev/null 2>&1`, "none", ""},
	{`echo done > /dev/termination-log`, "medium", ""},
	{`echo done >> /dev/termination-log`, "none", ""},
	{`echo x > /dev/nvme0n1`, "critical", "block_device_destroy"},
	{`echo x > /dev/mem`, "critical", "block_device_destroy"},
	{`echo x > /dev/disk2`, "critical", "block_device_destroy"},
	{`echo x > /dev/loop0`, "critical", "block_device_destroy"},
	{`echo x > /dev/mapper/vg-root`, "critical", "block_device_destroy"},
	{`echo x > /dev/rdisk1`, "critical", "block_device_destroy"},
	// NI3 双引号内反斜杠保留
	{`echo x >> "C:\Users\u\.ssh\authorized_keys"`, "high", ""},
	{`echo x >> "C:\Windows\System32\drivers\etc\hosts"`, "critical", ""},
	// NI5
	{`echo x >> .git/config`, "high", ""},
	{`echo x >> ~/.config/git/config`, "high", ""},
	// 收窄与外部变量
	{`echo x >> "$HOME/.local/usr/share/x.log"`, "none", ""},
	{`echo x >> "$BASH_ENV"`, "failsafe", ""},
	{`echo x >> "$ENV"`, "failsafe", ""},
}

func TestRedirectRegressionTableRound3(t *testing.T) {
	for _, c := range redirectRegressionCases3 {
		assertRedirectWant(t, "shell", c, analyzeShell(c.command))
		assertRedirectWant(t, "production", c, productionShell(c.command))
	}
}

func TestRedirectWorkingDirectoryReachesDynamicTargets(t *testing.T) {
	for _, command := range []string{`echo x >> "$PWD/foo"`, `L=foo; echo x >> "$L"`, `echo x >> ~+/foo`, `echo x >> foo`} {
		got := AnalyzeDestructiveOperation(DestructiveInput{ToolName: "Bash", ToolType: "shell", WorkingDirectory: "/etc",
			Arguments: map[string]any{"command": command}})
		if got.RiskLevel != "critical" || got.ParseRejected {
			t.Fatalf("wd=/etc %q must be critical: %+v", command, got)
		}
	}
}

func TestLexerFallbackChangesDirectory(t *testing.T) {
	cases := []struct{ command, risk, subcategory string }{
		{`cd C:\Windows\System32 && echo x >> foo.txt`, "critical", ""},
		{`cd /d C:\Windows\System32 & echo x > foo.txt`, "critical", ""},
		{`sl /etc; echo x > foo`, "critical", ""},
		{`pushd /etc & echo x >> foo`, "critical", ""},
		{`chdir /etc & echo x >> foo`, "critical", ""},
		{`Set-Location /etc; echo x >> foo`, "critical", ""},
		{`echo x >> hosts`, "high", ""},
		{`echo x > \\.\PhysicalDrive0`, "critical", "block_device_destroy"},
		{`cd C:\proj && make >> build.log`, "", ""},
	}
	for _, c := range cases {
		got := analyzeLexerShell(c.command)
		if c.risk == "" {
			if got.Category != "" {
				t.Fatalf("lexer %q must be quiet: %+v", c.command, got)
			}
			continue
		}
		if got.RiskLevel != c.risk || (c.subcategory != "" && got.Subcategory != c.subcategory) {
			t.Fatalf("lexer %q want %s %s: %+v", c.command, c.risk, c.subcategory, got)
		}
	}
}

func TestAppendCollectionIsBoundedByNodeBudget(t *testing.T) {
	var script strings.Builder
	for i := 0; i < 200; i++ {
		fmt.Fprintf(&script, `echo x >> "$V%d"; `, i)
	}
	for i := 0; i < 1000; i++ {
		fmt.Fprintf(&script, "V%d=x; ", i)
	}
	script.WriteString(repeatedCDs(400))
	start := time.Now()
	got := productionShell(script.String())
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("assignment and cd collection must stay bounded, took %s", elapsed)
	}
	if !got.ParseRejected && got.Category == "" {
		t.Fatalf("over-budget script must keep the fail-safe: %+v", got)
	}
}
