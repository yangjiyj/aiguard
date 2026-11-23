package agentguard

import "testing"

// 回归表：want 取值
//
//	none            不报（无类别、无兜底）
//	failsafe        解析不完整兜底（ParseRejected）
//	critical/high/medium  产生该级别的发现且无兜底
//	medium+failsafe 中危发现并保留兜底
type redirectRegressionCase struct {
	command, want string
	subcategory   string
}

var redirectRegressionCases = []redirectRegressionCase{
	// 大小写不敏感（macOS APFS）
	{`echo x >> /ETC/sudoers`, "critical", ""},
	{`echo x >> ~/.SSH/authorized_keys`, "high", ""},
	{`echo x > ~/.ZSHRC`, "high", ""},
	// 先 Clean 再判断空设备；/dev 下其它设备按块设备破坏
	{`echo x > /dev//null`, "none", ""},
	{`echo x > /dev/sda`, "critical", "block_device_destroy"},
	{`echo x > /dev/shm/a`, "none", ""},
	{`echo x >> /dev/fd/3`, "none", ""},
	{`echo x > /dev/tty`, "none", ""},
	// 补全的系统路径
	{`echo x >> /lib/systemd/system/x.service`, "critical", ""},
	{`echo x > /usr/lib/systemd/system/x.service`, "critical", ""},
	{`echo x >> /Library/LaunchDaemons/x.plist`, "critical", ""},
	{`echo x >> "C:/Windows/System32/drivers/etc/hosts"`, "critical", ""},
	{`echo x >> /c/windows/system32/x`, "critical", ""},
	// 补全的敏感路径与文件名
	{`echo x >> /proc/sysrq-trigger`, "high", ""},
	{`echo x > /sys/power/state`, "high", ""},
	{`echo x >> ~/.config/autostart/x.desktop`, "high", ""},
	{`echo x >> ~/Library/LaunchAgents/x.plist`, "high", ""},
	{`echo x >> .git/hooks/pre-commit`, "high", ""},
	{`echo x >> ~/.gitconfig`, "high", ""},
	{`echo x >> authorized_keys`, "high", ""},
	{`echo x >> ./sudoers`, "high", ""},
	{`echo x >> crontab`, "high", ""},
	{`echo x >> .zshenv`, "high", ""},
	{`echo x >> ~/.config/fish/config.fish`, "high", ""},
	{`echo x >> profile.ps1`, "high", ""},
	// C1 静态目标绕过
	{`echo x >> /tmp/*.log`, "failsafe", ""},
	{`echo x >> ~/.ba*rc`, "failsafe", ""},
	{`echo x >> build?.log`, "failsafe", ""},
	{`echo x > build/*.log`, "medium+failsafe", ""},
	{`echo x >> $'/etc/sudoers'`, "failsafe", ""},
	{`echo x >> ../../etc/sudoers`, "critical", ""},
	{`echo x >> ../../x/build.log`, "none", ""},
	{`echo x > ../out.txt`, "medium", ""},
	// C2 换工作目录
	{`cd /etc && echo x >> hosts`, "critical", ""},
	{`cd /etc; echo x > hosts`, "critical", ""},
	{`cd ~/.ssh && echo k >> keyfile`, "high", ""},
	{`cd /etc && echo x >> "$PWD/hosts"`, "critical", ""},
	{`cd /etc && echo x >> "$OLDPWD/hosts"`, "critical", ""},
	{`echo x >> "$DIRSTACK"`, "failsafe", ""},
	{`cd /home/dev/proj && make >> build.log 2>&1`, "none", ""},
	// C3 动态放行收窄
	{`echo x >> "$0"`, "failsafe", ""},
	{`echo x >> "$D/../etc/sudoers"`, "failsafe", ""},
	{`echo x >> "$BASH_REMATCH"`, "failsafe", ""},
	{`echo x >> "$REPLY"`, "failsafe", ""},
	{`echo x >> "$OPTARG"`, "failsafe", ""},
	{`builtin read X; echo >> "$X"`, "failsafe", ""},
	{`command eval "X=/etc/sudoers"; echo >> "$X"`, "failsafe", ""},
	{`trap 'X=/etc/sudoers' EXIT; echo >> "$X"`, "failsafe", ""},
	{`declare "X=/etc/sudoers"; echo >> "$X"`, "failsafe", ""},
	{`declare -n R=X; echo >> "$R"`, "failsafe", ""},
	{`builtin declare X=/etc/sudoers; echo >> "$X"`, "failsafe", ""},
	{`HOME=/etc; echo x >> ~/hosts`, "critical", ""},
	{`HOME=$(cmd); echo x >> ~/x.log`, "failsafe", ""},
	// 现场常见放行
	{`make >> build.log 2>&1`, "none", ""},
	{`npm test > /dev/null 2>&1`, "none", ""},
	{`echo x >> "$GITHUB_OUTPUT"`, "none", ""},
	{`LOG=build.log; make >> "$LOG"`, "none", ""},
	{`echo x >> ~/.cache/x.log`, "none", ""},
}

func assertRedirectWant(t *testing.T, label string, c redirectRegressionCase, got DestructiveAnalysis) {
	t.Helper()
	ok := false
	switch c.want {
	case "none":
		ok = got.Category == "" && !got.ParseRejected
	case "failsafe":
		ok = got.ParseRejected
	case "medium+failsafe":
		ok = got.RiskLevel == "medium" && got.ParseRejected
	default:
		ok = got.Category != "" && got.RiskLevel == c.want && !got.ParseRejected
	}
	if ok && c.subcategory != "" && got.Subcategory != c.subcategory {
		ok = false
	}
	if !ok {
		t.Errorf("%s %q want %s %s: %+v", label, c.command, c.want, c.subcategory, got)
	}
}

func TestRedirectRegressionTable(t *testing.T) {
	for _, c := range redirectRegressionCases {
		assertRedirectWant(t, "shell", c, analyzeShell(c.command))
		assertRedirectWant(t, "production", c, productionShell(c.command))
	}
}

func TestRedirectJoinsWorkingDirectory(t *testing.T) {
	got := AnalyzeDestructiveOperation(DestructiveInput{ToolName: "Bash", ToolType: "shell", WorkingDirectory: "/etc",
		Arguments: map[string]any{"command": "echo x >> hosts"}})
	if got.RiskLevel != "critical" {
		t.Fatalf("relative target must join the working directory: %+v", got)
	}
	got = AnalyzeDestructiveOperation(DestructiveInput{ToolName: "Bash", ToolType: "shell", WorkingDirectory: "/home/dev/proj",
		Arguments: map[string]any{"command": "make >> build.log"}})
	if got.Category != "" {
		t.Fatalf("ordinary project log must stay quiet: %+v", got)
	}
}

func TestLexerFallbackSensitiveDynamicTargets(t *testing.T) {
	cases := []struct{ command, risk string }{
		{`echo x >> $X/etc/sudoers`, "critical"},
		{`echo x >> $PROFILE`, "high"},
		{`echo x >> C:\Windows\System32\drivers\etc\hosts`, "critical"},
		{`echo x >> %USERPROFILE%\.ssh\authorized_keys`, "high"},
		{`echo x >> $LOG`, ""},
		{`echo x >> %TEMP%\build.log`, ""},
	}
	for _, c := range cases {
		got := analyzeLexerShell(c.command)
		if c.risk == "" {
			if got.Category != "" {
				t.Fatalf("lexer %q must be quiet: %+v", c.command, got)
			}
			continue
		}
		if got.RiskLevel != c.risk {
			t.Fatalf("lexer %q want %s: %+v", c.command, c.risk, got)
		}
	}
}

func TestDevNullRedirectDoesNotChangeVCSResult(t *testing.T) {
	bare := analyzeShell("git clean -fdx")
	with := analyzeShell("git clean -fdx 2>/dev/null")
	if bare.Category != with.Category || bare.Subcategory != with.Subcategory || bare.RiskLevel != with.RiskLevel ||
		bare.HighConfidence != with.HighConfidence || bare.SuggestedAction != with.SuggestedAction {
		t.Fatalf("/dev/null redirect must not change the result: bare %+v with %+v", bare, with)
	}
}
