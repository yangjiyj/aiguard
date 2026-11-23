package agentguard

import "testing"

// 第四轮：降噪误报（动态命令词、printf 首参、read 选项值）与低成本补漏。
var redirectRegressionCases4 = []redirectRegressionCase{
	// A1 动态命令词
	{`$PYTHON x.py >> "$LOG" 2>&1`, "none", ""},
	{`PY=python3; $PY x.py >> "$LOG"`, "none", ""},
	{`${PYTHON:-python3} x.py >> "$LOG"`, "none", ""},
	{`$(which python) x.py >> "$LOG"`, "none", ""},
	{`$(command -v python) x.py >> "$LOG"`, "none", ""},
	{`PY=eval; $PY 'X=/etc/sudoers'; echo >> "$X"`, "failsafe", ""},
	{`${PYTHON:-eval} 'X=/etc/sudoers'; echo >> "$LOG"`, "failsafe", ""},
	{`PY=$(cmd); $PY x >> "$LOG"`, "failsafe", ""},
	{`$1 x >> "$LOG"`, "failsafe", ""},
	{`$c /etc; echo x >> "$LOG"`, "none", ""},
	{`$c /etc; echo x >> hosts`, "high", ""},
	// A2 printf 首参
	{`printf "start $(date)\n" >> "$LOG"`, "none", ""},
	{`printf "Building ${PKG}\n" >> "$LOG"`, "none", ""},
	{`printf $fmt >> "$LOG"`, "failsafe", ""},
	{`printf -v$name x; echo >> "$LOG"`, "failsafe", ""},
	// A3 系统敏感文件名只对不带目录的文件名生效
	{`echo x >> inventory/hosts`, "none", ""},
	{`echo x >> fixtures/passwd`, "none", ""},
	{`echo x >> rootfs/etc/group`, "none", ""},
	{`echo x >> ./hosts`, "high", ""},
	{`echo x >> ././hosts`, "high", ""},
	{`echo x >> .//hosts`, "high", ""},
	{`echo x >> ./sub/../hosts`, "high", ""},
	{`mapfile -t -C 'X=/etc/sudoers; :' -c 1 A <<< a; echo >> "$X"`, "failsafe", ""},
	{`readarray -C cb -c1 A <<< a; echo >> "$X"`, "failsafe", ""},
	{`mapfile -tC cb A <<< a; echo >> "$X"`, "failsafe", ""},
	{`echo x >> sub/dir/authorized_keys`, "high", ""},
	{`echo x >> sub/dir/.bashrc`, "high", ""},
	// A4 用户级持久化
	{`echo x >> ~/.config/systemd/user/x.service`, "high", ""},
	{`echo x >> ~/.bashrc.d/x.sh`, "high", ""},
	{`echo x >> ~/.config/environment.d/x.conf`, "high", ""},
	// read 选项值不是变量名
	{`read -p "name: $X" Y; echo >> "$LOG"`, "none", ""},
	{`read -r -t 5 -p "x: $X" Y; echo >> "$LOG"`, "none", ""},
	{`read -a ARR; echo >> "$ARR"`, "failsafe", ""},
	{`read -p "name: " Y; echo >> "$Y"`, "failsafe", ""},
	// source/eval 下 ~ 前缀目标按家目录判定
	{`source .venv/bin/activate && python x.py >> ~/train.log`, "none", ""},
	{`source .venv/bin/activate && echo x >> ~/.bashrc`, "high", ""},
	{`source .venv/bin/activate && echo x >> "$LOG"`, "failsafe", ""},
	// /proc/<pid>/root 前缀
	{`echo x >> /proc/1/root/etc/hosts`, "critical", ""},
	{`echo x >> /proc/self/root/etc/hosts`, "critical", ""},
	{`echo x >> /proc/thread-self/root/etc/hosts`, "critical", ""},
	// 裸卷
	{`echo x > "\\.\C:"`, "critical", "block_device_destroy"},
	// cd 的 ${X:-默认值}
	{`cd "${X:-/etc}" && echo x >> cron.d/job`, "critical", ""},
	{`X=/tmp; cd "${X:-/etc}" && echo x >> cron.d/job`, "critical", ""},
}

func TestRedirectRegressionTableRound4(t *testing.T) {
	for _, c := range redirectRegressionCases4 {
		assertRedirectWant(t, "shell", c, analyzeShell(c.command))
		assertRedirectWant(t, "production", c, productionShell(c.command))
	}
}

func TestLexerFallbackPushLocationAndVolume(t *testing.T) {
	if got := analyzeLexerShell(`Push-Location /etc; echo x >> foo`); got.RiskLevel != "critical" {
		t.Fatalf("Push-Location must change the base directory: %+v", got)
	}
	got := analyzeLexerShell(`echo x > \\.\C:`)
	if got.RiskLevel != "critical" || got.Subcategory != "block_device_destroy" {
		t.Fatalf("bare volume must be a block device: %+v", got)
	}
}
