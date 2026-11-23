package handler

import (
	"context"
	"strings"
	"testing"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/agentguard"
)

func TestStructuredGateIgnoresDynamicAppendRedirect(t *testing.T) {
	for _, command := range []string{`echo x >> "$LOG"`, `echo k=v >> "$GITHUB_OUTPUT"`} {
		got := evaluateStructuredToolCall(structuredToolCallInput{
			ToolName: "Bash", ToolType: "shell", Mode: agentguard.ModeAudit,
			Arguments: map[string]interface{}{"command": command},
		})
		if got.Destructive.Category != "" || got.Destructive.ParseRejected ||
			strings.Contains(got.Decision.ReasonSummary, "fail_safe") || strings.Contains(got.Decision.ReasonSummary, "parse") {
			t.Fatalf("%q must not alert: analysis=%+v decision=%+v", command, got.Destructive, got.Decision)
		}
	}
}

func TestStructuredGateKeepsFailSafeForComplexDynamicAppend(t *testing.T) {
	for _, command := range []string{
		`echo x >> "$(printf /%s/sudo%s etc ers)"`,
		`echo k >> "$(printf %s/.ss%s ~ h)/authorized_keys"`,
		`echo x >> "${X:-/etc/sudoers}"`,
		`echo x >> "${X:-/tmp/a.log}"`,
	} {
		got := evaluateStructuredToolCall(structuredToolCallInput{
			ToolName: "Bash", ToolType: "shell", Mode: agentguard.ModeAudit,
			Arguments: map[string]interface{}{"command": command},
		})
		if !got.Destructive.ParseRejected || !strings.Contains(got.Decision.ReasonSummary, "fail_safe") {
			t.Fatalf("%q must keep the parse-rejected fail-safe: analysis=%+v decision=%+v", command, got.Destructive, got.Decision)
		}
	}
	// 进程替换里的 sudo tee 写 /etc/sudoers 现在能直接认出来：确定性的严重发现，解析不完整的标记仍保留。
	got := evaluateStructuredToolCall(structuredToolCallInput{
		ToolName: "Bash", ToolType: "shell", Mode: agentguard.ModeAudit,
		Arguments: map[string]interface{}{"command": `echo x >> >(sudo tee /etc/sudoers)`},
	})
	if !got.Destructive.ParseRejected || !got.Destructive.HighConfidence || got.Destructive.RiskLevel != "critical" ||
		got.Decision.RiskSubcategory != "filesystem_overwrite" || got.Decision.RiskCategory != agentguard.DestructiveRiskCategory {
		t.Fatalf("process substitution writing /etc/sudoers: analysis=%+v decision=%+v", got.Destructive, got.Decision)
	}
}

func TestStructuredGateDynamicAppendAssignmentTracking(t *testing.T) {
	eval := func(command string) structuredToolCallEvaluation {
		return evaluateStructuredToolCall(structuredToolCallInput{
			ToolName: "Bash", ToolType: "shell", Mode: agentguard.ModeAudit,
			Arguments: map[string]interface{}{"command": command},
		})
	}
	for _, command := range []string{
		`echo x >> /tmp/$$.log`,
		`LOG=build.log; make >> "$LOG"`,
		`LOG=/tmp/build.log; make >> "$LOG"`,
		`OUT_DIR=/tmp/o; cmd >> "${OUT_DIR}/run.log"`,
	} {
		got := eval(command)
		if got.Destructive.Category != "" || got.Destructive.ParseRejected ||
			strings.Contains(got.Decision.ReasonSummary, "fail_safe") {
			t.Fatalf("%q must not alert: analysis=%+v decision=%+v", command, got.Destructive, got.Decision)
		}
	}
	for _, command := range []string{
		`echo k >> $HOME$'/\x2essh/authorized_keys'`,
		`f(){ echo x >> "$1"; }; f /etc/sudoers`,
		`for f in a b; do echo >> "$f"; done`,
		`read X; echo >> "$X"`,
		`X=$Y; echo >> "$X"`,
	} {
		got := eval(command)
		if !got.Destructive.ParseRejected || !strings.Contains(got.Decision.ReasonSummary, "fail_safe") {
			t.Fatalf("%q must keep the fail-safe: analysis=%+v decision=%+v", command, got.Destructive, got.Decision)
		}
	}
	for command, risk := range map[string]string{
		`X=/etc/sudoers; echo x >> "$X"`:          "critical",
		`X=~/.bashrc; echo >> "$X"`:               "high",
		`X=/etc/sudoers; f(){ echo >> "$X"; }; f`: "critical",
	} {
		got := eval(command)
		if got.Destructive.Category == "" || got.Destructive.ParseRejected || got.Destructive.RiskLevel != risk {
			t.Fatalf("%q must be %s: analysis=%+v decision=%+v", command, risk, got.Destructive, got.Decision)
		}
	}
}

// 按写入目标定级的回归：注入真实的模式预设策略，strict 应阻断、light 应只告警（审计放行）。
func TestStructuredGateRedirectRiskByTarget(t *testing.T) {
	cases := []struct {
		command  string
		workdir  string
		risk     string // 空表示不报
		failsafe bool
	}{
		{`echo x >> /ETC/sudoers`, "", "critical", false},
		{`echo x > /dev/sda`, "", "critical", false},
		{`echo x >> ../../etc/sudoers`, "", "critical", false},
		{`X=/etc/sudoers; echo x >> "$X"`, "", "critical", false},
		{`cd /etc && echo x >> hosts`, "", "critical", false},
		{`cd /var/spool && cd cron/crontabs && echo x >> root`, "", "high", false},
		{`X=/etc; cd "$X" && echo x >> foo`, "", "critical", false},
		{`echo x >> "C:\Windows\System32\drivers\etc\hosts"`, "", "critical", false},
		{`echo x >> ~/.SSH/authorized_keys`, "", "high", false},
		{`echo x >> authorized_keys`, "", "high", false},
		{`echo x >> hosts`, "", "high", false},
		{`echo x >> .git/config`, "", "high", false},
		{`X=~/.bashrc; echo >> "$X"`, "", "high", false},
		{`echo x > ../out.txt`, "", "medium", false},
		{`echo done > /dev/termination-log`, "", "medium", false},
		{`echo x >> foo`, "/etc", "critical", false},
		{`L=foo; echo x >> "$L"`, "/etc", "critical", false},
		{`echo x >> "$PWD/foo"`, "/etc", "critical", false},
		{`make >> build.log 2>&1`, "", "", false},
		{`npm test > /dev/null 2>&1`, "", "", false},
		{`(echo > /dev/tcp/127.0.0.1/5432) >/dev/null 2>&1`, "", "", false},
		{`echo x >> "$GITHUB_OUTPUT"`, "", "", false},
		{`LOG=build.log; make >> "$LOG"`, "", "", false},
		{`cd /home/dev/proj && make >> build.log`, "", "", false},
		{`cd "$(git rev-parse --show-toplevel)" && make >> build.log`, "", "", false},
		{`echo x >> "$HOME/.local/usr/share/x.log"`, "", "", false},
		{`echo x >> /tmp/*.log`, "", "medium", true},
		{`echo x >> $'/etc/sudoers'`, "", "medium", true},
		{`echo x >> "$0"`, "", "medium", true},
		{`echo x >> "$BASH_ENV"`, "", "medium", true},
		{`echo x >> "$D/../etc/sudoers"`, "", "medium", true},
		{`read X; echo >> "$X"`, "", "medium", true},
		{`$PYTHON x.py >> "$LOG" 2>&1`, "", "", false},
		{`PY=python3; $PY x.py >> "$LOG"`, "", "", false},
		{`printf "start $(date)\n" >> "$LOG"`, "", "", false},
		{`echo x >> inventory/hosts`, "", "", false},
		{`echo x >> /proc/1/root/etc/hosts`, "", "critical", false},
		{`echo x >> ~/.config/systemd/user/x.service`, "", "high", false},
		{`c=eval; $c 'X=/etc/sudoers'; echo >> "$X"`, "", "medium", true},
		{`X=/et?/hosts; echo >> $X`, "", "medium", true},
	}
	for _, c := range cases {
		for _, mode := range []agentguard.Mode{agentguard.ModeStrict, agentguard.ModeLight} {
			action := agentguard.DestructiveActionBlock
			wantEffective := agentguard.DecisionBlock
			if mode == agentguard.ModeLight {
				action = agentguard.DestructiveActionAlertAllow
				wantEffective = agentguard.DecisionAudit
			}
			policy := &agentguard.EffectivePolicy{
				Mode: mode, ConfigSource: agentguard.ConfigSourceModePreset,
				Destructive: &agentguard.DestructivePolicy{Mode: mode, Action: action, ScopeType: "tenant"},
			}
			args := map[string]interface{}{"command": c.command}
			if c.workdir != "" {
				args["workdir"] = c.workdir // Codex 的工作目录参数名
			}
			base := agentguard.AnalyzeToolCall(context.Background(), agentguard.ToolCallAnalysisInput{
				ToolName: "Bash", ToolType: "shell", Arguments: args, Mode: mode})
			got := evaluateStructuredToolCall(structuredToolCallInput{
				ToolName: "Bash", ToolType: "shell", Arguments: args, Mode: mode, Policy: policy, BaseDecision: base})
			failsafe := strings.Contains(got.Decision.ReasonSummary, "fail_safe")
			if c.risk == "" {
				if got.Destructive.Category != "" || got.Destructive.ParseRejected || got.Decision.EffectiveDecision != agentguard.DecisionAllow {
					t.Fatalf("%s %q must stay quiet: %+v / %+v", mode, c.command, got.Destructive, got.Decision)
				}
				continue
			}
			want := wantEffective
			if c.failsafe {
				// 2.9.22：解析不了的重定向是兜底防护项 agent.parse_rejected（默认告警放行），不再随
				// 删除与破坏卡片阻断；原期望与卡片动作相同。
				want = agentguard.DecisionAudit
			}
			if got.Decision.RiskLevel != c.risk || got.Decision.EffectiveDecision != want || failsafe != c.failsafe {
				t.Fatalf("%s %q want risk=%s failsafe=%v effective=%s: risk=%q effective=%q reason=%q",
					mode, c.command, c.risk, c.failsafe, want, got.Decision.RiskLevel, got.Decision.EffectiveDecision, got.Decision.ReasonSummary)
			}
		}
	}
}
