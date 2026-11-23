package agentguard

import "testing"

// 2026-11-22：分析器给“日常开发操作”打 Routine 标记（只留痕、不进告警）。真危险、目标不完整、含动态目标、
// 严重级的一律不打。
func TestDestructiveRoutineMark(t *testing.T) {
	routine := []string{
		"rm -f /tmp/xxx.log",
		"rm -f CMakeCache.txt ; rm -rf CMakeFiles",
		"rm -rf /home/dev/proj/build/scratch_repro",
		"rm -f .commit_msg.txt",
		"rm -f /var/run/app.pid",
		"rm -f /var/log/app.log",
		"rm -rf /home/dev/proj/out/x",
		"rm -rf ~/proj/out/cache",
		"rm -rf target dist __pycache__",
		"rm -f *.log",
		"rm -f logs/*.pid",
		"echo x > /tmp/a.txt; rm -f /tmp/a.txt",
	}
	for _, command := range routine {
		got := AnalyzeDestructiveOperation(DestructiveInput{ToolName: "Bash", ToolType: "shell", Arguments: map[string]any{"command": command}})
		if got.Category == "" || !got.Routine {
			t.Errorf("%q 应标日常开发操作: %+v", command, got)
		}
	}
	danger := []string{
		"rm -rf /", "rm -rf /etc", "rm -rf /var/log", "rm -rf /var/log/audit/audit.log", "rm -f /var/log/auth.log", "rm -f /var/log/*.log",
		"rm -rf /var/run", "rm -rf ~", "rm -rf .", "rm -rf ..", "rm -rf *", "rm -rf .git", "rm -rf src", "rm -rf /home/dev/proj",
		"rm -rf /home/dev/proj/src", "rm -rf /home/dev/proj/*", "rm -rf /home/dev/.ssh/authorized_keys", "rm -rf ~/.ssh",
		"rm -rf build/../..", "rm -rf /tmp/../etc", "rm -rf /tmp", "rm -rf /tmp/*", "rm -rf $DIR", "rm -f /tmp/a; rm -rf src",
		"rm -f /tmp/a; git reset --hard HEAD~1", "rm -f .env", "echo x > .env", "rm -f ~/.ssh/id_ed25519", "rm -f /etc/app.log",
		"echo x > /etc/hosts", "git clean -fdx",
	}
	for _, command := range danger {
		got := AnalyzeDestructiveOperation(DestructiveInput{ToolName: "Bash", ToolType: "shell", Arguments: map[string]any{"command": command}})
		if got.Routine {
			t.Errorf("%q 不能标日常开发操作: %+v", command, got)
		}
	}
}

func TestWholeTreeDeleteUnknown(t *testing.T) {
	for command, want := range map[string]bool{
		"rm -rf $HOME": true, "rm -rf ${HOME}": true, "rm -rf \"$HOME\"/": true, "rm -rf $HOME/proj": false,
		"git clean -fdx": true, "git clean -xfd": true, "git clean -fd": false, "git clean -fdx src": false, "git clean -fdx -- src": false,
		"find . -delete": true, "find -delete": true, "find .. -depth -delete": true,
		"find . -name '*.pyc' -delete": false, "find /tmp -delete": false, "find . -type f -delete": false, "ls -la": false,
	} {
		raw := command
		words := destructiveCommandWordsForTest(command)
		if got := wholeTreeDeleteUnknown(raw, words); got != want {
			t.Errorf("%q: want %v got %v", command, want, got)
		}
	}
}

func destructiveCommandWordsForTest(command string) []string {
	var words []string
	for _, word := range splitSimpleWords(command) {
		words = append(words, word)
	}
	return words
}

func splitSimpleWords(command string) []string {
	var out []string
	current := ""
	quote := byte(0)
	for i := 0; i < len(command); i++ {
		c := command[i]
		switch {
		case quote != 0:
			if c == quote {
				quote = 0
			} else {
				current += string(c)
			}
		case c == '\'' || c == '"':
			quote = c
		case c == ' ':
			if current != "" {
				out = append(out, current)
				current = ""
			}
		default:
			current += string(c)
		}
	}
	if current != "" {
		out = append(out, current)
	}
	return out
}
