package filerestrict

import (
	"reflect"
	"testing"
)

// argv 拼成一条命令时，含空白或 shell 元字符的元素要加引号，否则元素会被拆开（"/opt/My Dir" 变成两个词）。
func TestScriptFromArgvQuotesElementsThatWouldSplit(t *testing.T) {
	for _, c := range []struct {
		argv []string
		want string
	}{
		{[]string{"rm", "-rf", "/opt/My Dir"}, `rm -rf '/opt/My Dir'`},
		{[]string{"env", "GH_TOKEN=a b", "git", "push", "-f"}, `env 'GH_TOKEN=a b' git push -f`},
		{[]string{"echo", "it's"}, `echo "it's"`},
		{[]string{"echo", `it's "$HOME"`}, `echo 'it'\''s "$HOME"'`},
		{[]string{"echo", "a;b", "x|y", ""}, `echo 'a;b' 'x|y' ''`},
		{[]string{"bash", "deploy.sh", "a b"}, `bash deploy.sh 'a b'`},
		{[]string{"pdftotext", "合同.pdf", "-"}, `pdftotext 合同.pdf -`},
		{[]string{"cat", `C:\Users\a\x.pdf`}, `cat 'C:\Users\a\x.pdf'`},
		// cmd /c 后面多个元素按 Windows 规则用双引号；只有一个元素时它就是整条命令，原样
		{[]string{"cmd", "/c", "del", `C:\My Dir\x`}, `del "C:\My Dir\x"`},
		{[]string{"cmd", "/c", "type", "a.pdf"}, `type a.pdf`},
		{[]string{"cmd", "/c", `mysql -uroot -e "drop database x"`}, `mysql -uroot -e "drop database x"`},
		// -c 后面的脚本原样
		{[]string{"bash", "-lc", "rm -rf '/opt/My Dir'"}, `rm -rf '/opt/My Dir'`},
	} {
		if got := scriptFromArgv(c.argv); got != c.want {
			t.Errorf("%q -> %q want %q", c.argv, got, c.want)
		}
	}
}

func TestExtractCommandScriptsReportsTheInterpreter(t *testing.T) {
	got := ExtractCommandScripts(map[string]any{
		"command": []any{"powershell", "-Command", "Remove-Item C:\\x"},
		"argv":    []any{"bash", "-lc", "rm -rf x"},
		"args":    []any{"cmd", "/c", "del x"},
	})
	want := []CommandScript{
		{Text: "Remove-Item C:\\x", Interpreter: InterpreterPowerShell},
		{Text: "rm -rf x", Interpreter: InterpreterPOSIX},
		{Text: "del x", Interpreter: InterpreterCmd},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v want %#v", got, want)
	}
	plain := ExtractCommandScripts(map[string]any{"command": []any{"rm", "-rf", "x"}})
	if len(plain) != 1 || plain[0].Interpreter != InterpreterNone || plain[0].Text != "rm -rf x" {
		t.Fatalf("plain argv: %#v", plain)
	}
	encoded := ExtractCommandScripts(map[string]any{"command": []any{"pwsh", "-ec", encodePS("Remove-Item C:\\x")}})
	if len(encoded) != 1 || encoded[0].Interpreter != InterpreterPowerShell || encoded[0].Text != "Remove-Item C:\\x" {
		t.Fatalf("encoded: %#v", encoded)
	}
	// 字符串形态和 JS 字面量不知道解释器。
	str := ExtractCommandScripts(map[string]any{"command": "rm -rf x"})
	if len(str) != 1 || str[0].Interpreter != InterpreterNone {
		t.Fatalf("string: %#v", str)
	}
}
