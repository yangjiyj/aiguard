package filerestrict

import (
	"encoding/base64"
	"reflect"
	"testing"
	"unicode/utf16"
)

func encodePS(script string) string {
	u16 := utf16.Encode([]rune(script))
	raw := make([]byte, 0, len(u16)*2)
	for _, u := range u16 {
		raw = append(raw, byte(u), byte(u>>8))
	}
	return base64.StdEncoding.EncodeToString(raw)
}

func TestExtractCommandTexts(t *testing.T) {
	tests := []struct {
		name         string
		args         map[string]any
		wantCommands []string
		wantCoarse   string
	}{
		{
			name:         "bash 数组 -lc",
			args:         map[string]any{"command": []any{"bash", "-lc", "rm -rf /"}},
			wantCommands: []string{"rm -rf /"},
		},
		{
			name:         "bash 数组 -c",
			args:         map[string]any{"command": []any{"bash", "-c", "cat a.pdf"}},
			wantCommands: []string{"cat a.pdf"},
		},
		{
			name:         "sh -lic",
			args:         map[string]any{"argv": []any{"sh", "-lic", "pdftotext a.pdf -"}},
			wantCommands: []string{"pdftotext a.pdf -"},
		},
		{
			name:         "powershell -Command",
			args:         map[string]any{"command": []any{"powershell", "-Command", "Get-Content a.pdf"}},
			wantCommands: []string{"Get-Content a.pdf"},
		},
		{
			name:         "pwsh -c",
			args:         map[string]any{"command": []any{"pwsh", "-c", "type secret.docx"}},
			wantCommands: []string{"type secret.docx"},
		},
		{
			name:         "powershell -EncodedCommand",
			args:         map[string]any{"command": []any{"powershell", "-EncodedCommand", encodePS("Get-Content 合同.pdf")}},
			wantCommands: []string{"Get-Content 合同.pdf"},
		},
		{
			name:         "powershell -EncodedCommand 非法 base64 原样",
			args:         map[string]any{"command": []any{"powershell", "-EncodedCommand", "!!!not-base64!!!"}},
			wantCommands: []string{"!!!not-base64!!!"},
		},
		{
			name:         "cmd /c",
			args:         map[string]any{"command": []any{"cmd", "/c", "type", "a.pdf"}},
			wantCommands: []string{"type a.pdf"},
		},
		{
			name:         "cmd.exe /k",
			args:         map[string]any{"command": []any{"cmd.exe", "/k", "dir"}},
			wantCommands: []string{"dir"},
		},
		{
			name:         "裸 argv 空格拼接",
			args:         map[string]any{"command": []any{"pdftotext", "合同.pdf", "-"}},
			wantCommands: []string{"pdftotext 合同.pdf -"},
		},
		{
			name:         "字符串 command（老形态）",
			args:         map[string]any{"command": "rm -rf /"},
			wantCommands: []string{"rm -rf /"},
		},
		{
			name:         "字符串 cmd（老形态）",
			args:         map[string]any{"cmd": "cat a.docx", "workdir": "/w"},
			wantCommands: []string{"cat a.docx"},
		},
		{
			name:         "JS exec_command 单个 cmd 字面量",
			args:         map[string]any{"input": `const r = await tools.exec_command({cmd:"rm -rf /",workdir:"/w"})`},
			wantCommands: []string{"rm -rf /"},
			wantCoarse:   `const r = await tools.exec_command({cmd:"rm -rf /",workdir:"/w"})`,
		},
		{
			name:         "JS exec_command 多个 cmd 字面量",
			args:         map[string]any{"input": `await tools.exec_command({cmd:"pdftotext a.pdf -"}); await tools.exec_command({cmd:"cat b.docx"})`},
			wantCommands: []string{"pdftotext a.pdf -", "cat b.docx"},
			wantCoarse:   `await tools.exec_command({cmd:"pdftotext a.pdf -"}); await tools.exec_command({cmd:"cat b.docx"})`,
		},
		{
			name:         "JS cmd 字面量带转义引号",
			args:         map[string]any{"input": `tools.exec_command({cmd:"grep \"secret\" a.pdf"})`},
			wantCommands: []string{`grep "secret" a.pdf`},
			wantCoarse:   `tools.exec_command({cmd:"grep \"secret\" a.pdf"})`,
		},
		{
			name:         "JS cmd 字面量带 Windows 路径反斜杠",
			args:         map[string]any{"input": `tools.exec_command({cmd:"type C:\\Users\\a\\合同.pdf"})`},
			wantCommands: []string{`type C:\Users\a\合同.pdf`},
			wantCoarse:   `tools.exec_command({cmd:"type C:\\Users\\a\\合同.pdf"})`,
		},
		{
			name:         "write_stdin 无 cmd 字面量 → 无命令但有 coarseText",
			args:         map[string]any{"input": `const r = await tools.write_stdin({session_id:39671, chars:"", yield_time_ms:30000})`},
			wantCommands: nil,
			wantCoarse:   `const r = await tools.write_stdin({session_id:39671, chars:"", yield_time_ms:30000})`,
		},
		{
			name:         "单引号 cmd 字面量",
			args:         map[string]any{"input": `tools.exec_command({cmd:'cat a.pdf'})`},
			wantCommands: []string{"cat a.pdf"},
			wantCoarse:   `tools.exec_command({cmd:'cat a.pdf'})`,
		},
		{
			name:         "普通 input 字符串按一条命令（老 shell 工具）",
			args:         map[string]any{"input": "ls -la /tmp"},
			wantCommands: []string{"ls -la /tmp"},
		},
		{
			name:         "非工具 JSON（无关参数）",
			args:         map[string]any{"path": "/x/a.pdf"},
			wantCommands: nil,
		},
		{
			name:         "空参数",
			args:         map[string]any{},
			wantCommands: nil,
		},
		{
			name:         "script 字符串按一条命令",
			args:         map[string]any{"script": "echo hi"},
			wantCommands: []string{"echo hi"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			commands, coarse := ExtractCommandTexts(tt.args)
			if !reflect.DeepEqual(commands, tt.wantCommands) {
				t.Errorf("commands = %#v, want %#v", commands, tt.wantCommands)
			}
			if coarse != tt.wantCoarse {
				t.Errorf("coarseText = %q, want %q", coarse, tt.wantCoarse)
			}
		})
	}
}

func TestExtractCommandTextsFromJSON(t *testing.T) {
	tests := []struct {
		name         string
		raw          string
		wantCommands []string
		wantCoarse   string
	}{
		{
			name:         "合法 JSON argv",
			raw:          `{"command":["bash","-lc","rm -rf /"]}`,
			wantCommands: []string{"rm -rf /"},
		},
		{
			name:         "合法 JSON cmd 字符串",
			raw:          `{"cmd":"cat a.pdf"}`,
			wantCommands: []string{"cat a.pdf"},
		},
		{
			name:       "非法 JSON 整串进 coarseText",
			raw:        `const r = await tools.exec_command({cmd:"cat a.pdf"})`,
			wantCoarse: `const r = await tools.exec_command({cmd:"cat a.pdf"})`,
		},
		{
			name: "空串",
			raw:  "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			commands, coarse := ExtractCommandTextsFromJSON(tt.raw)
			if !reflect.DeepEqual(commands, tt.wantCommands) {
				t.Errorf("commands = %#v, want %#v", commands, tt.wantCommands)
			}
			if coarse != tt.wantCoarse {
				t.Errorf("coarseText = %q, want %q", coarse, tt.wantCoarse)
			}
		})
	}
}
