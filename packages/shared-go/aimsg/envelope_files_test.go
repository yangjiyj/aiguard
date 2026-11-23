package aimsg

import (
	"reflect"
	"strings"
	"testing"
)

func TestExtractMentionedFilePaths(t *testing.T) {
	tests := []struct {
		name    string
		content string
		want    []string
	}{
		{
			name: "mentioned 头 + 换行路径",
			content: `# Files mentioned by the user:
## screenshot.png:
C:/Users/test/AppData/Local/Temp/screenshot.png
## My request:
请解释截图里的错误`,
			want: []string{"C:/Users/test/AppData/Local/Temp/screenshot.png"},
		},
		{
			name: "pasted 头",
			content: `# Files pasted by the user:
## "pasted-text.txt": C:\Users\a\pasted-text.txt
## My request:
总结`,
			want: []string{`C:\Users\a\pasted-text.txt`},
		},
		{
			name: "name: 换行路径 与 \"name\": path 两种条目混合",
			content: `# Files mentioned by the user:
## 合同.pdf:
/home/u/docs/合同.pdf
## "数据.xlsx": /home/u/data/数据.xlsx
## My request:
分析`,
			want: []string{"/home/u/docs/合同.pdf", "/home/u/data/数据.xlsx"},
		},
		{
			name: "Windows 与 POSIX 路径",
			content: `# Files mentioned by the user:
## a.pdf: C:\Users\a\合同.pdf
## b.pdf:
/home/u/b.pdf
## My request:
x`,
			want: []string{`C:\Users\a\合同.pdf`, "/home/u/b.pdf"},
		},
		{
			name:    "非 Codex 信封返回 nil",
			content: "普通用户消息，没有附件清单",
			want:    nil,
		},
		{
			name: "只有 Files 头没有 My request 返回 nil",
			content: `# Files mentioned by the user:
## a.pdf: /x/a.pdf`,
			want: nil,
		},
		{
			name: "超过 32 条截断",
			content: `# Files mentioned by the user:
` + func() string {
				s := ""
				for i := 0; i < 40; i++ {
					s += "## f.pdf: /x/f" + strings.Repeat("a", i+1) + ".pdf\n"
				}
				return s
			}() + `## My request:
x`,
			want: func() []string {
				out := make([]string, 32)
				for i := range out {
					out[i] = "/x/f" + strings.Repeat("a", i+1) + ".pdf"
				}
				return out
			}(),
		},
		{
			name: "去重",
			content: `# Files mentioned by the user:
## a.pdf: /x/a.pdf
## b.pdf: /x/a.pdf
## My request:
x`,
			want: []string{"/x/a.pdf"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ExtractMentionedFilePaths(tt.content)
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("ExtractMentionedFilePaths() = %#v, want %#v", got, tt.want)
			}
		})
	}
}
