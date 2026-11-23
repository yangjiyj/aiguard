package agentguard

import (
	"strings"
	"testing"
)

// 2.9.21 r2921i：本地文件工具的路径改为“只认本地写法，拿不准一律算外发”。
// 上一轮复核留下的写法（NT 命名空间 \??\UNC、@ 开头、/net 等自动挂载目录、codex 补丁的 Environment ID）
// 都要判 true（照 2.9.20 拦）；现场常见的本地写法要保持 false，现场的放宽靠它们。

func TestToolCallMayEgressLocalFormR2921i(t *testing.T) {
	write := func(path string) map[string]any {
		return map[string]any{"file_path": path, "content": "// CONFIDENTIAL AND PROPRIETARY\n"}
	}
	read := func(path string) map[string]any { return map[string]any{"file_path": path} }
	globPath := func(path string) map[string]any { return map[string]any{"pattern": "*.c", "path": path} }
	glob := func(pattern string) map[string]any { return map[string]any{"pattern": pattern, "path": "/repo"} }
	patch := func(body string) map[string]any {
		return map[string]any{"input": "*** Begin Patch\n" + body + "\n*** End Patch"}
	}
	cases := []struct {
		label string
		tool  string
		args  map[string]any
		want  bool
	}{
		// 上一轮复核留下的写法：NT 命名空间。
		{"Write NT UNC", "Write", write(`\??\UNC\srv\share\x`), true},
		{"Read NT UNC", "Read", read(`\??\UNC\srv\share\x`), true},
		{"Glob path NT UNC", "Glob", globPath(`\??\UNC\srv\share\x`), true},
		{"Write /??/UNC", "Write", write("/??/UNC/srv/x"), true},
		{"Read /??/UNC", "Read", read("/??/UNC/srv/x"), true},
		{"Glob path /??/UNC", "Glob", globPath("/??/UNC/srv/x"), true},
		// apply_patch 文件头 @ 开头。
		{"patch Add File @UNC", "apply_patch", patch(`*** Add File: @\\srv\share\x.txt` + "\n+CONFIDENTIAL"), true},
		{"patch Add File @//srv", "apply_patch", patch("*** Add File: @//srv/x\n+CONFIDENTIAL"), true},
		// 自动挂载目录。
		{"Write /net", "Write", write("/net/srv/share/x"), true},
		{"Write /Network/Servers", "Write", write("/Network/Servers/srv/x"), true},
		{"Write /./net", "Write", write("/./net/srv/x"), true},
		{"Write /tmp/../net", "Write", write("/tmp/../net/srv/x"), true},
		{"Write ../../../../net", "Write", write("../../../../net/srv/x"), true},
		{"Write /.vol", "Write", write("/.vol/1234/5678"), true},
		{"Write 反斜杠 \\net", "Write", write(`\net\srv\x`), true},
		{"patch Move to /net", "apply_patch", patch("*** Update File: src/a.c\n*** Move to: /net/srv/x\n@@\n-a\n+CONFIDENTIAL"), true},
		// codex 补丁的 Environment ID。
		{"patch Environment ID", "apply_patch", patch("*** Environment ID: env-1\n*** Add File: src/a.c\n+CONFIDENTIAL"), true},
		{"patch environment id 小写多空格", "apply_patch", patch("***  environment  id : env-1\n*** Update File: src/a.c\n@@\n-a\n+CONFIDENTIAL"), true},
		{"patch Environment ID 行首 U+FEFF", "apply_patch", patch("\ufeff*** Environment ID: env-1\n*** Add File: src/a.c\n+CONFIDENTIAL"), true},
		// 其他拿不准的首字符。
		{"Write @ 开头", "Write", write("@srv/share/x"), true},
		{"Write $HOME", "Write", write("$HOME/x"), true},
		{"Write %USERPROFILE%", "Write", write(`%USERPROFILE%\x`), true},
		{"Write 带引号", "Write", write(`"/tmp/x"`), true},
		{"Write ~user", "Write", write("~srv/x"), true},
		{"Write / 后接 U+200B", "Write", write("/\u200b/srv/x"), true},
		{"Write 前导 U+FEFF 本地路径", "Write", write("\ufeff/repo/a.c"), true},
		{"Glob pattern 花括号", "Glob", glob("{/,/srv}/x"), true},
		{"Glob pattern * 开头经 ../ 到 net", "Glob", glob("*/../../net/srv/*"), true},
		{"patch 冒号后 U+FEFF", "apply_patch", patch("*** Add File: \ufeffsrc/a.c\n+CONFIDENTIAL"), true},
		{"patch 冒号后 \\v", "apply_patch", patch("*** Add File: \vsrc/a.c\n+CONFIDENTIAL"), true},
		{"patch 文件头连前导空格超长", "apply_patch", patch("*** Add File: " + strings.Repeat("a", egressPatchHeaderMax) + "\n+CONFIDENTIAL"), true},
		{"patch +++ @//srv", "apply_patch", map[string]any{"input": "--- a/x\n+++ @//srv/x\n@@\n+CONFIDENTIAL\n"}, true},
		{"patch diff --git @//srv", "apply_patch", map[string]any{"input": "diff --git a/x @//srv/x\n"}, true},

		// 对照：Glob pattern 与 apply_patch 的本地写法。
		{"Glob **/*.c", "Glob", glob("**/*.c"), false},
		{"Glob src/**/*.h", "Glob", glob("src/**/*.h"), false},
		{"Glob 空 path", "Glob", globPath(""), false},
		{"patch Add File", "apply_patch", patch("*** Add File: src/a.c\n+// CONFIDENTIAL AND PROPRIETARY"), false},
		{"patch Update File 带上下文行", "apply_patch", patch("*** Update File: src/a.c\n@@ int main(void) {\n int x;\n-int y;\n+// CONFIDENTIAL\n return 0;"), false},
		{"patch Move to", "apply_patch", patch("*** Update File: src/a.c\n*** Move to: src/b.c\n@@\n-a\n+b"), false},
		{"patch Delete File", "apply_patch", patch("*** Delete File: src/old.c"), false},
		{"patch Add File Windows 盘符", "apply_patch", patch(`*** Add File: C:\Users\u\proj\a.c` + "\n+x"), false},
		{"patch CRLF", "apply_patch", map[string]any{"input": "*** Begin Patch\r\n*** Add File: src/a.c\r\n+x\r\n*** End Patch\r\n"}, false},
		{"unified diff +++ ---", "apply_patch", map[string]any{"input": "diff --git a/x b/x\n--- a/src/a.c\n+++ b/src/a.c\n@@ -1 +1 @@\n-a\n+// CONFIDENTIAL\n"}, false},
		{"unified diff --- /dev/null", "apply_patch", map[string]any{"input": "diff --git a/x b/x\nnew file mode 100644\n--- /dev/null\n+++ b/x\n@@ -0,0 +1 @@\n+// CONFIDENTIAL\n"}, false},
	}
	for _, tc := range cases {
		if got := ToolCallMayEgress(tc.tool, tc.args); got != tc.want {
			t.Errorf("%s: ToolCallMayEgress(%q, %q) = %v, want %v", tc.label, tc.tool, tc.args, got, tc.want)
		}
	}

	// 对照：现场常见的本地路径，Write、Read、Glob 的 path 都要保持 false。
	for _, path := range []string{
		"/home/u/proj/src/a.c", "/Users/u/proj/a.c", `C:\Users\u\proj\a.c`, "C:/Users/u/proj/a.c", `d:\work\a.c`,
		"src/a.c", "./src/a.c", "../lib/a.c", "~/proj/a.c", ".github/workflows/ci.yml", "_build/x", "3rdparty/x",
		"源码/驱动/a.c", "/home/u/my proj/a b.c", "/tmp/abs", "/dev/null", "~", `~\proj\a.c`, "-x.c", "/",
		// r2921i 复核：路径里有叫 net、proc 的普通目录、外接盘和 Data 卷上的本地路径、跳出工作区的兄弟目录、中文标点开头的顶层目录。
		"/home/u/linux/net/core/dev.c", "/Volumes/Work/proj/a.c", "/System/Volumes/Data/Users/u/proj/a.c", "/process/a.c",
		"/netdata/a.c", "/home/u/proj/.file/a.c", "/home/u/proc/a.c", "【设计】密级方案.md", "../common/network/client.py",
		"../linux/net/core/dev.c", "../lib/../shared/net/a.c",
	} {
		for _, call := range []struct {
			tool string
			args map[string]any
		}{{"Write", write(path)}, {"Read", read(path)}, {"Glob", globPath(path)}} {
			if ToolCallMayEgress(call.tool, call.args) {
				t.Errorf("本地路径 %q 在 %s 下应判 false", path, call.tool)
			}
		}
	}
}

// 2.9.21 r2921i 复核：
//   - BYP-1/CODE-01：/proc/self/root、/dev/fd、/System/Volumes/Data、/.resolve、/.nofollow、/.file、/Volumes/<启动卷>
//     这些别名能进到 /net、/Network 自动挂载目录，要判 true；
//   - BYP-2/CODE-04：带 _host、environment_id 这类分派参数的调用在别的机器或执行环境上执行，要判 true；
//   - REG-1/CODE-02：codex 补丁 Add/Update File 之后的正文行（删掉 "-- 注释" 得到的 "--- …"、上下文行）不是文件头；
//   - REG-2：工作区顶层目录以中文标点、带圈数字、罗马数字开头的相对路径算本地；
//   - REG-3：../ 开头的相对路径只看跳出之后的第一段；
//   - CODE-03：fileTypes、filePattern 这类通配键的值以 '*' 开头时按 Glob pattern 判。
func TestToolCallMayEgressReviewR2921i(t *testing.T) {
	write := func(path string) map[string]any {
		return map[string]any{"file_path": path, "content": "// CONFIDENTIAL AND PROPRIETARY\n"}
	}
	writeTo := func(path string) map[string]any { return map[string]any{"path": path, "content": "# 机密\n"} }
	patch := func(body string) map[string]any {
		return map[string]any{"input": "*** Begin Patch\n" + body + "\n*** End Patch\n"}
	}
	searchContent := func(key, value string) map[string]any {
		return map[string]any{"directory": "/repo", "pattern": "CONFIDENTIAL", key: value}
	}
	cases := []struct {
		label string
		tool  string
		args  map[string]any
		want  bool
	}{
		// BYP-1/CODE-01：内核魔术链接、macOS 的 Data 卷与 /.resolve 等别名进到自动挂载目录。
		{"Write /proc/self/root/net", "Write", write("/proc/self/root/net/srv/share/x"), true},
		{"Write /proc/thread-self/root/net", "Write", write("/proc/thread-self/root/net/srv/share/x"), true},
		{"Write /proc/1/root/net", "Write", write("/proc/1/root/net/srv/share/x"), true},
		{"Write /proc/self/cwd/../../net", "Write", write("/proc/self/cwd/../../net/srv/share/x"), true},
		{"Write /dev/fd/3/net", "Write", write("/dev/fd/3/net/srv/x"), true},
		{"Write /System/Volumes/Data/net", "Write", write("/System/Volumes/Data/net/srv/share/x"), true},
		{"Write /System/Volumes/Data/Network/Servers", "Write", write("/System/Volumes/Data/Network/Servers/srv/x"), true},
		{"Write /.resolve/0/net", "Write", write("/.resolve/0/net/srv/share/x"), true},
		{"Write /.resolve/0/Network/Servers", "Write", write("/.resolve/0/Network/Servers/srv/x"), true},
		{"Write /.nofollow/System/Volumes/Data/net", "Write", write("/.nofollow/System/Volumes/Data/net/srv/x"), true},
		{"Write /.file", "Write", write("/.file/id=16777220.2/x"), true},
		{"Write /Volumes/Macintosh HD/net", "Write", write("/Volumes/Macintosh HD/net/srv/x"), true},
		{"Write /Volumes/Macintosh HD/Network/Servers", "Write", write("/Volumes/Macintosh HD/Network/Servers/srv/x.c"), true},
		{"Write /Volumes/Macintosh HD/System/Volumes/Data/net", "Write", write("/Volumes/Macintosh HD/System/Volumes/Data/net/srv/x"), true},
		{"Read /proc/self/root/net", "Read", map[string]any{"file_path": "/proc/self/root/net/srv/机密-项目/x"}, true},
		{"Edit /proc/self/root/net", "Edit", map[string]any{"file_path": "/proc/self/root/net/srv/x.c", "old_string": "a", "new_string": "// CONFIDENTIAL"}, true},
		{"Glob pattern /proc/self/root/net", "Glob", map[string]any{"pattern": "/proc/self/root/net/srv/share/*"}, true},
		{"Glob path /System/Volumes/Data/net", "Glob", map[string]any{"pattern": "*", "path": "/System/Volumes/Data/net/srv/share"}, true},
		{"write_to_file filePath /proc/self/root/net", "write_to_file", map[string]any{"filePath": "/proc/self/root/net/srv/x.c", "content": "// 机密"}, true},
		{"LS /proc/self/root/net", "LS", map[string]any{"path": "/proc/self/root/net/srv"}, true},
		{"patch Add File /proc/self/root/net", "apply_patch", patch("*** Add File: /proc/self/root/net/srv/share/x.txt\n+CONFIDENTIAL"), true},
		{"patch Add File /.resolve/0/net", "apply_patch", patch("*** Add File: /.resolve/0/net/srv/share/x.txt\n+CONFIDENTIAL"), true},
		{"Write ../ 跳到 /proc/self/root/net", "Write", write("../../../proc/self/root/net/srv/x"), true},
		{"Write ../ 跳到 /System/Volumes/Data/net", "Write", write("../../System/Volumes/Data/net/srv/x"), true},
		{"Glob pattern * 开头经 ../ 到 /proc", "Glob", map[string]any{"pattern": "*/../../proc/self/root/net/srv/*"}, true},

		// REG-3：../ 开头只看跳出之后的第一段；上一轮钉住的写法仍判 true。
		{"Write ../../../../net", "Write", write("../../../../net/srv/x"), true},
		{"Write ../a/../../net", "Write", write("../a/../../net/srv/x"), true},
		{"Write ~/../../net", "Write", write("~/../../net/srv/x"), true},
		{"Write 反斜杠 ..\\..\\NET", "Write", write(`..\..\NET\srv\x`), true},
		{"Write ../../.vol", "Write", write("../../.vol/1/2"), true},
		{"Glob pattern * 开头经 ../ 到 net", "Glob", map[string]any{"pattern": "*/../../net/srv/*"}, true},
		{"write_to_file ../common/network", "write_to_file", writeTo("../common/network/client.py"), false},
		{"replace_in_file ../linux/net", "replace_in_file", map[string]any{"path": "../linux/net/core/dev.c", "diff": "------- SEARCH\na\n=======\n// CONFIDENTIAL\n+++++++ REPLACE"}, false},
		{"patch Update File ../shared/network", "apply_patch", patch("*** Update File: ../shared/network/http.c\n@@\n-a\n+// CONFIDENTIAL"), false},
		{"Glob pattern ../shared/net", "Glob", map[string]any{"pattern": "../shared/net/**/*.h"}, false},
		{"Glob path ../linux/net", "Glob", map[string]any{"pattern": "*.c", "path": "../linux/net"}, false},
		{"Grep path ../linux/net", "Grep", map[string]any{"pattern": "CONFIDENTIAL", "path": "../linux/net"}, false},
		{"read_file ../drivers/net", "read_file", map[string]any{"filePath": "../drivers/net/x.c"}, false},
		{"search_content ../pkg/network", "search_content", map[string]any{"directory": "../pkg/network", "pattern": "CONFIDENTIAL"}, false},

		// BYP-2/CODE-04：分派到别的机器或执行环境的参数。
		{"Write _host", "Write", map[string]any{"file_path": "/home/u/proj/src/a.c", "content": "CONFIDENTIAL", "_host": "gpu01"}, true},
		{"Edit _host", "Edit", map[string]any{"file_path": "src/a.c", "old_string": "a", "new_string": "CONFIDENTIAL", "_host": "build-box"}, true},
		{"Read _host", "Read", map[string]any{"file_path": "/home/u/机密.txt", "_host": "devbox"}, true},
		{"Glob _host", "Glob", map[string]any{"pattern": "**/*机密*", "_host": "devbox"}, true},
		{"Grep _host", "Grep", map[string]any{"pattern": "CONFIDENTIAL", "_host": "devbox"}, true},
		{"Write _host_context", "Write", map[string]any{"file_path": "src/a.c", "content": "CONFIDENTIAL", "_host_context": map[string]any{"name": "gpu01"}}, true},
		{"Write machine", "Write", map[string]any{"file_path": "src/a.c", "content": "CONFIDENTIAL", "machine": "gpu01"}, true},
		{"view_image environment_id", "view_image", map[string]any{"path": "diagram-机密.png", "environment_id": "remote-env"}, true},
		{"view_image environment_id 带 detail", "view_image", map[string]any{"path": "/tmp/CONFIDENTIAL AND PROPRIETARY.png", "environment_id": "remote-1", "detail": "high"}, true},
		{"view_image environmentId", "view_image", map[string]any{"path": "a.png", "environmentId": "remote-1"}, true},
		{"read_file env_id", "read_file", map[string]any{"file_path": "a.c", "env_id": "remote-1"}, true},
		{"view_image 不带 environment_id", "view_image", map[string]any{"path": "diagram-机密.png", "detail": "high"}, false},
		{"view_image environment_id 为空", "view_image", map[string]any{"path": "diagram-机密.png", "environment_id": ""}, false},
		{"Write 正文提到 host、environment_id", "Write", map[string]any{"file_path": "src/a.c", "content": "host: gpu01\nenvironment_id: remote-1\n// CONFIDENTIAL"}, false},

		// REG-1/CODE-02：codex 补丁正文行不是文件头。
		{"patch 删 SQL 横幅", "apply_patch", patch("*** Update File: db/proc.sql\n@@\n--- =============================================\n--- Author:\t\tdev\n--- =============================================\n+-- CONFIDENTIAL\n CREATE PROCEDURE p"), false},
		{"patch 删 -- @param", "apply_patch", patch("*** Update File: db/a.sql\n@@\n--- @param id 用户编号\n+-- CONFIDENTIAL"), false},
		{"patch 删 Haddock", "apply_patch", patch("*** Update File: src/L.hs\n@@\n--- | Compute level\n--- ^ the name\n+-- | CONFIDENTIAL"), false},
		{"patch 删各种符号开头的注释", "apply_patch", patch("*** Update File: db/v.sql\n@@\n--- (deprecated) old view\n--- $1 is the user id\n--- ****************\n--- [[ block\n--- （说明）\n--- #region\n+-- CONFIDENTIAL"), false},
		{"patch 删空注释行", "apply_patch", patch("*** Update File: db/a.sql\n@@\n--- \n+-- CONFIDENTIAL"), false},
		{"patch 上下文行 YAML 文档头", "apply_patch", patch("*** Update File: deploy/all.yaml\n@@\n --- # Source: chart/templates/svc.yaml\n --- \n +++ \n-a: 1\n+a: CONFIDENTIAL"), false},
		{"patch 上下文行 git 引号路径", "apply_patch", patch("*** Update File: fix.patch\n@@\n diff --git \"a/\\346\\272\\220.c\" \"b/\\346\\272\\220.c\"\n --- \"a/\\346\\272\\220.c\"\n +++ \"b/\\346\\272\\220.c\"\n-a\n+// CONFIDENTIAL"), false},
		{"patch Add File 正文 +++", "apply_patch", patch("*** Add File: src/a.lua\n+++ @param x\n+-- CONFIDENTIAL"), false},
		{"patch End of File 之后的块", "apply_patch", patch("*** Update File: db/a.sql\n@@\n-a\n+b\n*** End of File\n@@\n--- ====\n+-- CONFIDENTIAL"), false},
		{"patch 多个文件的正文", "apply_patch", patch("*** Update File: db/a.sql\n@@\n--- ====\n+-- x\n*** Update File: db/b.sql\n*** Move to: db/c.sql\n@@\n--- @param\n+-- CONFIDENTIAL"), false},
		{"patch CRLF 正文", "apply_patch", map[string]any{"input": "*** Begin Patch\r\n*** Update File: db/a.sql\r\n@@\r\n--- ====\r\n+-- CONFIDENTIAL\r\n*** End Patch\r\n"}, false},
		// 仍判 true：正文之后再出现的文件头、正文里的 Environment ID、codex 不认的正文行、Begin Patch 之外的 unified diff 头。
		{"patch 正文后 Add File //srv", "apply_patch", patch("*** Update File: src/a.c\n@@\n--- ====\n+b\n*** Add File: //srv/share/x\n+CONFIDENTIAL"), true},
		{"patch 正文后前导空格 Add File //srv", "apply_patch", patch("*** Update File: src/a.c\n@@\n-a\n *** Add File: //srv/share/x\n+CONFIDENTIAL"), true},
		{"patch 正文里 Environment ID", "apply_patch", patch("*** Update File: src/a.c\n@@\n-a\n*** Environment ID: env-1\n+CONFIDENTIAL"), true},
		{"patch 正文行 TAB 开头的 +++", "apply_patch", patch("*** Update File: src/a.c\n@@\n-a\n\t+++ //srv/share/x\n+CONFIDENTIAL"), true},
		{"patch Delete File 之后的 unified diff 头", "apply_patch", patch("*** Delete File: src/old.c\n--- a/x\n+++ //srv/share/x\n+CONFIDENTIAL"), true},
		{"patch End Patch 之后的 unified diff 头", "apply_patch", map[string]any{"input": "*** Begin Patch\n*** Update File: src/a.c\n@@\n-a\n+b\n*** End Patch\n--- a/x\n+++ //srv/share/x\n@@\n+CONFIDENTIAL\n"}, true},
		{"patch 文件头之前的 unified diff 头", "apply_patch", map[string]any{"input": "*** Begin Patch\n--- a/x\n+++ //srv/share/x\n*** Update File: src/a.c\n@@\n-a\n+CONFIDENTIAL\n*** End Patch\n"}, true},
		{"没有 Begin Patch 时 Update File 之后的 +++ 照判", "apply_patch", map[string]any{"input": "*** Update File: src/a.c\n--- a/x\n+++ //srv/share/x\n"}, true},

		// REG-2：顶层目录以中文标点、带圈数字、罗马数字开头的相对路径。
		{"write_to_file 【设计】", "write_to_file", writeTo("【设计】密级方案.md"), false},
		{"write_to_file （草稿）", "write_to_file", writeTo("（草稿）密级方案.md"), false},
		{"write_to_file 《用户手册》", "write_to_file", writeTo("《用户手册》.md"), false},
		{"write_to_file 「草稿」", "write_to_file", writeTo("「草稿」/a.md"), false},
		{"write_to_file ①需求", "write_to_file", writeTo("①需求.md"), false},
		{"write_to_file Ⅰ需求", "write_to_file", writeTo("Ⅰ需求.md"), false},
		{"write_to_file 〇号文件", "write_to_file", writeTo("〇号文件.md"), false},
		{"replace_in_file 【设计】", "replace_in_file", map[string]any{"path": "【设计】密级方案.md", "diff": "------- SEARCH\na\n=======\n机密\n+++++++ REPLACE"}, false},
		{"patch Add File 【设计】", "apply_patch", patch("*** Add File: 【设计】方案.md\n+# 机密"), false},

		// CODE-03：通配键的值以 '*' 开头。
		{"search_content fileTypes *.py", "search_content", searchContent("fileTypes", "*.py"), false},
		{"search_content fileTypes *.ts,*.tsx", "search_content", searchContent("fileTypes", "*.ts,*.tsx"), false},
		{"search_content fileTypes py", "search_content", searchContent("fileTypes", "py"), false},
		{"search_content filePattern *.c", "search_content", searchContent("filePattern", "*.c"), false},
		{"search_file filePattern *.c", "search_file", map[string]any{"target_directory": "/repo", "filePattern": "*.c"}, false},
		{"search_content fileTypes 花括号", "search_content", searchContent("fileTypes", "*.{ts,tsx}"), true},
		{"search_content fileTypes //srv", "search_content", searchContent("fileTypes", "//srv/share/*"), true},
		{"search_content fileTypes 反斜杠 UNC", "search_content", searchContent("fileTypes", `\\srv\share\*`), true},
		{"search_content fileTypes * 开头经 ../ 到 net", "search_content", searchContent("fileTypes", "*/../../../../net/srv/*"), true},
		{"search_content fileTypes scheme", "search_content", searchContent("fileTypes", "*smb://srv/share"), true},
	}
	for _, tc := range cases {
		if got := ToolCallMayEgress(tc.tool, tc.args); got != tc.want {
			t.Errorf("%s: ToolCallMayEgress(%q, %q) = %v, want %v", tc.label, tc.tool, tc.args, got, tc.want)
		}
	}

	// REG-2 放回本地的只是中文标点、带圈数字、罗马数字；会被 Windows best-fit 映射成 / 或 \ 的字符、全角空格、
	// 设计点名的 ASCII 符号仍算外发。
	for _, path := range []string{
		"／／srv/share/x", "＼＼srv＼share＼x", "∕∕srv/x", `∖∖srv\x`, `⧵⧵srv\x`, `﹨﹨srv\x`, `¥¥srv¥x`, `₩₩srv₩x`,
		"　/repo/a.c", "@/components/Level.vue", "[slug]/page.tsx", "{{cookiecutter.project_slug}}/setup.py", "$slug.tsx",
	} {
		if !ToolCallMayEgress("write_to_file", writeTo(path)) {
			t.Errorf("%q 不是本地写法，write_to_file 应判 true", path)
		}
	}
}

// 复验（r2921i recheck）留下的两类：POSIX 下 '\' 不是分隔符，"/home\x/.." 实际退到根；
// "~" 层数未知（root 的 HOME=/root 只有一层，HOME=/ 时是零层），"~/../net"、"~/net" 都可能落到 /net。
func TestToolCallMayEgressRecheckR2921i(t *testing.T) {
	write := func(path string) map[string]any {
		return map[string]any{"file_path": path, "content": "// CONFIDENTIAL AND PROPRIETARY\n"}
	}
	patch := func(body string) map[string]any {
		return map[string]any{"input": "*** Begin Patch\n" + body + "\n*** End Patch\n"}
	}
	cases := []struct {
		label string
		tool  string
		args  map[string]any
		want  bool
	}{
		{"Write /home\\x/../net", "Write", write(`/home\x/../net/srv/share/x`), true},
		{"Write /tmp/a\\b/../../net", "Write", write(`/tmp/a\b/../../net/srv/share/x`), true},
		{"Write /Users\\x/../Network/Servers", "Write", write(`/Users\x/../Network/Servers/srv/x`), true},
		{"Write /home\\x/../proc/self/root/net", "Write", write(`/home\x/../proc/self/root/net/srv/x`), true},
		{"Write /home\\x/../System/Volumes/Data/net", "Write", write(`/home\x/../System/Volumes/Data/net/srv/x`), true},
		{"Write /home\\x/../.resolve/0/net", "Write", write(`/home\x/../.resolve/0/net/srv/x`), true},
		{"Write 相对路径段里带 \\ 再退到根", "Write", write(`a\b\c\d\e\f\g\h/../../../../../../../../net/srv/x`), true},
		{"Read /home\\x/../net", "Read", map[string]any{"file_path": `/home\x/../net/srv/机密/x`}, true},
		{"write_to_file /home\\x/../net", "write_to_file", map[string]any{"filePath": `/home\x/../net/srv/x.c`, "content": "// 机密"}, true},
		{"Glob pattern /home\\x/../net", "Glob", map[string]any{"pattern": `/home\x/../net/srv/share/*`}, true},
		{"Glob path /home\\x/../net", "Glob", map[string]any{"pattern": "*", "path": `/home\x/../net/srv/share`}, true},
		{"patch Add File /tmp/a\\b/../../net", "apply_patch", patch(`*** Add File: /tmp/a\b/../../net/srv/share/x.txt` + "\n+CONFIDENTIAL"), true},
		{"Write ~/../net", "Write", write("~/../net/srv/share/x"), true},
		{"Write ~\\..\\net", "Write", write(`~\..\net\srv\x`), true},
		{"Write ~/../proc/self/root/net", "Write", write("~/../proc/self/root/net/x"), true},
		{"Write ~/../.resolve/0/net", "Write", write("~/../.resolve/0/net/x"), true},
		{"Edit ~/../net", "Edit", map[string]any{"file_path": "~/../net/srv/x.c", "old_string": "a", "new_string": "// CONFIDENTIAL"}, true},
		{"Glob path ~/../net", "Glob", map[string]any{"pattern": "*", "path": "~/../net/srv"}, true},
		{"patch Add File ~/../net", "apply_patch", patch("*** Add File: ~/../net/srv/x.c\n+CONFIDENTIAL"), true},
		{"Write ~/net（HOME=/）", "Write", write("~/net/srv/x.c"), true},

		{"Write ~", "Write", write("~"), false},
		{"Write ~/proj/a.c", "Write", write("~/proj/a.c"), false},
		{"Write ~\\proj\\a.c", "Write", write(`~\proj\a.c`), false},
		{"Write ~/../other/a.c", "Write", write("~/../other/a.c"), false},
		{"Write ~/proj/../other", "Write", write("~/proj/../other/a.c"), false},
		{"Write ~/.claude/settings.json", "Write", write("~/.claude/settings.json"), false},
		{"Write ~/projects/network/client.go", "Write", write("~/projects/network/client.go"), false},
		{"Write /home/u/proj/a\\b.c", "Write", write(`/home/u/proj/a\b.c`), false},
		{"Write src\\win\\a.c", "Write", write(`src\win\a.c`), false},
		{"Write C:\\Users\\u\\proj\\a.c", "Write", write(`C:\Users\u\proj\a.c`), false},
		{"Write C:\\Users\\u\\net\\a.c", "Write", write(`C:\Users\u\net\a.c`), false},
		{"Write ..\\..\\shared\\net\\a.c", "Write", write(`..\..\shared\net\a.c`), false},
		{"Write /home/u/proj/build/../src/a.c", "Write", write("/home/u/proj/build/../src/a.c"), false},
		{"patch Add File ~/proj/a.c", "apply_patch", patch("*** Add File: ~/proj/a.c\n+CONFIDENTIAL"), false},
	}
	for _, tc := range cases {
		if got := ToolCallMayEgress(tc.tool, tc.args); got != tc.want {
			t.Errorf("%s: ToolCallMayEgress(%q, %q) = %v, want %v", tc.label, tc.tool, tc.args, got, tc.want)
		}
	}
}
