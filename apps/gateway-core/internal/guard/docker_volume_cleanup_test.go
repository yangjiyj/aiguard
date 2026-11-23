package guard

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// 测试代码删容器必须带 -v（docker rm -f -v）：postgres 等镜像声明了 VOLUME，每次 docker run 都会建匿名卷，
// 不带 -v 时即使容器是 --rm 起的，被 rm -f 删掉后匿名卷也会留下。11-18 home 的 /fast 被测试辅助
// 每小时数百个泄漏的匿名卷撑满。辅助的约定见 packages/shared-go/testcontainer 与
// deploy/tests/lib/test-containers.sh。

// dockerRmAllowlist 是允许出现不带 -v 的 docker rm 的测试文件（相对仓库根）和理由。
// 只收不执行的文本（分析器样本、禁用词清单）；名单里的文件不再命中时要删掉条目。
var dockerRmAllowlist = map[string]string{
	"apps/gateway-core/internal/agentguard/destructive_test.go":       "破坏性命令分析器的输入样本（字符串），不执行",
	"apps/gateway-core/internal/handler/destructive_evidence_test.go": "破坏性命令证据展示的输入样本（字符串），不执行",
}

// dockerRmGuardSelf 是本文件：说明、正则和匹配器用例里都写着 docker rm，扫描时跳过。
const dockerRmGuardSelf = "apps/gateway-core/internal/guard/docker_volume_cleanup_test.go"

var (
	// 命令行写法：docker rm、docker container rm、"$docker_cmd" rm，后面跟着的选项。
	shellDockerRm = regexp.MustCompile(`\bdocker(?:_cmd)?["']?\s+(?:container\s+)?rm\b((?:\s+-{1,2}[A-Za-z][A-Za-z-]*)*)`)
	// 参数列表写法（Go、Python）："rm", "-f" …，可带前一个参数（"docker"、"container"、"image" 等）。
	listDockerRm = regexp.MustCompile(`(?:["']([A-Za-z_]+)["']\s*,\s*)?["']rm["']((?:\s*,\s*["']-{1,2}[A-Za-z][A-Za-z-]*["'])*)`)
	listFlag     = regexp.MustCompile(`["'](-{1,2}[A-Za-z][A-Za-z-]*)["']`)
	dockerRmFlag = regexp.MustCompile(`^(-[flv]+|--force|--volumes|--link)$`)
)

func hasVolumesFlag(flags []string) bool {
	for _, flag := range flags {
		if flag == "--volumes" || (strings.HasPrefix(flag, "-") && !strings.HasPrefix(flag, "--") && strings.Contains(flag, "v")) {
			return true
		}
	}
	return false
}

// dockerRmWithoutVolumes 返回一行里不带 -v 的 docker rm 写法。
func dockerRmWithoutVolumes(line string) []string {
	var found []string
	for _, m := range shellDockerRm.FindAllStringSubmatch(line, -1) {
		if !hasVolumesFlag(strings.Fields(m[1])) {
			found = append(found, strings.TrimSpace(m[0]))
		}
	}
	for _, m := range listDockerRm.FindAllStringSubmatch(line, -1) {
		prev := m[1]
		var flags []string
		for _, f := range listFlag.FindAllStringSubmatch(m[2], -1) {
			flags = append(flags, f[1])
		}
		switch prev {
		case "image", "volume", "network", "rmi":
			continue
		}
		docker := prev == "docker" || prev == "container"
		if !docker && len(flags) > 0 {
			docker = true
			for _, flag := range flags {
				if !dockerRmFlag.MatchString(flag) {
					docker = false // 如 "rm", "-rf"：文件删除，不是 docker rm
				}
			}
		}
		if docker && !hasVolumesFlag(flags) {
			found = append(found, strings.TrimSpace(m[0]))
		}
	}
	return found
}

// isContainerTestCode 判断相对路径是不是会起容器的测试代码（含测试辅助包、测试工具脚本）。
func isContainerTestCode(rel string) bool {
	name := filepath.Base(rel)
	ext := filepath.Ext(name)
	if ext != ".go" && ext != ".sh" && ext != ".py" && ext != ".bash" {
		return false
	}
	switch {
	case strings.HasSuffix(name, "_test.go"), strings.HasSuffix(name, ".e2e.sh"),
		strings.HasPrefix(name, "test_") && ext == ".py", strings.HasSuffix(name, "_test.py"):
		return true
	}
	for _, prefix := range []string{"deploy/tests/", "deploy/docker-compose/tests/", "tests/", "tools/performance/", "packages/shared-go/testcontainer/"} {
		if strings.HasPrefix(rel, prefix) {
			return true
		}
	}
	return strings.HasPrefix(rel, "scripts/") && strings.Contains(name, "test")
}

func TestDockerRmMatcher(t *testing.T) {
	d := "dock" + "er" // 拆开写，免得本文件自己命中
	bad := []string{
		d + ` rm -f "$container" >/dev/null`,
		`trap '` + d + ` rm -f ngx-a ngx-b' EXIT`,
		`xargs -r ` + d + ` rm -f`,
		`"$` + d + `_cmd" rm -f "$cid"`,
		d + ` container rm --force x`,
		d + ` rm "$portal" "$core"`,
		`run("", "rm", "-f", name)`,
		`exec.Command("` + d + `", "rm", "-f", id)`,
		`['` + d + `', 'rm', id]`,
	}
	good := []string{
		d + ` rm -f -v "$container"`,
		d + ` rm -fv x`,
		d + ` rm -vf x`,
		d + ` rm --force --volumes x`,
		`run(ctx, "rm", "-f", "-v", id)`,
		d + ` network rm net`,
		d + ` volume rm -f vol`,
		d + ` image rm -f img`,
		d + ` rmi img`,
		`['` + d + `', 'image', 'rm', '-f', base]`,
		`[]any{"rm", "-rf", "/srv/data"}`,
		`[]string{"rm", "-rf", "/opt/My Dir"}`,
		`rm -f "$tmp"`,
	}
	for _, line := range bad {
		if len(dockerRmWithoutVolumes(line)) == 0 {
			t.Errorf("should flag: %s", line)
		}
	}
	for _, line := range good {
		if found := dockerRmWithoutVolumes(line); len(found) != 0 {
			t.Errorf("should not flag %s: %v", line, found)
		}
	}
}

func TestTestCodeRemovesContainersWithVolumes(t *testing.T) {
	root := repoRoot(t)
	hitsByFile := map[string][]string{}
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			switch entry.Name() {
			case ".git", "node_modules", "vendor", "dist", "__pycache__", ".venv":
				return filepath.SkipDir
			}
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		rel = filepath.ToSlash(rel)
		if rel == dockerRmGuardSelf || !isContainerTestCode(rel) {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for i, line := range strings.Split(string(data), "\n") {
			for _, found := range dockerRmWithoutVolumes(line) {
				hitsByFile[rel] = append(hitsByFile[rel], strconv.Itoa(i+1)+": "+found)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	var files []string
	for rel := range hitsByFile {
		files = append(files, rel)
	}
	sort.Strings(files)
	for _, rel := range files {
		if _, allowed := dockerRmAllowlist[rel]; allowed {
			continue
		}
		t.Errorf("%s 删容器没带 -v（会泄漏匿名卷），改成 docker rm -f -v 或 testcontainer.RemoveArgs：%s", rel, strings.Join(hitsByFile[rel], "；"))
	}
	for rel, reason := range dockerRmAllowlist {
		if len(hitsByFile[rel]) == 0 {
			t.Errorf("%s 已不含不带 -v 的 docker rm，请从 dockerRmAllowlist 删除（%s）", rel, reason)
		}
	}
}
