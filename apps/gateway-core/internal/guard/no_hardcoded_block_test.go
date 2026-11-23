// Package guard 放跨模块的守门测试。
package guard

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// 2.9.22 起不允许有不读配置的强制拦截（用户 2026-11-17 决定，设计 D1）。
// 这些标识出现在非测试代码里，就说明有人把“产品内置安全底线”加回来了。
// 7 月删过一次 hard_floor（1cfc78a7），10-05 又以 independent_safety_floor 加回（b105a128）。
var forbidden = []string{
	"independent_safety_floor",
	"enforceableFloorAction",
	"productSafetyFloor",
	"AdmissionFloor",
	"hardFloor",
	"fixedBlocked",
	"内置，不可关闭",
	"产品内置安全底线",
}

var scanRoots = []string{
	"apps/gateway-core",
	"apps/proxy-server",
	"apps/control-plane",
	"apps/security-engine/app",
	"apps/web-console/src",
	"packages/shared-go",
}

func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 8; i++ {
		if _, err := os.Stat(filepath.Join(dir, "packages", "shared-go", "go.mod")); err == nil {
			return dir
		}
		dir = filepath.Dir(dir)
	}
	t.Fatal("repo root not found")
	return ""
}

func isTestFile(name string) bool {
	return strings.HasSuffix(name, "_test.go") ||
		strings.Contains(name, ".test.") ||
		(strings.HasPrefix(name, "test_") && strings.HasSuffix(name, ".py"))
}

func scannable(name string) bool {
	for _, ext := range []string{".go", ".py", ".ts", ".tsx"} {
		if strings.HasSuffix(name, ext) {
			return true
		}
	}
	return false
}

// hits 返回 root 下非测试源文件里出现的禁用标识（相对路径 → 标识）。
func hits(t *testing.T, root string) map[string][]string {
	t.Helper()
	found := map[string][]string{}
	for _, base := range scanRoots {
		start := filepath.Join(root, base)
		if _, err := os.Stat(start); err != nil {
			t.Fatalf("scan root missing: %s", base)
		}
		err := filepath.WalkDir(start, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				switch d.Name() {
				case "node_modules", "dist", "test", "tests", "__pycache__", "vendor", "testdata":
					return filepath.SkipDir
				}
				return nil
			}
			if isTestFile(d.Name()) || !scannable(d.Name()) {
				return nil
			}
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			rel, _ := filepath.Rel(root, path)
			rel = filepath.ToSlash(rel)
			for _, word := range forbidden {
				if strings.Contains(string(data), word) {
					found[rel] = append(found[rel], word)
				}
			}
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", base, err)
		}
	}
	return found
}

func TestNoHardcodedSafetyFloorIdentifiers(t *testing.T) {
	found := hits(t, repoRoot(t))
	files := make([]string, 0, len(found))
	for rel := range found {
		files = append(files, rel)
	}
	sort.Strings(files)
	for _, rel := range files {
		t.Errorf("%s 含禁用标识 %q：2.9.22 起不允许不读配置的强制拦截，改成防护项配置", rel, found[rel])
	}
}
