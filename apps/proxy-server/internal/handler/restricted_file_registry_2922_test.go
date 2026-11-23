package handler

import (
	"reflect"
	"testing"

	"github.com/yangjiyj/aiguard/packages/shared-go/protection"
)

// 复审第 3 项（部分）：指向受限文件的例外写法取注册表（防护项键与它的原因码），不再写死。
func TestRestrictedFileExceptionRule2922FollowsTheRegistry(t *testing.T) {
	item, ok := protection.Lookup(protection.KeyRestrictedFile)
	if !ok || len(item.Reasons) == 0 {
		t.Fatalf("registry must define %s with reasons", protection.KeyRestrictedFile)
	}
	for _, rule := range append([]string{protection.KeyRestrictedFile, " " + protection.KeyRestrictedFile + " "}, item.Reasons...) {
		if !restrictedFileExceptionRule(rule) {
			t.Errorf("%q names the restricted-file item", rule)
		}
	}
	for _, rule := range []string{"", "agent.ssh_private_key", "blocked_ssh_private_key_path", "restricted_file"} {
		if restrictedFileExceptionRule(rule) {
			t.Errorf("%q does not name the restricted-file item", rule)
		}
	}
}

// 复审次要项：路径参数按键排序遍历，命中顺序（拦截预览取第一条）稳定。
func TestFileToolPathArguments2922StableOrder(t *testing.T) {
	arguments := `{"file_path":"/a/secret.pem","destination":"/b/key.pem","target":"/c/id.pem","nested":{"path":"/d/x.pem","files":["/e/1.pem","/e/2.pem"]}}`
	want := []string{"/b/key.pem", "/a/secret.pem", "/e/1.pem", "/e/2.pem", "/d/x.pem", "/c/id.pem"}
	for i := 0; i < 50; i++ {
		if got := fileToolPathArguments(arguments); !reflect.DeepEqual(got, want) {
			t.Fatalf("run %d: got %v want %v", i, got, want)
		}
	}
}
