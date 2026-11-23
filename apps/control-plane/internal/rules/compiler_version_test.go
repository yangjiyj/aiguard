package rules

import (
	"regexp"
	"testing"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

// 3.7 RED：内容版本号 ContentVersion 应是规则包内容的确定性指纹，
// 用于「版本号 + 回滚安全的引擎重载 + 按节点拉取可见性」三件事的统一锚点。
// 这些断言引用尚不存在的 ContentVersion / RulePack.Version → 编译失败即正确的 RED。

func TestContentVersionIsDeterministic(t *testing.T) {
	p1 := Compile("tenant_default", []*repository.Rule{medicalRule()}, nil)
	p2 := Compile("tenant_default", []*repository.Rule{medicalRule()}, nil)
	if ContentVersion(p1) != ContentVersion(p2) {
		t.Fatalf("相同内容必须得到相同版本：%q != %q", ContentVersion(p1), ContentVersion(p2))
	}
}

func TestContentVersionIgnoresRuleOrder(t *testing.T) {
	a := Compile("tenant_default", []*repository.Rule{medicalRule(), privateKeyRule()}, nil)
	b := Compile("tenant_default", []*repository.Rule{privateKeyRule(), medicalRule()}, nil)
	if ContentVersion(a) != ContentVersion(b) {
		t.Fatalf("规则顺序不应影响版本（应先排序再哈希）：%q != %q", ContentVersion(a), ContentVersion(b))
	}
}

func TestContentVersionIgnoresGeneratedAt(t *testing.T) {
	p := Compile("tenant_default", []*repository.Rule{medicalRule()}, nil)
	v := ContentVersion(p)
	p.GeneratedAt = "2099-01-01T00:00:00Z"
	if ContentVersion(p) != v {
		t.Fatalf("generated_at 仅为盖戳时间，不应进入内容指纹：%q != %q", ContentVersion(p), v)
	}
}

func TestContentVersionChangesWithContent(t *testing.T) {
	one := Compile("tenant_default", []*repository.Rule{medicalRule()}, nil)
	two := Compile("tenant_default", []*repository.Rule{medicalRule(), privateKeyRule()}, nil)
	if ContentVersion(one) == ContentVersion(two) {
		t.Fatalf("规则集变化必须改变版本，否则回滚/变更不可见")
	}
}

func TestContentVersionChangesWithReplyPolicy(t *testing.T) {
	one := RulePack{TenantID: "tenant-a", Rules: []CompiledRule{}, Exceptions: []CompiledException{}, ReplyPolicy: &ReplyPolicy{SchemaVersion: 1, Enabled: true, Templates: map[string]string{"default": "A"}}}
	two := one
	two.ReplyPolicy = &ReplyPolicy{SchemaVersion: 1, Enabled: true, Templates: map[string]string{"default": "B"}}

	if ContentVersion(one) == ContentVersion(two) {
		t.Fatal("reply policy changes must alter the rule pack version")
	}
}

func TestCompileStampsContentVersion(t *testing.T) {
	p := Compile("tenant_default", []*repository.Rule{medicalRule()}, nil)
	if p.Version == "" {
		t.Fatalf("Compile 必须把 Version 盖进 RulePack")
	}
	if p.Version != ContentVersion(p) {
		t.Fatalf("pack.Version 必须等于 ContentVersion(pack)：%q != %q", p.Version, ContentVersion(p))
	}
	if len(p.Version) != 16 {
		t.Fatalf("Version 约定为 16 位十六进制（sha256 前 8 字节）：实际长度 %d", len(p.Version))
	}
	if !regexp.MustCompile(`^[0-9a-f]{16}$`).MatchString(p.Version) {
		t.Fatalf("Version 必须是小写十六进制：%q", p.Version)
	}
}

func TestAuthoringMetadataNotInRuntimePackOrVersion(t *testing.T) {
	original := medicalRule()
	original.ScopeJSON = []byte(`{"scene":"data_security","_authoring":{"version":1,"kind":"number","matcher_pattern":"test","segments":[{"kind":"digits","length":8}]}}`)
	withMeta := Compile("tenant_default", []*repository.Rule{original}, nil)
	original.ScopeJSON = []byte(`{"scene":"data_security"}`)
	withoutMeta := Compile("tenant_default", []*repository.Rule{original}, nil)
	if len(withMeta.Rules) != 1 || len(withoutMeta.Rules) != 1 {
		t.Fatalf("rule was not compiled: %d/%d", len(withMeta.Rules), len(withoutMeta.Rules))
	}
	if _, leaked := withMeta.Rules[0].Scope["_authoring"]; leaked {
		t.Fatal("author metadata leaked to runtime")
	}
	if withMeta.Version != withoutMeta.Version {
		t.Fatalf("author-only scope changed runtime version: %s/%s", withMeta.Version, withoutMeta.Version)
	}
}
