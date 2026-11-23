package repository

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"
	"unicode/utf8"
)

const engineCapabilityDocsDir = "../../../../apps/security-engine/app/data/capability_docs"

func TestCapabilityDocsAreEmbeddedAndLookedUpByCategory(t *testing.T) {
	doc, ok := CapabilityDocFor("ssh_private_key")
	if !ok {
		t.Fatal("内嵌的能力说明里应有 ssh_private_key")
	}
	if doc.Display != "marker" || doc.Matches == "" || len(doc.HitExamples) == 0 || len(doc.MissExamples) == 0 || doc.JudgedByAI {
		t.Fatalf("说明内容不完整：%+v", doc)
	}
	if _, ok := CapabilityDocFor("no_such_capability"); ok {
		t.Fatal("不存在的能力不应返回说明")
	}
}

func inRange(text string, min, max int) bool {
	n := utf8.RuneCountInString(text)
	return n >= min && n <= max
}

func TestEveryEmbeddedCapabilityDocIsUsable(t *testing.T) {
	displays := map[string]bool{"marker": true, "credential": true, "identifier": true, "plain": true, "auto": true}
	checks := map[string]bool{"input": true, "output": true, "none": true}
	for category, doc := range capabilityDocs() {
		if category == "" || doc.Category != category {
			t.Errorf("能力键不一致：%q %+v", category, doc)
			continue
		}
		if !displays[doc.Display] {
			t.Errorf("%s: display %q 不是允许的取值", category, doc.Display)
		}
		if !checks[doc.Check] {
			t.Errorf("%s: check %q 不是允许的取值", category, doc.Check)
		}
		if doc.JudgedByAI && doc.Check != "none" {
			t.Errorf("%s: judged_by_ai 为真时 check 必须是 none，实际 %q", category, doc.Check)
		}
		if doc.Check != "none" && len(doc.MissExamples) < 1 {
			t.Errorf("%s: check 不是 none 时至少要有 1 条 miss_examples", category)
		}
		if !inRange(doc.Matches, 1, 200) {
			t.Errorf("%s: matches 须为 1-200 字", category)
		}
		if len(doc.HitExamples) < 1 || len(doc.HitExamples) > 3 {
			t.Errorf("%s: hit_examples 须为 1-3 条，实际 %d", category, len(doc.HitExamples))
		}
		if len(doc.MissExamples) > 2 {
			t.Errorf("%s: miss_examples 至多 2 条，实际 %d", category, len(doc.MissExamples))
		}
		for _, example := range append(append([]string{}, doc.HitExamples...), doc.MissExamples...) {
			if !inRange(example, 1, 300) {
				t.Errorf("%s: 示例须为 1-300 字：%q", category, example)
			}
		}
	}
}

// 引擎目录是唯一来源；这里直接和它做结构比较，来源改了没重新生成就失败。
func TestEmbeddedCapabilityDocsMatchTheEngineSource(t *testing.T) {
	const hint = "重新生成：python3 deploy/maintenance/gen_capability_docs.py"
	files, err := filepath.Glob(filepath.Join(engineCapabilityDocsDir, "*.json"))
	if err != nil || len(files) == 0 {
		t.Fatalf("读不到引擎的能力说明目录：%v", err)
	}
	sort.Strings(files)
	source := map[string]CapabilityDoc{}
	for _, file := range files {
		raw, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		var entries []CapabilityDoc
		if err := json.Unmarshal(raw, &entries); err != nil {
			t.Fatalf("%s 解析失败：%v", file, err)
		}
		for _, entry := range entries {
			if _, dup := source[entry.Category]; dup {
				t.Fatalf("%s: 能力键 %q 在引擎目录里重复", file, entry.Category)
			}
			source[entry.Category] = entry
		}
	}
	if !reflect.DeepEqual(source, capabilityDocs()) {
		t.Fatalf("控制面内嵌的能力说明与引擎来源不一致（来源 %d 条，内嵌 %d 条），%s", len(source), len(capabilityDocs()), hint)
	}
}

// 语义裁判类能力（component = security-engine.semantic，见 IsSemanticJudgeCapability）的类别，
// 取自建这些能力的迁移：125（semantic_roleplay、semantic_instruction_override）、
// 993（semantic_jailbreak、semantic_exfil_induce、semantic_harassment、semantic_threat、semantic_hate）、
// 995（prompt_input_semantic_risk）。目录里有它们的说明时，必须标明由智能分析判定。
// 是否靠 AI 判断以组件 security-engine.semantic 为准，不能按能力名前缀推断：
// semantic_negation_bypass、semantic_hypothetical_bypass、semantic_step_by_step_bypass、
// semantic_translation_bypass 虽以 semantic_ 开头，实际是提示注入检测器里的固定说法匹配，judged_by_ai 为 false。
func TestSemanticJudgeCapabilityDocsAreMarkedJudgedByAI(t *testing.T) {
	for _, category := range []string{
		"semantic_roleplay", "semantic_instruction_override",
		"semantic_jailbreak", "semantic_exfil_induce", "semantic_harassment", "semantic_threat", "semantic_hate",
		"prompt_input_semantic_risk",
	} {
		if !IsSemanticJudgeCapability(SecurityPolicyCapability{Category: category, Component: SemanticJudgeComponent}) {
			t.Fatalf("测试清单有误：%s 应被判为语义裁判能力", category)
		}
		if doc, ok := CapabilityDocFor(category); ok && !doc.JudgedByAI {
			t.Errorf("%s 是语义裁判能力，说明里 judged_by_ai 必须为真", category)
		}
	}
}

// 预置规则绑定的每一个检测能力都要有匹配说明和会命中的示例（2.9.19 起策略抽屉逐条显示）。
func TestEveryPreloadedCapabilityHasMatchDoc(t *testing.T) {
	var missing []string
	seen := map[string]bool{}
	for _, binding := range exactPolicyCapabilityBindings {
		for _, category := range binding.CapabilityCategories {
			if seen[category] {
				continue
			}
			seen[category] = true
			doc, ok := CapabilityDocFor(category)
			if !ok || doc.Matches == "" || len(doc.HitExamples) == 0 {
				missing = append(missing, category)
			}
		}
	}
	if len(seen) < 255 {
		t.Fatalf("预置规则绑定的检测能力只有 %d 个，少于 255，绑定表可能读错了", len(seen))
	}
	if len(missing) > 0 {
		t.Fatalf("预置规则绑定的 %d 个检测能力里有 %d 个没有匹配说明：%v", len(seen), len(missing), missing)
	}
}

// 有固定格式（引擎实测过）的能力，至少要给一个不会命中的示例。
func TestCheckedCapabilityDocsHaveMissExamples(t *testing.T) {
	for category, doc := range capabilityDocs() {
		if doc.Check != "none" && len(doc.MissExamples) == 0 {
			t.Errorf("%s 有固定格式，应至少有一个不会命中的示例", category)
		}
	}
}
