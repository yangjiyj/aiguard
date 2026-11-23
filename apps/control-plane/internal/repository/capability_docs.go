package repository

import (
	_ "embed"
	"encoding/json"
	"log"
	"sync"
)

// capability_docs_gen.json 由 deploy/maintenance/gen_capability_docs.py 生成，来源是引擎里的
// apps/security-engine/app/data/capability_docs/*.json。不要手改，改了测试会报过期。
//
//go:embed capability_docs_gen.json
var capabilityDocsJSON []byte

// CapabilityDoc 是一个检测能力“具体匹配什么”的说明。
type CapabilityDoc struct {
	Category     string   `json:"category"`
	Display      string   `json:"display"`
	Matches      string   `json:"matches"`
	HitExamples  []string `json:"hit_examples"`
	MissExamples []string `json:"miss_examples"`
	JudgedByAI   bool     `json:"judged_by_ai"`
	Check        string   `json:"check"`
}

var (
	capabilityDocsOnce sync.Once
	capabilityDocsMap  map[string]CapabilityDoc
)

func capabilityDocs() map[string]CapabilityDoc {
	capabilityDocsOnce.Do(func() {
		var entries []CapabilityDoc
		capabilityDocsMap = map[string]CapabilityDoc{}
		if err := json.Unmarshal(capabilityDocsJSON, &entries); err != nil {
			log.Printf("嵌入的能力说明解析失败，页面将不显示“匹配什么”：%v", err)
			return // 不影响策略接口
		}
		for _, entry := range entries {
			capabilityDocsMap[entry.Category] = entry
		}
	})
	return capabilityDocsMap
}

// CapabilityDocFor 返回某个检测能力的说明；没有说明时第二个返回值为 false。
func CapabilityDocFor(category string) (CapabilityDoc, bool) {
	doc, ok := capabilityDocs()[category]
	return doc, ok
}
