package handler

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestInspectionPlanCoversLargeContentAndBoundary(t *testing.T) {
	text := strings.Repeat("甲", 4090) + "SYNTHETIC-BOUNDARY-SECRET" + strings.Repeat("乙", 20000) + "TAIL-RISK"
	parts := inspectionTextParts(text)
	if len(parts) < 2 {
		t.Fatal("not chunked")
	}
	covered := ""
	for i, p := range parts {
		if len([]rune(p)) > 4096 {
			t.Fatal("unbounded chunk")
		}
		if i == 0 {
			covered = p
		} else {
			covered += string([]rune(p)[512:])
		}
	}
	if covered != text {
		t.Fatal("text lost at chunk boundary")
	}
	found := false
	for _, p := range parts {
		if strings.Contains(p, "SYNTHETIC-BOUNDARY-SECRET") {
			found = true
		}
	}
	if !found || !strings.Contains(parts[len(parts)-1], "TAIL-RISK") {
		t.Fatal("boundary or tail omitted")
	}
}
func TestInspectionPlanSeparatesAttachmentsAndSources(t *testing.T) {
	e := ExtractedContent{Messages: []ConvMessage{{Source: "user", Content: "customer"}, {Source: "tool_result", Content: "tool data"}}, Attachments: []ExtractedAttachment{{ContentType: "image/png", DataBase64: strings.Repeat("A", 64*1024*1024)}}}
	p := map[string]interface{}{"request_id": "r", "content": "unused", "context": map[string]interface{}{"tenant_id": "t"}}
	tasks, err := buildInspectionPlan(p, e)
	if err != nil || len(tasks) != 3 {
		t.Fatalf("parts=%d err=%v", len(tasks), err)
	}
	for _, task := range tasks[:2] {
		b, _ := json.Marshal(task)
		if len(b) > 8192 {
			t.Fatal("base64 entered text scanner")
		}
	}
	if tasks[0]["content_source"] != "user" || tasks[1]["content_source"] != "tool_result" {
		t.Fatal("sources flattened")
	}
}

func TestInspectionFullTextAndCompressedTailSurviveRetentionLimits(t *testing.T) {
	text := strings.Repeat("normal technical content. ", 100000) + "TAIL-RISK"
	raw, _ := json.Marshal(map[string]interface{}{"messages": []interface{}{map[string]interface{}{"role": "user", "content": text}}})
	var zipped bytes.Buffer
	z := gzip.NewWriter(&zipped)
	_, _ = z.Write(raw)
	_ = z.Close()
	decoded, err := decodeInspectionBody(zipped.Bytes(), "gzip")
	if err != nil || !bytes.Equal(raw, decoded) {
		t.Fatalf("compressed content truncated: %v", err)
	}
	req := httptest.NewRequest("POST", "https://api.openai.com/v1/chat/completions", nil)
	req.Header.Set("Content-Type", "application/json")
	decoder, _ := detectLLMDecoders(req.Host, req.URL.Path)
	extracted := extractRequestContentWithDecoder(req, decoded, decoder)
	plan, err := buildInspectionPlan(simplePlan("")[0], extracted)
	if err != nil {
		t.Fatal(err)
	}
	tail := false
	for _, p := range plan {
		if strings.Contains(fmt.Sprint(p["content"]), "TAIL-RISK") {
			tail = true
		}
	}
	if !tail {
		t.Fatal("security plan used truncated retention preview")
	}
}

// 生产事故回归（2026-09）：unknown 来源的超长载荷（如未识别多模态类型的
// compactJSON，单请求 1.8MB）不得无限窗口化灌爆裁判队列——收敛为上限窗口 +
// 显式截断除证，而不是静默吞掉。
func TestInspectionPlanCapsUnknownSourceWindows(t *testing.T) {
	huge := strings.Repeat("甲", 3584*120) // ~120 正常窗
	extracted := ExtractedContent{Messages: []ConvMessage{{Source: "unknown", Content: huge}}}
	plan, err := buildInspectionPlan(simplePlan("")[0], extracted)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan) != 16 {
		t.Fatalf("unknown 载荷必须收敛到 16 片，got %d", len(plan))
	}
	last := fmt.Sprint(plan[len(plan)-1]["content"])
	if !strings.Contains(last, "已收敛为前 15 窗送审") {
		t.Fatalf("末窗必须带截断除证标记，got: %.80s", last)
	}
	for _, p := range plan {
		if p["content_source"] != "unknown" {
			t.Fatalf("截断窗口必须是 unknown 来源: %v", p["content_source"])
		}
	}
}

// 未超上限的 unknown 载荷行为不变。
func TestInspectionPlanSmallUnknownSourceUnchanged(t *testing.T) {
	extracted := ExtractedContent{Messages: []ConvMessage{{Source: "unknown", Content: strings.Repeat("x", 5000)}}}
	plan, err := buildInspectionPlan(simplePlan("")[0], extracted)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan) != 2 {
		t.Fatalf("小 unknown 载荷窗口数不得变化（4096+904→2 片），got %d", len(plan))
	}
	if strings.Contains(fmt.Sprint(plan[len(plan)-1]["content"]), "送审") {
		t.Fatal("未截断不得有除证标记")
	}
}

// 类型化来源（user/tool_result 等）不受 unknown 窗口上限影响。
func TestInspectionPlanTypedSourceNotCapped(t *testing.T) {
	huge := strings.Repeat("乙", 3584*20)
	extracted := ExtractedContent{Messages: []ConvMessage{{Source: "user", Content: huge}}}
	plan, err := buildInspectionPlan(simplePlan("")[0], extracted)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan) <= 16 {
		t.Fatalf("类型化来源不得被 unknown 上限截断，got %d", len(plan))
	}
}

