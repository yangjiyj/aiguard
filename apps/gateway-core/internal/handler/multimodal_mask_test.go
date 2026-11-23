package handler

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
)

// 2.9.11 实测 N03/N10/N12/N13：OpenAI 格式带图片附件时，消息文本的脱敏不能降级成原文放行。

const pngDataURL = "data:image/png;base64,iVBORw0KGgo="

func multimodalMaskRequest(blocks string) *ChatCompletionRequest {
	return &ChatCompletionRequest{Model: "m", Messages: []Message{{Role: "user", Content: json.RawMessage(blocks)}}}
}

func decodeBlocks(t *testing.T, content json.RawMessage) []map[string]any {
	t.Helper()
	var blocks []map[string]any
	if err := json.Unmarshal(content, &blocks); err != nil {
		t.Fatalf("content 应保持多模态数组: %v; content=%s", err, content)
	}
	return blocks
}

func maskedEvents(writer *MockAuditWriter) (masked, unavailable []SecurityEventWrite) {
	for _, write := range writer.SecurityEventWrites {
		if write.ActionTaken == "security_masked" {
			masked = append(masked, write)
		}
		if write.MaskUnavailable {
			unavailable = append(unavailable, write)
		}
	}
	return masked, unavailable
}

func TestApplyInputSecurity_MaskTextBesideImageKeepsImage(t *testing.T) {
	writer := &MockAuditWriter{}
	h := &ChatCompletionsHandler{
		securityClient: &MockSecurityChecker{
			InputAction: "mask",
			InputMasked: "看图，手机号<MASKED>",
			InputFindings: []SecurityFinding{{
				Type: "pii", Category: "phone_cn", Action: "mask", Severity: "medium",
				MatchedLocation: "content[6:17]", ContentSource: "user",
			}},
		},
		auditWriter: writer,
	}
	req := multimodalMaskRequest(`[{"type":"text","text":"看图，手机号13800138000"},{"type":"image_url","image_url":{"url":"` + pngDataURL + `","detail":"low"}}]`)

	action, err := h.applyInputSecurity(context.Background(), &modelrouter.RequestEnvelope{RequestID: "r", TenantID: "t"}, req)
	if err != nil {
		t.Fatalf("applyInputSecurity err: %v", err)
	}
	if action != "mask" {
		t.Fatalf("输入侧动作应为 mask, got %q", action)
	}
	if strings.Contains(string(req.Messages[0].Content), "13800138000") {
		t.Fatalf("上游不应收到手机号原文: %s", req.Messages[0].Content)
	}
	blocks := decodeBlocks(t, req.Messages[0].Content)
	if len(blocks) != 2 || blocks[0]["text"] != "看图，手机号<MASKED>" {
		t.Fatalf("文本块应被脱敏且结构不变: %s", req.Messages[0].Content)
	}
	image, _ := blocks[1]["image_url"].(map[string]any)
	if blocks[1]["type"] != "image_url" || image["url"] != pngDataURL || image["detail"] != "low" {
		t.Fatalf("图片块应原样保留: %s", req.Messages[0].Content)
	}
	masked, unavailable := maskedEvents(writer)
	if len(masked) != 1 || len(unavailable) != 0 {
		t.Fatalf("应只记一条脱敏事件、不记无法脱敏: masked=%d unavailable=%d", len(masked), len(unavailable))
	}
}

func TestApplyInputSecurity_MaskAttachmentHitStillAlertsUnavailable(t *testing.T) {
	writer := &MockAuditWriter{}
	h := &ChatCompletionsHandler{
		securityClient: &MockSecurityChecker{
			InputAction: "mask",
			InputMasked: "工号[工号]",
			InputFindings: []SecurityFinding{
				{Type: "custom", Category: "employee", Action: "mask", MatchedLocation: "content[2:12]", ContentSource: "user"},
				{Type: "custom", Category: "employee", Action: "mask", MatchedLocation: "content[13:23]", ContentSource: "file_attachment",
					Triage: map[string]any{"mask_unavailable": true}},
			},
		},
		auditWriter: writer,
	}
	req := multimodalMaskRequest(`[{"type":"text","text":"工号EMP-123456"},{"type":"image_url","image_url":{"url":"` + pngDataURL + `"}}]`)

	if _, err := h.applyInputSecurity(context.Background(), &modelrouter.RequestEnvelope{RequestID: "r", TenantID: "t"}, req); err != nil {
		t.Fatalf("applyInputSecurity err: %v", err)
	}
	blocks := decodeBlocks(t, req.Messages[0].Content)
	if len(blocks) != 2 || blocks[0]["text"] != "工号[工号]" || blocks[1]["type"] != "image_url" {
		t.Fatalf("文本块脱敏、附件保留: %s", req.Messages[0].Content)
	}
	masked, unavailable := maskedEvents(writer)
	if len(masked) != 1 || len(unavailable) != 1 {
		t.Fatalf("文本脱敏一条、附件无法脱敏告警一条: masked=%d unavailable=%d", len(masked), len(unavailable))
	}
	if !strings.Contains(unavailable[0].Summary, "attachment") {
		t.Fatalf("无法脱敏告警应指向附件: %q", unavailable[0].Summary)
	}
}

func TestApplyInputSecurity_MaskWithoutMaskedTextStillDowngrades(t *testing.T) {
	writer := &MockAuditWriter{}
	h := &ChatCompletionsHandler{
		securityClient: &MockSecurityChecker{
			InputAction:   "mask",
			InputFindings: []SecurityFinding{{Type: "pii", Category: "phone_cn", Action: "mask", ContentSource: "file_attachment"}},
		},
		auditWriter: writer,
	}
	original := `[{"type":"text","text":"请看附件"},{"type":"image_url","image_url":{"url":"` + pngDataURL + `"}}]`
	req := multimodalMaskRequest(original)

	if _, err := h.applyInputSecurity(context.Background(), &modelrouter.RequestEnvelope{RequestID: "r", TenantID: "t"}, req); err != nil {
		t.Fatalf("applyInputSecurity err: %v", err)
	}
	if string(req.Messages[0].Content) != original {
		t.Fatalf("没有可改写文本时原样放行: %s", req.Messages[0].Content)
	}
	if _, unavailable := maskedEvents(writer); len(unavailable) != 1 {
		t.Fatalf("应记一条无法脱敏告警, got %d", len(unavailable))
	}
}

func TestMaskMessageTextContent(t *testing.T) {
	image := `{"type":"image_url","image_url":{"url":"` + pngDataURL + `"}}`
	cases := []struct {
		name, content, original, masked string
		wantTexts                       []string
		wantImages                      int
	}{
		{"纯字符串", `"手机号13800138000"`, "手机号13800138000", "手机号<MASKED>", nil, 0},
		{"单文本块", `[{"type":"text","text":"手机号13800138000"},` + image + `]`, "手机号13800138000", "手机号<MASKED>", []string{"手机号<MASKED>"}, 1},
		{"多文本块按行对齐", `[{"type":"text","text":"图一\n手机13800138000"},` + image + `,{"type":"text","text":"图二 工号EMP-123456"}]`,
			"图一\n手机13800138000\n图二 工号EMP-123456", "图一\n手机<MASKED>\n图二 工号[工号]",
			[]string{"图一\n手机<MASKED>", "图二 工号[工号]"}, 1},
		{"行数对不上时文本并入首块", `[{"type":"text","text":"A13800138000"},` + image + `,{"type":"text","text":"B"}]`,
			"A13800138000\nB", "A<MASKED> B", []string{"A<MASKED> B"}, 1},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := maskMessageTextContent(json.RawMessage(c.content), c.original, c.masked)
			if c.wantTexts == nil {
				if string(got) != string(jsonQuote(c.masked)) {
					t.Fatalf("got %s", got)
				}
				return
			}
			blocks := decodeBlocks(t, got)
			var texts []string
			images := 0
			for _, block := range blocks {
				switch block["type"] {
				case "text":
					texts = append(texts, block["text"].(string))
				case "image_url":
					images++
				}
			}
			if strings.Join(texts, "|") != strings.Join(c.wantTexts, "|") || images != c.wantImages {
				t.Fatalf("texts=%q images=%d; content=%s", texts, images, got)
			}
			if strings.Contains(string(got), "13800138000") || strings.Contains(string(got), "EMP-123456") {
				t.Fatalf("不应残留原文: %s", got)
			}
		})
	}
}
