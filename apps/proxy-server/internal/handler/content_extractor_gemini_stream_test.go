package handler

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

// buildGeminiStreamFixture 构造忠实复刻 Gemini 网页 StreamGenerate 响应线格式的合成 fixture，
// 不含任何真实用户明文（安全：MITM 抓到的对话明文不得落入仓库/testdata）。线格式：
//
//	)]}'\n\n  +  反复的「<chunk字节长度>\n[["wrb.fr",null,"<内层JSON>"]]\n」
//
// 内层结构关键位（真实抓包 015 验证）：
//
//	inner[4][0][0]        = "rc_…" 候选 ID
//	inner[4][0][1][0]     = 模型回答正文
//	inner[4][0][37][0][0] = 思考过程(reasoning)
//
// 另在 inner[26] 塞入回答重复段落、inner[44] 塞入 UI 建议气泡，复现既有盲遍历把同一回答跨帧
// 重复抓取、并把思考草稿/重复段落/建议气泡一并当正文的 bug（访问留存里「一堆乱七八糟」）。
func buildGeminiStreamFixture(answer, reasoning string, chips []string, snapshots int) []byte {
	makeFirst := func() []interface{} {
		first := make([]interface{}, 38)
		first[0] = "rc_4d335c8b1c3eec7d"
		first[1] = []interface{}{answer}
		first[37] = []interface{}{[]interface{}{reasoning}}
		return first
	}
	makeInner := func() []interface{} {
		inner := make([]interface{}, 45)
		inner[1] = []interface{}{"c_synthetic", "r_synthetic", "rc_synthetic"}
		inner[4] = []interface{}{makeFirst()}
		inner[26] = []interface{}{answer} // 回答重复段落（盲遍历会再抓一次）
		chipList := make([]interface{}, 0, len(chips))
		for _, c := range chips {
			chipList = append(chipList, c)
		}
		inner[44] = chipList // UI 建议气泡（盲遍历会误当正文）
		return inner
	}
	var b strings.Builder
	b.WriteString(")]}'\n\n")
	for i := 0; i < snapshots; i++ {
		innerJSON, _ := json.Marshal(makeInner())
		row, _ := json.Marshal([]interface{}{[]interface{}{"wrb.fr", nil, string(innerJSON)}})
		b.WriteString(fmt.Sprintf("%d\n", len(row)))
		b.Write(row)
		b.WriteString("\n")
	}
	return []byte(b.String())
}

// TestExtractGeminiStreamGenerate_CleanConversation 锁定 Gemini Bug A 的修复目标：
// 访问留存里只出现一次干净回答、思考过程被 [reasoning] 标记并排在回答前、不夹带任何 UI 建议气泡。
func TestExtractGeminiStreamGenerate_CleanConversation(t *testing.T) {
	answer := "你好，这是模型给出的最终回答，应当只出现一次。"
	reasoning := "Interpreting the Query\nClarifying the user's intent before replying."
	chips := []string{"详尽一点", "简短一点", "不个性化", "重试", "立即回答"}
	// 3 帧增长快照，每帧都含完整回答 —— 复现「同一回答跨帧重复」的现场。
	fixture := buildGeminiStreamFixture(answer, reasoning, chips, 3)

	got := extractResponseContent(fixture, "application/json; charset=utf-8")

	if c := strings.Count(got.Text, answer); c != 1 {
		t.Fatalf("回答应恰好出现 1 次（不得跨快照/重复段落重复），实际 %d 次。\n--- 抽取结果 ---\n%s", c, got.Text)
	}
	if !strings.Contains(got.Text, "[reasoning] Interpreting the Query") {
		t.Fatalf("思考过程应被 [reasoning] 逐行标记并与回答分离，实际：\n%s", got.Text)
	}
	for _, chip := range chips {
		if strings.Contains(got.Text, chip) {
			t.Fatalf("UI 建议气泡 %q 不应出现在会话正文里，实际：\n%s", chip, got.Text)
		}
	}
	ri := strings.Index(got.Text, "[reasoning]")
	ai := strings.Index(got.Text, answer)
	if ri == -1 || ai == -1 || ri > ai {
		t.Fatalf("思考过程应排在回答之前（reasoning idx=%d, answer idx=%d）：\n%s", ri, ai, got.Text)
	}
}

// TestExtractGoogleBatchExecute_SummaryFallback 守护回退路径：batchexecute 摘要总线没有 rc_ 回答
// 候选帧，必须仍走既有盲遍历抓取人类文本，不能被 StreamGenerate 结构化解析吞掉（误判为空）。
func TestExtractGoogleBatchExecute_SummaryFallback(t *testing.T) {
	const human = "这是摘要总线里的一段普通文本应当照常抓取"
	inner, _ := json.Marshal([]interface{}{"af.httprm", nil, human})
	row, _ := json.Marshal([]interface{}{[]interface{}{"wrb.fr", nil, string(inner)}})
	body := []byte(fmt.Sprintf(")]}'\n\n%d\n%s\n", len(row), row))

	got := extractResponseContent(body, "application/json; charset=utf-8")
	if !strings.Contains(got.Text, human) {
		t.Fatalf("batchexecute 摘要文本应仍由盲遍历抓取，实际：\n%s", got.Text)
	}
}
