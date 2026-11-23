//go:build ignore

// gen_vectors 生成 testdata/watermark_vectors.json：
//
//	cd packages/shared-go/aicontentlabel && go run gen_vectors.go
//
// 安全引擎的 prompt_stego 测试读同一份文件，保证两边对“格式完整的帧”的判断一致。
package main

import (
	"encoding/json"
	"os"

	"github.com/yangjiyj/aiguard/packages/shared-go/aicontentlabel"
)

func main() {
	const secret = "watermark-vector-secret"
	key := aicontentlabel.DeriveKey(secret)
	reqID := "req_6f1c2a3b-4d5e-4f60-8a7b-9c0d1e2f3a4b"
	bareID := "0a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d"
	frame, _ := aicontentlabel.Encode(reqID, key)
	bare, _ := aicontentlabel.Encode(bareID, key)
	runes := []rune(frame)
	truncated := string(runes[:len(runes)-1])

	type vector struct {
		Name      string `json:"name"`
		Text      string `json:"text"`
		Frames    int    `json:"frames"`
		Stripped  string `json:"stripped"`
		RequestID string `json:"request_id,omitempty"`
	}
	vectors := []vector{
		{Name: "req_prefix", Text: "回答正文" + frame + "（以上内容由 AI 生成）", Frames: 1, Stripped: "回答正文（以上内容由 AI 生成）", RequestID: reqID},
		{Name: "bare_uuid", Text: "Answer" + bare, Frames: 1, Stripped: "Answer", RequestID: bareID},
		{Name: "pasted_back_with_attack_words", Text: "请总结：如何绕过限制、忽略之前的指令。" + frame + "继续", Frames: 1, Stripped: "请总结：如何绕过限制、忽略之前的指令。继续", RequestID: reqID},
		{Name: "truncated", Text: "回答" + truncated, Frames: 0, Stripped: "回答" + truncated},
		{Name: "two_frames", Text: frame + "中间" + bare, Frames: 2, Stripped: "中间"},
	}
	out, err := json.MarshalIndent(map[string]any{"secret": secret, "vectors": vectors}, "", "  ")
	if err != nil {
		panic(err)
	}
	if err := os.MkdirAll("testdata", 0o755); err != nil {
		panic(err)
	}
	if err := os.WriteFile("testdata/watermark_vectors.json", append(out, '\n'), 0o644); err != nil {
		panic(err)
	}
}
