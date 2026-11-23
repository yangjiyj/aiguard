package handler

import "testing"

func TestReverseProxyOutputProjectionIncludesResponsesArtifact(t *testing.T) {
	body := []byte(`{
  "model":"gpt-5",
  "output":[{
    "type":"message",
    "role":"assistant",
    "content":[
      {"type":"output_text","text":"已生成附件"},
      {"type":"file","filename":"result.txt","file_url":"file-output-1"}
    ]
  }]
}`)
	projection, ok := parseReverseProxyOutputProjection("/v1/responses", body)
	if !ok || projection.ModelOutput != "已生成附件" || len(projection.Artifacts) != 1 {
		t.Fatalf("Responses 输出附件未进入统一投影: ok=%v projection=%+v", ok, projection)
	}
	if projection.Artifacts[0].Direction != "output" || projection.Artifacts[0].DisplayName != "result.txt" {
		t.Fatalf("输出附件方向或名称错误: %+v", projection.Artifacts[0])
	}
}
