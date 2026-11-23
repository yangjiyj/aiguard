package handler

import (
	"encoding/json"
	"net/http/httptest"
	"testing"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

// 共用 UsageRecord 直接返回列表 API，新增字段必须穿过实际 JSON 响应封装。
func TestUsageErrorFieldsResponseContract(t *testing.T) {
	recorder := httptest.NewRecorder()
	writeJSON(recorder, map[string]interface{}{"records": []repository.UsageRecord{{ErrorMessage: "prompt is too long", ErrorHint: "对话上下文超过模型上限，请压缩上下文或新开对话", UpstreamErrorCode: "context_length_exceeded"}}})
	var response struct {
		Records []map[string]interface{} `json:"records"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if len(response.Records) != 1 {
		t.Fatalf("列表响应不符：%s", recorder.Body.String())
	}
	for key, want := range map[string]string{"error_message": "prompt is too long", "error_hint": "对话上下文超过模型上限，请压缩上下文或新开对话", "upstream_error_code": "context_length_exceeded"} {
		if response.Records[0][key] != want {
			t.Fatalf("字段 %s 未正确返回：%s", key, recorder.Body.String())
		}
	}
}
