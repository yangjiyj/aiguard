package security

import (
	"encoding/json"
	"testing"
)

// P1-2 配套：引擎响应 JSON 已在 finding 上带 exception_id（命中例外=已豁免标注，空串=未豁免）。
// SecurityFinding struct 必须能解出该字段，否则网关侧第一跳就丢字段。
func TestSecurityFindingDecodesExceptionID(t *testing.T) {
	raw := []byte(`{"type":"custom","rule_id":"rule_abc","severity":"high","exception_id":"exc_001"}`)
	var finding SecurityFinding
	if err := json.Unmarshal(raw, &finding); err != nil {
		t.Fatalf("unmarshal finding: %v", err)
	}
	if finding.ExceptionID != "exc_001" {
		t.Fatalf("exception_id 未解入 SecurityFinding, got %+v", finding)
	}
}

// 逆向（CheckTriage 请求把 findings 发回引擎）也要带上 exception_id，保证往返不丢。
func TestSecurityFindingEncodesExceptionID(t *testing.T) {
	body, err := json.Marshal(SecurityFinding{Type: "custom", ExceptionID: "exc_001"})
	if err != nil {
		t.Fatalf("marshal finding: %v", err)
	}
	var round map[string]interface{}
	if err := json.Unmarshal(body, &round); err != nil {
		t.Fatalf("unmarshal roundtrip: %v", err)
	}
	if round["exception_id"] != "exc_001" {
		t.Fatalf("exception_id 未序列化进 finding JSON: %s", body)
	}
}
