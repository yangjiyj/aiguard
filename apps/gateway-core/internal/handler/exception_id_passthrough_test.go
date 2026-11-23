package handler

import (
	"testing"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/security"
)

// P1-2 配套：引擎已在 finding 上带 exception_id（命中例外=已豁免标注），
// 网关侧曾在 client struct / handler struct / 两个拷贝函数 / summary 序列化四处丢字段。
// 以下测试钉死 exception_id 端到端透传：client→handler→matched_summary。

func TestConvertSecurityFindings_CarriesExceptionID(t *testing.T) {
	src := []security.SecurityFinding{{
		Type:        "custom",
		RuleID:      "rule_abc",
		ExceptionID: "exc_001",
	}}
	out := convertSecurityFindings(src)
	if out[0].ExceptionID != "exc_001" {
		t.Fatalf("exception_id 未从 client finding 透传到 handler finding: %+v", out[0])
	}
}

func TestHandlerFindingsToSecurity_CarriesExceptionID(t *testing.T) {
	src := []SecurityFinding{{
		Type:        "custom",
		RuleID:      "rule_abc",
		ExceptionID: "exc_001",
	}}
	out := handlerFindingsToSecurity(src)
	if out[0].ExceptionID != "exc_001" {
		t.Fatalf("exception_id 未从 handler finding 透传回 client finding: %+v", out[0])
	}
}

func TestSecurityFindingsToSummary_SerializesExceptionID(t *testing.T) {
	rows := securityFindingsToSummary([]SecurityFinding{{
		Type:        "custom",
		RuleID:      "rule_abc",
		ExceptionID: "exc_001",
	}})
	if got, _ := rows[0]["exception_id"].(string); got != "exc_001" {
		t.Fatalf("exception_id 未序列化进 matched_summary.findings: %+v", rows[0])
	}
}

// 引擎默认给空串 exception_id（未豁免），summary 不该输出空字段（照 triage 的条件输出风格）。
func TestSecurityFindingsToSummary_OmitsEmptyExceptionID(t *testing.T) {
	rows := securityFindingsToSummary([]SecurityFinding{{Type: "pii"}})
	if _, present := rows[0]["exception_id"]; present {
		t.Fatalf("空 exception_id 不得输出到 matched_summary: %+v", rows[0])
	}
}
