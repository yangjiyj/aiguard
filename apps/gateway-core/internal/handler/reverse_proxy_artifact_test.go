package handler

import (
	"strings"
	"testing"

	"github.com/yangjiyj/aiguard/packages/shared-go/aimsg"
)

func TestReverseProxyContentInsertSQLKeepsSafeArtifactMetadataContract(t *testing.T) {
	query := reverseProxyContentInsertSQL()
	if strings.Contains(query, "'[]'::jsonb") {
		t.Fatalf("反代附件元数据不得被固定空数组丢弃:\n%s", query)
	}
	if !strings.Contains(query, "$8::jsonb") {
		t.Fatalf("反代附件元数据必须作为受控 JSON 参数写入:\n%s", query)
	}
}

func TestBuildReverseProxyMessageRowsNormalizesCodexEnvelope(t *testing.T) {
	record := reverseProxyAuditRecord{TenantID: "tenant_default", RequestID: "req-envelope"}
	msgs := []aimsg.ConvMessage{{
		Role:    "user",
		Source:  aimsg.SourceUser,
		Content: "# AGENTS.md instructions\n<INSTRUCTIONS>\nprivate runtime instructions\n</INSTRUCTIONS>\n<environment_context>\nprivate context\n</environment_context>\n\n## My request for Codex:\n只保留真实用户回合",
	}}
	rows := buildReverseProxyMessageRows(record, msgs)
	if len(rows) != 1 || rows[0].Content != "只保留真实用户回合" {
		t.Fatalf("Codex 信封不得写入客户内容页: %+v", rows)
	}
}
