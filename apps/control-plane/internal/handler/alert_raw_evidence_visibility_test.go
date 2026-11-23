package handler

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
	"github.com/yangjiyj/aiguard/packages/shared-go/alertevidence"
)

// 契约：控制面剔除用的就是写入侧共用的 alertevidence.RawFields，名单变了两侧一起变。
func TestSummaryForViewerStripsSharedRawFields(t *testing.T) {
	finding := map[string]any{"raw_evidence_sha256": "h", alertevidence.IdentityKey: "i"}
	for _, key := range alertevidence.RawFields {
		finding[key] = "RAW-" + key
	}
	summary := map[string]any{"findings": []any{finding}, "primary_finding": finding}
	encoded, _ := json.Marshal(summaryForViewer(summary, false))
	if strings.Contains(string(encoded), "RAW-") || !strings.Contains(string(encoded), "raw_evidence_sha256") {
		t.Fatalf("无权限角色应剔除共用名单里的字段、保留哈希: %s", encoded)
	}
	if kept, _ := json.Marshal(summaryForViewer(summary, true)); !strings.Contains(string(kept), "RAW-raw_evidence") {
		t.Fatalf("有权限角色保留原文: %s", kept)
	}
}

func TestBlockAndAlertEvidenceStripHelpers(t *testing.T) {
	record := &repository.SecurityBlockRecord{RawEvidence: "R", EvidenceContext: "C", RawEvidenceTruncated: true, RawEvidenceOmitted: true, Detail: "D"}
	blockRecordForViewer(record, true)
	if record.RawEvidence != "R" || !record.RawEvidenceTruncated {
		t.Fatal("有权限不清空")
	}
	blockRecordForViewer(record, false)
	if record.RawEvidence != "" || record.EvidenceContext != "" || record.RawEvidenceTruncated || record.Detail != "D" || !record.RawEvidenceOmitted {
		t.Fatalf("无权限清空原文、前后文和截断标记（与原文同权限），展示值与省略标记不变: %+v", record)
	}
	item := &repository.AlertOccurrence{RawEvidence: "R", MatchedTextPreview: "P", EvidenceContext: "C", RedactedEvidence: "X"}
	stripAlertOccurrenceEvidence(item)
	if item.RawEvidence != "" || item.MatchedTextPreview != "" || item.EvidenceContext != "" || item.RedactedEvidence != "X" {
		t.Fatalf("命中明细清空原文、预览、前后文，打码值不变: %+v", item)
	}
}
