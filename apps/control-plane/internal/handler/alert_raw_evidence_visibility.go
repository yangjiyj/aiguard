package handler

import (
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/types"
	"github.com/yangjiyj/aiguard/packages/shared-go/alertevidence"
)

// 2.9.22 起（用户 11-17 定）告警命中原文和不打码的前后文随安全事件、请求审计结果入库。
// 能看原文的角色与“内容证据”权限一致，判定只用 canReadFullTenantContentEvidence（平台管理员、
// 租户所有者和管理员、安全保密员、审计员，部门应急指派除外）；其余能读安全事件的角色（部门负责人、
// 按项目授权的角色、门户集成等）拿到的摘要里剔除 alertevidence.RawFields（与写入侧共用的字段名），其余字段照旧。

// summaryForViewer 按内容证据权限决定摘要里是否保留原文。
func summaryForViewer(summary map[string]any, canReadEvidence bool) map[string]any {
	if canReadEvidence || summary == nil {
		return summary
	}
	stripped, _ := alertevidence.StripRaw(summary).(map[string]any)
	return stripped
}

// securityEventInfoForViewer 是 mapSecurityEventToInfo 加内容证据权限：没有权限的角色拿不到原文。
func securityEventInfoForViewer(event *repository.SecurityEvent, canReadEvidence bool) types.SecurityEventInfo {
	info := mapSecurityEventToInfo(event)
	info.MatchedSummary = summaryForViewer(info.MatchedSummary, canReadEvidence)
	return info
}

// inboxItemsForViewer 处理收件箱条目：2.9.22 起告警桥写库前已去掉原文（alert.storedAlertBody），
// 这里兜住之前写入、正文 matched 和 primary_finding 里带原文的旧行，没有内容证据权限的角色拿到剔除后的正文。
// 条目是本次请求新查出来的，直接替换其正文。
func inboxItemsForViewer(items []*repository.AlertInboxItem, canReadEvidence bool) {
	for _, item := range items {
		if item != nil {
			item.BodyJSON = summaryForViewer(item.BodyJSON, canReadEvidence)
		}
	}
}

// blockRecordForViewer 清空没有内容证据权限的角色看到的阻断命中原文；命中内容展示值（detail）不变。
func blockRecordForViewer(record *repository.SecurityBlockRecord, canReadEvidence bool) {
	if !canReadEvidence {
		stripBlockRecordEvidence(record)
	}
}

// stripBlockRecordEvidence 清空阻断记录的命中原文、前后文和原文截断标记（与原文同权限）：列表一律清空，
// 详情、溯源按权限。原文省略标记不是敏感信息，保留。
func stripBlockRecordEvidence(record *repository.SecurityBlockRecord) {
	if record != nil {
		record.RawEvidence, record.EvidenceContext, record.RawEvidenceTruncated = "", "", false
	}
}

// stripAlertOccurrenceEvidence 清空命中明细的原文、预览和前后文（打码展示值 redacted_evidence 不变）。
func stripAlertOccurrenceEvidence(item *repository.AlertOccurrence) {
	if item != nil {
		item.RawEvidence, item.MatchedTextPreview, item.EvidenceContext = "", "", ""
	}
}
