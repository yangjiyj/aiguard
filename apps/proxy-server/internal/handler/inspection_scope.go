package handler

import (
	"context"
	"encoding/json"
	"github.com/yangjiyj/aiguard/packages/shared-go/aimsg"
	"github.com/yangjiyj/aiguard/packages/shared-go/inspectionscope"
	"github.com/yangjiyj/aiguard/packages/shared-go/securityexit"
)

func attachmentInspectionIdentity(a ExtractedAttachment) string {
	if a.SHA256 != "" {
		return "sha:" + a.SHA256
	}
	b, _ := json.Marshal([]any{a.ReferenceID, a.DownloadURL, a.DataBase64})
	return string(b)
}

func anchorExtractedAttachments(content *ExtractedContent) {
	latest := aimsg.LatestUserPosition(content.Messages)
	var anchored []ExtractedAttachment
	known := map[string]bool{}
	originals := map[string]ExtractedAttachment{}
	for _, a := range content.Attachments {
		originals[attachmentInspectionIdentity(a)] = a
	}
	occurrences := map[string]bool{}
	for i, m := range content.Messages {
		if len(m.RawContent) == 0 {
			continue
		}
		parts := extractHTTPContent(m.RawContent, "application/json", "request").Attachments
		for _, a := range parts {
			key := attachmentInspectionIdentity(a)
			position, _ := json.Marshal([]any{key, m.MessageIndex, m.SourcePath})
			if occurrences[string(position)] {
				continue
			}
			occurrences[string(position)] = true
			if original, ok := originals[key]; ok {
				if original.Source != "" {
					a.Source = original.Source
				}
				if original.DataBase64 != "" {
					a.DataBase64 = original.DataBase64
				}
				if original.FieldName != "" {
					a.FieldName = original.FieldName
				}
				if original.FileName != "" {
					a.FileName = original.FileName
				}
			}
			a.MessageIndex = m.MessageIndex
			a.MessageRole = m.Role
			a.ContentSource = m.Source
			a.SourcePath = m.SourcePath
			a.InspectionIsHistory = aimsg.InspectionIsHistory(content.Messages, i, latest)
			a.IsLatestUser = aimsg.IsLatestUser(content.Messages, i, latest)
			known[attachmentInspectionIdentity(a)] = true
			anchored = append(anchored, a)
		}
	}
	for _, a := range content.Attachments {
		if !known[attachmentInspectionIdentity(a)] {
			anchored = append(anchored, a)
		}
	}
	content.Attachments = anchored
}

func selectExtractedInspection(content ExtractedContent, policy inspectionscope.Policy) ExtractedContent {
	content.InspectionPolicyFingerprint = policy.Fingerprint()
	if len(content.Messages) > 0 {
		populateSemanticTaskContexts(&content)
		content.UserTask = aimsg.LatestUserTask(content.Messages)
		content.InspectionScopeKnown = true
		content.JudgmentContext = aimsg.JudgmentContext(content.Messages, policy)
		content.Messages = aimsg.SelectInspectionMessages(content.Messages, policy)
		content.SecurityText = aimsg.FlattenMessages(content.Messages)
		content.SecurityTextKnown = true
	}
	attachments := make([]ExtractedAttachment, 0, len(content.Attachments))
	for _, a := range content.Attachments {
		if policy.Includes(a.ContentSource, a.IsLatestUser, a.InspectionIsHistory) {
			attachments = append(attachments, a)
		}
	}
	content.Attachments = attachments
	return content
}

func inspectionMessageContext(base map[string]interface{}, m ConvMessage, extracted ExtractedContent) {
	base["content_source"] = m.Source
	base["message_role"] = m.Role
	base["inspection_is_history"] = m.InspectionIsHistory
	base["is_latest_user"] = m.IsLatestUser
	if m.MessageIndex != nil {
		base["message_index"] = *m.MessageIndex
	} else {
		delete(base, "message_index")
	}
	if m.SourcePath != "" {
		base["source_path"] = m.SourcePath
	} else {
		delete(base, "source_path")
	}
	base["judgment_context"] = extracted.JudgmentContext
	base["user_task"] = extracted.UserTask
	base["inspection_policy_fingerprint"] = extracted.InspectionPolicyFingerprint
	if task, ok := extracted.SemanticTaskContexts[semanticSourceTaskKey(m)]; ok && task.Enabled {
		for key, value := range proxyContextWithTask(base, task) {
			base[key] = value
		}
	}
}

func inspectionAttachmentContext(base map[string]interface{}, attachment ExtractedAttachment, extracted ExtractedContent) {
	message := attachmentInspectionMessage(attachment)
	inspectionMessageContext(base, message, extracted)
	task := proxySemanticTask{Enabled: true, Status: "missing"}
	if causal, ok := extracted.SemanticAttachmentTaskContexts[semanticAttachmentTaskKey(message)]; ok {
		task = causal
	}
	for key, value := range proxyContextWithTask(base, task) {
		base[key] = value
	}
}

func (s *SecurityClient) checkSelectedInputSources(ctx context.Context, url string, payload map[string]interface{}, extracted ExtractedContent) (map[string]interface{}, error) {
	if extracted.SemanticTaskContexts == nil {
		populateSemanticTaskContexts(&extracted)
	}
	parts := make([]map[string]interface{}, 0, len(extracted.Messages)+len(extracted.Attachments))
	for _, m := range extracted.Messages {
		task := copyInspectionPayload(payload)
		task["content"] = m.Content
		task["content_source"] = m.Source
		contextMap := task["context"].(map[string]interface{})
		inspectionMessageContext(contextMap, m, extracted)
		parts = append(parts, task)
	}
	// Materialized objects retain their original order and cleanup owner. Send
	// each file separately so user text cannot authorize another message's file.
	var materialized []map[string]interface{}
	switch attachments := payload["context"].(map[string]interface{})["attachments"].(type) {
	case []map[string]interface{}:
		materialized = attachments
	case []interface{}:
		for _, attachment := range attachments {
			if entry, ok := attachment.(map[string]interface{}); ok {
				materialized = append(materialized, entry)
			}
		}
	}
	if len(materialized) == 0 {
		materialized = attachmentContext(extracted.Attachments)
	}
	for i, material := range materialized {
		attachment := ExtractedAttachment{}
		if i < len(extracted.Attachments) {
			attachment = extracted.Attachments[i]
		}
		task := copyInspectionPayload(payload)
		task["content"] = ""
		task["content_source"] = attachmentInspectionMessage(attachment).Source
		contextMap := task["context"].(map[string]interface{})
		inspectionAttachmentContext(contextMap, attachment, extracted)
		contextMap["attachments"] = []map[string]interface{}{material}
		parts = append(parts, task)
	}
	merged := map[string]interface{}{"action": "allow", "findings": []interface{}{}, "semantic_status": "not_requested", "semantic_reason": ""}
	for _, task := range parts {
		result, err := s.postJSON(ctx, url, task)
		if proxyClientGone(ctx, err) {
			// 客户端已断开：后面的分片不再送检（每片都会再打一次引擎），交给调用方按断开收尾。
			return nil, err
		}
		if err != nil {
			merged["semantic_status"] = "incomplete"
			merged["semantic_reason"] = securityexit.FailureReason(err, "security_engine_unavailable")
			action, _, meta := s.inspectionFailure(ctx, err, "security_engine_unavailable")
			if inspectionActionRank(action) > inspectionActionRank(fmtAction(merged)) {
				merged["action"] = action
			}
			merged["inspection_capacity_rejected"] = meta.CapacityRejected || merged["inspection_capacity_rejected"] == true
			merged["inspection_detection_rejected"] = meta.DetectionRejected || merged["inspection_detection_rejected"] == true
			continue
		}
		if len(parts) == 1 {
			return result, nil
		}
		if inspectionActionRank(fmtAction(result)) > inspectionActionRank(fmtAction(merged)) {
			merged["action"] = result["action"]
		}
		if f, ok := result["findings"].([]interface{}); ok {
			merged["findings"] = append(merged["findings"].([]interface{}), f...)
		}
		if proxySemanticStatusRank(result["semantic_status"]) > proxySemanticStatusRank(merged["semantic_status"]) {
			merged["semantic_status"] = result["semantic_status"]
			merged["semantic_reason"] = result["semantic_reason"]
		}
	}
	return merged, nil
}
func fmtAction(result map[string]interface{}) string {
	value, _ := result["action"].(string)
	return value
}

// Durable parts and their stored results outlive the binary and the policy that
// created them. The live inspection policy decides at execution and at
// materialization time; only markers written by the protocol parser are trusted.
// A part without a scope marker is treated as current so an older payload can
// never lose user coverage, while an excluded protocol source never reaches the
// engine again and never becomes an alert.
func inspectionPartInScope(policy inspectionscope.Policy, payload map[string]interface{}) bool {
	source, _ := payload["content_source"].(string)
	latest, history := true, false
	if ctx, ok := payload["context"].(map[string]interface{}); ok {
		if value, ok := ctx["is_latest_user"].(bool); ok {
			latest = value
		}
		if value, ok := ctx["inspection_is_history"].(bool); ok {
			history = value
		}
	}
	return policy.Includes(source, latest, history)
}

func inspectionFindingInScope(policy inspectionscope.Policy, finding map[string]interface{}) bool {
	source, _ := finding["content_source"].(string)
	latest, history := true, false
	if value, ok := finding["is_latest_user"].(bool); ok {
		latest = value
	}
	if value, ok := finding["inspection_is_history"].(bool); ok {
		history = value
	}
	return policy.Includes(source, latest, history)
}

func inspectionScopeExcludedResult() map[string]interface{} {
	return map[string]interface{}{"action": "allow", "findings": []interface{}{}, "raw_findings": []interface{}{},
		"semantic_status": "skipped", "semantic_reason": "inspection_scope_excluded", "inspection_status": "completed"}
}
