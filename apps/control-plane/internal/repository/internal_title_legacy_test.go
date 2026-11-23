package repository

import (
	"github.com/yangjiyj/aiguard/packages/shared-go/internaltitle"
	"strings"
	"testing"
)

// 988 之前的完整规则快照，只用于与新读路径逐行比较，不作为生产规则来源。
const legacyInternalTitlePredicate = `NOT (
		(
			LOWER(COALESCE(rl.agent_type, '')) = 'workbuddy'
			AND LOWER(COALESCE(rl.proxy_target_host, '')) = 'copilot.tencent.com'
			AND SPLIT_PART(LOWER(BTRIM(COALESCE(rl.proxy_target_path, ''))), '?', 1) = '/v2/chat/completions'
			AND COALESCE(rl.proxy_request_bytes, 0) BETWEEN 1 AND 4096
			AND EXISTS (
				SELECT 1
				FROM access_content_logs acl_internal
				WHERE acl_internal.tenant_id = rl.tenant_id
					AND acl_internal.request_id = rl.request_id
					AND acl_internal.environment_scope = rl.environment_scope
					AND LOWER(BTRIM(COALESCE(acl_internal.model, ''))) = 'deepseek-v4-flash'
					AND COALESCE(acl_internal.file_metadata_json, '[]'::jsonb) = '[]'::jsonb
					AND BTRIM(COALESCE(acl_internal.request_content_redacted, '')) LIKE '<session>%'
					AND BTRIM(COALESCE(acl_internal.request_content_redacted, '')) LIKE '%</session>'
					AND BTRIM(COALESCE(acl_internal.response_content_redacted, '')) ~ '^[{][[:space:]]*(("isNewTopic"[[:space:]]*:[[:space:]]*true[[:space:]]*,[[:space:]]*"title"[[:space:]]*:[[:space:]]*"[^"[:cntrl:]]*[^"[:space:][:cntrl:]][^"[:cntrl:]]*")|("title"[[:space:]]*:[[:space:]]*"[^"[:cntrl:]]*[^"[:space:][:cntrl:]][^"[:cntrl:]]*"[[:space:]]*,[[:space:]]*"isNewTopic"[[:space:]]*:[[:space:]]*true))[[:space:]]*[}]$'
				OFFSET 0
			)
		)
		OR (
			(LOWER(COALESCE(rl.agent_type, '')) = 'workbuddy' OR EXISTS (
 SELECT 1 FROM content_logs title_system WHERE title_system.tenant_id=rl.tenant_id AND title_system.request_id=rl.id
 AND title_system.environment_scope=rl.environment_scope AND title_system.role='system'
 AND title_system.content LIKE 'Generate a concise, sentence-case title (3-7 words)%%'
 AND title_system.content LIKE '%%only summarize its intent%%'
 OFFSET 0))
 AND COALESCE(rl.proxy_mode, '') = 'chat_completion'
			AND LOWER(COALESCE(rl.endpoint_type, '')) = 'chat'
			AND COALESCE(rl.evidence_run_source, '') = ''
			AND EXISTS (
				SELECT 1
				FROM content_logs cl_internal_user
				WHERE cl_internal_user.tenant_id = rl.tenant_id
					AND cl_internal_user.request_id = rl.id
					AND cl_internal_user.environment_scope = rl.environment_scope
					AND cl_internal_user.role = 'user'
					AND BTRIM(COALESCE(cl_internal_user.content, '')) ~ '^<session>([[:space:]]|$)'
				OFFSET 0
			)
			AND EXISTS (
				SELECT 1
				FROM content_logs cl_internal_assistant
				WHERE cl_internal_assistant.tenant_id = rl.tenant_id
					AND cl_internal_assistant.request_id = rl.id
					AND cl_internal_assistant.environment_scope = rl.environment_scope
					AND cl_internal_assistant.role = 'assistant'
					AND BTRIM(COALESCE(cl_internal_assistant.content, '')) ~ '^[{][[:space:]]*(("isNewTopic"[[:space:]]*:[[:space:]]*true[[:space:]]*,[[:space:]]*"title"[[:space:]]*:[[:space:]]*"[^"[:cntrl:]]*[^"[:space:][:cntrl:]][^"[:cntrl:]]*")|("title"[[:space:]]*:[[:space:]]*"[^"[:cntrl:]]*[^"[:space:][:cntrl:]][^"[:cntrl:]]*"[[:space:]]*,[[:space:]]*"isNewTopic"[[:space:]]*:[[:space:]]*true))[[:space:]]*[}]$'
				OFFSET 0
			)
		)
		OR (
			LOWER(COALESCE(rl.agent_type, '')) = 'codebuddy'
			AND LOWER(COALESCE(rl.proxy_target_host, '')) = 'copilot.tencent.com'
			AND SPLIT_PART(LOWER(BTRIM(COALESCE(rl.proxy_target_path, ''))), '?', 1) = '/v2/chat/completions'
			AND COALESCE(rl.proxy_request_bytes, 0) BETWEEN 1 AND 4096
			AND EXISTS (
				SELECT 1
				FROM access_content_logs acl_internal
				WHERE acl_internal.tenant_id = rl.tenant_id
					AND acl_internal.request_id = rl.request_id
					AND acl_internal.environment_scope = rl.environment_scope
					AND LOWER(BTRIM(COALESCE(acl_internal.model, ''))) = 'deepseek-v4-pro'
					AND COALESCE(acl_internal.file_metadata_json, '[]'::jsonb) = '[]'::jsonb
					AND BTRIM(COALESCE(acl_internal.request_content_redacted, '')) LIKE 'Q:%'
					AND STRPOS(REPLACE(COALESCE(acl_internal.request_content_redacted, ''), E'\r\n', E'\n'), E'\nA:') > 0
					AND BTRIM(COALESCE(acl_internal.response_content_redacted, '')) <> ''
					AND STRPOS(BTRIM(COALESCE(acl_internal.response_content_redacted, '')), E'\n') = 0
					AND CHAR_LENGTH(BTRIM(COALESCE(acl_internal.response_content_redacted, ''))) <= 80
				OFFSET 0
			)
		)
		OR (
			LOWER(COALESCE(rl.agent_type, '')) = 'openai-codex'
			AND SPLIT_PART(LOWER(BTRIM(COALESCE(rl.proxy_target_path, ''))), '?', 1) = '/v1/responses'
			AND EXISTS (
				SELECT 1
				FROM access_content_logs acl_internal
				WHERE acl_internal.tenant_id = rl.tenant_id
					AND acl_internal.request_id = rl.request_id
					AND acl_internal.environment_scope = rl.environment_scope
					AND LOWER(BTRIM(COALESCE(acl_internal.model, ''))) = 'gpt-5.6-luna'
					AND BTRIM(COALESCE(acl_internal.response_content_redacted, '')) LIKE '{%}'
					AND STRPOS(acl_internal.response_content_redacted, '"description"') > 0
					AND STRPOS(acl_internal.response_content_redacted, '"title"') > 0
					AND (
						BTRIM(COALESCE(acl_internal.request_content_redacted, '')) LIKE 'You are a helpful assistant. You will be presented with a user prompt, and your job is to provide a short title for a task that will be created from that prompt.%'
						AND STRPOS(acl_internal.request_content_redacted, 'The tasks typically have to do with coding-related tasks') > 0
						AND STRPOS(acl_internal.request_content_redacted, 'The title you generate will be shown in the UI to represent the prompt.') > 0
						AND STRPOS(acl_internal.request_content_redacted, 'Generate a clear, informative task title based solely on the prompt provided.') > 0
					)
				OFFSET 0
			)
		)
	)`

// 除消息来源被替换为有屏障的请求级底表查询外，四条协议规则逐字保持不变。
func TestInternalTitleRuleMatchesLegacySQL(t *testing.T) {
	got := internaltitle.RawPredicate()
	for _, role := range []string{"'system'", "'user'", "'assistant'"} {
		got = strings.ReplaceAll(got, internaltitle.ContentRows(role), "content_logs")
	}
	if got != legacyInternalTitlePredicate {
		t.Fatal("协议规则与 988 之前的快照不一致")
	}
}
