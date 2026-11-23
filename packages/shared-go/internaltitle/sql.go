package internaltitle

// RawPredicate 是唯一的内部标题判定规则，绑定 request_logs 别名 rl。
// 保留 PostgreSQL 的 BTRIM、LIKE、POSIX 正则与 NULL 语义，避免另写 Go 规则产生漂移。
func RawPredicate() string {
	return `NOT (
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
 SELECT 1 FROM ` + ContentRows("'system'") + ` title_system WHERE title_system.tenant_id=rl.tenant_id AND title_system.request_id=rl.id
 AND title_system.environment_scope=rl.environment_scope AND title_system.role='system'
 AND title_system.content LIKE 'Generate a concise, sentence-case title (3-7 words)%%'
 AND title_system.content LIKE '%%only summarize its intent%%'
 OFFSET 0))
 AND COALESCE(rl.proxy_mode, '') = 'chat_completion'
			AND LOWER(COALESCE(rl.endpoint_type, '')) = 'chat'
			AND COALESCE(rl.evidence_run_source, '') = ''
			AND EXISTS (
				SELECT 1
				FROM ` + ContentRows("'user'") + ` cl_internal_user
				WHERE cl_internal_user.tenant_id = rl.tenant_id
					AND cl_internal_user.request_id = rl.id
					AND cl_internal_user.environment_scope = rl.environment_scope
					AND cl_internal_user.role = 'user'
					AND BTRIM(COALESCE(cl_internal_user.content, '')) ~ '^<session>([[:space:]]|$)'
				OFFSET 0
			)
			AND EXISTS (
				SELECT 1
				FROM ` + ContentRows("'assistant'") + ` cl_internal_assistant
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
}

// Predicate 只在尚未判定时执行正文回退；CASE 保证已落列的行不执行昂贵子计划。
func Predicate() string {
	return "(CASE WHEN rl.internal_title_request IS NULL THEN " + RawPredicate() + " ELSE NOT rl.internal_title_request END)"
}

// ContentRows 先按租户、请求、环境和角色取消息引用，再按正文主键取值。
// 三层 OFFSET 0 阻止规划器把外层 LIKE/正则下推为正文表全扫；历史行也先按请求取出。
// role 只能传入代码中的固定 SQL 常量，空串表示全部角色。
func ContentRows(role string) string {
	roleClause := ""
	if role != "" {
		roleClause = " AND role = " + role
	}
	return `(SELECT e.id, e.created_at, e.session_id, e.tenant_id, e.request_id, e.environment_scope, e.role, b.content
 FROM (SELECT id, created_at, session_id, tenant_id, request_id, environment_scope, role, content_sha256
       FROM content_log_entries
       WHERE tenant_id = rl.tenant_id AND request_id = rl.id
         AND environment_scope = rl.environment_scope` + roleClause + ` OFFSET 0) e
 CROSS JOIN LATERAL (SELECT content FROM content_log_bodies b
       WHERE b.tenant_id = e.tenant_id AND b.content_sha256 = e.content_sha256 OFFSET 0) b
 UNION ALL
 SELECT id, created_at, session_id, tenant_id, request_id, environment_scope, role, content
 FROM (SELECT id, created_at, session_id, tenant_id, request_id, environment_scope, role, content FROM content_logs_legacy
       WHERE tenant_id = rl.tenant_id AND request_id = rl.id
         AND environment_scope = rl.environment_scope` + roleClause + ` OFFSET 0) legacy)`
}

// MetadataRows 仅查消息元数据，不连接正文表；会话候选集无需读取大字段。
func MetadataRows() string {
	return `(SELECT id, created_at, session_id, tenant_id, request_id, environment_scope
 FROM content_log_entries WHERE tenant_id = rl.tenant_id AND request_id = rl.id
 AND environment_scope = rl.environment_scope
 UNION ALL
 SELECT id, created_at, session_id, tenant_id, request_id, environment_scope
 FROM content_logs_legacy WHERE tenant_id = rl.tenant_id AND request_id = rl.id
 AND environment_scope = rl.environment_scope)`
}
