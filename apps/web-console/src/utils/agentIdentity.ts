export interface IdentityRecord {
 user_name?: string; key_name?: string; project_name?: string;
 request_id: string; created_at: string; agent_type: string; source: string; declared_type: string;
 declared_name: string; user_agent: string; client_id: string; user_id: string; source_ip: string; channel: string; environment: string
}
export const identityScopeOptions = (a: IdentityRecord) => [
 { value: 'request', label: '只确认当前请求' },
 { value: 'fingerprint', label: '登记同一调用方与客户端特征', disabled: !a.client_id || !(a.user_agent || a.declared_name || (a.declared_type && a.declared_type !== 'agent-tool-call' && !['content', 'user_agent_runtime'].includes(a.source))) },
 { value: 'dedicated_key', label: '登记此客户端的专用访问密钥', disabled: !a.client_id },
]
