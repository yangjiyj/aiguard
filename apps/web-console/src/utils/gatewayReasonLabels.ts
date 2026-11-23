import { securityModeLabel } from '../services/securityExecutionMode'

// 网关原因码与破坏性子类的中文字典。这是叶子模块：risk.ts 与 alertReadable.ts 都从这里取，互不依赖。

// 原因码“像码”的统一判断（含 would-block:内层码、semantic_capability:a,b 这类复合码）。
export const GATEWAY_CODE_LIKE = /^[a-z][a-z0-9_.:,-]*$/i

// 以网关 agentguard_block_notice.go 的 destructiveSubcategoryLabels 为准。
export const DESTRUCTIVE_SUBCATEGORY_LABELS: Record<string, string> = {
  filesystem_delete: '删除文件', filesystem_overwrite: '覆盖文件', storage_destroy: '销毁存储卷或磁盘',
  block_device_destroy: '破坏块设备', vcs_destroy: '丢弃版本库改动', container_destroy: '删除容器',
  cluster_destroy: '删除集群资源', infrastructure_destroy: '销毁基础设施', cloud_resource_destroy: '删除云资源',
  resource_destroy: '删除资源', database_destroy: '删除数据库对象', database_unscoped_mutation: '无条件批量修改数据库',
}

const RECORD_MODE = securityModeLabel('record') // 仅用于全局观察留痕模式

// 网关与控制面写进告警 reason / effective_reason 的原因码。含义取自网关源码与控制面 security_block_records_agent.go。
// 注意：analyzer_result / analyzer_default 在观察留痕模式下，网关也会用来标记显式规则的结果（decision.go），
// 所以这两条只能写“按风险分析处置”，不能断言一定来自分析器。
export const GATEWAY_REASON_LABELS: Record<string, string> = {
  // 策略判定
  explicit_block: '智能体行为策略要求阻断',
  explicit_confirm: '智能体行为策略要求人工确认',
  explicit_audit: '智能体行为策略要求放行并留痕',
  explicit_allow: '智能体行为策略要求放行',
  // MCP 策略有自己的模式，would-* 不一定来自全局观察留痕，所以不写模式名。
  'would-block': '按策略应阻断，当前模式仅记录',
  'would-confirm': '按策略应人工确认，当前模式仅记录',
  analyzer_default: '按风险分析默认处置',
  analyzer_result: '按风险分析结果处置',
  analyzer_unconfigured_alert_only: '未配置阻断规则，告警放行',
  analyzer_high_risk_block: '判定为高风险调用，已阻断',
  analyzer_high_risk_recorded: '判定为高风险调用，仅记录',
  global_default: '按智能体行为策略默认动作',
  exception_downgrade: '命中例外，已降级处置',
  protection_item: '按防护项设置处置',
  skill_admission_floor: 'Skill 未通过准入，需人工确认',
  confirm_channel_available: '需人工确认',
  // 2.9.22 起由防护项“需要确认但无法确认”处置，结果不一定是阻断。
  confirm_without_channel_fail_closed: '需要确认但无法确认',
  human_approved_confirmation_consumed: '人工确认后放行一次',
  human_confirmation_approved_once: '人工确认后放行一次',
  approval_context_drift: '确认后调用内容有变化，已阻断',
  mcp_confirmation_policy_recorded: '当前策略要求阻断，当前模式仅记录',
  tool_policy_recorded: '按策略应阻断或确认，当前模式仅记录',
  tool_name_policy_block: '命中工具名称阻断策略',
  tool_failure_loop: '工具连续失败',
  policy_fail_closed: '策略不可用，按安全策略阻断',
  policy_runtime_unavailable: '策略运行时不可用，已阻断',
  agentguard_policy_load_failed: '策略加载失败',
  mcp_redline_block: '命中 MCP 红线阻断规则',
  semantic_capability: '线路不支持本次请求所需的能力',
  // 控制面 apps/control-plane/internal/handler/confirmation_replayer.go:45 写入的英文原因
  'human approved; execution awaits client retry': '人工确认通过，等待客户端重试执行',
  // 删除与破坏
  destructive_alert_allow: '按策略仅告警，已放行',
  destructive_confirmation_required: '需人工确认',
  destructive_blocked: '已阻断',
  destructive_recorded: '仅记录',
  destructive_confidence_record_only: '置信度不足，仅记录',
  destructive_global_audit_only_recorded: `${RECORD_MODE}模式，仅记录`,
  destructive_parse_rejected_fail_safe: '命令无法解析，按兜底规则处理',
  destructive_parse_incomplete_no_signal: '命令无法完整解析，未发现破坏性特征',
  // 旧码保留，只用于显示升级前的记录。
  destructive_confirmation_extension_required: '需人工确认，但客户端不支持确认扩展，已阻断',
  destructive_target_incomplete: '破坏性操作的目标未解析',
  deterministic_destructive_operation: '识别为明确的破坏性操作',
  destructive_command_requires_confirm: '执行删除或破坏性命令',
  blocked_destructive_sql: '执行删除或破坏性 SQL 语句',
  scoped_mutation_requires_confirm: '带条件的数据修改',
  unknown_sql_requires_audit: '无法识别的 SQL 语句',
  discardable_development_path: '目标在可丢弃的开发目录',
  // 受限资源与外发
  // 旧码保留，只用于显示升级前的记录。
  restricted_file_explicit_block: '访问了受限文件，已阻断',
  restricted_file_pattern: '命中受限文件规则',
  blocked_cloud_metadata: '访问云平台元数据地址',
  blocked_cloud_metadata_hostname: '访问云平台元数据地址',
  blocked_loopback_or_private_ip: '访问本机或内网地址',
  blocked_cloud_credential_path: '读取云平台凭据文件',
  blocked_ssh_private_key_path: '读取 SSH 私钥文件',
  // 旧码保留，用于显示升级前的记录；2.9.22 拆成下面五个，显示名与防护项注册表的 Label 一致。
  blocked_sensitive_local_file_path: '读取本机敏感文件',
  blocked_env_file: '.env 文件',
  blocked_system_secret_file: '系统口令与进程环境',
  blocked_secret_mount_path: '密钥挂载目录',
  blocked_git_credentials_file: 'git 口令',
  blocked_git_credential_dump: 'git 口令',
  // 防跳板出站（网关、独立代理、控制面写的事件类型）。
  forward_proxy_internal_egress_denied: '正向代理访问内网地址被拒绝',
  forward_proxy_internal_egress_allowed: '正向代理按放行设置访问内网地址',
  reverse_proxy_internal_egress_denied: '反向代理回源内网地址被拒绝',
  mcp_upstream_internal_egress_denied: 'MCP 上游内网地址被拒绝',
  mcp_upstream_egress_denied: 'MCP 上游地址被拒绝',
  platform_egress_denied: '控制面出站地址被拒绝',
  sensitive_name_hint: '名字像敏感文件',
  high_confidence_secret_egress: '调用参数带有高置信度密钥或凭据',
  sensitive_personal_data_egress: '调用参数带有个人敏感信息',
  behavior_sensitive_read_then_egress: '读取敏感内容后又向外发送',
  // 命令形态
  shell_interpolation_requires_confirm: '命令含变量或命令替换',
  shell_composition_observed: '命令含管道或连接符',
  shell_interpreter_observed: '命令经由 shell 解释器执行',
  command_allowlisted: '命令在允许清单内',
  command_not_allowlisted: '命令不在允许清单内',
  readonly_sql: '只读 SQL',
  // Skill 与终端
  skill_dangerous_command: 'Skill 携带的命令包含高危操作',
  skill_version_quarantined: '调用的 Skill 版本已被隔离',
  skill_version_revoked: '调用的 Skill 版本已被吊销',
  skill_admission_unavailable: 'Skill 准入状态暂时无法确认',
  skill_identity_incomplete: '无法确认调用的是哪个 Skill 版本',
  endpoint_policy_rule: '命中终端策略规则',
  t13_authorization_denied: '终端授权未通过',
  agentguard_decision: '按智能体行为策略判定',
}

// 复合码 “前缀:内层码”：先译前缀，内层认识就用括号补上，不认识只给前缀。
// 返回 undefined 表示不认识（调用方决定显示空还是通用说法）。
export const translateGatewayReason = (value?: string | null): string | undefined => {
  const text = String(value ?? '').trim()
  if (!text) return undefined
  if (GATEWAY_REASON_LABELS[text]) return GATEWAY_REASON_LABELS[text]
  const cut = text.indexOf(':')
  if (cut <= 0) return undefined
  const prefix = GATEWAY_REASON_LABELS[text.slice(0, cut)]
  if (!prefix || !GATEWAY_CODE_LIKE.test(text)) return undefined
  const inner = translateGatewayReason(text.slice(cut + 1))
  return inner ? `${prefix}（${inner}）` : prefix
}
