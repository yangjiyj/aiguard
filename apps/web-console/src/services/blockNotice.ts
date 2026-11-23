// 与网关 gateway-core/internal/handler/block_notice.go 同一份契约：
// 占位符集合、默认模板、"整行占位符都为空则整行省略"的渲染规则。

export const BLOCK_NOTICE_PLACEHOLDERS = [
  { token: '{reason}', label: '阻断原因' },
  { token: '{rule}', label: '命中规则（名称 + 编号）' },
  { token: '{detail}', label: '命中内容（已脱敏）' },
  { token: '{block_id}', label: '阻断编号（阻断记录可查）' },
  { token: '{operation_id}', label: '操作编号（仅工具调用）' },
  { token: '{request_id}', label: '请求 ID' },
] as const

export const DEFAULT_BLOCK_NOTICE_TEMPLATE = [
  '【JJDGuard 安全网关】本次请求已被安全策略阻断。',
  '阻断原因：{reason}',
  '命中规则：{rule}',
  '命中内容：{detail}',
  '阻断编号：{block_id}',
  '请求 ID：{request_id}',
  '操作编号：{operation_id}',
  '如需核查，请联系管理员并提供阻断编号或请求 ID（管理后台「风险处理 → 阻断记录」可查）。',
].join('\n')

const LEGACY_DEFAULT_BLOCK_NOTICE_TEMPLATE = [
  '【JJDGuard 安全网关】本次请求已被安全策略阻断。',
  '阻断原因：{reason}',
  '命中规则：{rule}',
  '命中内容：{detail}',
  '阻断编号：{block_id}',
  '操作编号：{operation_id}',
  '如需放行，请联系管理员并提供阻断编号（管理后台「安全护栏 → 阻断记录」可查）。',
].join('\n')

export function normalizeBlockNoticeTemplate(template: string): string {
  return !template.trim() || template.trim() === LEGACY_DEFAULT_BLOCK_NOTICE_TEMPLATE
    ? DEFAULT_BLOCK_NOTICE_TEMPLATE : template
}

export const MAX_BLOCK_NOTICE_TEMPLATE_CHARS = 2000

export interface BlockNoticeValues {
  reason?: string
  rule_name?: string
  rule_id?: string
  detail?: string
  block_id?: string
  operation_id?: string
  request_id?: string
}

// A customer may paste the whole notice instead of just its identifier.
// Only explicit identifier labels are extracted; rule text never becomes an ID.
export function blockRecordSearchQuery(value: string): string {
  const text = value.trim()
  for (const label of ['阻断编号', '请求\\s*ID', '操作编号', 'Trace\\s*ID']) {
    const match = text.match(new RegExp(`${label}\\s*[：:]\\s*([A-Za-z0-9_.:-]+(?:…)?)(?![A-Za-z0-9_])`, 'i'))
    if (match) return match[1]
  }
  return text
}

export function validateBlockNoticeTemplate(template: string): string | null {
  if ([...template].length > MAX_BLOCK_NOTICE_TEMPLATE_CHARS) return `模板不能超过 ${MAX_BLOCK_NOTICE_TEMPLATE_CHARS} 个字符`
  const known = new Set<string>(BLOCK_NOTICE_PLACEHOLDERS.map((item) => item.token))
  const tokens = template.match(/\{[^{}]*\}/g) || []
  const unknown = tokens.find((token) => !known.has(token))
  return unknown ? `模板包含未知占位符 ${unknown}` : null
}

export function renderBlockNotice(template: string, values: BlockNoticeValues): string {
  const normalized = normalizeBlockNoticeTemplate(template)
  const source = !validateBlockNoticeTemplate(normalized) ? normalized : DEFAULT_BLOCK_NOTICE_TEMPLATE
  let rule = values.rule_name || ''
  if (values.rule_id && values.rule_id !== values.rule_name) {
    rule = rule ? `${rule}（${values.rule_id}）` : values.rule_id
  }
  const map: Record<string, string> = {
    '{reason}': values.reason || '',
    '{rule}': rule,
    '{detail}': values.detail || '',
    '{block_id}': values.block_id || '',
    '{operation_id}': values.operation_id || '',
    '{request_id}': values.request_id || '',
  }
  const rendered = source
    .split('\n')
    .flatMap((line) => {
      let hasPlaceholder = false
      let hasValue = false
      let rendered = line
      for (const [token, value] of Object.entries(map)) {
        if (rendered.includes(token)) {
          hasPlaceholder = true
          if (value) hasValue = true
          rendered = rendered.split(token).join(value)
        }
      }
      return hasPlaceholder && !hasValue ? [] : [rendered]
    })
    .join('\n')
    .trim()
  const lines = rendered ? [rendered] : []
  if (values.block_id && !rendered.includes(values.block_id)) lines.push(`阻断编号：${values.block_id}`)
  if (values.request_id && !rendered.includes(values.request_id)) lines.push(`请求 ID：${values.request_id}`)
  return lines.join('\n')
}

export const BLOCK_LAYER_LABELS: Record<string, string> = {
  input_content: '输入内容',
  output_content: '模型输出',
  tool_arguments: '工具调用参数',
  file: '附件文件',
  restricted_file: '受限文件',
  tool_definition: '工具定义',
  destructive_operation: '删除与破坏',
  agent_tool: '智能体工具调用',
  mcp_tool: 'MCP 工具调用',
}

export function blockLayerLabel(layer?: string): string {
  return (layer && BLOCK_LAYER_LABELS[layer]) || '其它阻断'
}
