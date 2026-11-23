// MCP 上游连接配置：表单模型 ↔ capabilities 的双向转换，以及「厂商预设」。
// 预设只是预填表单的数据，不写死任何后端逻辑——后端只认 transport / 鉴权位置 / 参数名 / 值模板 / 额外请求头。

export type McpTransport = 'auto' | 'streamable_http' | 'sse'
export type McpAuthLocation = 'header' | 'query' | 'path'

export const MCP_TRANSPORT_OPTIONS: Array<{ value: McpTransport; label: string }> = [
  { value: 'auto', label: '自动识别（推荐）' },
  { value: 'streamable_http', label: 'Streamable HTTP' },
  { value: 'sse', label: 'SSE（旧版）' },
]

export const MCP_TRANSPORT_LABELS: Record<string, string> = {
  auto: '自动识别',
  streamable_http: 'Streamable HTTP',
  sse: 'SSE（旧版）',
}

export const MCP_AUTH_LOCATION_OPTIONS: Array<{ value: McpAuthLocation; label: string }> = [
  { value: 'header', label: '请求头' },
  { value: 'query', label: 'URL 参数' },
  { value: 'path', label: 'URL 路径' },
]

// 值模板：后端协议值是 'Bearer {secret}' / '{secret}'（接口与存储格式不变）。
// 前端 Select 的 option value 一律使用内部代号（bearer / raw / 自定义的不透明代号）：antd 会把 option value 写进
// 下拉虚拟列表的无障碍辅助节点，读屏软件会读出 `{secret}`（R1）。提交时再映射回后端认得的模板值，
// 编辑已保存的服务时做反向映射。表单模型里的 auth_template 仍是后端模板值（预设、capabilities 转换、提交都不变），
// 只在 Select 这一层（McpTemplateSelect）做 值↔代号 的转换，代号不会流出该组件。
export const MCP_TEMPLATE_BEARER = 'Bearer {secret}'
export const MCP_TEMPLATE_RAW = '{secret}'
const TEMPLATE_CODE_BEARER = 'bearer'
const TEMPLATE_CODE_RAW = 'raw'
export const MCP_TEMPLATE_OPTIONS = [
  { value: TEMPLATE_CODE_BEARER, label: 'Bearer + 密钥' },
  { value: TEMPLATE_CODE_RAW, label: '仅密钥（原样）' },
]

// 自定义/历史模板的不透明代号：custom- 前缀 + 稳定哈希（不含任何模板原文）。
function customTemplateCode(template: string): string {
  let h = 5381
  for (let i = 0; i < template.length; i++) h = ((h << 5) + h + template.charCodeAt(i)) | 0
  return `custom-${(h >>> 0).toString(36)}`
}

/**
 * 后端模板值 → 界面内部代号。
 * 空值的语义是「按鉴权位置取默认」（Authorization 请求头默认 Bearer，URL 参数与自定义头默认原样），不是 Bearer，
 * 所以空值返回 undefined（下拉不选中任何项），绝不显示成 Bearer（L-3）。
 */
export function templateToOptionValue(template?: string): string | undefined {
  const t = (template || '').trim()
  if (!t) return undefined
  if (t === MCP_TEMPLATE_BEARER) return TEMPLATE_CODE_BEARER
  if (t === MCP_TEMPLATE_RAW) return TEMPLATE_CODE_RAW
  return customTemplateCode(t)
}

/**
 * 界面内部代号 → 后端模板值。custom 代号需要传入当前已保存的原始模板才能还原。
 * 空值与认不出的代号返回 ''（表示「按位置取默认」，由 capabilitiesFromForm 统一处理），
 * 绝不悄悄变成 Bearer 前缀写进密钥。
 */
export function templateFromOptionValue(code?: string, savedTemplate?: string): string {
  const c = (code || '').trim()
  if (c === TEMPLATE_CODE_RAW) return MCP_TEMPLATE_RAW
  if (c === TEMPLATE_CODE_BEARER) return MCP_TEMPLATE_BEARER
  const saved = (savedTemplate || '').trim()
  if (c && saved && customTemplateCode(saved) === c) return saved
  return ''
}

// 已保存的服务可能带预置之外的值模板（如 "Token {secret}"）：补一个中文标签的选项（value 是不透明代号）。
export function mcpTemplateOptionsFor(savedTemplate?: string): { value: string; label: string }[] {
  const t = (savedTemplate || '').trim()
  if (!t || t === MCP_TEMPLATE_BEARER || t === MCP_TEMPLATE_RAW) return MCP_TEMPLATE_OPTIONS
  return [...MCP_TEMPLATE_OPTIONS, { value: customTemplateCode(t), label: t.replace(/\{secret\}/gi, '{密钥}') }]
}

export interface McpExtraHeaderRow {
  name: string
  value: string
}

export interface McpUpstreamFormValues {
  transport: McpTransport
  auth_location: McpAuthLocation
  auth_name: string
  auth_template: string
  extra_headers: McpExtraHeaderRow[]
}

export const MCP_UPSTREAM_DEFAULTS: McpUpstreamFormValues = {
  transport: 'auto',
  auth_location: 'header',
  auth_name: 'Authorization',
  auth_template: MCP_TEMPLATE_BEARER,
  extra_headers: [],
}

export interface McpVendorPreset {
  key: string
  label: string
  hint: string
  transport: McpTransport
  auth_location: McpAuthLocation
  auth_name: string
  auth_template: string
  url_example: string
}

// 厂商预设：仅预填表单。地址示例中的 {…} 是需要用户替换的占位说明，不会被当成真实地址保存。
export const MCP_VENDOR_PRESETS: McpVendorPreset[] = [
  {
    key: 'generic_bearer', label: '通用 Bearer', hint: '大多数托管 MCP 服务：请求头 Authorization: Bearer 密钥',
    transport: 'auto', auth_location: 'header', auth_name: 'Authorization', auth_template: MCP_TEMPLATE_BEARER,
    url_example: 'https://mcp.example.com/mcp',
  },
  {
    key: 'dashscope', label: '阿里云百炼', hint: '请求头 Authorization: Bearer 密钥；/mcp 为 Streamable，/sse 为旧版 SSE',
    transport: 'auto', auth_location: 'header', auth_name: 'Authorization', auth_template: MCP_TEMPLATE_BEARER,
    url_example: 'https://dashscope.aliyuncs.com/api/v1/mcps/服务名/mcp',
  },
  {
    key: 'amap', label: '高德地图', hint: 'URL 参数 key；未鉴权时上游返回 HTTP 200 的业务错误，连接测试会提示疑似鉴权失败',
    transport: 'auto', auth_location: 'query', auth_name: 'key', auth_template: MCP_TEMPLATE_RAW,
    url_example: 'https://mcp.amap.com/mcp',
  },
  {
    key: 'baidu_map', label: '百度地图', hint: 'URL 参数 ak',
    transport: 'auto', auth_location: 'query', auth_name: 'ak', auth_template: MCP_TEMPLATE_RAW,
    url_example: 'https://mcp.map.baidu.com/mcp',
  },
  {
    key: 'baidu_appbuilder', label: '百度千帆 AppBuilder', hint: 'URL 参数 api_key，值带 Bearer 前缀',
    transport: 'sse', auth_location: 'query', auth_name: 'api_key', auth_template: MCP_TEMPLATE_BEARER,
    url_example: 'https://qianfan.baidubce.com/v2/ai_search/mcp/sse',
  },
  {
    key: 'zhipu_sse', label: '智谱（旧版 SSE）', hint: '/sse 端点：URL 参数 Authorization，值为密钥本身',
    transport: 'sse', auth_location: 'query', auth_name: 'Authorization', auth_template: MCP_TEMPLATE_RAW,
    url_example: 'https://open.bigmodel.cn/api/mcp/服务名/sse',
  },
  {
    key: 'zhipu_mcp', label: '智谱（Streamable）', hint: '/mcp 端点：请求头 Authorization: Bearer 密钥',
    transport: 'streamable_http', auth_location: 'header', auth_name: 'Authorization', auth_template: MCP_TEMPLATE_BEARER,
    url_example: 'https://open.bigmodel.cn/api/mcp/服务名/mcp',
  },
  {
    key: 'tencent_map', label: '腾讯位置服务', hint: 'URL 参数 key',
    transport: 'auto', auth_location: 'query', auth_name: 'key', auth_template: MCP_TEMPLATE_RAW,
    url_example: 'https://mcp.map.qq.com/sse',
  },
  {
    key: 'path_secret', label: '密钥在 URL 路径中', hint: '密钥是地址路径的一段：在服务地址里用 {密钥} 标出位置，例如 https://x.com/mcp/{密钥}/sse',
    transport: 'auto', auth_location: 'path', auth_name: '', auth_template: MCP_TEMPLATE_RAW,
    url_example: 'https://x.com/mcp/{密钥}/sse',
  },
  {
    key: 'modelscope', label: '魔搭 ModelScope', hint: '路径中带服务专属 ID；鉴权可选，需要时用 Bearer',
    transport: 'auto', auth_location: 'header', auth_name: 'Authorization', auth_template: MCP_TEMPLATE_BEARER,
    url_example: 'https://mcp.api-inference.modelscope.net/服务专属ID/mcp',
  },
]

export function applyVendorPreset(preset: McpVendorPreset): Pick<McpUpstreamFormValues, 'transport' | 'auth_location' | 'auth_name' | 'auth_template'> {
  return {
    transport: preset.transport,
    auth_location: preset.auth_location,
    auth_name: preset.auth_name,
    auth_template: preset.auth_template,
  }
}

const CAP_AUTH_HEADER_NAME = 'auth_header_name'
const CAP_AUTH_LOCATION = 'upstream_auth_location'
const CAP_AUTH_QUERY_PARAM = 'upstream_auth_query_param'
const CAP_AUTH_TEMPLATE = 'upstream_auth_template'
const CAP_EXTRA_HEADERS = 'upstream_extra_headers'
const UPSTREAM_CAP_KEYS = [CAP_AUTH_HEADER_NAME, CAP_AUTH_LOCATION, CAP_AUTH_QUERY_PARAM, CAP_AUTH_TEMPLATE, CAP_EXTRA_HEADERS]

const asString = (v: unknown) => (typeof v === 'string' ? v.trim() : '')

// 从服务记录的 capabilities 还原表单取值（存量记录没有新字段时得到与历史行为一致的默认值）。
export function formValuesFromServer(transport: string | undefined, caps: Record<string, unknown> | undefined): McpUpstreamFormValues {
  const c = caps || {}
  const rawLocation = asString(c[CAP_AUTH_LOCATION])
  const location: McpAuthLocation = rawLocation === 'query' ? 'query' : rawLocation === 'path' ? 'path' : 'header'
  const t: McpTransport = transport === 'auto' || transport === 'sse' ? transport : 'streamable_http'
  let name: string
  let template: string
  if (location === 'path') {
    // 路径模式：密钥原样替换占位，没有头名 / 参数名 / 值模板
    name = ''
    template = MCP_TEMPLATE_RAW
  } else if (location === 'query') {
    name = asString(c[CAP_AUTH_QUERY_PARAM])
    template = asString(c[CAP_AUTH_TEMPLATE]) || MCP_TEMPLATE_RAW
  } else {
    name = asString(c[CAP_AUTH_HEADER_NAME]) || 'Authorization'
    template = asString(c[CAP_AUTH_TEMPLATE]) || (name.toLowerCase() === 'authorization' ? MCP_TEMPLATE_BEARER : MCP_TEMPLATE_RAW)
  }
  const rawExtra = c[CAP_EXTRA_HEADERS]
  const extra: McpExtraHeaderRow[] = []
  if (rawExtra && typeof rawExtra === 'object') {
    Object.entries(rawExtra as Record<string, unknown>).forEach(([k, v]) => {
      if (typeof v === 'string') extra.push({ name: k, value: v })
    })
  }
  return { transport: t, auth_location: location, auth_name: name, auth_template: template, extra_headers: extra }
}

// 把表单取值合并进现有 capabilities：只改动上游连接相关键，其余键（协议版本、探测结果等）原样保留。
export function capabilitiesFromForm(values: McpUpstreamFormValues, existing: Record<string, unknown> | undefined): Record<string, unknown> {
  const caps: Record<string, unknown> = { ...(existing || {}) }
  UPSTREAM_CAP_KEYS.forEach((k) => delete caps[k])
  // 改了 transport 或鉴权位置后，旧的 auto 探测结果不再可信，交给后端下次同步重新探测。
  delete caps.detected_transport
  const name = (values.auth_name || '').trim()
  if (values.auth_location === 'path') {
    caps[CAP_AUTH_LOCATION] = 'path'
  } else if (values.auth_location === 'query') {
    caps[CAP_AUTH_LOCATION] = 'query'
    caps[CAP_AUTH_QUERY_PARAM] = name
    caps[CAP_AUTH_TEMPLATE] = values.auth_template || MCP_TEMPLATE_RAW
  } else {
    // 请求头模式且保持默认（Authorization + Bearer）时不写任何新字段，保证存量服务的数据与行为不变。
    const isDefault = name.toLowerCase() === 'authorization' && (values.auth_template || MCP_TEMPLATE_BEARER) === MCP_TEMPLATE_BEARER
    if (!isDefault) {
      if (name && name.toLowerCase() !== 'authorization') caps[CAP_AUTH_HEADER_NAME] = name
      caps[CAP_AUTH_TEMPLATE] = values.auth_template || MCP_TEMPLATE_RAW
    }
  }
  const extra: Record<string, string> = {}
  ;(values.extra_headers || []).forEach((row) => {
    const n = (row?.name || '').trim()
    const v = (row?.value || '').trim()
    if (n && v) extra[n] = v
  })
  if (Object.keys(extra).length > 0) caps[CAP_EXTRA_HEADERS] = extra
  return caps
}

// 客户端侧的轻量校验（后端有同口径的权威校验，这里只为尽早给出中文提示）。
// 占位符：界面写成 {密钥}，提交前转换成后端的 {secret}（也接受直接写 {secret}，或被浏览器编码后的形式）。
const UI_PLACEHOLDER = /\{密钥\}|%7B密钥%7D|%7b密钥%7d|%7B%E5%AF%86%E9%92%A5%7D|%7b%e5%af%86%e9%92%a5%7d/g
const BACKEND_PLACEHOLDER = /\{secret\}|%7Bsecret%7D|%7bsecret%7d/gi

export function serverUrlForSubmit(url: string, location: McpAuthLocation): string {
  if (location !== 'path') return url
  return (url || '').replace(UI_PLACEHOLDER, '{secret}').replace(/%7Bsecret%7D/gi, '{secret}')
}

export function serverUrlForDisplay(url: string, location: McpAuthLocation): string {
  if (location !== 'path') return url
  return (url || '').replace(BACKEND_PLACEHOLDER, '{密钥}')
}

function countPlaceholders(url: string): number {
  return ((url || '').match(UI_PLACEHOLDER) || []).length + ((url || '').match(BACKEND_PLACEHOLDER) || []).length
}

export function validateUpstreamForm(values: McpUpstreamFormValues, serverUrl?: string): string | null {
  const name = (values.auth_name || '').trim()
  if (serverUrl !== undefined) {
    const n = countPlaceholders(serverUrl)
    if (values.auth_location === 'path') {
      if (n !== 1) return `鉴权位置为「URL 路径」时，服务地址必须恰好包含一个 {密钥} 占位（用来标出密钥所在的路径位置），当前包含 ${n} 个`
      const authority = (serverUrl.split('://')[1] || '').split('/')[0]
      const query = serverUrl.includes('?') ? serverUrl.slice(serverUrl.indexOf('?')) : ''
      if (countPlaceholders(authority) > 0 || countPlaceholders(query) > 0) return '{密钥} 占位只能出现在 URL 路径里，不能出现在主机、端口或参数中'
    } else if (n > 0) {
      return '服务地址里出现了 {密钥} 占位，但鉴权位置不是「URL 路径」。请把鉴权位置改为「URL 路径」，或删除该占位'
    }
  }
  if (values.auth_location === 'query' && !/^[A-Za-z0-9_.-]{1,64}$/.test(name)) {
    return 'URL 参数名只能包含字母、数字、下划线、点和短横线'
  }
  if (values.auth_location === 'header' && name && !/^[A-Za-z0-9!#$%&'*+.^_`|~-]{1,128}$/.test(name)) {
    return '请求头名称格式不合法'
  }
  const forbidden = ['host', 'cookie', 'set-cookie', 'content-length', 'content-type', 'transfer-encoding', 'connection', 'proxy-authorization']
  for (const row of values.extra_headers || []) {
    const n = (row?.name || '').trim().toLowerCase()
    if (!n) continue
    if (forbidden.includes(n)) return `额外请求头不允许使用 ${row.name}`
    if (/secret|token|api-?key|password/.test(n)) return `额外请求头 ${row.name} 疑似密钥，请改在「鉴权」中填写`
  }
  return null
}

// URL 里直接写了密钥参数时给出提示（保存时后端会自动拆出并加密存储）。
export function urlHasInlineSecret(url: string | undefined): boolean {
  if (!url) return false
  try {
    const u = new URL(url)
    for (const k of u.searchParams.keys()) {
      const n = k.toLowerCase().replace(/[-_.]/g, '')
      if (['key', 'ak', 'sk', 'apikey', 'accesstoken', 'token', 'authorization', 'secret', 'password'].includes(n)) return true
    }
  } catch {
    return false
  }
  return false
}
