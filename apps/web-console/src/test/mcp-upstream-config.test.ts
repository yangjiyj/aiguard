import { describe, expect, it } from 'vitest'
import {
  MCP_TEMPLATE_OPTIONS,
  templateFromOptionValue,
  templateToOptionValue,
  MCP_TRANSPORT_OPTIONS,
  MCP_VENDOR_PRESETS,
  MCP_UPSTREAM_DEFAULTS,
  applyVendorPreset,
  capabilitiesFromForm,
  formValuesFromServer,
  mcpTemplateOptionsFor,
  urlHasInlineSecret,
  validateUpstreamForm,
} from '../pages/mcp/upstreamConfig'

describe('MCP 上游连接配置（表单 ↔ capabilities）', () => {
  it('存量服务（capabilities 无新字段）还原为与历史行为一致的默认值', () => {
    const v = formValuesFromServer('streamable_http', { protocol_version: '2025-11-25' })
    expect(v).toMatchObject({ transport: 'streamable_http', auth_location: 'header', auth_name: 'Authorization', auth_template: 'Bearer {secret}', extra_headers: [] })
    const custom = formValuesFromServer('streamable_http', { auth_header_name: 'X-Mcp-Token' })
    expect(custom).toMatchObject({ auth_name: 'X-Mcp-Token', auth_template: '{secret}' })
  })

  it('请求头默认配置保存时不写任何新字段，存量数据与行为不变', () => {
    const caps = capabilitiesFromForm(
      { transport: 'streamable_http', auth_location: 'header', auth_name: 'Authorization', auth_template: 'Bearer {secret}', extra_headers: [] },
      { protocol_version: '2025-11-25', detected_transport: 'sse' },
    )
    expect(caps).toEqual({ protocol_version: '2025-11-25' }) // 协议版本保留；旧探测结果因配置变更被清除
  })

  it('URL 参数鉴权：写入参数名与值模板，并保留其它既有键', () => {
    const caps = capabilitiesFromForm(
      { transport: 'sse', auth_location: 'query', auth_name: 'api_key', auth_template: 'Bearer {secret}', extra_headers: [{ name: 'Stripe-Account', value: 'acct_1' }, { name: '', value: 'x' }] },
      { protocol_version: '2025-03-26', auth_header_name: 'Old-Header' },
    )
    expect(caps).toEqual({
      protocol_version: '2025-03-26',
      upstream_auth_location: 'query',
      upstream_auth_query_param: 'api_key',
      upstream_auth_template: 'Bearer {secret}',
      upstream_extra_headers: { 'Stripe-Account': 'acct_1' },
    })
  })

  it('往返一致：保存后再还原得到同样的表单取值', () => {
    const values = { transport: 'auto' as const, auth_location: 'query' as const, auth_name: 'key', auth_template: '{secret}', extra_headers: [{ name: 'X-Tenant', value: 'a' }] }
    const caps = capabilitiesFromForm(values, undefined)
    expect(formValuesFromServer('auto', caps)).toEqual(values)
  })

  it('新建默认「自动识别」，选项文案全部中文化', () => {
    expect(MCP_UPSTREAM_DEFAULTS.transport).toBe('auto')
    expect(MCP_TRANSPORT_OPTIONS.map((o) => o.label)).toEqual(['自动识别（推荐）', 'Streamable HTTP', 'SSE（旧版）'])
  })

  it('厂商预设只预填表单四项，不含任何逻辑开关', () => {
    const amap = MCP_VENDOR_PRESETS.find((p) => p.key === 'amap')!
    expect(applyVendorPreset(amap)).toEqual({ transport: 'auto', auth_location: 'query', auth_name: 'key', auth_template: '{secret}' })
    const baidu = MCP_VENDOR_PRESETS.find((p) => p.key === 'baidu_appbuilder')!
    expect(applyVendorPreset(baidu)).toEqual({ transport: 'sse', auth_location: 'query', auth_name: 'api_key', auth_template: 'Bearer {secret}' })
    for (const label of ['阿里云百炼', '高德地图', '百度地图', '腾讯位置服务', '魔搭 ModelScope', '通用 Bearer']) {
      expect(MCP_VENDOR_PRESETS.some((p) => p.label === label)).toBe(true)
    }
    expect(MCP_VENDOR_PRESETS.some((p) => p.label.startsWith('智谱'))).toBe(true)
    // 预设数据里不应出现可直接保存的明文密钥
    for (const p of MCP_VENDOR_PRESETS) expect(p.url_example).not.toMatch(/[?&](key|ak|api_key|Authorization)=/)
  })

  it('客户端校验：非法参数名、禁用头、疑似密钥头给出中文提示', () => {
    const base = { ...MCP_UPSTREAM_DEFAULTS }
    expect(validateUpstreamForm({ ...base, auth_location: 'query', auth_name: 'a b' })).toContain('URL 参数名')
    expect(validateUpstreamForm({ ...base, extra_headers: [{ name: 'Host', value: 'x' }] })).toContain('不允许')
    expect(validateUpstreamForm({ ...base, extra_headers: [{ name: 'X-Api-Token', value: 'x' }] })).toContain('疑似密钥')
    expect(validateUpstreamForm({ ...base, extra_headers: [{ name: 'Stripe-Account', value: 'acct' }] })).toBeNull()
  })

  it('识别服务地址中的明文密钥参数', () => {
    expect(urlHasInlineSecret('https://mcp.amap.com/mcp?key=abc')).toBe(true)
    expect(urlHasInlineSecret('https://x.example/sse?Authorization=t')).toBe(true)
    expect(urlHasInlineSecret('https://x.example/mcp?region=cn')).toBe(false)
    expect(urlHasInlineSecret('not a url')).toBe(false)
  })
})

// D6：值模板下拉不得向用户露出后端占位符 {secret}；value 仍是后端协议值，不变。
describe('值模板选项中文化（D6）与内部代号（R1）', () => {
  it('预置选项的 value 是内部代号，label 是中文；任何字段都不含 {secret}', () => {
    expect(MCP_TEMPLATE_OPTIONS).toEqual([
      { value: 'bearer', label: 'Bearer + 密钥' },
      { value: 'raw', label: '仅密钥（原样）' },
    ])
    expect(JSON.stringify(MCP_TEMPLATE_OPTIONS)).not.toContain('{secret}')
  })

  it('后端模板值与内部代号双向映射；预置值互逆', () => {
    expect(templateToOptionValue('Bearer {secret}')).toBe('bearer')
    expect(templateToOptionValue('{secret}')).toBe('raw')
    expect(templateFromOptionValue('bearer')).toBe('Bearer {secret}')
    expect(templateFromOptionValue('raw')).toBe('{secret}')
  })

  it('自定义/历史模板走同样逻辑：用不透明代号承载，提交时还原为原始模板值', () => {
    const code = templateToOptionValue('Token {secret}')
    expect(code).not.toContain('{secret}')
    expect(code).not.toBe('bearer')
    expect(code).not.toBe('raw')
    expect(templateFromOptionValue(code, 'Token {secret}')).toBe('Token {secret}')
    // 不同的自定义模板得到不同的代号，同一个模板得到稳定的代号
    expect(templateToOptionValue('Basic {secret}')).not.toBe(code)
    expect(templateToOptionValue('Token {secret}')).toBe(code)
  })

  // L-3：空模板的语义是「按鉴权位置取默认」（请求头 Authorization 默认 Bearer，URL 参数与自定义头默认原样），
  // 不是「Bearer」。空值既不能在下拉里显示成 Bearer，认不出的代号也不能悄悄变成 Bearer 前缀写进密钥。
  it('空值与未知代号不映射成 Bearer，也不抛错', () => {
    expect(templateToOptionValue('')).toBeUndefined()
    expect(templateToOptionValue(undefined)).toBeUndefined()
    expect(templateToOptionValue('   ')).toBeUndefined()
    expect(templateFromOptionValue('', undefined)).toBe('')
    expect(templateFromOptionValue(undefined, undefined)).toBe('')
    expect(templateFromOptionValue('no-such-code', undefined)).toBe('')
  })

  it('空模板提交时按鉴权位置取默认，与回显口径一致', () => {
    const base = { transport: 'auto' as const, auth_name: '', extra_headers: [] }
    // URL 参数：空 → 原样 {secret}
    expect(capabilitiesFromForm({ ...base, auth_location: 'query', auth_name: 'key', auth_template: '' }, {}).upstream_auth_template).toBe('{secret}')
    // 自定义请求头：空 → 原样
    expect(capabilitiesFromForm({ ...base, auth_location: 'header', auth_name: 'X-Api-Key', auth_template: '' }, {}).upstream_auth_template).toBe('{secret}')
    // 默认的 Authorization 头：空 → 沿用默认 Bearer，不写任何新字段（存量行为不变）
    const caps = capabilitiesFromForm({ ...base, auth_location: 'header', auth_name: 'Authorization', auth_template: '' }, {})
    expect(caps).not.toHaveProperty('upstream_auth_template')
  })

  it('自定义/历史模板也以中文展示，不露出 {secret}', () => {
    const opts = mcpTemplateOptionsFor('Token {secret}')
    const custom = opts.find((o) => o.label === 'Token {密钥}')
    expect(custom).toBeTruthy()
    expect(custom!.value).not.toContain('{secret}')
    for (const o of opts) {
      expect(String(o.label)).not.toContain('{secret}')
      expect(String(o.value)).not.toContain('{secret}')
    }
    expect(mcpTemplateOptionsFor('Bearer {secret}')).toHaveLength(2)
    expect(mcpTemplateOptionsFor('')).toHaveLength(2)
    expect(mcpTemplateOptionsFor(undefined)).toHaveLength(2)
  })
})
