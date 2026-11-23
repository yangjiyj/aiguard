import { describe, expect, it } from 'vitest'
import {
  MCP_AUTH_LOCATION_OPTIONS,
  MCP_VENDOR_PRESETS,
  applyVendorPreset,
  capabilitiesFromForm,
  formValuesFromServer,
  serverUrlForSubmit,
  serverUrlForDisplay,
  validateUpstreamForm,
  type McpUpstreamFormValues,
} from '../pages/mcp/upstreamConfig'

const pathForm = (over: Partial<McpUpstreamFormValues> = {}): McpUpstreamFormValues => ({
  transport: 'auto', auth_location: 'path', auth_name: '', auth_template: '{secret}', extra_headers: [], ...over,
})

describe('MCP 鉴权位置：URL 路径（密钥在路径中）', () => {
  it('选项文案是「URL 路径」，且与请求头、URL 参数并列', () => {
    expect(MCP_AUTH_LOCATION_OPTIONS.map((o) => o.label)).toEqual(['请求头', 'URL 参数', 'URL 路径'])
    expect(MCP_AUTH_LOCATION_OPTIONS.map((o) => o.value)).toEqual(['header', 'query', 'path'])
  })

  it('提交前把界面占位 {密钥} 转成后端的 {secret}；展示时转回 {密钥}', () => {
    expect(serverUrlForSubmit('https://x.com/mcp/{密钥}/sse', 'path')).toBe('https://x.com/mcp/{secret}/sse')
    expect(serverUrlForSubmit('https://x.com/mcp/%7B密钥%7D/sse', 'path')).toBe('https://x.com/mcp/{secret}/sse')
    // 用户直接写 {secret} 也接受
    expect(serverUrlForSubmit('https://x.com/mcp/{secret}/sse', 'path')).toBe('https://x.com/mcp/{secret}/sse')
    // 非 path 模式不做转换（后端会拒绝其中的占位）
    expect(serverUrlForSubmit('https://x.com/mcp/{密钥}/sse', 'header')).toBe('https://x.com/mcp/{密钥}/sse')
    expect(serverUrlForDisplay('https://x.com/mcp/%7Bsecret%7D/sse', 'path')).toBe('https://x.com/mcp/{密钥}/sse')
    expect(serverUrlForDisplay('https://x.com/mcp/{secret}/sse', 'path')).toBe('https://x.com/mcp/{密钥}/sse')
    expect(serverUrlForDisplay('https://x.com/mcp?key=***', 'query')).toBe('https://x.com/mcp?key=***')
  })

  it('保存 capabilities：只写鉴权位置 path，不写参数名 / 值模板 / 头名', () => {
    const caps = capabilitiesFromForm(pathForm(), { protocol_version: '2025-11-25', auth_header_name: 'X-Old', upstream_auth_query_param: 'key' })
    expect(caps).toEqual({ protocol_version: '2025-11-25', upstream_auth_location: 'path' })
  })

  it('往返一致：保存后再还原仍是 path', () => {
    const caps = capabilitiesFromForm(pathForm(), undefined)
    const back = formValuesFromServer('auto', caps)
    expect(back.auth_location).toBe('path')
    expect(back.auth_name).toBe('')
  })

  it('客户端校验：path 模式服务地址必须恰好含一个 {密钥}，给出中文提示', () => {
    expect(validateUpstreamForm(pathForm(), 'https://x.com/mcp/sse')).toContain('必须恰好包含一个 {密钥}')
    expect(validateUpstreamForm(pathForm(), 'https://x.com/mcp/{密钥}/{密钥}')).toContain('必须恰好包含一个 {密钥}')
    expect(validateUpstreamForm(pathForm(), 'https://x.com/mcp/{密钥}/sse')).toBeNull()
    expect(validateUpstreamForm(pathForm(), 'https://{密钥}.x.com/mcp')).toContain('只能出现在 URL 路径')
    // 非 path 模式地址里出现 {密钥}：提示改成 URL 路径
    expect(validateUpstreamForm(pathForm({ auth_location: 'header', auth_name: 'Authorization', auth_template: 'Bearer {secret}' }), 'https://x.com/mcp/{密钥}/sse')).toContain('URL 路径')
  })

  it('厂商预设包含路径密钥示例，且只预填表单、示例地址用 {密钥} 占位而不含任何真实密钥', () => {
    const preset = MCP_VENDOR_PRESETS.find((p) => p.auth_location === 'path')
    expect(preset).toBeTruthy()
    expect(preset!.label).toContain('路径')
    expect(applyVendorPreset(preset!)).toMatchObject({ auth_location: 'path' })
    expect(preset!.url_example).toContain('{密钥}')
    for (const p of MCP_VENDOR_PRESETS) expect(p.url_example).not.toMatch(/[?&](key|ak|api_key|Authorization)=/)
  })
})
