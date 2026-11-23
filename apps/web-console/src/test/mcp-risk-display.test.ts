import { describe, expect, it } from 'vitest'
import {
  getMcpRiskTagDescription,
  getMcpTrustLevelDescription,
  getMcpServerStatusDescription,
  getMcpTestConnErrorLabel,
  getMcpJsonRpcFieldLabel,
  MCP_RISK_TAG_ORDER,
  MCP_HIGH_RISK_TAGS,
} from '../utils/risk'

describe('MCP 展示层中文文案（打磨车道新增字典）', () => {
  it('风险标签图例：每个已知标签都有可读中文说明，未知标签也不露英文', () => {
    MCP_RISK_TAG_ORDER.forEach((tag) => {
      const desc = getMcpRiskTagDescription(tag)
      expect(desc.length).toBeGreaterThan(0)
      expect(/[a-z]{4,}/i.test(desc)).toBe(false)
    })
    expect(getMcpRiskTagDescription('some_unknown_tag')).toBe('其他需关注的工具能力')
    expect(getMcpRiskTagDescription(undefined)).toBe('未归类的工具能力')
  })

  it('高危标签集合覆盖破坏性与凭证访问', () => {
    expect(MCP_HIGH_RISK_TAGS.has('destructive')).toBe(true)
    expect(MCP_HIGH_RISK_TAGS.has('cred_access')).toBe(true)
    expect(MCP_HIGH_RISK_TAGS.has('network_egress')).toBe(false)
  })

  it('信任级别与服务状态语义说明可读且有兜底', () => {
    expect(getMcpTrustLevelDescription('low')).toContain('低信任')
    expect(getMcpTrustLevelDescription('high')).toContain('高信任')
    expect(getMcpTrustLevelDescription('weird')).toContain('自定义')
    expect(getMcpTrustLevelDescription(undefined)).toBe('')
    expect(getMcpServerStatusDescription('active')).toContain('启用')
    expect(getMcpServerStatusDescription('disabled')).toContain('停用')
    expect(getMcpServerStatusDescription(undefined)).toBe('')
  })

  it('测试连接错误分类：DNS/超时/401/TLS 都归为可读中文原因', () => {
    expect(getMcpTestConnErrorLabel('dns')).toContain('域名解析')
    expect(getMcpTestConnErrorLabel('timeout')).toContain('超时')
    expect(getMcpTestConnErrorLabel('unauthorized')).toContain('401')
    expect(getMcpTestConnErrorLabel('tls')).toContain('TLS')
    // 未知 kind：优先用后端 message 兜底，其次通用中文
    expect(getMcpTestConnErrorLabel('weird_kind', '后端原始信息')).toBe('后端原始信息')
    expect(getMcpTestConnErrorLabel(undefined)).toContain('连接失败')
  })

  it('JSON-RPC 字段中文回显，未知键原样返回', () => {
    expect(getMcpJsonRpcFieldLabel('method')).toBe('JSON-RPC 方法')
    expect(getMcpJsonRpcFieldLabel('arguments')).toBe('原始入参')
    expect(getMcpJsonRpcFieldLabel('custom_field')).toBe('custom_field')
  })
})
