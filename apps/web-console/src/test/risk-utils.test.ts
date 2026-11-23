import { describe, expect, it } from 'vitest'
import { getEventMatchedRules, getRiskCategoryLabel, getToolAuditNoteLabel, getToolParameterLabel, responsibilityDisplay, responsibilitySearchText, sourceIpDisplay, upstreamPrincipalLabel, MASQUERADE_GATEWAY_IP, severityTone, riskStateTone } from '../utils/risk'

describe('tool audit completion notes', () => {
  it('maps gateway _audit_notes markers to Chinese text instead of raw English keys', () => {
    expect(getToolParameterLabel('_audit_notes')).toBe('审计补全说明')
    expect(getToolAuditNoteLabel('tool_name_missing')).toContain('未提供工具名称')
    expect(getToolAuditNoteLabel('tool_type_missing')).toContain('未提供工具类型')
    expect(getToolAuditNoteLabel('something_new')).toBe('审计补全说明（未识别）')
    expect(getToolAuditNoteLabel(undefined)).toBe('审计补全说明（未识别）')
  })
})

describe('risk display labels', () => {
  it('turns detector internals into customer-readable risk categories', () => {
    expect(getRiskCategoryLabel('keyword_classic_injection')).toBe('Prompt 注入')
    expect(getRiskCategoryLabel('aws_secret_key')).toBe('敏感凭据泄露')
    expect(getRiskCategoryLabel('config_file')).toBe('配置文件风险')
  })

  it('labels data-security, file-control and deterministic redline categories for enterprise users', () => {
    // 自定义/数据安全分类
    expect(getRiskCategoryLabel('custom')).toBe('客户敏感数据')
    expect(getRiskCategoryLabel('custom_medical_record')).toBe('客户敏感数据')
    expect(getRiskCategoryLabel('data_security')).toBe('数据安全')
    // 文件格式管控分类（engine 文件检视器统一 file_ 前缀）
    expect(getRiskCategoryLabel('file_security')).toBe('文件安全')
    expect(getRiskCategoryLabel('file_fingerprint')).toBe('文件指纹')
    expect(getRiskCategoryLabel('file_disguised_executable')).toBe('文件安全')
    expect(getRiskCategoryLabel('file_zip_bomb')).toBe('文件安全')
    expect(getRiskCategoryLabel('file_unknown_type')).toBe('未知文件类型审计')
    expect(getRiskCategoryLabel('structured_html_comment')).toBe('HTML 注释结构审计')
    expect(getRiskCategoryLabel('structured_template_injection')).toBe('模板结构审计')
    expect(getRiskCategoryLabel('private_key')).toBe('私钥外发')
    expect(getRiskCategoryLabel('credential_path')).toBe('系统凭证路径')
    expect(getRiskCategoryLabel('malicious_script')).toBe('恶意脚本外发')
    expect(getRiskCategoryLabel('cloud_metadata')).toBe('云元数据地址')
    expect(getRiskCategoryLabel('internal_endpoint')).toBe('内网高危地址')
  })

  it('formats matched detector rules as readable rule names', () => {
    expect(
      getEventMatchedRules({
        matched_summary: {
          findings: [
            {
              rule_id: 'prompt_injection_classic_injection',
              category: 'keyword_classic_injection',
            },
          ],
        },
      })
    ).toEqual(['Prompt 注入：经典指令绕过'])
  })
})

describe('semantic tone discipline (no rainbow tags)', () => {
  it('collapses severity onto only red/orange/green/gray', () => {
    // 风险：严重/高危 → 红
    expect(severityTone('critical')).toBe('red')
    expect(severityTone('high')).toBe('red')
    // 预警：中危/低危 → 橙
    expect(severityTone('medium')).toBe('orange')
    expect(severityTone('low')).toBe('orange')
    // 安全/放行 → 绿
    expect(severityTone('normal')).toBe('green')
    expect(severityTone('allow')).toBe('green')
    // 中性提示/未知 → 灰，绝不再出现 blue/gold/cyan/purple 等彩虹色
    expect(severityTone('info')).toBe('gray')
    expect(severityTone('whatever')).toBe('gray')
    expect(severityTone()).toBe('gray')
  })

  it('maps risk-state conclusions onto the same four semantic tones', () => {
    expect(riskStateTone('blocked')).toBe('red')
    expect(riskStateTone('risk')).toBe('orange')
    expect(riskStateTone('normal')).toBe('green')
    // 审计线索等非结论态收灰，而不是过去的蓝色
    expect(riskStateTone('audit')).toBe('gray')
    expect(riskStateTone()).toBe('gray')
  })
})

describe('source IP honest display', () => {
  it('honestly labels the bridge-gateway IP instead of passing it off as the client source', () => {
    // userland-proxy 把环回连接的源地址改写成网关 IP，真实客户端 IP 已不可得——
    // 必须诚实标注，不能把网关 IP 当成「来源」误导排查。
    const r = sourceIpDisplay(MASQUERADE_GATEWAY_IP)
    expect(r.masqueraded).toBe(true)
    expect(r.text).toBe('本机/隧道接入')
    expect(r.text).not.toContain(MASQUERADE_GATEWAY_IP)
    expect(r.tooltip).toContain(MASQUERADE_GATEWAY_IP)
  })

  it('passes real external (LAN / tailscale) IPs through unchanged', () => {
    expect(sourceIpDisplay('10.10.10.8')).toEqual({ text: '10.10.10.8', masqueraded: false })
    expect(sourceIpDisplay('100.64.0.7')).toEqual({ text: '100.64.0.7', masqueraded: false })
  })

  it('renders a dash for a missing source IP', () => {
    expect(sourceIpDisplay()).toEqual({ text: '-', masqueraded: false })
    expect(sourceIpDisplay('')).toEqual({ text: '-', masqueraded: false })
  })
})

describe('responsibility display', () => {
  it('prefers a bound user and keeps source IP as trace evidence', () => {
    expect(responsibilityDisplay({ username: 'zhangsan', userId: 'user_1', sourceIp: '10.10.10.8', direction: 'reverse' }))
      .toEqual({ primary: 'zhangsan', secondary: '反向代理 · 10.10.10.8', kind: 'user' })
  })

  it('shows the API key and its bound user as one responsibility identity', () => {
    expect(responsibilityDisplay({
      username: 'sec', userId: 'user_1', clientName: '大模型评估，攻击', clientId: 'key_1',
      sourceIp: '172.23.0.1', direction: 'chat_completion',
    })).toEqual({
      primary: 'sec',
      secondary: 'API Key：大模型评估，攻击 · 172.23.0.1',
      kind: 'api_key',
    })
  })

  it('labels an unbound reverse proxy without treating caller id as a person', () => {
    expect(responsibilityDisplay({ clientId: 'caller_abc', sourceIp: '100.64.0.7', direction: 'reverse' }))
      .toEqual({ primary: '反向代理', secondary: '100.64.0.7', kind: 'channel' })
  })

  it('labels a caller without direction as a caller instead of an unbound user', () => {
    expect(responsibilityDisplay({ clientId: 'caller_abc', sourceIp: '100.64.0.7' }))
      .toEqual({ primary: '未关联账号', secondary: '100.64.0.7', kind: 'channel' })
  })

  it('shows an unbound API key without treating its name as a person', () => {
    expect(responsibilityDisplay({ clientName: '研发助手', clientId: 'caller_abc', sourceIp: '100.64.0.7', direction: 'reverse' }))
      .toEqual({ primary: '未绑定用户', secondary: 'API Key：研发助手 · 100.64.0.7', kind: 'api_key' })
  })

  it('labels an unmatched credential as an unbound API key', () => {
    expect(responsibilityDisplay({
      credentialType: 'api_key', sourceIp: '100.107.122.106', direction: 'reverse',
    })).toEqual({
      primary: '未绑定 API Key', secondary: '反向代理 · 100.107.122.106', kind: 'api_key',
    })
  })

  it('labels forward proxy and MCP traffic when no user is bound', () => {
    expect(responsibilityDisplay({ sourceIp: '10.0.0.5', direction: 'forward' }).primary).toBe('正向代理')
    expect(responsibilityDisplay({ sourceIp: '10.0.0.6', direction: 'mcp' }).primary).toBe('MCP 网关')
  })

  it('builds searchable text from user, caller, IP and channel metadata', () => {
    const text = responsibilitySearchText({
      username: 'zhangsan', userId: 'user_1', clientName: '研发助手', clientId: 'caller_abc',
      sourceIp: '10.10.10.8', direction: 'reverse',
    })
    for (const value of ['zhangsan', '研发助手', 'API Key', '密钥', '10.10.10.8', '反向代理', 'reverse']) {
      expect(text).toContain(value.toLowerCase())
    }
    expect(text).not.toContain('user_1')
    expect(text).not.toContain('caller_abc')
  })
})

describe('upstream principal labels', () => {
  it('turns an upstream account key into a readable label with a truncated id', () => {
    expect(upstreamPrincipalLabel('upstream:openai_account:7f3a91c0deadbeef')).toBe('上游账号 openai:7f3a91c0')
    expect(upstreamPrincipalLabel('upstream:anthropic_account:123e4567-e89b-12d3-a456-426614174000')).toBe('上游账号 anthropic:123e4567')
  })

  it('labels a hashed credential as a fingerprint and never as the raw value', () => {
    expect(upstreamPrincipalLabel('upstream:credential:0123456789abcdef')).toBe('上游凭据指纹 0123456789abcdef')
  })

  it('ignores anything that is not an upstream principal so the source IP still wins', () => {
    expect(upstreamPrincipalLabel(undefined)).toBe('')
    expect(upstreamPrincipalLabel('')).toBe('')
    expect(upstreamPrincipalLabel('192.168.56.1')).toBe('')
    expect(upstreamPrincipalLabel('upstream:')).toBe('')
    expect(upstreamPrincipalLabel('upstream:unknown_kind:abc')).toBe('')
  })

  it('shows the upstream account as the subject when the request carries no user', () => {
    const display = responsibilityDisplay({ sourceIp: '192.168.56.1', proxyNat: true, principalKey: 'upstream:openai_account:7f3a91c0deadbeef' })
    expect(display.kind).toBe('upstream')
    expect(display.primary).toBe('上游账号 openai:7f3a91c0')
    expect(display.secondary).toContain('（经 NAT，不能定位到人）')
  })

  it('marks the source IP as NAT-only when the gateway rewrote it', () => {
    const display = responsibilityDisplay({ sourceIp: '192.168.56.1', proxyNat: true })
    expect(display.kind).toBe('channel')
    // responsibilityDisplay 直接给裸 IP 加说明；"来源 IP"前缀只由页面在抽屉里补。
    expect(display.secondary).toBe('192.168.56.1（经 NAT，不能定位到人）')
  })

  it('keeps a plain source IP untouched when it is not behind NAT', () => {
    const display = responsibilityDisplay({ sourceIp: '192.168.56.1' })
    expect(display.secondary).toBe('192.168.56.1')
    expect(display.secondary).not.toContain('（经 NAT，不能定位到人）')
  })
})
