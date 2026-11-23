import { describe, it, expect } from 'vitest'
import { clientBaseUrls, gatewayAddressRisks, PLAINTEXT_GATEWAY_PORTS } from '../utils/clientBaseUrl'

// 现场 P3-9：Anthropic 协议客户端（Claude Code）自己拼 /v1/messages，Base URL 不能带 /v1；
// OpenAI 协议客户端的 base_url 要带 /v1。地址必须来自「对外调用地址」配置，不能写死。
describe('按协议给出的客户端 Base URL', () => {
  it('OpenAI 协议带 /v1，Anthropic 协议不带 /v1', () => {
    expect(clientBaseUrls('https://gateway.customer.test/v1')).toEqual({
      openai: 'https://gateway.customer.test/v1',
      anthropic: 'https://gateway.customer.test',
    })
  })

  it('保留端口、IPv6 和反向代理路径前缀，只去掉末尾的 /v1', () => {
    expect(clientBaseUrls('http://[2001:db8::1]:8084/proxy/prefix/v1')).toEqual({
      openai: 'http://[2001:db8::1]:8084/proxy/prefix/v1',
      anthropic: 'http://[2001:db8::1]:8084/proxy/prefix',
    })
    expect(clientBaseUrls('http://192.168.20.246:8080/v1').anthropic).toBe('http://192.168.20.246:8080')
  })

  it('重复的 /v1 先合并成一层，不会把重复写法原样显示给用户', () => {
    expect(clientBaseUrls('https://gw.test/v1/v1/')).toEqual({ openai: 'https://gw.test/v1', anthropic: 'https://gw.test' })
  })

  it('没有配置或地址不合法时不给出任何地址，不猜测端口', () => {
    for (const raw of ['', undefined, null, 'javascript:alert(1)', 'https://u:p@gw.test/v1', 'not a url']) {
      expect(clientBaseUrls(raw)).toEqual({ openai: '', anthropic: '' })
    }
  })
})

describe('接入地址的常见错误提示', () => {
  it('https 配到网关的明文端口时给出提示，并说明可能的例外', () => {
    for (const port of PLAINTEXT_GATEWAY_PORTS) {
      const risks = gatewayAddressRisks(`https://gw.test:${port}/v1`)
      expect(risks.some(text => text.includes('https') && text.includes(`${port}`) && text.includes('明文'))).toBe(true)
    }
    expect(gatewayAddressRisks('https://gw.test:8080/v1')[0]).toMatch(/改成 http|确认该端口前面已配置 TLS/)
  })

  it('http 配 8080、https 配 443/8453 等正常组合不提示', () => {
    for (const ok of ['http://gw.test:8080/v1', 'https://gw.test/v1', 'https://gw.test:443/v1', 'https://gw.test:8453/v1', 'https://gw.test:8443/v1', 'http://gw.test:8084/v1']) {
      expect(gatewayAddressRisks(ok)).toEqual([])
    }
  })

  it('原始输入里重复写了 /v1 时提示，大小写不敏感，路径中间的 v1 不算', () => {
    expect(gatewayAddressRisks('https://gw.test/v1/v1').some(text => text.includes('/v1') && text.includes('重复'))).toBe(true)
    expect(gatewayAddressRisks('https://gw.test/prefix/V1/v1/').some(text => text.includes('重复'))).toBe(true)
    expect(gatewayAddressRisks('https://gw.test/v1/prefix/v1')).toEqual([])
    expect(gatewayAddressRisks('https://gw.test/v1')).toEqual([])
  })

  it('同时犯两个错误时两条提示都给出；非字符串、无法解析的输入不报错', () => {
    expect(gatewayAddressRisks('https://gw.test:8080/v1/v1')).toHaveLength(2)
    for (const raw of ['', undefined, null, 42, '::::', 'ftp://gw.test:8080/v1']) {
      expect(gatewayAddressRisks(raw)).toEqual([])
    }
  })

  it('提示文案是中文，不含请求之外的英文原文', () => {
    for (const text of [...gatewayAddressRisks('https://gw.test:8080/v1/v1')]) {
      expect(text).not.toMatch(/\b(wrong version|handshake|error)\b/i)
    }
  })
})
