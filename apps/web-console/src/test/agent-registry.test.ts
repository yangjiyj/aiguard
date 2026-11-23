import { describe, expect, it } from 'vitest'
import { formatAgentType, getAgentDetection, isKnownAgentType } from '../utils/agents'
import { getAgentRuleInfo } from '../utils/risk'

describe('agent registry', () => {
  it('contains domestic and global coding agents', () => {
    expect(formatAgentType('codebuddy')).toBe('腾讯 CodeBuddy')
    expect(formatAgentType('tongyi-lingma')).toBe('通义灵码')
    expect(formatAgentType('codearts-snap')).toBe('华为 CodeArts Snap')
    expect(formatAgentType('trae')).toBe('Trae')
    expect(formatAgentType('openai-codex')).toBe('OpenAI Codex')
    expect(formatAgentType('github-copilot')).toBe('GitHub Copilot')
    expect(formatAgentType('deepseek-harness')).toBe('DeepSeek Harness')
    expect(isKnownAgentType('deepseek-harness')).toBe(true)
  })

  it('treats registered agents as client fingerprint detections', () => {
    expect(isKnownAgentType('baidu-comate')).toBe(true)
    expect(getAgentDetection('baidu-comate').label).toBe('客户端标识/特征识别')
    expect(getAgentRuleInfo('baidu-comate').rule).toBe('客户端请求头/特征指纹')
  })
})
