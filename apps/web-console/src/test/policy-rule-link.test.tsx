import { render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { beforeEach, describe, expect, it } from 'vitest'
import PolicyRuleLink from '../components/PolicyRuleLink'
import { withEvent } from '../utils/policyEventLink'
import { useAuthStore } from '../stores/auth'

describe('命中规则链接带上事件编号', () => {
  beforeEach(() => {
    useAuthStore.setState({ token: 't', user: { id: 'a', username: 'a', role: 'platform_admin', tenant_id: 't' }, isAuthenticated: true })
  })

  it('只给策略中心的链接加 event 参数', () => {
    expect(withEvent('/security/policies?policy=rule_1', 'evt_9')).toBe('/security/policies?policy=rule_1&event=evt_9')
    expect(withEvent('/security/policies?policy=rule_1', '')).toBe('/security/policies?policy=rule_1')
    expect(withEvent('/security/agent-behaviors?behavior=x', 'evt_9')).toBe('/security/agent-behaviors?behavior=x')
  })

  it('事件编号里的特殊字符会被转义', () => {
    expect(withEvent('/security/policies?policy=rule_1', 'evt 9&x')).toBe('/security/policies?policy=rule_1&event=evt%209%26x')
  })

  it('链接带上事件编号', () => {
    render(<MemoryRouter><PolicyRuleLink link={{ kind: 'policy', path: '/security/policies?policy=rule_1', label: '规则' }} eventId="evt_9" /></MemoryRouter>)
    expect(screen.getByTestId('policy-rule-link').getAttribute('href')).toBe('/security/policies?policy=rule_1&event=evt_9')
  })

  it('已删除的策略仍显示纯文本', () => {
    render(<MemoryRouter><PolicyRuleLink link={{ kind: 'deleted', label: '旧规则' }} eventId="evt_9" /></MemoryRouter>)
    expect(screen.getByText('旧规则（已删除）')).toBeTruthy()
  })
})
