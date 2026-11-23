import { render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { describe, expect, it, vi } from 'vitest'
import AgentBehaviorPolicy from '../pages/security-policy/AgentBehaviorPolicy'
import type { PolicyCenterAgentBehavior } from '../services/securityPoliciesApi'

const item = (overrides: Partial<PolicyCenterAgentBehavior> = {}): PolicyCenterAgentBehavior => ({
  key: 'system_command',
  label: '系统命令',
  description: '管理智能体调用系统命令工具时的处理动作',
  configured_action: 'record',
  current_action: 'record',
  health: 'ok',
  allowed_actions: ['record', 'alert_allow', 'block'],
  has_advanced_overrides: false,
  configured: true,
  version: 'v1',
  ...overrides,
})

describe('智能体行为直接配置', () => {
  it('保留六类动作配置，但不提供推荐方案或失效的运行方案链接', () => {
    const items = [
      item({ key: 'destructive_operation' }),
      item({ key: 'system_command' }),
      item({ key: 'sensitive_resource' }),
      item({ key: 'network_egress', has_advanced_overrides: true }),
      item({ key: 'database_change' }),
      item({ key: 'external_tool' }),
    ]
    render(
      <MemoryRouter>
        <AgentBehaviorPolicy
          items={items}
          auditOnly={false}
          canManage
          loadItems={vi.fn(async () => items)}
          onReload={vi.fn()}
        />
      </MemoryRouter>,
    )

    expect(screen.getAllByRole('radiogroup')).toHaveLength(6)
    expect(screen.queryByRole('button', { name: '采用推荐方案' })).not.toBeInTheDocument()
    expect(screen.queryByRole('link', { name: '查看单独调整' })).not.toBeInTheDocument()
  })
})
