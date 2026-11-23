import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'
import SequenceRuleSettings from '../pages/agentguard/SequenceRuleSettings'
import { SEQUENCE_MAX_MINUTES, sequenceWindowSeconds } from '../pages/agentguard/sequenceRule'
import { agentGuardSequenceRuleApi, isBasicAction, type PolicyCenterAgentBehavior } from '../services/securityPoliciesApi'

const network = (seconds: number): PolicyCenterAgentBehavior & { sensitive_read_egress_window_seconds: number } => ({
  key: 'network_egress',
  label: 'network',
  description: 'network',
  configured_action: 'alert_allow',
  current_action: 'alert_allow',
  health: 'ok',
  allowed_actions: ['record', 'alert_allow', 'block'],
  has_advanced_overrides: false,
  configured: true,
  version: 'v7',
  sensitive_read_egress_window_seconds: seconds,
})

describe('W5 5.5 sequence rule settings', () => {
  it('maps the switch and minutes to a bounded window in seconds', () => {
    expect(sequenceWindowSeconds(false, 30)).toBe(0)
    expect(sequenceWindowSeconds(true, 10)).toBe(600)
    expect(sequenceWindowSeconds(true, null)).toBe(600)
    expect(sequenceWindowSeconds(true, 0)).toBe(60)
    expect(sequenceWindowSeconds(true, 99999)).toBe(SEQUENCE_MAX_MINUTES * 60)
  })

  it('saves the window with the current action and version', async () => {
    const update = vi.spyOn(agentGuardSequenceRuleApi, 'update').mockResolvedValue({ data: network(600) } as never)
    const onSaved = vi.fn()
    render(<SequenceRuleSettings item={network(0)} canManage onSaved={onSaved} />)
    const save = screen.getByTestId('sequence-rule-save')
    expect(save).toBeDisabled()
    fireEvent.click(screen.getByRole('switch'))
    fireEvent.click(save)
    await waitFor(() => expect(onSaved).toHaveBeenCalled())
    expect(update).toHaveBeenCalledWith({ action: 'alert_allow', version: 'v7', sensitive_read_egress_window_seconds: 600 })
    update.mockRestore()
  })

  it('is read-only without manage permission and hidden on an unhealthy item', () => {
    const { rerender } = render(<SequenceRuleSettings item={network(300)} canManage={false} onSaved={vi.fn()} />)
    expect(screen.queryByTestId('sequence-rule-save')).toBeNull()
    expect(screen.getByRole('switch')).toBeDisabled()
    rerender(<SequenceRuleSettings item={{ ...network(300), health: 'error' }} canManage onSaved={vi.fn()} />)
    expect(screen.queryByTestId('sequence-rule-settings')).toBeNull()
  })

  it.each([
    ['record', true],
    ['alert_allow', true],
    ['block', true],
    ['confirm', false],
    ['unknown', false],
    ['toString', false],
    ['constructor', false],
    ['', false],
  ] as const)('保存' + ': isBasicAction(%s)', (action, expected) => {
    expect(isBasicAction(action)).toBe(expected)
  })

  it.each([
    ['confirm', 0], ['confirm', 300],
    ['unknown', 0], ['unknown', 300],
    ['toString', 0], ['toString', 300],
    ['constructor', 0], ['constructor', 300],
  ] as const)('敏感读取后外发' + ': configured_action=%s storedSeconds=%i', (action, seconds) => {
    const update = vi.spyOn(agentGuardSequenceRuleApi, 'update').mockResolvedValue({ data: network(600) } as never)
    try {
      render(<SequenceRuleSettings item={{ ...network(seconds), configured_action: action, current_action: 'unknown', raw_configured_action: action }} canManage onSaved={vi.fn()} />)
      expect(screen.getByTestId('sequence-rule-settings')).toBeInTheDocument()
      const toggle = screen.getByRole('switch')
      expect(toggle).toBeDisabled()
      expect(toggle).toHaveAttribute('aria-checked', seconds > 0 ? 'true' : 'false')
      fireEvent.click(toggle)
      expect(toggle).toHaveAttribute('aria-checked', seconds > 0 ? 'true' : 'false')
      if (seconds > 0) {
        const window = screen.getByRole('spinbutton')
        expect(window).toBeDisabled()
        expect(window).toHaveValue('5')
      } else {
        expect(screen.queryByRole('spinbutton')).toBeNull()
      }
      expect(screen.queryByTestId('sequence-rule-save')).toBeNull()
      expect(update).not.toHaveBeenCalled()
    } finally {
      update.mockRestore()
    }
  })

  it.each([
    ['confirm', 0], ['confirm', 300],
    ['unknown', 0], ['unknown', 300],
    ['toString', 0], ['toString', 300],
    ['constructor', 0], ['constructor', 300],
  ] as const)('敏感读取后外发' + ': dirty configured_action=%s storedSeconds=%i', (action, seconds) => {
    const update = vi.spyOn(agentGuardSequenceRuleApi, 'update').mockResolvedValue({ data: network(600) } as never)
    try {
      const { rerender } = render(<SequenceRuleSettings item={network(seconds)} canManage onSaved={vi.fn()} />)
      const draftToggle = screen.getByRole('switch')
      if (seconds === 0) fireEvent.click(draftToggle)
      fireEvent.change(screen.getByRole('spinbutton'), { target: { value: '17' } })
      expect(screen.getByRole('spinbutton')).toHaveValue('17')
      if (seconds > 0) fireEvent.click(draftToggle)
      expect(draftToggle).toHaveAttribute('aria-checked', seconds === 0 ? 'true' : 'false')
      rerender(<SequenceRuleSettings item={{ ...network(seconds), configured_action: action, current_action: 'unknown', raw_configured_action: action }} canManage onSaved={vi.fn()} />)
      expect(screen.getByTestId('sequence-rule-settings')).toBeInTheDocument()
      const savedToggle = screen.getByRole('switch')
      expect(savedToggle).toBeDisabled()
      expect(savedToggle).toHaveAttribute('aria-checked', seconds > 0 ? 'true' : 'false')
      if (seconds > 0) {
        const window = screen.getByRole('spinbutton')
        expect(window).toBeDisabled()
        expect(window).toHaveValue('5')
      } else {
        expect(screen.queryByRole('spinbutton')).toBeNull()
      }
      expect(screen.queryByTestId('sequence-rule-save')).toBeNull()
      expect(update).not.toHaveBeenCalled()
    } finally {
      update.mockRestore()
    }
  })
})
