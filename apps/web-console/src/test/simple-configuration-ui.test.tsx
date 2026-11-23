import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it, vi } from 'vitest'
import {
  SaveImpactDialog,
  SaveResultBanner,
  ScenarioActionRow,
} from '../pages/security-policy/SimpleConfigurationUI'

describe('SimpleConfigurationUI', () => {
  it('提供有标签的动作控件，并只在配置与实际不同时重复显示配置', () => {
    const { rerender } = render(
      <ScenarioActionRow
        title="提示词攻击"
        description="识别绕过指令"
        effectiveLabel="告警并阻止"
        configuredLabel="告警并阻止"
        value="block"
        options={[{ value: 'block', label: '阻止' }]}
        onChange={vi.fn()}
      />,
    )

    expect(screen.getByRole('radiogroup', { name: '提示词攻击处理方式' })).toBeInTheDocument()
    expect(screen.getByText('当前生效：告警并阻止')).toBeInTheDocument()
    expect(screen.queryByText(/已配置：/)).not.toBeInTheDocument()

    rerender(
      <ScenarioActionRow
        title="提示词攻击"
        description="识别绕过指令"
        effectiveLabel="仅记录"
        configuredLabel="告警并阻止"
        mismatchReason="当前为记录模式"
        value="block"
        options={[{ value: 'block', label: '阻止' }]}
        onChange={vi.fn()}
      />,
    )
    expect(screen.getByText('已配置：告警并阻止')).toBeInTheDocument()
    expect(screen.getByText('当前为记录模式')).toBeInTheDocument()
  })

  it('在确认前列出每项影响', () => {
    render(
      <SaveImpactDialog
        open
        changes={[
          { key: 'prompt', label: '提示词攻击', from: '记录', to: '阻止' },
          { key: 'file', label: '文件上传', from: '关闭正文检测', to: '开启正文检测' },
        ]}
        impact="阻止可能中断高风险请求。"
        onConfirm={vi.fn()}
        onCancel={vi.fn()}
      />,
    )

    expect(screen.getByRole('dialog', { name: '确认保存全部调整' })).toBeInTheDocument()
    expect(screen.getByText('提示词攻击：记录 -> 阻止')).toBeInTheDocument()
    expect(screen.getByText('文件上传：关闭正文检测 -> 开启正文检测')).toBeInTheDocument()
  })

  it('展示精确的部分失败结果，并只重试失败项', async () => {
    const user = userEvent.setup()
    const onRetry = vi.fn()
    render(
      <SaveResultBanner
        results={[
          { key: 'prompt', status: 'saved', previousAction: 'record', requestedAction: 'block' },
          { key: 'network', status: 'failed', previousAction: 'record', requestedAction: 'alert_allow', message: '版本冲突' },
        ]}
        itemLabels={{ prompt: '提示词攻击', network: '访问外部网络' }}
        onRetry={onRetry}
      />,
    )

    expect(screen.getByText(/已保存：提示词攻击/)).toBeInTheDocument()
    expect(screen.getByText(/未保存：访问外部网络（版本冲突）/)).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '重试未保存项' }))
    expect(onRetry).toHaveBeenCalledWith(['network'])
  })


  it("展示精确的部分失败结果，并只重试失败项" + ': skipped is not success', () => {
    render(<SaveResultBanner results={[{ key: 'network', status: 'skipped', previousAction: 'record', requestedAction: 'block', message: 'unavailable' }]} itemLabels={{ network: 'network' }} />)
    expect(screen.getByText("部分调整未保存")).toBeInTheDocument()
    expect(screen.queryByText("全部保存成功")).not.toBeInTheDocument()
    expect(screen.getByText(/unavailable/)).toBeInTheDocument()
  })
})
