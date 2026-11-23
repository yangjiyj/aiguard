import { render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { describe, expect, it, vi } from 'vitest'
import PolicyCenterSimpleView from '../pages/security-policy/PolicyCenterSimpleView'

vi.mock('../pages/security-policy/FilePolicySettings', () => ({
  default: ({ showExceptions }: { showExceptions?: boolean }) => (
    <div>{showExceptions ? '内容例外' : '网页 AI 附件准入'}</div>
  ),
}))

describe('策略中心标签布局', () => {
  it('只展示四个业务标签，不展示系统推荐或采用入口', () => {
    render(
      <MemoryRouter>
        <PolicyCenterSimpleView
          policies={[]}
          auditOnly={false}
          canManage
          onReload={vi.fn(async () => undefined)}
        />
      </MemoryRouter>,
    )

    for (const name of ['策略设置', '敏感数据外发', '网页 AI 附件准入', '全部策略']) {
      expect(screen.getByRole('tab', { name })).toBeInTheDocument()
    }
    expect(screen.queryByText('系统推荐')).not.toBeInTheDocument()
    expect(screen.queryByText('稳妥保护')).not.toBeInTheDocument()
    expect(screen.queryByText('当前所有命中只记录')).not.toBeInTheDocument()
    expect(screen.queryByText('按已启用的数据类型配置处置动作')).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '采用推荐方案' })).not.toBeInTheDocument()
  })
})
