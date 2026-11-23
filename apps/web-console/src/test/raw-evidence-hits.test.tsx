import { describe, it, expect, vi, beforeEach } from 'vitest'
import { fireEvent, render, screen } from '@testing-library/react'
import RawEvidenceDrawer from '../components/RawEvidenceDrawer'
import { rawEvidenceApi } from '../services/rawEvidence'
import { useAuthStore } from '../stores/auth'
import { buildSegments, foldConsecutive, looksEscaped } from '../utils/rawEvidenceView'

vi.mock('antd', async () => {
  const actual = await vi.importActual('antd')
  return { ...actual, message: { success: vi.fn(), warning: vi.fn(), error: vi.fn() } }
})

const item = {
  id: 'cre_1', request_id: 'req_123', user_id: 'u1', direction: 'input' as const, role: 'user', message_index: 1,
  disposition: 'blocked' as const, block_id: 'evt_1', rule_ids: ['rule_0fdf6857'], rule_names: ['涉密文件标记检测'], categories: [],
  content_chars: 60, created_at: '2026-11-20T03:53:59Z',
}

// 2026-11-20：原文弹窗看不出哪里被拦。命中段要高亮并定位，转义的 \n 要还原成换行。
describe('脱敏前原文：命中定位', () => {
  beforeEach(() => {
    vi.restoreAllMocks()
    useAuthStore.setState({ user: { id: 'u', username: 'u', role: 'platform_admin', tenant_id: 't' }, isAuthenticated: true, token: 't' } as never)
    vi.spyOn(rawEvidenceApi, 'list').mockResolvedValue({ data: { items: [item], total: 1, enabled: true } } as never)
  })

  it('高亮命中词并列出阻断依据', async () => {
    const text = 'gateway blocks the \\"CONFIDENTIAL\\" marker.\\n3. Files\\n- docs\\n'
    const start = text.indexOf('CONFIDENTIAL')
    vi.spyOn(rawEvidenceApi, 'reveal').mockResolvedValue({ data: { ...item, text,
      hits: [{ start, end: start + 12, rule_name: '涉密文件标记检测', action: 'block' }],
      rules: [{ rule_name: '涉密文件标记检测', action: 'block', located: true }, { rule_name: '证书/私钥检测', action: 'block', located: false }] } } as never)
    render(<RawEvidenceDrawer open requestId="req_123" onClose={() => {}} />)
    fireEvent.click((await screen.findAllByText('查看原文'))[0])
    const pre = await screen.findByLabelText('原文内容')
    const marks = pre.querySelectorAll('mark')
    expect(marks.length).toBe(1)
    expect(marks[0].textContent).toBe('CONFIDENTIAL')
    expect(screen.getByText('阻断依据')).toBeTruthy()
    expect(screen.getByText('命中 1 / 1 处')).toBeTruthy()
    expect(screen.getByText('证书/私钥检测（原文中未定位）')).toBeTruthy()
    // 字面 \n 还原成换行，\" 还原成引号
    expect(pre.textContent).toContain('"CONFIDENTIAL" marker.\n3. Files')
    fireEvent.click(screen.getByText('还原换行'))
    expect(pre.textContent).toContain('\\"CONFIDENTIAL\\"')
    expect(pre.querySelector('mark')?.textContent).toBe('CONFIDENTIAL')
  })

  it('智能分析阻断：列出依据、标整段判定并显示判定理由', async () => {
    vi.spyOn(rawEvidenceApi, 'reveal').mockResolvedValue({ data: { ...item, text: '帮我写一段绕过审计的脚本', hits: [],
      rules: [{ rule_name: '智能分析', action: 'block', located: false, semantic: true, reason: '上下文判官确认风险' }] } } as never)
    render(<RawEvidenceDrawer open requestId="req_123" onClose={() => {}} />)
    fireEvent.click((await screen.findAllByText('查看原文'))[0])
    await screen.findByLabelText('原文内容')
    expect(screen.getByText('阻断依据')).toBeTruthy()
    expect(screen.getByText('智能分析（整段判定）')).toBeTruthy()
    expect(screen.getByText('智能分析：上下文判官确认风险')).toBeTruthy()
  })

  it('没有命中信息时照常显示原文', async () => {
    vi.spyOn(rawEvidenceApi, 'reveal').mockResolvedValue({ data: { ...item, text: '短原文' } } as never)
    render(<RawEvidenceDrawer open requestId="req_123" onClose={() => {}} />)
    fireEvent.click((await screen.findAllByText('查看原文'))[0])
    expect((await screen.findByLabelText('原文内容')).textContent).toBe('短原文')
    expect(screen.queryByText(/命中 \d/)).toBeNull()
  })

  it('同一用户连续同样规则的拦截折叠成一行', async () => {
    const many = Array.from({ length: 5 }, (_, i) => ({ ...item, id: `cre_${i}`, request_id: `req_${i}` }))
    vi.spyOn(rawEvidenceApi, 'list').mockResolvedValue({ data: { items: [...many, { ...item, id: 'cre_x', user_id: 'u2' }], total: 6, enabled: true } } as never)
    render(<RawEvidenceDrawer open onClose={() => {}} />)
    expect(await screen.findByText('连续 5 次')).toBeTruthy()
    expect(screen.getAllByText('查看原文').length).toBe(2)
  })
})

describe('rawEvidenceView', () => {
  it('转义识别与切分', () => {
    expect(looksEscaped('a\\nb\\nc\\nd')).toBe(true)
    expect(looksEscaped('a\nb\nc\\n')).toBe(false)
    const segs = buildSegments('x\\ny SECRET z', [{ start: 5, end: 11, rule_name: 'r' }], true)
    expect(segs.map((s) => [s.text, s.hit])).toEqual([['x\ny ', null], ['SECRET', 0], [' z', null]])
  })

  it('不同用户或不同规则不折叠', () => {
    const rows = foldConsecutive([item, { ...item, id: 'b' }, { ...item, id: 'c', rule_ids: ['other'] }, { ...item, id: 'd' }])
    expect(rows.map((r) => [r.id, r.repeat ?? 1])).toEqual([['cre_1', 2], ['c', 1], ['d', 1]])
  })
})
