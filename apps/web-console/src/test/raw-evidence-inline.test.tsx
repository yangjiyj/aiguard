import { act, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import RawEvidenceInline from '../components/RawEvidenceInline'
import { pickEvidence, rawEvidenceDirection, errorMessage } from '../utils/rawEvidence'
import { rawEvidenceApi } from '../services/rawEvidence'

vi.mock('../services/rawEvidence', () => ({ rawEvidenceApi: { list: vi.fn(), reveal: vi.fn() } }))

const sha = async (text: string) =>
  Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text))), (b) => b.toString(16).padStart(2, '0')).join('')
const header = '-----BEGIN RSA PRIVATE KEY-----'
const original = `帮我看看\n${header}\nMIIEowFAKE`
const meta = { id: 'cre_1', request_id: 'req_1', direction: 'input', role: 'user', message_index: 0, disposition: 'blocked', rule_ids: [], rule_names: [], categories: [], content_chars: original.length, created_at: '2026-11-14T00:00:00Z' }

describe('告警详情里就地查看原文', () => {
  beforeEach(() => {
    vi.mocked(rawEvidenceApi.list).mockReset()
    vi.mocked(rawEvidenceApi.reveal).mockReset()
  })

  it('点开之前不请求原文', () => {
    render(<RawEvidenceInline requestId="req_1" direction="input" messageIndex={0} />)
    expect(screen.getByRole('button', { name: '查看原文' })).toBeTruthy()
    expect(rawEvidenceApi.list).not.toHaveBeenCalled()
    expect(rawEvidenceApi.reveal).not.toHaveBeenCalled()
  })

  it('点开后显示原文并高亮命中位置', async () => {
    vi.mocked(rawEvidenceApi.list).mockResolvedValue({ data: { items: [meta], total: 1, enabled: true } } as never)
    vi.mocked(rawEvidenceApi.reveal).mockResolvedValue({ data: { ...meta, text: original } } as never)
    render(<RawEvidenceInline requestId="req_1" direction="input" messageIndex={0} matchedLocation="content[5:36]" rawEvidenceSha256={await sha(header)} />)
    fireEvent.click(screen.getByRole('button', { name: '查看原文' }))
    await waitFor(() => expect(screen.getByTestId('raw-evidence-hit').textContent).toBe(header))
    expect(rawEvidenceApi.list).toHaveBeenCalledWith({ request_id: 'req_1', direction: 'input', limit: 50 })
    expect(rawEvidenceApi.reveal).toHaveBeenCalledWith('cre_1')
    expect(screen.getByTestId('raw-evidence-text').textContent).toBe(original)
  })

  it('摘要对不上时只显示原文，不高亮', async () => {
    vi.mocked(rawEvidenceApi.list).mockResolvedValue({ data: { items: [meta], total: 1, enabled: true } } as never)
    vi.mocked(rawEvidenceApi.reveal).mockResolvedValue({ data: { ...meta, text: original } } as never)
    render(<RawEvidenceInline requestId="req_1" direction="input" messageIndex={0} matchedLocation="content[5:36]" rawEvidenceSha256={await sha('别的内容')} />)
    fireEvent.click(screen.getByRole('button', { name: '查看原文' }))
    await waitFor(() => expect(screen.getByTestId('raw-evidence-text').textContent).toBe(original))
    expect(screen.queryByTestId('raw-evidence-hit')).toBeNull()
  })

  it('没有对应的原文留证时说明原因', async () => {
    vi.mocked(rawEvidenceApi.list).mockResolvedValue({ data: { items: [], total: 0, enabled: true } } as never)
    render(<RawEvidenceInline requestId="req_1" direction="input" messageIndex={0} />)
    fireEvent.click(screen.getByRole('button', { name: '查看原文' }))
    await waitFor(() => expect(screen.getByText('没有找到这条命中对应的原文留证')).toBeTruthy())
    expect(rawEvidenceApi.reveal).not.toHaveBeenCalled()
  })

  it('读取失败时可以重试', async () => {
    vi.mocked(rawEvidenceApi.list).mockRejectedValue(new Error('boom'))
    render(<RawEvidenceInline requestId="req_1" direction="input" messageIndex={0} />)
    fireEvent.click(screen.getByRole('button', { name: '查看原文' }))
    await waitFor(() => expect(screen.getByText('原文读取失败')).toBeTruthy())
    // antd 的加载图标退出动画在 jsdom 里不会结束，按钮名称会带着残留的 loading，所以用正则匹配
    const retry = screen.getByRole('button', { name: /查看原文/ })
    expect(retry.className).not.toContain('ant-btn-loading')
  })

  it('按消息序号取留证；只有一条时直接用它', () => {
    const other = { ...meta, id: 'cre_2', message_index: 3 }
    expect(pickEvidence([meta, other] as never, 3)?.id).toBe('cre_2')
    expect(pickEvidence([other] as never, 0)?.id).toBe('cre_2')
    expect(pickEvidence([meta, other] as never, 7)).toBeUndefined()
  })

  it('失败时显示后端给的原因，取不到再用默认文字', async () => {
    vi.mocked(rawEvidenceApi.list).mockResolvedValue({ data: { items: [meta], total: 1, enabled: true } } as never)
    vi.mocked(rawEvidenceApi.reveal).mockRejectedValue({ response: { data: { error: { message: '审计写入失败，已拒绝返回原文' } } } })
    render(<RawEvidenceInline requestId="req_1" direction="input" messageIndex={0} />)
    fireEvent.click(screen.getByRole('button', { name: '查看原文' }))
    await waitFor(() => expect(screen.getByText('审计写入失败，已拒绝返回原文')).toBeTruthy())
    expect(errorMessage(new Error('x'), '原文读取失败')).toBe('原文读取失败')
  })

  it('原文限高；截断时提示总字数和保存字数', async () => {
    vi.mocked(rawEvidenceApi.list).mockResolvedValue({ data: { items: [meta], total: 1, enabled: true } } as never)
    vi.mocked(rawEvidenceApi.reveal).mockResolvedValue({ data: { ...meta, text: original, truncated: true, original_chars: 900000, content_chars: 524288 } } as never)
    render(<RawEvidenceInline requestId="req_1" direction="input" messageIndex={0} />)
    fireEvent.click(screen.getByRole('button', { name: '查看原文' }))
    await waitFor(() => expect(screen.getByText('原文共 900000 字，仅保存前 524288 字')).toBeTruthy())
    expect(screen.getByTestId('raw-evidence-text').style.maxHeight).toBe('420px')
  })

  it('没截断时不显示截断提示', async () => {
    vi.mocked(rawEvidenceApi.list).mockResolvedValue({ data: { items: [meta], total: 1, enabled: true } } as never)
    vi.mocked(rawEvidenceApi.reveal).mockResolvedValue({ data: { ...meta, text: original } } as never)
    render(<RawEvidenceInline requestId="req_1" direction="input" messageIndex={0} />)
    fireEvent.click(screen.getByRole('button', { name: '查看原文' }))
    await waitFor(() => expect(screen.getByTestId('raw-evidence-text')).toBeTruthy())
    expect(screen.queryByText(/仅保存前/)).toBeNull()
  })

  it('点击后、列表返回前卸载，不再调查看接口', async () => {
    let resolveList: (v: unknown) => void = () => {}
    vi.mocked(rawEvidenceApi.list).mockReturnValue(new Promise((resolve) => { resolveList = resolve }) as never)
    const view = render(<RawEvidenceInline requestId="req_1" direction="input" messageIndex={0} />)
    fireEvent.click(screen.getByRole('button', { name: '查看原文' }))
    view.unmount()
    await act(async () => { resolveList({ data: { items: [meta], total: 1, enabled: true } }) })
    expect(rawEvidenceApi.reveal).not.toHaveBeenCalled()
  })

  it('方向以阶段为准，阶段缺失时才按来源推断', () => {
    for (const source of ['user', 'model_output', undefined]) expect(rawEvidenceDirection('output', source)).toBe('output')
    for (const [stage, source] of [['input', 'assistant'], ['input', 'model_output'], ['tool', 'model_output']]) expect(rawEvidenceDirection(stage, source)).toBe('input')
    expect(rawEvidenceDirection(undefined, 'model_output')).toBe('output')
    expect(rawEvidenceDirection(null, 'verified_final_output')).toBe('output')
    for (const source of ['assistant', 'assistant_history', 'user', undefined]) expect(rawEvidenceDirection(undefined, source)).toBe('input')
  })
})
