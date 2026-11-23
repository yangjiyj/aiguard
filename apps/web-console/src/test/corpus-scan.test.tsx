import { beforeEach, describe, expect, it, vi } from 'vitest'
import { act, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'
import { ConfigProvider } from 'antd'
import CorpusScan from '../pages/CorpusScan'
import { useAuthStore } from '../stores/auth'
import { canAccessPath, canSeeMenuItem, PAGE_ACCESS } from '../utils/access'
import { CORPUS_CHUNK_BYTES, Sha256, corpusDownloadUrl, sha256Hex, uploadCorpusFile } from '../services/corpusScan'

const corpusApi = vi.hoisted(() => ({ list: vi.fn(), get: vi.fn(), create: vi.fn(), uploadChunk: vi.fn(), start: vi.fn(), cancel: vi.fn(), remove: vi.fn() }))
vi.mock('../services/corpusScan', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../services/corpusScan')>()
  return { ...actual, corpusScanApi: corpusApi }
})

const baseJob = (overrides: Record<string, unknown> = {}) => ({
  job_id: 'corpus_6f1c9a52-6a43-4d8b-9a4e-3f0d6c1b2a10', created_by: 'u1', file_name: '训练集.jsonl', format: 'jsonl',
  size_bytes: 2048, sha256: 'a'.repeat(64), status: 'succeeded', error_code: '', cancel_requested: false,
  uploaded_bytes: 2048, next_chunk: 1, processed_bytes: 2048, total_records: 10, scanned_records: 9, hit_records: 3,
  unscanned_records: 1, incomplete_records: 0,
  stats: [{ type: 'id_card_cn', label: '身份证号', hits: 4, records: 2 }, { type: 'phone_cn', label: '手机号', hits: 2, records: 1 }],
  samples: [{ line: 2, field: 'messages[0].content', type: 'id_card_cn', label: '身份证号', start: 3, end: 21, preview: '1****X' }],
  unscanned: [{ line: 7, reason: 'unparsable' }], notes: [], masked_format: 'jsonl', rule_pack_version: 'rp-1',
  has_report: true, has_masked: true, expires_at: '2026-11-06T00:00:00Z', created_at: '2026-10-30T00:00:00Z',
  updated_at: '2026-10-30T00:00:00Z', started_at: null, completed_at: '2026-10-30T00:01:00Z',
  ...overrides,
})

const renderPage = () => render(
  <MemoryRouter>
    <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } })}>
      <ConfigProvider theme={{ token: { motion: false } }}><CorpusScan /></ConfigProvider>
    </QueryClientProvider>
  </MemoryRouter>,
)

const loginAs = (role: string) => useAuthStore.setState({ token: 'fixture', user: { id: 'u1', username: 'u1', role, tenant_id: 'tenant-a' }, isAuthenticated: true })

describe('训练语料扫描：访问控制', () => {
  it('系统管理员与安全保密员可见，其他角色不可见', () => {
    expect(PAGE_ACCESS['/security/corpus-scan']).toBeDefined()
    for (const role of ['platform_admin', 'admin', 'security_officer']) {
      expect(canAccessPath(role, '/security/corpus-scan'), role).toBe(true)
      expect(canSeeMenuItem(role, '/security/corpus-scan'), role).toBe(true)
    }
    for (const role of ['auditor', 'tenant_admin', 'tenant_owner', 'dept_manager', 'developer', 'viewer', 'chat_user', '']) {
      expect(canAccessPath(role, '/security/corpus-scan'), role).toBe(false)
      expect(canSeeMenuItem(role, '/security/corpus-scan'), role).toBe(false)
    }
  })
})

describe('训练语料扫描：上传', () => {
  it('sha256Hex 与已知向量一致（含分块边界）', async () => {
    expect(await sha256Hex(new Blob(['abc']))).toBe('ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad')
    expect(await sha256Hex(new Blob([]))).toBe('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855')
    expect(await sha256Hex(new Blob(['abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq'])))
      .toBe('248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1')
    for (const size of [55, 56, 63, 64, 65, 119, 120, 1000]) {
      const data = new Uint8Array(size).map((_, index) => (index * 31 + 7) & 0xff)
      const expected = Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', data)), (b) => b.toString(16).padStart(2, '0')).join('')
      expect(await sha256Hex(new Blob([data])), String(size)).toBe(expected)
      const split = new Sha256().update(data.subarray(0, 13)).update(data.subarray(13)).hex()
      expect(split, `split ${size}`).toBe(expected)
    }
  })

  it('按 8 MiB 分片顺序上传，最后开始扫描', async () => {
    corpusApi.create.mockResolvedValue({ data: { job_id: 'corpus_x', chunk_size: CORPUS_CHUNK_BYTES } })
    corpusApi.uploadChunk.mockResolvedValue({ data: {} })
    corpusApi.start.mockResolvedValue({ data: baseJob({ status: 'queued' }) })
    const size = CORPUS_CHUNK_BYTES * 2 + 5
    const file = new File([new Uint8Array(size)], 'big.txt')
    const progress: number[] = []
    const id = await uploadCorpusFile(file, (done) => progress.push(done), undefined, undefined, corpusApi as any)
    expect(id).toBe('corpus_x')
    expect(corpusApi.create).toHaveBeenCalledWith({ file_name: 'big.txt', size_bytes: size, sha256: expect.stringMatching(/^[0-9a-f]{64}$/) })
    expect(corpusApi.uploadChunk.mock.calls.map((call) => [call[1], (call[2] as Blob).size])).toEqual([[0, CORPUS_CHUNK_BYTES], [1, CORPUS_CHUNK_BYTES], [2, 5]])
    expect(corpusApi.start).toHaveBeenCalledWith('corpus_x')
    expect(progress[progress.length - 1]).toBe(size)
  })

  it('下载链接是同源 /admin/v1 地址（cookie 鉴权，不读进内存）', () => {
    expect(corpusDownloadUrl('corpus_x', 'masked')).toBe('/admin/v1/security/corpus-scans/corpus_x/masked')
    expect(corpusDownloadUrl('corpus_x', 'report')).toBe('/admin/v1/security/corpus-scans/corpus_x/report')
  })
})

describe('训练语料扫描：页面', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    loginAs('security_officer')
    corpusApi.list.mockResolvedValue({ data: { items: [baseJob()], local_storage: true } })
    corpusApi.get.mockResolvedValue({ data: baseJob() })
  })

  it('列表展示状态与条数，报告展示统计和打码样例，下载用链接', async () => {
    renderPage()
    expect(await screen.findByText('训练集.jsonl')).toBeInTheDocument()
    expect(screen.getByText('已完成')).toBeInTheDocument()
    await userEvent.click(screen.getByRole('button', { name: '查看报告' }))
    const drawer = await screen.findByRole('dialog')
    expect(await within(drawer).findByText('1****X')).toBeInTheDocument()
    expect(within(drawer).getByText('messages[0].content')).toBeInTheDocument()
    expect(within(drawer).getAllByText('身份证号').length).toBeGreaterThan(0)
    expect(within(drawer).getByText(/第 7 行/)).toBeInTheDocument()
    const masked = within(drawer).getByRole('link', { name: '下载脱敏副本' })
    expect(masked).toHaveAttribute('href', '/admin/v1/security/corpus-scans/corpus_6f1c9a52-6a43-4d8b-9a4e-3f0d6c1b2a10/masked')
    expect(within(drawer).getByRole('link', { name: '下载报告' })).toHaveAttribute('href', expect.stringMatching(/\/report$/))
  })

  it('未完成的任务每秒轮询，到终态停止', async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true })
    try {
      const running = baseJob({ status: 'running', has_report: false, has_masked: false, processed_bytes: 512 })
      corpusApi.list.mockResolvedValue({ data: { items: [running], local_storage: true } })
      renderPage()
      expect(await screen.findByText('扫描中')).toBeInTheDocument()
      const calls = corpusApi.list.mock.calls.length
      await act(async () => { await vi.advanceTimersByTimeAsync(1100) })
      await waitFor(() => expect(corpusApi.list.mock.calls.length).toBeGreaterThan(calls))
      corpusApi.list.mockResolvedValue({ data: { items: [baseJob()], local_storage: true } })
      await act(async () => { await vi.advanceTimersByTimeAsync(1100) })
      expect(await screen.findByText('已完成')).toBeInTheDocument()
      const settled = corpusApi.list.mock.calls.length
      await act(async () => { await vi.advanceTimersByTimeAsync(3000) })
      expect(corpusApi.list.mock.calls.length).toBe(settled)
    } finally {
      vi.useRealTimers()
    }
  })

  it('运行中的任务可以取消，取消后刷新列表', async () => {
    corpusApi.list.mockResolvedValue({ data: { items: [baseJob({ status: 'running', has_report: false, has_masked: false })], local_storage: true } })
    corpusApi.cancel.mockResolvedValue({ data: baseJob({ status: 'running', cancel_requested: true }) })
    renderPage()
    await userEvent.click(await screen.findByRole('button', { name: '取消扫描' }))
    await waitFor(() => expect(corpusApi.cancel).toHaveBeenCalledWith('corpus_6f1c9a52-6a43-4d8b-9a4e-3f0d6c1b2a10'))
  })

  it('配置为对象存储时提示需要本地存储并禁用上传', async () => {
    corpusApi.list.mockRejectedValue({ response: { status: 503, data: { error: { code: 'local_storage_required' } } } })
    renderPage()
    expect(await screen.findByText(/需要本地留存存储/)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /上传语料/ })).toBeDisabled()
  })

  it('失败任务展示中文原因，不提供下载', async () => {
    corpusApi.list.mockResolvedValue({ data: { items: [baseJob({ status: 'failed', error_code: 'engine_unavailable', has_report: false, has_masked: false })], local_storage: true } })
    renderPage()
    expect(await screen.findByText('失败')).toBeInTheDocument()
    expect(screen.getByText('安全引擎不可用')).toBeInTheDocument()
    expect(screen.queryByRole('link', { name: '下载脱敏副本' })).not.toBeInTheDocument()
  })
})
