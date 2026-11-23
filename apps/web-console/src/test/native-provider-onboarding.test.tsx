import { afterEach, beforeEach, expect, it, vi } from 'vitest'
import { cleanup, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { ConfigProvider } from 'antd'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'
import Providers from '../pages/Providers'
import ModelManagement from '../pages/ModelManagement'
import { fxApi, modelApi, providerApi } from '../services/api'

const ok = (data: unknown) => ({ data } as never)
let client: QueryClient
beforeEach(() => {
  client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } })
  vi.spyOn(providerApi, 'list').mockResolvedValue(ok({ data: [] }))
  vi.spyOn(providerApi, 'metrics').mockResolvedValue(ok({ data: [] }))
  vi.spyOn(modelApi, 'list').mockResolvedValue(ok({ data: [] }))
  vi.spyOn(modelApi, 'evalStatus').mockResolvedValue(ok({ data: [] }))
  vi.spyOn(fxApi, 'current').mockResolvedValue(ok({ data: { rate: 7 } }))
})
afterEach(() => { cleanup(); client.clear(); vi.restoreAllMocks(); document.body.innerHTML = '' })
const page = (element: React.ReactNode) => render(<ConfigProvider virtual={false}><MemoryRouter><QueryClientProvider client={client}>{element}</QueryClientProvider></MemoryRouter></ConfigProvider>)

it.each(['gemini', 'vertex', 'bedrock'])('requires actual native generation verification when adding a %s model', async type => {
  vi.mocked(providerApi.list).mockResolvedValue(ok({ data: [{ id: 'native', name: '原生渠道', provider_type: type, status: 'active' }] }))
  const create = vi.spyOn(modelApi, 'create').mockResolvedValue(ok({}))
  page(<ModelManagement />)
  await userEvent.click(await screen.findByRole('button', { name: /手动添加模型/ }))
  const dialog = await screen.findByRole('dialog')
  await userEvent.click(within(dialog).getByLabelText('模型上游'))
  await userEvent.click(await screen.findByText(type === 'bedrock' ? '原生渠道' : '原生渠道（Vertex AI / Gemini）'))
  expect(within(dialog).getByRole('checkbox', { name: '验证原生生成能力' })).toBeChecked()
  expect(within(dialog).queryByRole('checkbox', { name: 'Responses' })).not.toBeInTheDocument()
  expect(within(dialog).queryByRole('checkbox', { name: 'Anthropic Messages' })).not.toBeInTheDocument()
  await userEvent.type(within(dialog).getByLabelText('对外模型名称'), 'native-fixture')
  await userEvent.click(within(dialog).getByRole('button', { name: '添加并启用' }))
  await waitFor(() => expect(create).toHaveBeenCalledWith(expect.objectContaining({ provider_id: 'native', model_name: 'native-fixture', protocols: undefined })))
})

it('offers the Gemini API-key address separately from service-account Vertex configuration', async () => {
  const create = vi.spyOn(providerApi, 'create').mockResolvedValue(ok({}))
  page(<Providers />)
  await userEvent.click(await screen.findByRole('button', { name: /添加渠道/ }))
  const dialog = await screen.findByRole('dialog')
  await userEvent.type(within(dialog).getByLabelText('渠道名称'), 'Gemini fixture')
  await userEvent.click(within(dialog).getByLabelText('渠道类型'))
  await userEvent.click(await screen.findByText('Google Gemini（API Key / 服务账号 JSON）'))
  expect(within(dialog).getByLabelText('API 地址')).toHaveValue('https://generativelanguage.googleapis.com')
  await userEvent.type(within(dialog).getByLabelText('API Key / 服务账号 JSON'), 'fixture-api-key')
  await userEvent.click(within(dialog).getByRole('button', { name: '添加渠道' }))
  await waitFor(() => expect(create).toHaveBeenCalledWith(expect.objectContaining({ provider_type: 'gemini', base_url: 'https://generativelanguage.googleapis.com', api_key: 'fixture-api-key' })))
})
