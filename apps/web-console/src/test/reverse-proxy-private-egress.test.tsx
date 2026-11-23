import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { Modal } from 'antd'

import ReverseProxy from '../pages/ReverseProxy'
import * as api from '../services/api'
import { useAuthStore } from '../stores/auth'

vi.mock('antd', async () => {
	const actual = await vi.importActual<typeof import('antd')>('antd')
	return {
		...actual,
		message: {
			success: vi.fn(),
			warning: vi.fn(),
			error: vi.fn(),
		},
	}
})

describe('ReverseProxy private egress authorization', () => {
	let queryClient: QueryClient

	beforeEach(() => {
		queryClient = new QueryClient({
			defaultOptions: {
				queries: { retry: false },
				mutations: { retry: false },
			},
		})
		vi.clearAllMocks()
		// 2.9.22 起“允许私网回源”只有平台级角色能打开。
		useAuthStore.setState({ token: 't', user: { id: 'u1', username: 'u', role: 'platform_admin', tenant_id: 'tenant_default' }, isAuthenticated: true })

	afterEach(() => {
		Modal.destroyAll()
		cleanup()
		document.body.innerHTML = ''
	})
	})

	function renderPage() {
		return render(
			<QueryClientProvider client={queryClient}>
				<ReverseProxy />
			</QueryClientProvider>,
		)
	}

	function mockList() {
		return vi.spyOn(api.reverseProxyApi, 'list').mockResolvedValue({
			data: {
				data: [{
					id: 'rpr_acme',
					tenant_id: 'tenant_demo',
					name: 'Acme',
					path_prefix: '/proxy/acme',
					target_url: 'https://api.example.cn',
					target_path_prefix: '',
					allow_private_egress: true,
					private_egress_cidrs: ['172.16.20.17/32'],
					security_enabled: true,
					stats_enabled: true,
					status: 'active',
					description: '',
					created_at: '2026-07-17T00:00:00Z',
					updated_at: '2026-07-17T00:00:00Z',
				}],
				total: 1,
			},
			status: 200,
			statusText: 'OK',
			headers: {},
			config: {},
		} as any)
	}

	it('shows the authorization warning and route CIDRs when editing', async () => {
		mockList()
		renderPage()

		await screen.findByText('Acme')
		expect(screen.getByText('已授权私网')).toBeInTheDocument()
		fireEvent.click(screen.getByRole('button', { name: /编辑/ }))

		await waitFor(() => {
			expect(screen.getByText('允许私网回源会扩大该路由的网络访问范围')).toBeInTheDocument()
		})
		expect(screen.getAllByRole('switch')[0]).toBeChecked()
		expect(screen.getByDisplayValue('172.16.20.17/32')).toBeInTheDocument()
	})

	// 2.9.22：二次确认移到打开开关时（与 MCP 服务一致），保存已授权的路由不再弹确认。
	it('saves an already authorized route without a second prompt and submits CIDRs as an array', async () => {
		mockList()
		const update = vi.spyOn(api.reverseProxyApi, 'update').mockResolvedValue({
			data: {}, status: 200, statusText: 'OK', headers: {}, config: {},
		} as any)
		const confirm = vi.spyOn(Modal, 'confirm')
		renderPage()

		await screen.findByText('Acme')
		fireEvent.click(screen.getByRole('button', { name: /编辑/ }))
		const cidrInput = await screen.findByDisplayValue('172.16.20.17/32')
		const form = cidrInput.closest('form')
		fireEvent.submit(form!)

		expect(confirm).not.toHaveBeenCalled()
		await waitFor(() => {
			expect(update).toHaveBeenCalledWith('rpr_acme', expect.objectContaining({
				allow_private_egress: true,
				private_egress_cidrs: ['172.16.20.17/32'],
			}))
		})
	})

	it('defaults new routes to private egress disabled and reveals controls only when enabled', async () => {
		vi.spyOn(api.reverseProxyApi, 'list').mockResolvedValue({
			data: { data: [], total: 0 },
			status: 200, statusText: 'OK', headers: {}, config: {},
		} as any)
		renderPage()

		await screen.findByRole('button', { name: /添加规则/ })
		fireEvent.click(screen.getByRole('button', { name: /添加规则/ }))
		const privateSwitch = screen.getAllByRole('switch')[0]
		expect(privateSwitch).not.toBeChecked()
		expect(screen.queryByText('允许私网回源会扩大该路由的网络访问范围')).not.toBeInTheDocument()

		fireEvent.click(privateSwitch)
		// 打开时二次确认，写明后果。
		expect(await screen.findByText('网关可被用来访问这些地址。')).toBeInTheDocument()
		fireEvent.click(screen.getByRole('button', { name: '确认打开' }))
		expect(await screen.findByText('允许私网回源会扩大该路由的网络访问范围')).toBeInTheDocument()
		expect(screen.getByPlaceholderText(/172\.16\.20\.17\/32/)).toBeInTheDocument()
	})
})
