import { beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'
import Login from '../pages/Login'
import * as api from '../services/api'

describe('登录验证码', () => {
  beforeEach(() => {
    vi.restoreAllMocks()
    vi.spyOn(api.authApi, 'captcha').mockResolvedValue({
      data: {
        captcha_id: 'captcha-1',
        image: 'data:image/svg+xml;base64,PHN2Zy8+',
        expires_in: 300,
      },
    } as any)
    vi.spyOn(api.authApi, 'login').mockResolvedValue({
      data: { token: 'token', user: { id: 'u1', username: 'admin', role: 'platform_admin' } },
    } as any)
  })

  const renderPage = () => {
    const queryClient = new QueryClient({
      defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
    })
    return render(
      <MemoryRouter>
        <QueryClientProvider client={queryClient}>
          <Login />
        </QueryClientProvider>
      </MemoryRouter>,
    )
  }

  it('loads and refreshes the captcha image', async () => {
    renderPage()

    const image = await screen.findByRole('img', { name: '验证码' })
    expect(image).toHaveAttribute('src', 'data:image/svg+xml;base64,PHN2Zy8+')
    expect(api.authApi.captcha).toHaveBeenCalledTimes(1)

    const refreshButton = screen.getByRole('button', { name: '刷新验证码' })
    await waitFor(() => expect(refreshButton).not.toBeDisabled())
    fireEvent.click(refreshButton)
    await waitFor(() => expect(api.authApi.captcha).toHaveBeenCalledTimes(2))
  })

  it('submits captcha id and answer with credentials', async () => {
    renderPage()
    await screen.findByRole('img', { name: '验证码' })

    fireEvent.change(screen.getByPlaceholderText('用户名'), { target: { value: 'admin' } })
    fireEvent.change(screen.getByPlaceholderText('密码'), { target: { value: 'secret' } })
    fireEvent.change(screen.getByPlaceholderText('请输入验证码'), { target: { value: 'A7BK2' } })
    fireEvent.click(screen.getByRole('button', { name: /登\s*录/ }))

    await waitFor(() => {
      expect(api.authApi.login).toHaveBeenCalledWith('admin', 'secret', 'captcha-1', 'A7BK2')
    })
  })
})
