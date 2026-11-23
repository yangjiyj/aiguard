import { describe, it, expect, vi, afterEach } from 'vitest'
import { cleanup, fireEvent, render, screen } from '@testing-library/react'
import ClientBaseUrlGuide from '../components/ClientBaseUrlGuide'

afterEach(() => cleanup())

describe('ClientBaseUrlGuide 按协议展示接入地址', () => {
  it('Anthropic 协议显示不带 /v1 的地址并可复制，OpenAI 协议提示沿用带 /v1 的地址', () => {
    const copy = vi.fn()
    render(<ClientBaseUrlGuide url="https://gateway.customer.test/proxy/v1" onCopy={copy} />)

    // 地址来自传入的「对外调用地址」，不是写死的。
    expect(screen.getByText('https://gateway.customer.test/proxy')).toBeInTheDocument()
    // 各协议自己的说明句。
    expect(screen.getByText(/适用于 Claude Code 等：地址不带 \/v1，客户端会自己拼接 \/v1\/messages/)).toBeInTheDocument()
    expect(screen.getByText(/适用于 Codex、Cherry Studio 等：地址带一层 \/v1/)).toBeInTheDocument()
    expect(screen.getByText('https://gateway.customer.test/proxy/v1')).toBeInTheDocument()

    fireEvent.click(screen.getByRole('button', { name: '复制 Anthropic 协议地址' }))
    expect(copy).toHaveBeenCalledWith('https://gateway.customer.test/proxy')
  })

  it('当前地址是 https 配明文端口时给出针对性的红色提示', () => {
    render(<ClientBaseUrlGuide url="https://gw.test:8080/v1" />)
    const alerts = screen.getAllByRole('alert')
    expect(alerts.length).toBe(1)
    expect(alerts.some(node => node.textContent?.includes('8080') && node.textContent?.includes('明文'))).toBe(true)
  })

  it('地址为空时不渲染任何地址和复制按钮，也不猜测端口', () => {
    render(<ClientBaseUrlGuide url="" />)
    expect(screen.queryByRole('button', { name: /复制/ })).toBeNull()
    // 不展示任何地址：地址一律渲染在 code 元素里；常驻提示里以文字举例的端口、协议头不算地址。
    expect(document.querySelector('code')).toBeNull()
    expect(screen.queryByText('Anthropic 协议')).toBeNull()
  })

  it('不提供 onCopy 时不显示复制按钮', () => {
    render(<ClientBaseUrlGuide url="https://gw.test/v1" />)
    expect(screen.queryByRole('button', { name: /复制/ })).toBeNull()
    expect(screen.getByText('https://gw.test')).toBeInTheDocument()
  })
})
