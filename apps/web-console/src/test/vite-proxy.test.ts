import { describe, expect, it } from 'vitest'
import config from '../../vite.config'

type ProxyConfig = {
  target?: string
  changeOrigin?: boolean
}

const adminProxy = (config as {
  server?: { proxy?: Record<string, ProxyConfig> }
}).server?.proxy?.['/admin']

describe('Vite 本地开发代理', () => {
  it('将管理端请求代理到隔离的源码开发控制面服务', () => {
    expect(adminProxy).toMatchObject({
      target: 'http://127.0.0.1:28081',
      changeOrigin: true,
    })
  })
})
