import { describe, expect, it } from 'vitest'
import viteConfig from '../../vite.config'

// 生产构建不得产出 source map：index-*.js.map 会随镜像发布，暴露前端源码。
describe('生产构建配置', () => {
  it('不产出 source map', () => {
    const config = viteConfig as { build?: { sourcemap?: unknown } }
    expect(config.build?.sourcemap ?? false).toBe(false)
  })
})
