import { describe, expect, it } from 'vitest'
import zhCN from 'antd/es/locale/zh_CN'
import { readFileSync } from 'node:fs'

// 生产打包下 antd/locale/zh_CN（CommonJS 转发）的默认导入会变成 { default }，整站语言包失效。
describe('控制台中文语言包', () => {
  it('使用 ESM 语言包且分页、空状态为中文', () => {
    const source = readFileSync('src/ThemedApp.tsx', 'utf8')
    expect(source).toContain("from 'antd/es/locale/zh_CN'")
    expect(source).not.toMatch(/from 'antd\/locale\/zh_CN'/)
    expect(zhCN.Pagination?.items_per_page).toBe('条/页')
    expect(zhCN.Empty?.description).toBe('暂无数据')
  })
})
