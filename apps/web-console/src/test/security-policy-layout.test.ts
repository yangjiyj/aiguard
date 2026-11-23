import { readFileSync } from 'node:fs'
import { describe, expect, it } from 'vitest'

const policyStyles = readFileSync('src/index.css', 'utf8')

describe('策略中心工具栏布局', () => {
  it('为批量操作区预留完整列宽，避免桌面端溢出到视口外', () => {
    expect(policyStyles).toContain(
      'grid-template-columns: minmax(0, 1fr) 156px minmax(330px, auto);',
    )
  })
})
