import { describe, expect, it } from 'vitest'
import { collapseSystemSections } from '../utils/retentionCollapse'

describe('Codex 留证客户投影', () => {
  it('全部是系统段时不保留全文供展开', () => {
    const text = '【系统】You are Codex. current_turn uses shell_command.\n\n【工具】tool runtime details'
    const got = collapseSystemSections(text)

    expect(got.collapsedCount).toBe(2)
    expect(got.head).toBe('')
    expect(got.body).toBe('')
  })
})
