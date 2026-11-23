import { describe, expect, it } from 'vitest'
import { getRiskCategoryLabel } from '../utils/risk'

describe('文件风险新类别显示名', () => {
  it.each([
    ['file_script', '脚本文件'],
    ['file_id_unverified', '未核验的文件引用'],
    ['file_id_lookup_failed', '文件引用核验失败'],
  ])('%s 显示为 %s', (category, label) => {
    expect(getRiskCategoryLabel(category)).toBe(label)
  })
})
