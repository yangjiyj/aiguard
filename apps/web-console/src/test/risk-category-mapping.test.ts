import { describe, it, expect } from 'vitest'
import categories from '../utils/engine_categories.json'
import { getRiskCategoryLabel } from '../utils/risk'
import { getStaticCapabilityLabel } from '../utils/securityCapabilityLabels'

// class_key 中文映射对账（设计 3b 验收项）：引擎枚举清单 vs risk.ts 字典，缺失即 fail。
const GENERIC = new Set(['其他风险', '未分类'])
const CONTENT_SAFETY_PREFIXES = ['political_', 'illegal_', 'discrimination_', 'multilingual_']

describe('class_key 中文映射对账', () => {
  it('引擎每个 category 都有非泛化中文标签', () => {
    const missing = (categories as string[]).filter((c) => GENERIC.has(getRiskCategoryLabel(c)))
    expect(missing, `以下 category 缺中文映射: ${missing.join(', ')}`).toEqual([])
  })
  it('content_safety 大类给二级中文标签，不折进泛化「内容合规风险」', () => {
    const folded = (categories as string[])
      .filter((c) => CONTENT_SAFETY_PREFIXES.some((p) => c.startsWith(p)))
      .filter((c) => getRiskCategoryLabel(c) === '内容合规风险')
    expect(folded, `以下 content_safety 类被折进泛化标签: ${folded.join(', ')}`).toEqual([])
  })
  it('内置检测器使用唯一、可读且不暴露内部 key 的名称', () => {
    const labels = (categories as string[]).map((category) => getStaticCapabilityLabel(category))
    const rawOrGeneric = (categories as string[]).filter((category, index) => (
      labels[index] === category || labels[index].includes('_') || GENERIC.has(labels[index])
    ))
    expect(rawOrGeneric, `以下检测器仍暴露内部名称: ${rawOrGeneric.join(', ')}`).toEqual([])
    expect(new Set(labels).size, '内置检测器名称必须可以一一区分').toBe(labels.length)
  })
})
