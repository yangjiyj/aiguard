// W1 1.12：MCP 策略参数条件——表单值与后端 arg_conditions 互转（纯函数，便于单测）。
import type { McpArgCondition, McpArgConditionFormRow, McpArgConditionOp } from '../services/api'

export const argConditionOps: { value: McpArgConditionOp; label: string }[] = [
  { value: 'eq', label: '等于' },
  { value: 'ne', label: '不等于' },
  { value: 'in', label: '属于列表' },
  { value: 'not_in', label: '不属于列表' },
  { value: 'contains', label: '包含' },
  { value: 'prefix', label: '以…开头' },
  { value: 'suffix', label: '以…结尾' },
  { value: 'regex', label: '正则匹配' },
  { value: 'gt', label: '大于' },
  { value: 'gte', label: '大于等于' },
  { value: 'lt', label: '小于' },
  { value: 'lte', label: '小于等于' },
  { value: 'exists', label: '存在' },
  { value: 'not_exists', label: '不存在' },
]

const STRING_OPS = new Set<McpArgConditionOp>(['prefix', 'suffix', 'regex'])
const NUMBER_OPS = new Set<McpArgConditionOp>(['gt', 'gte', 'lt', 'lte'])
const LIST_OPS = new Set<McpArgConditionOp>(['in', 'not_in'])
export const valuelessOps = new Set<McpArgConditionOp>(['exists', 'not_exists'])

// 表单行 → 后端条件。文本型运算符原样作字符串；数值型必须是数字；列表型必须是 JSON 数组；
// 等于/不等于/包含：能按 JSON 解析就用解析结果（数字、布尔、数组），否则当字符串。
export function toArgConditions(rows: McpArgConditionFormRow[] | undefined): McpArgCondition[] {
  const out: McpArgCondition[] = []
  for (const row of rows || []) {
    const path = String(row.path || '').trim()
    const op = row.op
    if (!path || !op) continue
    if (valuelessOps.has(op)) {
      out.push({ path, op })
      continue
    }
    const text = String(row.value ?? '')
    if (STRING_OPS.has(op)) {
      out.push({ path, op, value: text })
      continue
    }
    if (NUMBER_OPS.has(op)) {
      const n = Number(text.trim())
      if (text.trim() === '' || !Number.isFinite(n)) throw new Error(`「${path}」需要填写数字`)
      out.push({ path, op, value: n })
      continue
    }
    let parsed: unknown = text
    try {
      parsed = JSON.parse(text)
    } catch {
      parsed = text
    }
    if (LIST_OPS.has(op) && !Array.isArray(parsed)) throw new Error(`「${path}」需要填写 JSON 数组，如 ["a","b"]`)
    out.push({ path, op, value: parsed })
  }
  return out
}

// 后端条件 → 表单行（字符串原样回显，其余按 JSON 回显）。
export function fromArgConditions(conds: McpArgCondition[] | undefined): McpArgConditionFormRow[] {
  return (conds || []).map((c) => ({
    path: c.path,
    op: c.op,
    value: c.value === undefined ? '' : typeof c.value === 'string' ? c.value : JSON.stringify(c.value),
  }))
}
