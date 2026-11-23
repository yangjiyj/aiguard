// 历史员工金额 CSV 解析与导出（CSV，UTF-8 带 BOM，Excel 直接打开不乱码）。
// 导入必须先预览：逐行校验，非法行（负数、未知员工、金额格式错、重复）不会写入。

const BOM = '\uFEFF'
const BOM_PATTERN = /^\uFEFF/

import { currencyUnitSuffix } from '../../utils/currencyUnit'

// 表头跟随系统币种；缺省保持人民币旧模板，兼容已有导入文件。
export const allowanceCsvHeader = (currency?: string | null) => ['员工账号', '部门', '月额度' + currencyUnitSuffix(currency)]
export const ALLOWANCE_CSV_HEADER = allowanceCsvHeader('CNY')

// 防公式注入：以 = + - @ 开头的文本加单引号，读回时去掉。
const escapeCell = (value: string) => {
  const text = /^[=+\-@]/.test(value) ? "'" + value : value
  return /[",\r\n]/.test(text) ? '"' + text.replace(/"/g, '""') + '"' : text
}
const unescapeCell = (value: string) => (/^'[=+\-@]/.test(value) ? value.slice(1) : value)

export function toCsv(rows: string[][]): string {
  return BOM + rows.map((row) => row.map(escapeCell).join(',')).join('\r\n') + '\r\n'
}

export function parseCsv(text: string): string[][] {
  const source = text.replace(BOM_PATTERN, '')
  const rows: string[][] = []
  let row: string[] = []
  let cell = ''
  let quoted = false
  for (let i = 0; i < source.length; i++) {
    const ch = source[i]
    if (quoted) {
      if (ch === '"' && source[i + 1] === '"') { cell += '"'; i++ }
      else if (ch === '"') quoted = false
      else cell += ch
      continue
    }
    if (ch === '"') quoted = true
    else if (ch === ',') { row.push(cell); cell = '' }
    else if (ch === '\n' || ch === '\r') {
      if (ch === '\r' && source[i + 1] === '\n') i++
      row.push(cell); rows.push(row); row = []; cell = ''
    } else cell += ch
  }
  if (cell !== '' || row.length) { row.push(cell); rows.push(row) }
  return rows.filter((r) => r.some((c) => c.trim() !== ''))
}

export type AllowanceEmployee = { user_id: string; username: string; department_name?: string }
export type AllowancePreviewRow = {
  line: number
  username: string
  department: string
  amountText: string
  ok: boolean
  error?: string
  userId?: string
  micros?: number | null // null = 跟随默认金额
}

export function validateAllowanceRows(rows: string[][], employees: AllowanceEmployee[], currency?: string | null) {
  const header = (rows[0] || []).map((c) => c.trim())
  const expected = allowanceCsvHeader(currency)
  if (header[0] !== expected[0] || header[2] !== expected[2]) {
    return { headerError: '表头不对：第一行必须是“' + expected.join(',') + '”，请先导出模板再填写', rows: [] as AllowancePreviewRow[], validCount: 0, errorCount: 0 }
  }
  const byName = new Map(employees.map((e) => [e.username, e]))
  const seen = new Set<string>()
  const out: AllowancePreviewRow[] = rows.slice(1).map((cells, index) => {
    const username = unescapeCell((cells[0] || '').trim())
    const department = (cells[1] || '').trim()
    const amountText = (cells[2] || '').trim()
    const base = { line: index + 2, username, department, amountText }
    const employee = byName.get(username)
    if (!username || !employee) return { ...base, ok: false, error: '系统中没有这个员工' }
    if (seen.has(employee.user_id)) return { ...base, ok: false, error: '同一员工重复出现' }
    seen.add(employee.user_id)
    if (amountText === '') return { ...base, ok: true, userId: employee.user_id, micros: null }
    if (/^-/.test(amountText)) return { ...base, ok: false, error: '月额度不能为负数' }
    if (!/^\d+(\.\d+)?$/.test(amountText)) return { ...base, ok: false, error: '金额格式不对，请填数字' }
    if (!/^\d+(\.\d{1,2})?$/.test(amountText)) return { ...base, ok: false, error: '金额最多两位小数' }
    const [whole, fraction = ''] = amountText.split('.')
    if (whole.length > 10) return { ...base, ok: false, error: '金额超过可配置上限' }
    const micros = Number(whole) * 1_000_000 + Number(fraction.padEnd(6, '0'))
    if (micros > 1_000_000_000_000_000) return { ...base, ok: false, error: '金额超过可配置上限' }
    return { ...base, ok: true, userId: employee.user_id, micros }
  })
  return { headerError: '', rows: out, validCount: out.filter((r) => r.ok).length, errorCount: out.filter((r) => !r.ok).length }
}
