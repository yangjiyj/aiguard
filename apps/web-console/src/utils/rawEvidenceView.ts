import type { RawEvidenceHit, RawEvidenceMeta } from '../services/rawEvidence'

// 原文常是 JSON 再转义过的字符串（字面 \n、\"），大段挤成一行看不清。
// 字面 \n 明显多于真实换行时，默认按换行还原显示；原文本身不改，命中下标仍按原文计算。
export function looksEscaped(text: string): boolean {
  const literal = (text.match(/\\n/g) || []).length
  const real = (text.match(/\n/g) || []).length
  return literal >= 3 && literal > real
}

const ESCAPES: Record<string, string> = { n: '\n', t: '\t', r: '', '"': '"', '\\': '\\', '/': '/' }

export type RawEvidenceSegment = { text: string; hit: number | null }

// 按命中段切分原文；unescape 时把 \n、\t、\" 等还原（转义序列不拆开）。
export function buildSegments(text: string, hits: RawEvidenceHit[], unescape: boolean): RawEvidenceSegment[] {
  const sorted = hits.map((h, i) => ({ ...h, i })).sort((a, b) => a.start - b.start)
  const hitAt = (pos: number): number | null => {
    for (const h of sorted) {
      if (h.start > pos) break
      if (pos < h.end) return h.i
    }
    return null
  }
  const segments: RawEvidenceSegment[] = []
  let buf = ''
  let cur: number | null = hitAt(0)
  const flush = () => {
    if (buf) segments.push({ text: buf, hit: cur })
    buf = ''
  }
  for (let i = 0; i < text.length; ) {
    const state = hitAt(i)
    if (state !== cur) {
      flush()
      cur = state
    }
    if (unescape && text[i] === '\\' && i + 1 < text.length && text[i + 1] in ESCAPES) {
      buf += ESCAPES[text[i + 1]]
      i += 2
      continue
    }
    buf += text[i]
    i += 1
  }
  flush()
  return segments
}

export type RawEvidenceRow = RawEvidenceMeta & { repeat?: number; children?: RawEvidenceMeta[] }

// 同一用户、同一方向与处置、同样规则的连续留证折叠成一行（智能体重试时一夜能有上百条一模一样的拦截）。
export function foldConsecutive(items: RawEvidenceMeta[]): RawEvidenceRow[] {
  const out: RawEvidenceRow[] = []
  const key = (r: RawEvidenceMeta) => [r.user_id || '', r.direction, r.disposition, [...r.rule_ids].sort().join(',')].join('|')
  for (const item of items) {
    const last = out[out.length - 1]
    if (last && key(last) === key(item)) {
      last.repeat = (last.repeat || 1) + 1
      last.children = [...(last.children || []), item]
      continue
    }
    out.push({ ...item })
  }
  return out
}
