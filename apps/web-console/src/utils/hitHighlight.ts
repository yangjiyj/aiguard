// 原文里的命中位置高亮。位置是引擎按字符（Unicode 码点）算的，摘要是命中片段 UTF-8 字节的 SHA-256。
// 只有按位置截出的片段摘要等于事件里记的摘要才高亮；对不上就不高亮，绝不猜。
export type HitRange = { start: number; end: number }

export const parseMatchedLocation = (location?: string | null): HitRange | null => {
  const match = /^content\[(\d+):(\d+)\]$/.exec(location || '')
  if (!match) return null
  const start = Number(match[1])
  const end = Number(match[2])
  return end > start ? { start, end } : null
}

const sha256Hex = async (text: string) => {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text))
  return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, '0')).join('')
}

export const verifiedHitRange = async (text: string, location?: string | null, expectedSha256?: string | null): Promise<HitRange | null> => {
  const range = parseMatchedLocation(location)
  if (!range || !expectedSha256) return null
  const chars = Array.from(text)
  if (range.end > chars.length) return null
  const piece = chars.slice(range.start, range.end).join('')
  try {
    return (await sha256Hex(piece)) === expectedSha256.toLowerCase() ? range : null
  } catch {
    // 非安全上下文（HTTP、IP 访问）没有 crypto.subtle：算不出摘要就等于没核对上，不高亮。
    return null
  }
}

// 只接受 verifiedHitRange 返回的范围，自己不做越界校验。
export const splitByRange = (text: string, range: HitRange): [string, string, string] => {
  const chars = Array.from(text)
  return [chars.slice(0, range.start).join(''), chars.slice(range.start, range.end).join(''), chars.slice(range.end).join('')]
}
