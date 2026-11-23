import { afterEach, describe, expect, it, vi } from 'vitest'
import { parseMatchedLocation, splitByRange, verifiedHitRange } from '../utils/hitHighlight'

const sha = async (text: string) =>
  Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text))), (b) => b.toString(16).padStart(2, '0')).join('')

afterEach(() => vi.unstubAllGlobals())

describe('命中位置高亮判定', () => {
  it('只认 content[起:止] 形式的位置', () => {
    expect(parseMatchedLocation('content[3:9]')).toEqual({ start: 3, end: 9 })
    expect(parseMatchedLocation('content[9:3]')).toBeNull()
    expect(parseMatchedLocation('request_context')).toBeNull()
    expect(parseMatchedLocation(undefined)).toBeNull()
  })

  it('片段摘要对得上才返回高亮范围', async () => {
    const text = '帮我看看\n-----BEGIN RSA PRIVATE KEY-----\nMIIE'
    const header = '-----BEGIN RSA PRIVATE KEY-----'
    await expect(verifiedHitRange(text, 'content[5:36]', await sha(header))).resolves.toEqual({ start: 5, end: 36 })
    await expect(verifiedHitRange(text, 'content[4:35]', await sha(header))).resolves.toBeNull()
    await expect(verifiedHitRange(text, 'content[5:36]', '')).resolves.toBeNull()
    await expect(verifiedHitRange(text, 'content[5:999]', await sha(header))).resolves.toBeNull()
  })

  it('位置按字符算，不按 UTF-16 码元算', async () => {
    const text = '😀密码是 password=abc'
    await expect(verifiedHitRange(text, 'content[5:13]', await sha('password'))).resolves.toEqual({ start: 5, end: 13 })
    expect(splitByRange(text, { start: 5, end: 13 })).toEqual(['😀密码是 ', 'password', '=abc'])
  })

  it('期望摘要大小写不敏感', async () => {
    const header = '-----BEGIN RSA PRIVATE KEY-----'
    const text = `帮我看看\n${header}\nMIIE`
    await expect(verifiedHitRange(text, 'content[5:36]', (await sha(header)).toUpperCase())).resolves.toEqual({ start: 5, end: 36 })
  })

  it('算不出摘要（crypto.subtle 不可用）时不高亮而不是抛异常', async () => {
    const header = '-----BEGIN RSA PRIVATE KEY-----'
    const expected = await sha(header)
    vi.stubGlobal('crypto', {})
    await expect(verifiedHitRange(`帮我看看\n${header}\nMIIE`, 'content[5:36]', expected)).resolves.toBeNull()
  })
})
