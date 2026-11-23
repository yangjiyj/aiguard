import { chromium } from 'playwright-core'

export const BASE = process.env.E2E_WEB_BASE || `http://127.0.0.1:${process.env.E2E_WEB_PORT || 28390}`
export const CHROME = process.env.E2E_CHROME || (process.platform === 'win32' ? 'C:/Program Files/Google/Chrome/Application/chrome.exe' : '/usr/bin/google-chrome')

export async function launch() {
  const browser = await chromium.launch({ executablePath: CHROME, headless: true })
  const context = await browser.newContext({ viewport: { width: 1440, height: 900 }, locale: 'zh-CN' })
  return { browser, context }
}

export async function login(page, username, password) {
  await page.goto(`${BASE}/login`, { waitUntil: 'networkidle' })
  for (let attempt = 0; attempt < 4; attempt++) {
    await page.fill('#username', username)
    await page.fill('#password', password)
    const src = await page.getAttribute('img[src^="data:image/svg+xml"]', 'src')
    const svg = Buffer.from(src.split('base64,')[1], 'base64').toString('utf8')
    const code = [...svg.matchAll(/<text[^>]*>([^<]+)<\/text>/g)].map((m) => m[1]).join('').trim()
    await page.fill('#captcha_code', code)
    await page.click('button[type=submit]')
    try {
      await page.waitForURL((url) => !url.pathname.startsWith('/login'), { timeout: 8000 })
      return
    } catch {
      await page.click('button[aria-label="刷新验证码"]').catch(() => {})
    }
  }
  throw new Error(`login failed for ${username}`)
}

let failures = []
export function check(label, ok, detail = '') {
  console.log(`${ok ? 'PASS' : 'FAIL'} ${label}${detail ? `  (${detail})` : ''}`)
  if (!ok) failures.push(label)
  return ok
}
export const failed = () => failures

// ---- direct API access through the console's own proxy (same origin the browser uses) ----
export async function apiLogin(username, password) {
  const ch = await (await fetch(`${BASE}/admin/v1/captcha`)).json()
  const svg = Buffer.from(ch.image.split('base64,')[1], 'base64').toString('utf8')
  const code = [...svg.matchAll(/<text[^>]*>([^<]+)<\/text>/g)].map((m) => m[1]).join('').trim()
  const resp = await fetch(`${BASE}/admin/v1/login`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, password, captcha_id: ch.captcha_id, captcha_code: code }),
  })
  const body = await resp.json()
  if (!body.token) throw new Error(`api login failed ${resp.status} ${JSON.stringify(body)}`)
  return body.token
}

export function apiClient(token) {
  return async (method, path, body) => {
    const resp = await fetch(`${BASE}/admin/v1${path}`, {
      method, headers: { Authorization: `Bearer ${token}`, ...(body ? { 'Content-Type': 'application/json' } : {}) },
      body: body ? JSON.stringify(body) : undefined,
    })
    const text = await resp.text()
    let json = null
    try { json = text ? JSON.parse(text) : null } catch { json = text }
    return { status: resp.status, body: json }
  }
}
