// Real-browser check of "delete custom policy" in the console (Playwright + Chrome).
// Needs the isolated stack (console on E2E_WEB_BASE) and an admin / auditor1 account.
import fs from 'node:fs'
import { launch, login, check, failed, BASE, apiLogin, apiClient } from './lib.mjs'

const ADMIN_PASSWORD = process.env.E2E_ADMIN_PASSWORD || 'Delbtn#E2e-Changed-20261109'
const AUDITOR_PASSWORD = process.env.E2E_AUDITOR_PASSWORD || 'Auditor#E2e-20261109'
const SUFFIX = Math.random().toString(36).slice(2, 8)
fs.mkdirSync('shots', { recursive: true })

const adminApi = apiClient(await apiLogin('admin', ADMIN_PASSWORD))
const shot = (page, name) => page.screenshot({ path: `shots/${name}.png` })

async function listPolicies() {
  const { body } = await adminApi('GET', '/security/policies')
  return body
}
async function apiCreate(name, extra = {}) {
  const { status, body } = await adminApi('POST', '/security/policies', {
    name, description: 'playwright e2e', scene: 'data_leak', severity: 'medium', action: 'audit', enabled: true,
    matcher: { type: 'keyword', config: { keywords: [`${name}-词`] } }, capability_categories: [], binding_mode: 'any', ...extra,
  })
  if (status !== 201 && status !== 200) throw new Error(`create ${name}: ${status} ${JSON.stringify(body)}`)
  return body
}

// leftovers from an aborted run
for (const p of (await listPolicies()).data) {
  if (p.origin === 'organization_created' && p.name.startsWith('E2E-PW-')) await adminApi('DELETE', `/security/policies/${p.id}`)
}

const { browser, context } = await launch()
const page = await context.newPage()
const consoleErrors = []
page.on('pageerror', (e) => consoleErrors.push(`pageerror: ${e.message}`))
const badResponses = new Set()
page.on('response', (r) => { if (r.status() >= 400) badResponses.add(`${r.status()} ${r.request().method()} ${new URL(r.url()).pathname}`) })
const deleteRequests = []
const policyReadsAfterDelete = []
page.on('request', (req) => {
  const url = new URL(req.url())
  if (req.method() === 'DELETE' && url.pathname.includes('/security/policies/')) deleteRequests.push({ id: decodeURIComponent(url.pathname.split('/').pop()), at: Date.now() })
  if (req.method() === 'GET' && url.pathname.endsWith('/security/policies') && deleteRequests.length > 0) policyReadsAfterDelete.push(Date.now())
})

await login(page, 'admin', ADMIN_PASSWORD)

// ---------- helpers that read the numbers the console shows ----------
async function metric(scope, label) {
  const small = scope.locator('small', { hasText: new RegExp(`^${label}`) }).first()
  await small.waitFor({ timeout: 15000 })
  return Number((await small.locator('xpath=following-sibling::strong[1]').innerText()).trim())
}
async function scenarioCounts() {
  await page.goto(`${BASE}/security/policies`, { waitUntil: 'networkidle' })
  const box = page.locator('.security-execution-mode-metrics')
  await box.waitFor({ timeout: 15000 })
  await page.waitForFunction(() => !document.querySelector('.security-execution-mode-metrics')?.innerText.includes('待加载'), null, { timeout: 15000 })
  return { custom: await metric(box, '组织自建策略'), running: await metric(box, '运行中策略项') }
}
async function catalogCounts() {
  await page.goto(`${BASE}/security/policies?advanced=catalog`, { waitUntil: 'networkidle' })
  const box = page.locator('[aria-label="系统策略目录统计"]')
  await box.waitFor({ timeout: 15000 })
  return { total: await metric(box, '目录总数'), active: await metric(box, '参与运行'), inactive: await metric(box, '未参与运行') }
}
async function settled(read, ok, what, timeout = 90000) {
  const end = Date.now() + timeout
  let last
  while (Date.now() < end) {
    last = await read()
    if (ok(last)) return last
    await page.waitForTimeout(3000)
  }
  console.log(`note: ` + what + ` did not settle: ` + JSON.stringify(last))
  return last
}
async function runtimeRow(name) {
  await page.goto(`${BASE}/security/policies?tab=runtime&q=${encodeURIComponent(name)}`, { waitUntil: "networkidle" })
  return page.locator('table.enterprise-policy-table tbody tr', { hasText: name })
}
const drawerGone = () => page.waitForFunction(() => document.querySelectorAll('.ant-drawer-content-wrapper').length === 0 || [...document.querySelectorAll('.ant-drawer')].every((d) => d.classList.contains('ant-drawer-hidden') || getComputedStyle(d).display === 'none'), null, { timeout: 8000 }).then(() => true).catch(() => false)

async function createViaUI(name, keyword) {
  await page.goto(`${BASE}/security/policies?scene=sensitive-data`, { waitUntil: 'networkidle' })
  await page.getByRole('button', { name: /新建自定义敏感信息策略/ }).click()
  const drawer = page.locator('.ant-drawer-content').last()
  await drawer.waitFor()
  await drawer.getByLabel('策略名称').fill(name)
  await drawer.getByLabel('词条').fill(keyword)
  await drawer.getByRole('button', { name: /保存并应用/ }).click()
  await page.getByRole('button', { name: /确认保存并应用/ }).click()
  await page.locator('.ant-message-notice', { hasText: '已保存' }).first().waitFor({ timeout: 15000 })
  await page.locator('.custom-sensitive-policy-list button', { hasText: name }).waitFor({ timeout: 15000 })
}

// ===================== 1. baseline numbers =====================
const sc0 = await scenarioCounts()
const cat0 = await catalogCounts()
console.log('baseline', sc0, cat0)

// ===================== 2. create through the UI, numbers go up =====================
const NAME1 = `E2E-PW-详情删除-${SUFFIX}`
await createViaUI(NAME1, `PW词条${SUFFIX}`)
const sc1 = await settled(scenarioCounts, (c) => c.custom === sc0.custom + 1 && c.running === sc0.running + 1, "概览计数")
const cat1 = await settled(catalogCounts, (c) => c.total === cat0.total + 1 && c.active === cat0.active + 1, "目录计数")
check('新建后：概览「组织自建策略」+1', sc1.custom === sc0.custom + 1, `${sc0.custom} -> ${sc1.custom}`)
check('新建后：系统策略目录「目录总数」+1', cat1.total === cat0.total + 1, `${cat0.total} -> ${cat1.total}`)
check('新建后：「参与运行」+1', cat1.active === cat0.active + 1, `${cat0.active} -> ${cat1.active}`)

// ===================== 3. detail drawer: 删除策略 -> 确认 -> 抽屉关闭 =====================
let row = await runtimeRow(NAME1)
await row.waitFor({ timeout: 15000 })
check('运行策略表里有新建的自建策略', (await row.count()) === 1)
check('自建策略行有行内「删除」', (await row.getByRole('button', { name: `删除策略 ${NAME1}` }).count()) === 1)
await row.getByRole('button', { name: '查看' }).click()
const drawer = page.locator('.ant-drawer-content', { hasText: NAME1 }).last()
await drawer.waitFor()
check('URL 带上 policy 参数', page.url().includes('policy='), page.url())
const delBtn = drawer.getByRole('button', { name: '删除策略' })
check('自建策略详情抽屉里有「删除策略」', (await delBtn.count()) === 1)
await shot(page, '01-drawer-with-delete')
await delBtn.click()
const pop = page.locator('.ant-popconfirm')
await pop.waitFor({ timeout: 5000 })
check('点删除只弹一次小确认，没有必填理由', (await pop.locator('input,textarea').count()) === 0 && (await pop.innerText()).includes('删除这条策略'), (await pop.innerText()).replace(/\s+/g, ' '))
await shot(page, '02-confirm-popover')
const delCountBefore = deleteRequests.length
check('确认前没有发出删除请求', delCountBefore === 0)
await pop.getByRole('button', { name: /删\s*除/ }).click()
await page.locator('.ant-message-notice', { hasText: '策略已删除' }).first().waitFor({ timeout: 15000 })
check('发出了一次删除请求', deleteRequests.length === 1, JSON.stringify(deleteRequests.map((d) => d.id)))
check('抽屉真的关闭了（真实浏览器里动画走完）', await drawerGone())
check('URL 里的 policy 参数被清掉', !page.url().includes('policy='), page.url())
check('删除后列表已回读', policyReadsAfterDelete.length >= 1)
await page.waitForTimeout(500)
check('运行策略表里该行消失', (await page.locator('table.enterprise-policy-table tbody tr', { hasText: NAME1 }).count()) === 0)
await shot(page, '03-after-delete')
const sc2 = await settled(scenarioCounts, (c) => c.custom === sc0.custom && c.running === sc0.running, "概览计数")
const cat2 = await settled(catalogCounts, (c) => c.total === cat0.total && c.active === cat0.active, "目录计数")
check('删除后：概览「组织自建策略」回到删除前', sc2.custom === sc0.custom, `${sc1.custom} -> ${sc2.custom}`)
check('删除后：概览「运行中策略项」回到删除前', sc2.running === sc0.running, `${sc0.running} vs ${sc2.running}`)
check('删除后：「目录总数」回到删除前', cat2.total === cat0.total, `${cat1.total} -> ${cat2.total}`)
check('删除后：「参与运行」回到删除前', cat2.active === cat0.active, `${cat1.active} -> ${cat2.active}`)
check('服务端也确实没有这条策略了', !(await listPolicies()).data.some((p) => p.name === NAME1))

// ===================== 4. row-level delete from the runtime table =====================
const NAME2 = `E2E-PW-行内删除-${SUFFIX}`
await apiCreate(NAME2)
row = await runtimeRow(NAME2)
await row.waitFor({ timeout: 15000 })
const before = deleteRequests.length
await row.getByRole('button', { name: `删除策略 ${NAME2}` }).click()
await pop.waitFor()
await shot(page, '04-row-confirm')
await pop.getByRole('button', { name: /删\s*除/ }).click()
await page.locator('.ant-message-notice', { hasText: '策略已删除' }).first().waitFor({ timeout: 15000 })
await page.locator('table.enterprise-policy-table tbody tr', { hasText: NAME2 }).waitFor({ state: 'detached', timeout: 15000 })
check('运行策略表行内删除：请求已发出、行消失', deleteRequests.length === before + 1)
check('行内删除：服务端已没有它', !(await listPolicies()).data.some((p) => p.name === NAME2))

// ===================== 5. server error: toast, list re-read, drawer stays =====================
const NAME3 = `E2E-PW-失败回读-${SUFFIX}`
const created3 = await apiCreate(NAME3)
row = await runtimeRow(NAME3)
await row.waitFor({ timeout: 15000 })
await row.getByRole('button', { name: '查看' }).click()
const drawer3 = page.locator('.ant-drawer-content', { hasText: NAME3 }).last()
await drawer3.waitFor()
await page.route(/\/security\/policies\/[^/]+$/, (route) => (route.request().method() === 'DELETE'
  ? route.fulfill({ status: 500, contentType: 'application/json', body: JSON.stringify({ error: { code: 'internal_error', message: 'boom' } }) })
  : route.continue()))
const readsBeforeFailure = policyReadsAfterDelete.length
await drawer3.getByRole('button', { name: '删除策略' }).click()
await pop.waitFor()
await pop.getByRole('button', { name: /删\s*除/ }).click()
await page.locator('.ant-message-notice', { hasText: '策略删除失败' }).first().waitFor({ timeout: 15000 })
check('服务端报错：弹出失败提示', true)
await page.waitForTimeout(800)
check('服务端报错：列表重新回读', policyReadsAfterDelete.length > readsBeforeFailure, `${readsBeforeFailure} -> ${policyReadsAfterDelete.length}`)
check('服务端报错：抽屉仍开着，策略还在', (await drawer3.isVisible()) && (await drawer3.getByRole('button', { name: '删除策略' }).count()) === 1)
check('服务端报错：服务端确实没删', (await listPolicies()).data.some((p) => p.id === created3.id))
await shot(page, '05-server-error')
await page.unroute(/\/security\/policies\/[^/]+$/)
// the same drawer still works once the server recovers
await drawer3.getByRole('button', { name: '删除策略' }).click()
await pop.waitFor()
await pop.getByRole('button', { name: /删\s*除/ }).click()
await page.locator('.ant-message-notice', { hasText: '策略已删除' }).first().waitFor({ timeout: 15000 })
check('报错恢复后再删：抽屉关闭、策略被删', (await drawerGone()) && !(await listPolicies()).data.some((p) => p.id === created3.id))

// ===================== 6. already deleted elsewhere (404) =====================
const NAME4 = `E2E-PW-别处已删-${SUFFIX}`
const created4 = await apiCreate(NAME4)
row = await runtimeRow(NAME4)
await row.waitFor({ timeout: 15000 })
await row.getByRole('button', { name: '查看' }).click()
const drawer4 = page.locator('.ant-drawer-content', { hasText: NAME4 }).last()
await drawer4.waitFor()
await adminApi('DELETE', `/security/policies/${created4.id}`) // someone else deletes it first
await drawer4.getByRole('button', { name: '删除策略' }).click()
await pop.waitFor()
await pop.getByRole('button', { name: /删\s*除/ }).click()
await page.locator('.ant-message-notice', { hasText: '策略已不存在' }).first().waitFor({ timeout: 15000 })
check('别处已删（404）：提示“策略已不存在”，抽屉关闭，列表无此策略',
  (await drawerGone()) && (await page.locator('table.enterprise-policy-table tbody tr', { hasText: NAME4 }).count()) === 0)

// ===================== 7. every entry reaches the delete, built-ins never do =====================
const NAME5 = `E2E-PW-入口覆盖-${SUFFIX}`
const created5 = await apiCreate(NAME5)
const capPolicyName = `E2E-PW-组件策略-${SUFFIX}`
const capList = (await adminApi('GET', '/security/policies/capabilities')).body.data
const cap = capList.find((c) => c.enabled && c.allowed_actions.includes('audit'))
const createdCap = await apiCreate(capPolicyName, { matcher: undefined, capability_categories: [cap.category], binding_mode: 'any' })

// (a) sensitive-data scene: custom list -> detail drawer
await page.goto(`${BASE}/security/policies?scene=sensitive-data`, { waitUntil: 'networkidle' })
await page.locator('.custom-sensitive-policy-list button', { hasText: NAME5 }).click()
const dA = page.locator('.ant-drawer-content', { hasText: NAME5 }).last()
await dA.waitFor()
check('入口 a：场景页「自定义敏感信息策略」列表 → 详情里有删除策略', (await dA.getByRole('button', { name: '删除策略' }).count()) === 1)
await dA.getByRole('button', { name: /取\s*消/ }).click()
await drawerGone()

// (b) scene page table (rows of the scene)
const sceneTableRow = page.locator('table.enterprise-policy-table tbody tr', { hasText: NAME5 })
if (await sceneTableRow.count()) check('入口 b：场景页策略表自建行有行内删除', (await sceneTableRow.getByRole('button', { name: `删除策略 ${NAME5}` }).count()) === 1)
else console.log('note: scene page has no policy table row for the custom policy (list-only scene)')

// (c) advanced maintenance -> system policy catalog: only org rows show 删除
await page.goto(`${BASE}/security/policies?advanced=catalog`, { waitUntil: 'networkidle' })
const catalogTable = page.locator('.policy-advanced-drawer table.enterprise-policy-table').first()
await catalogTable.waitFor()
await page.locator('div.ant-select[aria-label="系统策略目录状态筛选"]').click()
await page.locator('.ant-select-item-option', { hasText: '组织自建' }).click()
await page.waitForTimeout(500)
const orgRowCount = await catalogTable.locator('tbody tr').count()
const orgDeletes = await catalogTable.getByRole('button', { name: /^删除策略 / }).count()
const expectedOrg = (await listPolicies()).data.filter((p) => p.origin === 'organization_created').length
check('入口 c：高级维护·系统策略目录（组织自建筛选）每个自建行都有删除', orgRowCount === expectedOrg && orgDeletes === expectedOrg, `rows=${orgRowCount} deletes=${orgDeletes} expected=${expectedOrg}`)
await shot(page, '06-catalog-org-filter')
// all items: built-in rows have none
await page.locator('div.ant-select[aria-label="系统策略目录状态筛选"]').click()
await page.locator('.ant-select-item-option', { hasText: '全部目录项' }).click()
await page.waitForTimeout(500)
const allDeletes = await catalogTable.getByRole('button', { name: /^删除策略 / }).count()
check('入口 c：全部目录项第一页（内置策略）没有删除按钮', allDeletes === 0, `deletes=${allDeletes} org=${expectedOrg}`)

// (d) advanced maintenance -> detection components -> related policies -> drawer
await page.goto(`${BASE}/security/policies?advanced=capabilities&usage=all&capability_q=${encodeURIComponent(cap.category)}`, { waitUntil: 'networkidle' })
const capRow = page.locator('.capability-table tbody tr', { hasText: cap.category }).first()
await capRow.waitFor({ timeout: 15000 })
await capRow.getByRole('button', { name: '查看关联' }).click()
await page.locator('button.capability-related-policy', { hasText: capPolicyName }).click()
const dD = page.locator('.ant-drawer-content', { hasText: capPolicyName }).last()
await dD.waitFor()
check('入口 d：高级维护·检测组件·关联策略 → 详情里有删除策略', (await dD.getByRole('button', { name: '删除策略' }).count()) === 1)
await dD.getByRole('button', { name: /取\s*消/ }).click()
await drawerGone()

// (e) built-in policy: no delete anywhere
await page.goto(`${BASE}/security/policies?tab=runtime`, { waitUntil: 'networkidle' })
const builtinRow = page.locator('table.enterprise-policy-table tbody tr').filter({ hasNotText: 'E2E-PW-' }).first()
await builtinRow.waitFor()
check('内置策略行没有行内删除', (await builtinRow.getByRole('button', { name: /删除/ }).count()) === 0)
const builtinName = (await builtinRow.locator('td strong').first().innerText()).trim()
await builtinRow.getByRole('button', { name: '查看' }).click()
const dE = page.locator('.ant-drawer-content', { hasText: builtinName }).last()
await dE.waitFor()
check('内置策略详情里没有删除策略', (await dE.getByRole('button', { name: '删除策略' }).count()) === 0)
await dE.getByRole('button', { name: /取\s*消/ }).click()
await drawerGone()
// every delete button on the runtime table belongs to a custom policy
const firstPageDeletes = await page.getByRole("button", { name: /^删除策略 / }).count()
check("运行策略表第一页（全是内置策略）一个删除都没有", firstPageDeletes === 0, String(firstPageDeletes))
await page.goto(`${BASE}/security/policies?tab=runtime&q=E2E-PW-`, { waitUntil: "networkidle" })
const customRows = page.locator("table.enterprise-policy-table tbody tr")
await customRows.first().waitFor()
const runtimeCustom = await customRows.count()
const runtimeDeletes = await page.getByRole("button", { name: /^删除策略 / }).count()
check("运行策略表（只看自建）：每个自建行都有删除", runtimeCustom >= 2 && runtimeDeletes === runtimeCustom, `rows=${runtimeCustom} deletes=${runtimeDeletes}`)
await shot(page, "08-runtime-custom-rows")

// ===================== 8. read-only roles =====================
const officerName = `officer1`
const teamId = (await adminApi('GET', '/users')).body.data?.find((u) => u.username === 'auditor1')?.department_id
let officerReady = false
{
  const existing = (await adminApi('GET', '/users')).body.data?.find((u) => u.username === officerName)
  if (existing) officerReady = true
  else {
    const r = await adminApi('POST', '/users', { username: officerName, password: 'Offi#E2e-Pass-20261109', email: 'officer1@e2e.local', role: 'security_officer', department_id: teamId })
    officerReady = r.status === 200 || r.status === 201
  }
}
for (const [user, pwd, roleLabel] of [['auditor1', AUDITOR_PASSWORD, 'auditor'], ...(officerReady ? [[officerName, 'Offi#E2e-Pass-20261109', 'security_officer']] : [])]) {
  const ctx = await browser.newContext({ viewport: { width: 1440, height: 900 }, locale: 'zh-CN' })
  const p2 = await ctx.newPage()
  try {
    await login(p2, user, pwd)
    await p2.goto(`${BASE}/security/policies?tab=runtime&q=E2E-PW-`, { waitUntil: "networkidle" })
    await p2.waitForTimeout(1500)
    const onPage = p2.url().includes('/security/policies')
    const text = await p2.evaluate(() => document.body.innerText)
    const rows = p2.locator('table.enterprise-policy-table tbody tr', { hasText: 'E2E-PW-' })
    const hasRows = await rows.count()
    const deleteButtons = await p2.getByRole('button', { name: /删除/ }).count()
    console.log(`${roleLabel}: url=${p2.url()} rows=${hasRows} deleteButtons=${deleteButtons} readonlyBanner=${text.includes('当前为只读视图')}`)
    check(`${roleLabel}：策略中心里一个删除按钮都没有`, deleteButtons === 0)
    if (hasRows > 0) {
      await rows.first().getByRole('button', { name: '查看' }).click()
      const d6 = p2.locator('.ant-drawer-content').last()
      await d6.waitFor()
      check(`${roleLabel}：自建策略详情里没有删除策略`, (await d6.getByRole('button', { name: '删除策略' }).count()) === 0)
    } else {
      console.log(`note: ${roleLabel} cannot see the custom policy rows at all (${onPage ? 'page loads without data' : 'redirected away'})`)
    }
    await p2.screenshot({ path: `shots/07-${roleLabel}.png` })
  } finally {
    await ctx.close()
  }
}

// ===================== 9. the operation audit shows the delete in Chinese =====================
await page.goto(`${BASE}/system/audit-operations`, { waitUntil: 'networkidle' })
const deleteTag = page.locator('.ant-tag', { hasText: '删除安全策略' }).first()
await deleteTag.waitFor({ timeout: 15000 }).catch(() => {})
check('操作审计页：策略删除显示为“删除安全策略”，不是“系统操作”', (await deleteTag.count()) === 1)
await shot(page, '09-audit-operations')

// ===================== cleanup =====================
for (const id of [created5.id, createdCap.id]) await adminApi('DELETE', `/security/policies/${id}`)
console.log('HTTP >=400 seen by admin page:', [...badResponses].join(' ; ') || '(none)')
check('页面没有未捕获的前端异常', consoleErrors.length === 0, consoleErrors.join(' | ').slice(0, 300))
await browser.close()
console.log(failed().length ? `FAILED: ${failed().join(' | ')}` : 'ALL PASSED')
process.exit(failed().length ? 1 : 0)
