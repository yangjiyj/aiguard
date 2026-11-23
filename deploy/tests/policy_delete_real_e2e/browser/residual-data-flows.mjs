// 控制台“残留数据”流程巡检（真实 Chrome）：先建后删（删密钥、删应用、调部门、停用、有成员的部门），
// 再把用户 / 应用 / 密钥 / 部门页的删除、禁用、编辑、跳转逐个点一遍。
// 数据都由真实账号经接口造出来（应用负责人用 tenant_admin 登录后自己建），不碰数据库。
import { launch, login, check, failed, apiLogin, apiClient, BASE } from './lib.mjs'

const ADMIN_PW = process.env.E2E_ADMIN_PASSWORD
if (!ADMIN_PW) throw new Error('E2E_ADMIN_PASSWORD is required')
const PW = 'Res#Pass-20261110x'
const sfx = Date.now().toString(36).slice(-5)
const admin = apiClient(await apiLogin('admin', ADMIN_PW))
const ok = (r, what) => { if (r.status >= 300) throw new Error(`${what} failed: ${r.status} ${JSON.stringify(r.body)}`); return r.body }

// ---------- 造数据 ----------
const teams = ok(await admin('GET', '/teams'), 'list teams').data
const dept = teams[0].id
const mkUser = async (name, role = 'developer', department_id = dept) =>
  ok(await admin('POST', '/users', { username: `${name}_${sfx}`, password: PW, email: `${name}_${sfx}@res.local`, role, department_id }), `create user ${name}`)
const mkTeam = async (name, parent_team_id) => ok(await admin('POST', '/teams', { name: `${name}-${sfx}`, parent_team_id, create_app: false }), `create team ${name}`).team
const mkKey = async (client, project_id, user_id, name) => ok(await client('POST', '/keys', { project_id, user_id, name }), `create key ${name}`)

const keydel = await mkUser('res_keydel')                 // 在密钥管理里删过密钥
const kd = await mkKey(admin, 'project_default', keydel.id, `res-key-deleted-${sfx}`)
ok(await admin('DELETE', `/keys/${kd.id}`), 'delete key')
const keyactive = await mkUser('res_keyactive')           // 名下还有活跃密钥
const ka = await mkKey(admin, 'project_default', keyactive.id, `res-key-active-${sfx}`)
const appowner = await mkUser('res_appowner', 'tenant_admin') // 应用负责人：自己登录、自己建应用和密钥
const ownerApi = apiClient(await apiLogin(appowner.username, PW))
const ownedApp = ok(await ownerApi('POST', '/projects', { name: `res-owned-app-${sfx}`, code: `own-${sfx}`, environment: 'staging' }), 'create owned app')
await mkKey(ownerApi, ownedApp.id, appowner.id, `res-key-in-owned-app-${sfx}`)
const deptB = await mkTeam('res-dept-b')
const moved = await mkUser('res_moved')                   // 管理员把他挪到别的部门（来源变成 admin）
ok(await admin('POST', `/teams/${deptB.id}/members`, { user_id: moved.id, role: 'member' }), 'move user')
const cfgApp = ok(await admin('POST', '/projects', { name: `res-config-app-${sfx}`, code: `cfg-${sfx}`, environment: 'production' }), 'create config app')
ok(await admin('PATCH', `/projects/${cfgApp.id}/team`, { team_id: deptB.id }), 'assign team')
ok(await admin('PATCH', `/projects/${cfgApp.id}/model-config`, { model_whitelist: JSON.stringify(['mock-model']), quota_limits: JSON.stringify({ daily_tokens: 1000 }) }), 'model config')
const deptMem = await mkTeam('res-dept-members')
const deptMember = await mkUser('res_member', 'developer', deptMem.id)
const deptParent = await mkTeam('res-dept-parent')
const deptChild = await mkTeam('res-dept-child', deptParent.id)
const deptEmpty = await mkTeam('res-dept-empty')

const { browser, context } = await launch()
const page = await context.newPage()
const api = []
page.on('response', async (r) => {
  if (r.url().includes('/admin/v1') && r.request().method() !== 'GET' && r.status() >= 400) api.push(`${r.status()} ${r.request().method()} ${r.url().replace(BASE, '')}`)
})
await login(page, 'admin', ADMIN_PW)

const rowOf = (text) => page.locator('tr', { hasText: text })
const confirmPopover = async () => { await page.locator('.ant-popover:not(.ant-popover-hidden)').getByRole('button', { name: /删\s*除/ }).click(); await page.waitForTimeout(1200) }
const toast = async () => (await page.locator('.ant-message').allInnerTexts()).join(' ').replace(/\s+/g, ' ')
const drawerText = async () => (await page.locator('.ant-drawer').allInnerTexts()).join(' ').replace(/\s+/g, ' ')
const apiGet = async (path) => (await admin('GET', path)).body

// ---------- 用户：删除 ----------
await page.goto(`${BASE}/users`, { waitUntil: 'networkidle' })
for (const [label, user] of [['密钥已在密钥管理删除的用户', keydel]]) {
  await rowOf(user.username).getByRole('button', { name: /删\s*除/ }).click()
  await confirmPopover()
  check(`${label}：直接删掉，不弹“用户无法删除”`, (await page.locator('.ant-modal:has-text("用户无法删除")').count()) === 0 && (await rowOf(user.username).count()) === 0, await toast())
}

// 有活跃密钥：占用清单 -> 去处理 -> 密钥页只剩那一把 -> 撤销 -> 回来删
await rowOf(keyactive.username).getByRole('button', { name: /删\s*除/ }).click()
await confirmPopover()
const modal = page.locator('.ant-modal:has-text("用户无法删除")')
check('活跃密钥：弹出占用清单并列出这把密钥', (await modal.count()) === 1 && (await modal.innerText()).includes('内部密钥'), (await modal.allInnerTexts()).join('|').slice(0, 80))
await modal.getByRole('link', { name: '去处理' }).first().click()
await page.waitForURL(/\/keys\?/, { timeout: 8000 })
await page.waitForTimeout(1200)
const keyRows = await page.locator('.ant-table-row').allInnerTexts()
check('“去处理”落在密钥页，列表只剩被指的那把密钥', keyRows.length === 1 && keyRows[0].includes(`res-key-active-${sfx}`), `${keyRows.length} rows`)
await page.locator('.ant-table-row').getByRole('button', { name: /撤\s*销/ }).first().click()
await page.locator('.ant-modal-confirm').getByRole('button', { name: /撤 ?销/ }).click()
await page.waitForTimeout(1500)
check('在密钥页撤销这把密钥', (await toast()).includes('密钥已撤销'), await toast())
await page.goto(`${BASE}/users`, { waitUntil: 'networkidle' })
await rowOf(keyactive.username).getByRole('button', { name: /删\s*除/ }).click()
await confirmPopover()
check('撤销密钥后回到用户列表可以删除', (await page.locator('.ant-modal:has-text("用户无法删除")').count()) === 0 && (await rowOf(keyactive.username).count()) === 0)

// 应用负责人：应用数、占用 -> 去处理 -> 应用抽屉 -> 删除应用 -> 回来删用户
await page.goto(`${BASE}/users`, { waitUntil: 'networkidle' })
check('应用负责人的“应用数”是 1', (await rowOf(appowner.username).innerText()).includes('1'))
await rowOf(appowner.username).getByRole('button', { name: /删\s*除/ }).click()
await confirmPopover()
const appModal = page.locator('.ant-modal:has-text("用户无法删除")')
check('应用负责人：占用清单里有应用负责人', (await appModal.count()) === 1 && (await appModal.innerText()).includes(ownedApp.name))
await appModal.getByRole('link', { name: '去处理' }).first().click()
await page.waitForURL(/\/apps\?project_id=/, { timeout: 8000 })
await page.waitForTimeout(1500)
const appDrawer = await drawerText()
check('“去处理”落在应用页并打开该应用的抽屉', appDrawer.includes(ownedApp.name))
check('应用的代码和环境能显示（不是“-”）', appDrawer.includes(`代码：${ownedApp.code}`) && appDrawer.includes('预发布'), appDrawer.slice(0, 120))
await page.locator('.ant-drawer').getByRole('button', { name: /删\s*除/ }).first().click()
await confirmPopover()
check('在应用页删除该应用', (await toast()).includes('删除成功'), await toast())
await page.goto(`${BASE}/users`, { waitUntil: 'networkidle' })
check('删除应用后，负责人的“应用数”回到 0', (await rowOf(appowner.username).innerText()).replace(/\s+/g, ' ').includes(' 0 '), (await rowOf(appowner.username).innerText()).replace(/\s+/g, ' ').slice(0, 100))
await rowOf(appowner.username).getByRole('button', { name: /删\s*除/ }).click()
await confirmPopover()
check('应用已删除、密钥已撤销：负责人可以直接删掉', (await page.locator('.ant-modal:has-text("用户无法删除")').count()) === 0 && (await rowOf(appowner.username).count()) === 0)

// 调过部门的本地用户：禁用 / 启用
await page.goto(`${BASE}/users`, { waitUntil: 'networkidle' })
const movedSwitch = rowOf(moved.username).getByRole('switch')
await movedSwitch.click(); await page.waitForTimeout(1500)
check('被管理员挪过部门的本地用户可以禁用（没有“由外部身份源管理”的误报）', (await movedSwitch.getAttribute('aria-checked')) === 'false', await toast())
await movedSwitch.click(); await page.waitForTimeout(1500)
check('……也可以再启用', (await movedSwitch.getAttribute('aria-checked')) === 'true', await toast())

// ---------- 应用：配置不丢 ----------
await page.goto(`${BASE}/apps?project_id=${cfgApp.id}`, { waitUntil: 'networkidle' })
await page.waitForTimeout(1500)
const cfgDrawer = await drawerText()
check('应用抽屉回填已配置的模型白名单和所属部门', cfgDrawer.includes('mock-model') && cfgDrawer.includes(deptB.name), cfgDrawer.slice(-160))
await page.locator('.ant-drawer').getByRole('button', { name: /保\s*存\s*模\s*型/ }).click(); await page.waitForTimeout(1500)
let cfg = await apiGet(`/projects/${cfgApp.id}`)
check('点“保存模型”不会清空白名单、额度或把应用移出部门', cfg.model_whitelist?.[0] === 'mock-model' && cfg.quota_limits?.daily_tokens === 1000 && cfg.team_id === deptB.id, JSON.stringify(cfg).slice(0, 160))
await page.locator('.ant-drawer').getByRole('button', { name: /编\s*辑/ }).first().click(); await page.waitForTimeout(600)
const editInputs = await page.locator('.ant-modal input').evaluateAll((els) => els.map((e) => e.value))
check('编辑窗口回填代码', editInputs.includes(cfgApp.code), JSON.stringify(editInputs))
await page.locator('.ant-modal input').first().fill(`${cfgApp.name}-改名`)
await page.locator('.ant-modal').getByRole('button', { name: /保\s*存/ }).click(); await page.waitForTimeout(1500)
cfg = await apiGet(`/projects/${cfgApp.id}`)
check('改名后模型白名单和额度仍在', cfg.name.endsWith('-改名') && cfg.model_whitelist?.[0] === 'mock-model' && cfg.quota_limits?.daily_tokens === 1000, JSON.stringify(cfg).slice(0, 160))

// ---------- 应用页深链 ----------
await page.goto(`${BASE}/apps?project_id=proj_does_not_exist`, { waitUntil: 'networkidle' }); await page.waitForTimeout(1200)
check('指向不存在的应用：提示“该应用已不存在”', (await toast()).includes('该应用已不存在'), await toast())
await page.goto(`${BASE}/apps?highlight=${cfgApp.id}`, { waitUntil: 'networkidle' }); await page.waitForTimeout(1500)
check('highlight 参数打开应用抽屉', (await drawerText()).includes(cfgApp.code))
await page.goto(`${BASE}/apps?team_id=${deptB.id}`, { waitUntil: 'networkidle' }); await page.waitForTimeout(1200)
check('team_id 参数打开“新建应用”并选好部门', (await page.locator('.ant-modal:has-text("新建应用")').count()) === 1 && (await page.locator('.ant-modal').innerText()).includes(deptB.name))

// ---------- 密钥页深链 / 已删除标记 ----------
await page.goto(`${BASE}/keys?key_id=key_does_not_exist`, { waitUntil: 'networkidle' }); await page.waitForTimeout(1200)
check('指向不存在的密钥：明确的空状态', (await page.locator('.ant-table-placeholder').innerText()).includes('没有找到这把密钥'))
await page.goto(`${BASE}/keys`, { waitUntil: 'networkidle' }); await page.waitForTimeout(1200)
const keyTable = await page.locator('.ant-table-tbody').innerText()
check('密钥页不再露出已删除应用/用户的内部 ID', !/proj_[0-9a-f]{6}/.test(keyTable) && !/[0-9a-f]{8}-[0-9a-f]{3}/.test(keyTable) && keyTable.includes('已删除'), keyTable.replace(/\s+/g, ' ').slice(0, 200))

// ---------- 部门 ----------
await page.goto(`${BASE}/organizations?team_id=${deptMem.id}`, { waitUntil: 'networkidle' }); await page.waitForTimeout(1500)
check('用户页的部门标签带 team_id 跳来：自动选中本单位和该部门', (await page.locator('.ant-col-16').innerText()).includes(deptMem.name))
await page.locator('.ant-col-16').getByRole('button', { name: /删\s*除/ }).first().click()
await confirmPopover()
check('删除有成员的部门：中文说明数量，不是数据库报错', (await toast()).includes('1 名成员') && !/violates|SQLSTATE/.test(await toast()), await toast())
check('……部门还在', (await apiGet('/teams')).data.some((t) => t.id === deptMem.id))
await page.locator('.ant-tree').getByText(deptParent.name, { exact: true }).click(); await page.waitForTimeout(800)
await page.locator('.ant-col-16').getByRole('button', { name: /删\s*除/ }).first().click()
await confirmPopover()
check('删除有下级的部门：说明有几个下级，不悄悄提成一级', (await toast()).includes('1 个下级'), await toast())
check('……下级部门仍挂在原父级下', (await apiGet('/teams')).data.find((t) => t.id === deptChild.id)?.parent_team_id === deptParent.id)
await page.locator('.ant-tree').getByText(deptEmpty.name, { exact: true }).click(); await page.waitForTimeout(800)
await page.locator('.ant-col-16').getByRole('button', { name: /删\s*除/ }).first().click()
await confirmPopover()
check('空部门可以删除', !(await apiGet('/teams')).data.some((t) => t.id === deptEmpty.id), await toast())
await page.goto(`${BASE}/organizations?team_id=team_does_not_exist`, { waitUntil: 'networkidle' }); await page.waitForTimeout(1500)
check('team_id 指向已不存在的部门：提示一句', (await toast()).includes('已不存在'), await toast())

// ---------- 单位：置灰的“删除单位”要讲原因 ----------
await page.goto(`${BASE}/organizations`, { waitUntil: 'networkidle' })
await page.locator('.ant-list-item').first().click(); await page.waitForTimeout(800)
const delUnit = page.getByRole('button', { name: /删除单位/ })
await delUnit.hover({ force: true }); await page.waitForTimeout(800)
check('“删除单位”置灰时悬停说明原因', (await delUnit.isDisabled()) && (await page.locator('.ant-tooltip:not(.ant-tooltip-hidden)').allInnerTexts()).join('').includes('不能删除你自己所在的主单位'))

// ---------- 收尾：没有意外的服务端错误 ----------
check('整个过程没有出现意外的 4xx/5xx 写请求（用户占用 409 与部门占用 409 除外）',
  api.every((l) => /^409 DELETE \/admin\/v1\/(users|teams)\//.test(l)), api.join(' | ') || '-')
await browser.close()
if (failed().length) { console.error(`\n${failed().length} check(s) failed:`, failed()); process.exit(1) }
console.log('\nall residual-data flow checks passed')
