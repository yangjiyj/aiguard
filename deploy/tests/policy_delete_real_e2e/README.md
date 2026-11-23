# 自建策略删除 · 真实栈端到端

验证“组织自建策略可以删除”的整条链路：控制台（真实浏览器）→ control-plane → 真实 gateway-core 与 security-engine。
不依赖任何长期环境：每次起一个独立 compose 项目（唯一项目名、回环端口、临时密钥），跑完 `down -v`。

```bash
bash deploy/tests/policy_delete_real_e2e/run.sh                    # 后端端到端（约 5～8 分钟，含构建）
E2E_BROWSER=1 E2E_CHROME=/path/to/chrome bash .../run.sh            # 再加真实浏览器步骤
E2E_KEEP=1 bash .../run.sh                                          # 跑完保留栈，便于手工看
```

前置：docker、go、python3、openssl、宿主机的 /usr/share/zoneinfo（alpine 运行镜像没有时区库，会挂进去）；web-console 需要 `apps/web-console/node_modules`（`npm ci` 或软链）；
需要一个带 Python 依赖的 security-engine 镜像（默认取本机第一个 `jjdguard-dev/security-engine:*`，
也可用 `E2E_ENGINE_IMAGE` 指定，本工作树的 `apps/security-engine/app` 会被挂进去）。

| 环境变量 | 作用 |
|---|---|
| `E2E_PROJECT` | compose 项目名（默认 `jjdguard-poldel-<时间>`，必须唯一） |
| `E2E_PORT_BASE` | 回环端口起点（默认 28400：控制面 +1、网关 +2、控制台 +3） |
| `E2E_KEEP=1` | 结束后不清理 |
| `E2E_SKIP_WEB_BUILD=1` | 不重新构建 web-console |
| `E2E_BROWSER=1`、`E2E_CHROME` | 打开浏览器步骤、指定 Chrome 可执行文件 |

## 验证内容

`test_policy_delete_api.py`（真实网关 + 真实引擎，默认“防护阻断”模式）：
- 建 keyword + block 策略，等引擎持有新规则包；含关键词的请求被拦（403 `security_blocked`，提示里带策略名），上游没收到；
- 删除 → 204，审计 `security_policy.delete`；规则包版本回到创建前，引擎持有后同样请求放行；
- 删除前后：策略总数/启用数/运行中/自建数、`GET /rules`、内容安全规则列表、策略资产、检测组件引用数都回到基线；
- 已产生的告警仍在，审计事件/拦截记录/请求详情/告警事件继续显示策略名，墓碑行保留；
- 再删、改、启停已删策略 → 404；同名策略可以重建且重建后重新生效；
- 内置策略 DELETE → 409 `policy_not_deletable`；不存在的 id → 404；auditor → 403；
- 旧接口 `DELETE /rules/{id}`：custom.* 走同一条路径；已产生告警的老规则返回 204（不再 500）且之后同样请求放行；
- 豁免随策略一起消失（并且带豁免的规则包引擎照常接收）。

`browser/delete-policy.mjs`（Playwright + Chrome）：
- 详情抽屉：删除策略 → 一次小确认（无必填项）→ 抽屉关闭、URL 里的 `policy=` 清掉、列表回读、行消失；
- 概览“组织自建策略”“运行中策略项”、高级维护“目录总数/参与运行”随之同步；
- 运行策略表行内删除；服务端 500 时有提示、列表回读、抽屉保留；别处已删（404）时按已删除处理；
- 入口：场景页自定义敏感信息列表、系统策略目录（组织自建筛选）、检测组件 → 关联策略；
- 内置策略的行和详情里没有删除；auditor 进不了策略中心，security_officer 只读、看不到删除。

`browser/residual-data-flows.mjs`（Playwright + Chrome，`E2E_BROWSER=1` 时紧接着跑）——控制台“带残留数据”的流程巡检，
数据都由真实账号经接口先建后删（应用负责人用 tenant_admin 登录后自己建应用和密钥），不碰数据库：
- 用户：删掉“密钥已在密钥管理删除”的用户直接成功；有活跃密钥时占用清单 → “去处理”落在密钥页且只剩那一把 → 撤销后可删；
  应用负责人的“应用数”、占用清单 → 应用抽屉 → 删除应用 → “应用数”回 0 → 可删；被管理员挪过部门的本地用户可禁用/启用；
- 应用：抽屉回填模型白名单/所属部门、代码/环境能显示；“保存模型”“改名”不清空白名单和额度；
  `?highlight=`、`?team_id=`、不存在的 `?project_id=` 的落点；
- 密钥：`?key_id=` 空状态、已删除应用/用户不露内部 ID；
- 部门：`?team_id=` 自动选中、删除有成员/有下级的部门给中文数量、空部门可删、“删除单位”置灰时悬停说明原因。

## 在别的机器上跑浏览器步骤

栈只监听 127.0.0.1。要从另一台机器（例如没有 Docker 的 Windows）驱动浏览器：
`ssh -L <E2E_WEB_PORT>:127.0.0.1:<E2E_WEB_PORT> <栈所在机器>`，然后在 `browser/` 下
`npm install && E2E_WEB_PORT=<端口> E2E_ADMIN_PASSWORD=<栈里 ADMIN_PASSWORD> node delete-policy.mjs`（另一个脚本同理：`node residual-data-flows.mjs`）
（`E2E_KEEP=1` 保留栈时密钥在 `$WORK/stack.env`）。

## 注意

- 全新栈上切到“防护阻断”后，网关要隔一会儿（实测最长 1～2 分钟）才按新模式拦截；脚本会等到第一次真拦住再往下。

## 局限

栈里没有 LLM 裁判 / tier1 / 代理服务 / worker，语义检测关闭；“运行态”回执因此显示 degraded，
只看规则包版本是否被引擎持有。上游是本目录的 `mock_upstream.py`。
