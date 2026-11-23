# 检测容量部署配置

客户按部署环境填写容量。软件接受正整数并按该值建立线程池和准入队列，
不再将窗口并发截断为 8，也不再将单次窗口数量截断为 256。
默认值只用于未配置的新安装；显式配置优先。扩容 CPU、内存、推理服务或
增加节点后，可调整相应参数，通过安装/升级或受控发布流程重新创建服务生效。
这些参数属于部署容量配置，当前不在策略动作页面设置。

## 配置入口

源码模板：`deploy/docker-compose/.env.example`。
客户安装：实际 Compose 部署目录的 `.env`；普通和离线 Compose 都读取下面的参数。
使用编排平台时，把同名环境变量写入各 `security-engine` 工作负载；
`SECURITY_ENGINE_URL` 写入调用检测服务的网关等工作负载。
本文不创建 Kubernetes 集群，也不假设节点数、显存或硬件型号。

例如客户为每个检测进程配置 64 个裁判调用：

```dotenv
SECURITY_SEMANTIC_WINDOW_PARALLELISM=64
SECURITY_JUDGE_WORKERS=64
SECURITY_JUDGE_CAPACITY=64
SECURITY_JUDGE_QUEUE_CAPACITY=256
SECURITY_INPUT_WORKERS=64
SECURITY_INPUT_CAPACITY=256
```

`SECURITY_JUDGE_WORKERS` 未设置时继承窗口并发，`SECURITY_JUDGE_CAPACITY`
未设置时继承裁判线程数。旧 `.env` 已显式设置这两个参数时，显式值仍优先；
同时修改或删除这两个旧值后，才会使用新的继承值。
上面的 64、256 都是部署示例，不是软件最大值。

| 参数 | 配置对象 | 未配置时 |
|---|---|---|
| SECURITY_SEMANTIC_WINDOW_PARALLELISM | 每进程窗口调度并发、每请求在途窗口数 | 4 |
| SECURITY_JUDGE_WORKERS | 每进程裁判 HTTP 调用线程 | 继承窗口并发 |
| SECURITY_JUDGE_CAPACITY | 每进程同时受理的裁判调用数 | 继承裁判线程数 |
| SECURITY_JUDGE_QUEUE_CAPACITY | 普通裁判调用排队名额 | 8 |
| SECURITY_INPUT_WORKERS / SECURITY_INPUT_CAPACITY | 输入检查执行线程 / 执行加排队容量 | 2 / 32 |
| SECURITY_OUTPUT_WORKERS / SECURITY_OUTPUT_CAPACITY | 输出检查执行线程 / 执行加排队容量 | 2 / 32 |
| SECURITY_BATCH_ITEM_CONCURRENCY | 单个 batch 请求内同时检测的条目数（不超过输入容量；检测受单进程 GIL 限制，调大只会增加规则超时） | 2 |
| SECURITY_ENGINE_WEB_CONCURRENCY（容器内 WEB_CONCURRENCY） | 检测进程数；由 `engine-resource-autotune.sh` 按 CPU 档位写入，进程内状态已外置到 valkey，可跨进程共享 | 按档位（1/4/8/16） |
| SECURITY_CUSTOM_REGEX_RULE_SECONDS / SECURITY_CUSTOM_REGEX_PACK_SECONDS | 自定义正则单条 / 整包 CPU 预算（秒） | 0.01 / 0.05 |
| SECURITY_CUSTOM_REGEX_RULE_MAX_SECONDS / SECURITY_CUSTOM_REGEX_PACK_MAX_SECONDS | 长内容按长度放大后的单条 / 整包 CPU 预算上限（秒） | 0.2 / 0.5 |
| SECURITY_CUSTOM_REGEX_PACK_WALL_MAX_SECONDS | 自定义正则整包墙钟上限（秒） | 3 |
| SECURITY_CATALOG_BUDGET_SECONDS / SECURITY_CATALOG_REGEX_TIMEOUT_SECONDS | 内置策略目录整体 / 单次正则 CPU 预算（秒） | 2 / 0.25 |
| SECURITY_REGEX_WALL_SLACK / SECURITY_REGEX_WALL_MAX_SECONDS | 等待 CPU 导致超时后的单次重试：墙钟倍数 / 封顶（秒） | 10 / 2 |
| GATEWAY_SECURITY_RETRY_BACKOFF | 网关对 batch 未完成条目单条恢复的首次退避 | 200ms |
| SECURITY_TIER1_CLIENT_WORKERS / SECURITY_TIER1_CLIENT_CAPACITY | 一级分类器调用线程 / 调用容量 | 4 / 32 |
| SECURITY_TIER1_MAX_INFLIGHT | 每进程、每一级分类器地址的在途调用数 | 1 |
| TIER1_WORKERS / TIER1_THREADS | 一级分类器容器自身的 uvicorn 进程数 / 每进程线程数（容器侧真实并发，由 `engine-resource-autotune.sh` 按档位写入） | 按档位（1/2、2/4、4/4、8/4） |
| TIER1_INFERENCE_WORKERS / TIER1_INFERENCE_CAPACITY | 一级分类器每进程的推理 worker 数 / 执行加排队容量（决定容器能同时受理多少请求） | 按档位（2/64、4/128、8/256、8/512） |
| SECURITY_SEMANTIC_MAX_WINDOWS | 一次内容检查最多覆盖的窗口数 | 32 |

`SECURITY_TIER1_WORKERS` / `SECURITY_TIER1_THREADS` 已删除：它们只被 `/health` 读来展示，不控制任何并发。tier1 真正的并发由 `TIER1_WORKERS`×`TIER1_INFERENCE_CAPACITY` 决定，验收口径见下面第 1 节。

上述并发、容量和窗口数无产品固定数值上限。等待时间仍可按现有参数配置：
`SECURITY_JUDGE_QUEUE_WAIT`、`SECURITY_JUDGE_REGULAR_QUEUE_WAIT`、
`SECURITY_JUDGE_QUEUE_CALL_RESERVE`、`SECURITY_INPUT_BUDGET_SECONDS`、
`SECURITY_OUTPUT_BUDGET_SECONDS`、`SECURITY_BATCH_BUDGET_SECONDS` 和
`GATEWAY_INPUT_SECURITY_REQUEST_TIMEOUT`。裁判语义预算服从现有托管配置。
修改容量不会替换客户设置的超时或策略动作。

## 正则预算与 batch 恢复（2026-11-05）

检测线程共用一个 GIL。原先正则预算按墙钟计，线程多时等锁就把预算耗光，规则被记为超时，batch 返回未完成，网关再逐条重试，最终出现 503。本版改为：

- 单个 batch 默认只有 2 个条目同时进入检测线程，输入、输出检测线程默认各 2 个。
- 正则预算按检测线程实际消耗的 CPU 时间计。墙钟超时但 CPU 未用到预算的 80%，视为等锁，重试一次；用到 80% 以上视为规则本身慢，照旧记超时。整包墙钟最长 3 秒；同一次检测中有规则重试后仍失败，其余规则不再重试。
- 网关只对语义检测的临时失败和 batch 超时、容量溢出的条目单条恢复，每轮退避一次。快层规则超时、策略目录超时等原因不再整条重检，按原失败策略处理（默认放行并留审计）。
- 语义裁判就绪不再要求 5 分钟窗口内零失败：样本足够时看成功率，样本不足时只要有失败就不判就绪。

存量现场升级后行为变化：检测线程默认值 8→2（输入）、4→2（输出），batch 条目并发 2，快层原因不再单条重试，裁判就绪判定放宽。已在 .env 中显式写了线程数的现场保持原值，建议改为 2。

`SECURITY_ENGINE_WEB_CONCURRENCY` 大于 1 已按多进程验证（见下节）：
熔断器、判官意见缓存、`file_id_registry`、MCP 工具定义 pin、判官全局并发预算、
扫描准入都已外置到 valkey，节点号默认 `hostname#pid`，控制面按前缀聚合展示。
规则包拉取、语义配置轮询仍在每个进程各跑一份，这是有意的：它们是幂等只读拉取。
容器重启后控制面会保留旧节点记录，按 `node_id_prefix` 看不会重复计数。

## 多节点

```dotenv
SECURITY_ENGINE_URL=http://inspection-cluster.example:8000
```

网关把检查请求发送到该入口，由客户的负载均衡分配到检测节点。
每个检测进程独立使用自身配置，没有集群统一的 8 并发门槛。例如三个节点，
每节点一个检测进程且每进程裁判容量为 64，则配置允许的合计在途裁判调用数为
192；这不是吞吐量或延迟承诺。每节点运行多个进程时，容量也按进程相加。

裁判模型的地址使用现有“自定义裁判”配置，可指向客户推理集群的服务入口。
模型服务的并行参数由客户部署决定；网关不会按显卡型号代填、修改或限制它。
多节点使用同一租户配置、鉴权/签名配置和受支持的共享依赖；各检测进程的窗口
缓存仍在本地，负载均衡切换节点不会共享本地续检缓存。这里提供可配置入口，
未在本次现场建立或验收三节点集群。

## 当前开发 VM 的受控发布

已有 VM 由发布生成的 Compose 配置管理，不要只改旧 `.env` 后认为已经生效。
`build_vm_development.py --semantic-window-parallelism N` 接受任意正整数，
将窗口并发、裁判线程及裁判容量明确写入候选 manifest；
`deploy_vm_development.py` 在发布事务中应用、核验并保留回滚配置。
普通 `.env` 部署入口与此开发 VM 发布入口都没有 8 的硬上限。
当前现场的配置值仍为 8，模型进程和权重未改；本次消除的是软件硬上限。


### Batch deadline and request fairness (2026-09-23)

`SECURITY_SEMANTIC_REQUEST_PARALLELISM` bounds each request independently of
the shared window/inference pool. Unset inherits shared window parallelism;
it accepts any positive integer and cannot consume more shared slots than exist.
This changes scheduling only: every planned window remains subject to the
original coverage and deadline checks, and uninspected tails stay incomplete.

The batch deadline defaults to at most 18 seconds (or a shorter input envelope),
leaving transport headroom under the default 20-second gateway client. Explicit
operator settings remain authoritative. Existing deployments with an explicit
8-second value must be updated deliberately; the candidate release supports
`--security-batch-budget-seconds` and `--semantic-request-parallelism`, records
both in its manifest, and restores old values on rollback. Select the batch
deadline above the managed semantic budget and below the outer caller deadline;
the home candidate uses 18 / 15 / 14 seconds (batch / semantic / judge), an
16-slot shared pool, and at most 4 windows per request. This is a candidate
capacity setting, not a throughput promise.

The engine now reports non-operational when a five-minute window has at least
five attempts and fewer than 95% succeeded. A successful probe cannot erase
real traffic timeouts. Old failures expire normally; the circuit breaker and
incomplete-detection policy are unchanged. The control plane consumes this
degraded receipt even when its legacy independent success floor is lower.


### Long-content completeness profile

For deployments explicitly preferring complete synchronous inspection over the
previous short deadline, the controlled full VM release can record
`--gateway-security-budget-seconds 60`,
`--security-engine-client-timeout-seconds 59`,
`--security-input-budget-seconds 58`, and
`--security-batch-budget-seconds 55`. The managed semantic and judge budgets
are then saved separately through the admin API (50 and 20 seconds in the home
profile). Keep the inner budgets strictly below the caller, preserve the original
failure policy, and measure long/short mixed traffic. Healthy short requests
return immediately when inspection completes; these values are upper limits.
The deployment rejects inverted envelopes and preserves all prior values for
rollback. Customer defaults stay unchanged unless this profile is explicit.

### 1. 资源档位（实测：档位解析与 `deploy/tests/test_engine_resource_autotune.sh`）

`engine-resource-autotune.sh` 在安装/升级时按 cgroup quota 优先、`nproc` 兜底解析档位，
写入 `.env`；用户在 `.env` 里显式写的值优先，永不被覆盖。

档位必须同时决定**引擎侧客户端槽位**和 **tier1 容器侧真实供应量**。只调前者会把并发
堆在容器门口：引擎允许 64 个在途请求，而 tier1 只有 1 个推理 worker、容量 8，
其余请求全部拿 503。

| 档位 | CPU | WEB_CONCURRENCY | INPUT_WORKERS | TIER1_MAX_INFLIGHT | 引擎侧在途<br>WEB×INFLIGHT | tier1 容器<br>TIER1_WORKERS×THREADS | 推理供应<br>INFERENCE_WORKERS×CAPACITY | 供应量 | 校验 |
|---|---|---|---|---|---|---|---|---|---|
| small | ≤8 | 2 | 2 | 2 | 4 | 1×2 | 2×64 | 64 | within_limit |
| medium | 9–32 | 4 | 4 | 4 | 16 | 2×4 | 4×128 | 256 | within_limit |
| large | 33–64 | 8 | 8 | 8 | 64 | 4×8 | 8×256 | 1024 | within_limit |
| xlarge | >64 | 16 | 8 | 8 | 128 | 8×8 | 8×512 | 4096 | within_limit |

写入的真实键是 `TIER1_WORKERS`（容器 uvicorn 进程数）、`TIER1_THREADS`、
`TIER1_INFERENCE_WORKERS`、`TIER1_INFERENCE_CAPACITY`，每一个都遵循"显式值优先"。
旧版本里的 `SECURITY_TIER1_WORKERS` / `SECURITY_TIER1_THREADS` 已删除：那两个键
只被 `/health` 读来展示，不控制任何东西，容易让运维误以为改了就扩了容。

autotune 结束时校验一次供需，写法与判官预算校验一致：

```
引擎侧在途 = WEB_CONCURRENCY × SECURITY_TIER1_MAX_INFLIGHT
tier1 供应 = TIER1_WORKERS × TIER1_INFERENCE_CAPACITY
```

不满足就 `[engine-autotune][warn] ... the sidecar would answer 503 under load`，
并把 `ENGINE_RESOURCE_TIER1_CONCURRENCY_STATUS=over_limit:<demand>/<supply>` 写进 `.env`，
`/health` → `runtime.resource_profile.tier1_concurrency_status` 与控制台
"服务健康 → 安全检测引擎"会一直显示这个不匹配，直到有人把它改对。

`/health` 的 `tier1_runtime` 块是**实测值**而不是配置回显：引擎按 15 秒 TTL、0.25 秒超时
去问 tier1 容器的 `/health`，回填 `execution_provider` / `threads` / `batch_windows`。
tier1 挂了或超时只把 `reachable=false`，不会把引擎自己标成不健康。几个"否"和"未知"要分清
（控制台把 `false` 显示成"否"、`null` 显示成"未获取"）：未启用 tier1 时 `reachable` 是 `null`，
不是 `false`；`capacity_matches_profile` 在 tier1 镜像太旧、不报告自己的池子时也是 `null`
（无法验证，tier1 镜像不是每个版本都重建），只有池子真的和档位不一致才是 `false`。

`TIER1_BATCH_WINDOWS`（C4）只是单次 `session.run` 的滑窗上限，用来压峰值内存。长文本的所有窗口
本来就在一次图执行里跑完，这个旋钮默认不改变任何行为，**不是吞吐优化**，不要指望它降低延迟。

跨进程判官并发由 `SECURITY_JUDGE_GLOBAL_CONCURRENCY`（默认 96）封顶，低于 vLLM 实测
打满的约 128，留出余量。
`large` / `xlarge` 档默认的"每进程判官容量 x 进程数"（16 x 8 = 128、16 x 16 = 256）本来就大于 96：
每进程容量是上限，全局预算才是约束，这是有意的。这种情况状态写 `bounded_by_global:<乘积>`，
不告警；只有运维显式改过判官容量、进程数或全局并发使乘积超过全局预算，才写 `over_budget:<乘积>` 并告警。档位与预算状态见 `GET /health` → `runtime.resource_profile`，
以及控制台"服务健康 → 安全检测引擎 → 诊断指标"。

### 2. 进程内状态外置（实测：`apps/security-engine/tests/test_scale_out_shared_state.py`）

| 状态 | valkey 不可用时 | 用户可见表现 |
|---|---|---|
| `file_id_registry` 判定 | fail-closed，`lookup` 返回 `not_found`，不发放绑定 token | 上传被拒（`409`/`not_found`），不产生误判 |
| 绑定 token | 原子消费，跨进程只能成功一次 | 无 |
| `ToolDefinitionPinner` | 返回 `tool_definition_pinner_unavailable` finding（检测降级可见） | 审计出现该 finding，`semantic_status` 不完整 |
| 熔断器 open 状态 | 显式 capacity 降级并审计，仍按本地熔断继续 | 与单进程行为一致，不放大误报 |
| 判官全局并发预算 | 显式降级到进程内信号量，审计可见 | 可能更早进入 `judge_capacity_deferred` |
| **扫描准入**（文件扫描） | fail-closed，`AdmissionError("shared_state_unavailable")` | **仅文件上传返回 503**，见下 |
| 判官意见缓存 / 文件扫描缓存 | 只影响性能，标 `performance` 降级 | 检测照常重算，只变慢 |

`ToolDefinitionPinner` 的基线（pin）TTL 是**滑动**的：键的有效期默认 24 小时
（`SECURITY_TOOL_PIN_TTL`，秒），每次检查都把它顺延一个 TTL，用的是后端的 `GETEX`，
和原来的读取是同一次往返，没有额外开销。被换掉的工具定义只要还在被检查，就会一直报
`tool_definition_drift`；pin 只会在该工具**整个 TTL 都没被检查过**之后才过期，之后的
重新钉住才是合理的。此前是固定 TTL：从首次见到起算，到期后第一次检查找不到 pin，
会把已经换掉的定义悄悄当成新基线。`GETEX` 需要 Valkey / Redis ≥ 6.2，随包的 valkey 服务满足。
| 检测指标聚合 | 集群值显示为未知，不伪造 0 | 控制台显示"未知" |

**扫描准入 fail-closed 到底挡住谁**（容易被误读成"valkey 一抖全站不可用"）：

* 走准入的只有一个入口：`PUT /v1/scan/objects`（文件扫描上传，`scan_objects.py`），
  它拿不到槽位就抛 `HTTPException(503, "scan admission denied: shared_state_unavailable")`。
* **文字检测不走准入控制器**（`/v1/check-input`、`/v1/check-output`、batch 都不经过它），
  所以 valkey 抖动不会让普通对话检测 503，也不会变成"静默放行"。
* 拒绝会同时记 `degradation(consumer=scan_admission, reason=scan_admission_shared_state_unavailable,
  impact=detection)`，出现在 `/health` 的 `degradation_reasons` 与审计里——
  它是**可见的容量拒绝**，不是放行。
* `SECURITY_SHARED_STATE_REQUIRED=true`（compose 默认）时，启动自检拿不到 valkey
  直接拒绝启动；这条路径在 `upgrade.sh` 里被提前到停服之前，见下。

**默认 50ms 单命令超时是否偏紧**（实测，本机 loopback、单 valkey 实例、db3，
客户端为仓库自己的 `_RESP2`，超时故意放到 5s 以测真实分布）：

| 并发（在途） | 操作 | p50 | p99 | p99.9 | max | >50ms 占比 |
|---|---|---|---|---|---|---|
| 1 | `PING` | 0.06ms | 0.11ms | — | 1.6ms | 0 |
| 64 | `PING` | 1.21ms | 5.36ms | — | 9.9ms | 0 |
| 1 | `EVAL lease_acquire` | 0.09ms | 0.14ms | — | 0.5ms | 0 |
| 64 | `EVAL lease_acquire` | 1.54ms | 6.80ms | 16.8ms | 16.3ms | 0 / 12 800 |
| 128 | `EVAL lease_acquire` | 2.75ms | 12.94ms | 18.8ms | 29.3ms | 0 / 25 600 |
| 256 | `EVAL lease_acquire` | 2.81ms | 14.89ms | 23.10ms | **43.94ms** | 0 / 25 600 |
| 64 | `lease_acquire`+`ZREM` | 3.34ms | 9.71ms | — | 20.2ms | 0 / 12 800 |

端到端再验一遍（`ScanAdmission` + 256 容量，64 线程 × 50 次，共 3 200 次准入）：
socket 超时 0.05s 与 1.00s 的 fail-closed 次数**都是 0**。

结论：50ms 在 256 并发下仍有约 3.4 倍 p99 余量，但最差单样本已到 43.9ms，
**余量只剩 1.1 倍**。所以默认值不改，`large` 以上建议显式 `SECURITY_SHARED_STATE_TIMEOUT=0.2`：
单命令超时被打穿一次的代价是一次文件上传被拒（可见、可重试），代价不高但没必要吃。
注意上面的数字是 loopback，跨 docker bridge 通常再加 0.1–0.3ms，不改变结论。

`upgrade.sh` 现在把这件事提前：`verify_shared_state_namespace()` 在 `switch_images` **之前**
用 `redis-cli -n ${SECURITY_SHARED_STATE_DB:-3} ping` 探一次库 3，拿不到 `PONG` 直接中止升级。
旧行为是先 `up -d` 再靠健康检查发现问题，此时老服务已经停了，回滚窗口被吃掉。

### 3. 每请求判官调用次数

`tier1_low_threshold=0.0` 时级联关闭，每个窗口都是一次判官调用，所以
**窗口数 = 判官调用次数**。

#### 3.1 真机实测：窗口越宽，召回越低

条件：172.16.20.10（gpu-server），单卡 L40，vLLM 4B 判官，`gpu_memory_utilization=0.5`，
模型 `bundled-judge`；每轮 100 条语料，随机位置注入一条 40–80 字攻击句，同时跑原文作对照；
测量日期 2026-11-07 至 2026-11-09。

第 1 轮：

| 窗口 / 重叠 | 召回 | 对照误报 | 判官调用总数 | 单次 p50 / p95 | 单次 prompt |
|---|---|---|---|---|---|
| **1200 / 200** | **49/100** | 5/100 | 800 | 0.72s / 0.89s | 1842 token |
| 2000 / 250 | 32/100 | 4/100 | 600 | — / — | — |
| 4000 / 300 | 30/100 | 0/100 | 200 | 1.37s / 1.87s | 2849 token |

交叉比对（第 1 轮）：**1200 抓到、4000 漏掉的 25 条；只有 4000 抓到的 6 条。**
净差 −19 个百分点。

第 2 轮（换种子 `SEED=2026`，同一台机器、同样 100 条语料）：

| 窗口 / 重叠 | 召回 | 对照误报 | 判官调用总数 | 单次 p50 | 总耗时 |
|---|---|---|---|---|---|
| **1200 / 200** | **58/100** | 9/100 | 800 | 0.76s | 78s |
| 4000 / 300 | 31/100 | 2/100 | 200 | 1.58s | 41s |

交叉比对（第 2 轮）：**1200 抓到、4000 漏掉的 28 条；只有 4000 抓到的 1 条。**

两轮合起来看，**召回约 50–58%，对照误报约 5–9%**。每轮样本只有 100 条，
所以给区间而不是点值。窗口越小召回越高、误报也略高，这是有意的取舍：
误报可以用白名单和规则豁免消化，漏报没有补救手段。

原因是**稀释**：攻击句只有 40–80 字，塞进 4000 字上下文后，4B 判官的注意力分配不过来。
同一现象在 2000 字就已经出现（32 vs 49），说明这不是 4000 的边界问题，而是单调趋势。

**降本也没成立**：判官调用数 800 → 200（−75%），但总判官耗时只从 72s 降到 35s
（第 1 轮，约 0.52 倍；第 2 轮 78s → 41s，比例一致）。
时间 ≈ 调用数 × 单次 prompt 长度，窗口放大 3.3 倍后 prompt 从 1842 涨到 2849 token，
把省下来的调用次数吃了大半。用 3.3 倍上下文换 0.5 倍时间，再贴上 19 个百分点的召回，不划算。

因此 C3 的默认值回到实测安全宽度：

* `docker-compose.yml` / `docker-compose.offline.yml` 兜底、`.env.example` 示例、
  引擎 `semantic_window_chars()` 默认值，三处统一 `1200 / 200`。
* 4000/300 只作为**显式可选**保留，`.env.example` 注释里写明"召回 30/100 对 49/100（第 1 轮）、
  单次 2849 token"的代价，不做推荐。
* `apps/security-engine/tests/test_window_dilution_contract.py` 用 9 条断言把这个默认值钉住
  （不调模型、只读配置与 compose 文本），任何人把它悄悄改大都会红。
* `apps/security-engine/bench/window_dilution.py` 可在真机上复现上表，需 `--url` 与 `--key`。

#### 3.2 窗口数与覆盖率（离线确定，不依赖模型）

窗口几何是确定性的，可在无模型环境下测量（`tests/test_window_cost.py`）：

| 文本长度 | 1200/200（默认，现网） | 4000/300（显式可选） | 覆盖率 |
|---|---|---|---|
| 2 000 字 | 2 | 1 | 都 100% |
| 8 000 字 | 8 | 3 | 都 100% |
| 32 000 字 | 32 | 9 | 都 100% |
| 60 000 字 | 32（只扫 32 200 字，46% 未检） | 17 | 1200 窗口**截断**，4000 全覆盖 |
| 128 000 字 | 32（只扫 32 200 字） | 32（扫 118 700 字） | 25% → 93% |
| 600 000 字 | 32（25%） | 32（93%） | 靠 C2 指纹复用才可行 |

`SECURITY_SEMANTIC_MAX_WINDOWS=32` 截断时会返回 `window_budget_exceeded` 未完成结果，
不会伪造干净结论。系统提示逐字节未改，vLLM 前缀缓存命中率不受影响。

极长文本（>32 200 字）上 4000 窗口确实更完整（25% → 93%）。这是 C3 唯一的真实收益，
但它与"短中文本召回 −19pp"是同一个旋钮。选宽的现场必须同时接受召回下降，
并在 `semantic_status=incomplete` 之外单独记录"长尾被覆盖多少"——不要用覆盖率提升去
抵消召回下降，两者不是同一维度。

#### 3.3 窗口降本的正确方向（只记录，本分支不实现）

C3 错在**改窗口宽度**换调用数；正确方向是**降低单次成本**或**减少该送的窗口**：

1. **tier1 分数选窗**：先用 tier1 对每个窗口打分，只把高分窗送判官。风险是
   tier1 本身就是当前召回下界（离线语料 43.8%），等于用弱模型筛弱模型。
   门槛应与 `SECURITY_SEMANTIC_CASCADE_GUARD` 一致：离线语料下界做到 1.0 才允许开。
2. **判官改 token 级打分**：一次前向拿到整窗逐 token 风险，避免每窗重复塞一份系统提示
   （现在每窗 1842 token 里有相当比例是常量前缀）。需要改 4B 服务侧的返回结构，本分支不动。

两条都能把"每请求 token 总量"降下来而不动窗口几何，是真正兼容召回的方向。

### 4. 容量表（建模，输入为实测吞吐）

实测基线（每条都带条件，缺条件的数字不进这张表）：

* 判官直压（172.16.20.10，单卡 L40，vLLM 4B `bundled-judge`，
  `gpu_memory_utilization=0.5`，2026-11-07）：64 并发 72 次/秒，128 并发 85 次/秒封顶。
* 引擎（现网 248，64 核，引擎 8 进程，64 并发，2026-11-08 实测）：约 53 rps，p95 1.57s。
  这就是 CPU 侧的上限，没有 16 进程的实测记录，不写进表。
* 现网每请求 10.8 次判官调用（3437 请求 / 37259 次调用，agent 型长上下文，2026-11-07 采集）。

由此 `可持续 rps ≈ min(85 ÷ 每请求判官次数, 53)`：

| 场景 | 每请求判官次数 | 判官允许 rps | CPU 允许 rps | 可持续 rps | 说明 |
|---|---|---|---|---|---|
| **默认：1200 窗口 + 级联关闭（0.0）** | 10.8 | 7.9 | 53 | **≈7.9** | C3 默认不启用后，这就是默认容量 |
| 4000 窗口（显式可选，**不推荐**） | 3.2 | 26.6 | 53 | ≈26 | 召回 30/100 对 49/100（第 1 轮），−19pp |
| 1.0（短网页聊天，单窗口） | 1.0 | 85 | 53 | **≈53** | CPU 转为瓶颈 |

窗口几何的取舍（数据见 §3.1）：窗口小了，召回明显更高（50–58% 对 30–31%），误报也略高
（5–9% 对 0–2%）。这是有意的取舍——误报靠白名单和规则豁免就能消化，漏报无法补救，
所以默认值站在召回一侧，容量不够就加卡或另找降本手段。

C2（历史段复用）的收益**不进入上表**：它只复用"同任务、无 findings、`semantic_status=complete`"
的历史段（见 §6），现网 `inspect_history=false` 时可用面本来就窄，
必须真机回放测出实际降幅再算，不先给数字。

每 1 张 GPU（4B judge）+ 64 核折算人数，峰值口径：

| 用户画像 | 对应的容量行 | 峰值请求率假设 | 单卡可支撑 |
|---|---|---|---|
| agent 型（claude-code / codebuddy 长上下文） | 10.8 次/请求 → ≈7.9 rps | 0.675 rps/人（现网 8 人峰值 5.4 rps） | **≈11–12 人** |
| 网页聊天型（短问题、单窗口） | 1.0 次/请求 → ≈53 rps | 0.033 rps/人（约 30 秒一条，建模） | **≈1 600 人** |

两种画像必须各走各的容量行：把 agent 型的请求率套到 53 rps 上会得出虚高的人数，
因为 agent 型不会缩到单窗口。

**上一版本把"≤2 次/请求 ≈ 42 rps"当验收目标，R1 之后这个目标撤回。** 42 rps 在
10.8 次/请求下需要 `42 × 10.8 ÷ 85 ≈ 5.3`，也就是**约 5–6 张 L40**；单卡想拿到 42 rps
只能靠降本，而降本的默认手段（C3）已被真机否掉。要把 agent 型人数从 ~12 提到 ~60，
只有三条路，都要单独评估：

1. 加卡：判官上限线性放大，但很快就撞 CPU 的 ~53 rps。
2. 走 §3.3 的两条降本方向（选窗 / token 级打分），不动窗口几何。
3. 启用级联（提高 `tier1_low_threshold` 让低分窗不送判官）——受离线语料下界 43.8% 约束，
   当前只能到 `legacy` 策略，不能当默认。

假设与边界：

1. 人数按**峰值**折算，不是均值；agent 型按现网 8 人峰值 5.4 rps 外推。
2. 判官 85 次/秒是单卡 4B、`gpu_memory_utilization=0.5` 的实测值（172.16.20.10，
   2026-11-07）。现网该实例已调到 `gpu_memory_utilization=0.85`：KV cache 更大，
   能撑住更高的并发和更长的 prompt，**吞吐上限待复测**。复测之前本表继续用
   85 次/秒作保守值，不按推算改数字；加卡仍按线性放大估算。
3. CPU ≈53 rps 是现网 248（64 核、引擎 8 进程、64 并发）的实测（2026-11-08，p95 1.57s）；
   减核按比例下调。
4. 上表没有计入 C2 收益，实际值只会更好，不会更差。

### 5. C1 溯源：`tier1_low_threshold=0.0` 从哪来（已定案）

代码里没有任何一处把下限默认成 0.0（本次逐处核对）：

| 来源 | 值 |
|---|---|
| `feature_flags.DEFAULT_TIER1_LOW_THRESHOLD` | 0.2 |
| `docker-compose.yml` / `docker-compose.offline.yml` 的 `${...:-}` 兜底 | 0.30 |
| `deploy/migrations/139_semantic_bundled_defaults.sql` 出厂行 | 0.30 |
| 控制面 `defaultTier1LowThreshold` / `defaultSemanticTier1Low` | 0.30 |

`feature_flags.get_float()` 对空值和非法值都回落到默认，不会变成 0。
0.0 只可能来自运行期覆盖：客户 `.env`，或者控制面写入。

**现网库已定案，走的是通用设置接口，不是 `smart-detection/config`：**

```
2026-09-17 05:30:08 | user_admin | update_system_settings | {"tier1_low_threshold": "0.0"} | 172.18.0.1
```

也就是说：`PUT /admin/v1/system/settings`（通用键值设置），`action_type=update_system_settings`，
`action_detail={"tier1_low_threshold":"0.0"}`，来源 IP `172.18.0.1`。
`172.18.0.1` 是 docker bridge 网关地址，据此**推断**（不是事实）：这次写不是外部浏览器直连，
而是从宿主或同网段容器发出的一次脚本/接口调用。这一点只有现场能确认。

本分支让这条路径以后可追溯、可告警、可校验：

* 通用设置接口现在对 `tier1_low_threshold` / `tier1_high_threshold` 复用
  `smartThresholdOutOfRange()`：必须是 `[0,1]` 内的十进制数（`NaN`、`Inf`、十六进制浮点、
  下划线一律 400，引擎读不了这些值，会整份拒收托管语义配置），且 `low < high`
  （相等也拒绝，引擎同样拒收）；清空某一项时按部署默认值回落再比较。
  旧行为是照单全收。
* **`low < 0.05` 在通用设置接口上直接 400**（0.0 就是 9-17 那次写进去的值：这条接口
  什么键都收，没人会读审计里的 warning，级联就这样被悄悄关掉）。只有请求里显式设置下限
  才按它判断，所以库里已存的旧 0.0 不会挡住别人去修正上限；**绝不改写**运维已保存的值。
  确实要这么配，走控制台「智能检测」专用接口：它仍接受 `low < 0.05`，写入审计追加
  `warning=tier1_cascade_disabled`，读接口 `status.warnings` 给同一告警。
* 引擎 `GET /health` 的 `cascade_warnings` 用同一口径（<0.05），服务健康页直接显示。

按新事实查责任人（表名 `audit_operations`，列名 `action_type` / `action_detail` / `ip_address`）：

```sql
-- 谁在 2026-09-17 前后把下限写成 0
SELECT ao.created_at, u.username, ao.action_type, ao.action_detail, ao.ip_address
  FROM audit_operations ao
  LEFT JOIN users u ON u.id = ao.user_id
 WHERE ao.action_type = 'update_system_settings'
   AND ao.action_detail ? 'tier1_low_threshold'
   AND ao.created_at >= '2026-09-16' AND ao.created_at < '2026-09-19'
 ORDER BY ao.created_at;

-- 当前生效值（以数据库为准，不以 .env 为准）
SELECT key, value, updated_at FROM system_settings WHERE key LIKE 'tier1_%' ORDER BY key;
```

`action_detail` 是 `jsonb`，所以用 `?` 判存在键，不要用 `LIKE '%tier1_low_threshold%'`
（会命中无关的嵌套字段）。若现场历史更长，把时间窗放宽到 ±7 天再排。

### 6. C2 的生效边界：任务上下文不可丢

历史段复用依赖 `path=/messages/N` 稳定。agent 客户端是追加式的，索引不变，能命中；
如果客户端做**滑动窗口历史**（每轮丢掉最早几条），索引整体前移，历史段全部失配、
退回全量检测——方向是保守的，不会漏检，只是拿不到收益。

更关键的是**安全语义**，这是本分支修掉的缺陷：

* `tool_result` / `rag` / `rag_context` / `retrieval` / `web_content` 这些来源的内容
  是否良性命中**依赖用户意图**。同一段"删除数据库并跳过确认"的脚本，
  用户说"总结一下这个脚本"是 benign，说"按这个脚本执行"就是恶意。
  原实现把 `userTask` / `judgment` 从 scope 里去掉，等于让任务 A 的 benign 结论
  给任务 B 背书。
* 现在（`app/gateway-core/internal/handler/inspection_scope.go`）：不可信来源的历史段
  scope 里重新带上"首见时的 `user_task` 哈希"，**只在同一任务内复用**；
  换任务必然重检。可信历史（`assistant` / `user_history`）保持原样，
  不动它们的 occurrence 折叠，避免审计量膨胀。
* 命中后的处理与基线一致：无 findings 的历史段直接跳过；**带 findings 的不可信历史段在
  同一任务内重放**（经 `/apply-context` 按当前策略重算处置），并折叠成首个事件的
  occurrence，不再每轮重检、重写完整事件。换任务必然未命中，重判一次，之后在该任务内
  同样折叠。一个片段从"最新消息"变成"历史"时 scope 不同，会按历史 scope 多判一次，
  所以带 findings 的片段每个任务最多 2 条完整事件，其余都是 occurrence，不随轮数增长
  （6 轮 agent 循环实测：引擎调用 2、完整事件 2、occurrence 4；此前是 6 / 6 / 0）。
* assistant 消息携带的结构化 `tool_calls`（引擎据此产出 `high_risk_action`）进入指纹 scope：
  同样一句"Let me check."，带 `ls` 的结论不能给带 `rm -rf /` 的背书，不论同任务还是跨任务。
  没有 `tool_calls` 的消息 scope 不变，已有缓存继续有效；相同文本加相同调用仍然复用。
* 消息携带的附件字节（走独立的 `attachments` 通道，文件类型策略和文件 DLP 必须始终看到真实字节）
  也进入指纹 scope：同样一句"see this"，换一张图、或在纯文本与带附件之间切换，都不会命中
  对方的结论。没有附件的消息 scope 不变，已有缓存继续有效；相同文本加相同附件仍然复用。
* 想回到跨任务复用（收益最大、风险自负）用 `GATEWAY_FP_HISTORY_TASK_AGNOSTIC=true`，
  **默认 false**，且只在明确接受"同一工具结果跨任务共享结论"的现场才开；开启后带
  findings 的历史段也跨任务重放折叠。该变量已透传进 compose（gateway-core），改 `.env` 即生效。

`inspectionscope.IsUntrustedSource()` 是这份名单的单一真源（`packages/shared-go/inspectionscope`），
网关与控制面都调它，不要各自维护一份字符串表。

命中率与每请求判官次数经网关注入的 `X-JJD-FP-Checks` / `X-JJD-FP-Hits` 回传，
`/metrics` 给出集群聚合值。

**取舍**：任务哈希让"同一个工具结果被不同任务引用"的场景不再命中，
C2 的收益因此比初版小。选择是明确的——这类内容复用错一次就是跨任务误判，
而现网 `inspect_history=false`、`inspect_tool_results=true`，上一轮之前的工具结果
确实会被当历史扫到，路径是真实生效的，不能拿"收益"换掉这条。

### 7. 待验收（必须在真机完成，本分支未采集）

```bash
# 1) 窗口默认值：确认生效值是 1200/200（不是 4000）
docker compose exec -T security-engine env | grep SEMANTIC_WINDOW
python3 -m pytest apps/security-engine/tests/test_window_dilution_contract.py -q   # 9 passed

# 2) 召回/误报基线（需要真判官）。bench/ 没打进引擎镜像，必须在源码树里跑。
#    语料：content_log_bodies 里 customer_text 且 ≥4000 字的正文，一行一个 JSON 对象
docker compose exec -T postgres psql -U "${POSTGRES_USER:-jjdguard}" -d "${POSTGRES_DB:-jjdguard}" -At -c \
  "SELECT json_build_object('text', content)::text FROM content_log_bodies \
   WHERE customer_text AND char_length(content) >= 4000 ORDER BY created_at DESC LIMIT 200" \
  > /tmp/bodies.jsonl
#    攻击句：/tmp/attacks.txt，一行一句，40–80 字
cd apps/security-engine && python3 bench/window_dilution.py \
  --corpus /tmp/bodies.jsonl --attack /tmp/attacks.txt \
  --window 1200 --overlap 200 --count 100 --seed 2026
#    --url / --model / --key 默认取 SECURITY_LLM_JUDGE_URL / SECURITY_LLM_JUDGE_MODEL /
#    SECURITY_LLM_JUDGE_API_KEY（老 JUDGE_KEY 仍兼容）：现网判官是
#    http://172.16.20.10:8100/v1/chat/completions，模型 bundled-judge，不必手抄密钥。
#    也可以让脚本自己从库里取语料（只读一条 SQL，需 psql 在 PATH 上）：
#    python3 bench/window_dilution.py --from-db "$DATABASE_URL" --attack /tmp/attacks.txt ...
# 离线准入下界（无需模型）：
python3 -c "from app.cascade_recall_gate import evaluate_corpus as e; print(e())"

# 3) tier1 并发：默认值下压 64 并发，503 应为 0
#    供给必须在途：supply = 副本 x TIER1_WORKERS x TIER1_INFERENCE_CAPACITY
#    在 deploy/docker-compose 下执行（脚本默认读同目录 .env，也可显式传 env 文件）
cd deploy/docker-compose && ./tier1-scale.sh cpu 1 --check
#    期望 within_limit demand=64 supply=1024 replicas=1 workers=4 capacity=256
curl -s http://<engine>:8000/health | jq '.runtime.resource_profile | {tier1_concurrency_status, tier1_workers, tier1_inference_workers, tier1_inference_capacity}'
#    capacity_matches_profile=false 表示 overlay 把池子压过（实测值与档位不一致）
curl -s http://<engine>:8000/health | jq '.runtime.tier1_runtime | {inference_workers, inference_capacity, uvicorn_workers, capacity_matches_profile}'

# 4) 真机流量回放：judge/请求、p95、降级比例
#    关注 window_budget_exceeded / security_pipeline_timeout / breaker_open 三项占比 <0.5%
curl -s http://<engine>:8000/metrics | jq '.metrics.effective'
curl -s http://<engine>:8000/health  | jq '.runtime | {resource_profile, cascade_warnings, degradation_reasons}'

# 5) C2 跨任务重检（网关侧，无需模型即可跑）
cd apps/gateway-core && /usr/local/go/bin/go test -buildvcs=false \
  ./internal/handler -run 'TestHistoryToolResult|TestHistorySegmentWithFindings|TestUserHistory' -count=1

# 6) 多副本一致性（文件上传跨副本引用、MCP 工具定义偷换、熔断状态）
SECURITY_ENGINE_REPLICAS=4 \
  docker compose -f docker-compose.offline.yml -f docker-compose.scale.yml up -d
sh tier1-scale.sh cpu 2 --check
```

`cascade_recall_gate` 的结论是**准入下界**：现有高精线索并集只覆盖 80 条越狱样本中的
35 条（43.8%），良性误标 17/82。所以按"低分且无线索就跳过判官"会直接掉 56% 召回，
本分支因此**没有**把该行为设为默认：`SECURITY_SEMANTIC_CASCADE_GUARD=false`，
`SECURITY_SEMANTIC_CASCADE_POLICY` 仍为 `legacy`。只有离线语料下界达到 1.0
且显式打开 guard 才会启用，`/health` 的 `cascade_warnings` 与
`semantic_status` 会持续提示。

### 8. 存量升级：旧 .env 迁移与扩容拓扑持久化（U1/U2）

前七节都假设"新装"。存量客户是另一回事：`.env` 里还留着旧模板的 tier1 生效默认值，
而 `engine-resource-autotune.sh` 把任何生效键当成运维的决定，所以档位永远写不进去。
本节的机制把这条链路补齐；完整说明与 release note 见
`docs/operations/2026-11-08-tier1-upgrade-migration.md`。

**U1 迁移**：autotune 在算档位前先跑 `migrate_legacy_tier1_defaults`，把仍等于旧模板
默认值的行注释掉（不删除），行前写
`# migrated-by-autotune <日期>: legacy template default, now follows the autotuned tier (<键>)`，
并把原 `.env` 备份成 `.env.bak-tier1-migrate-<YYYYmmddHHMMSS>`。不等于旧默认值的行一律
不动——site 248 的 `TIER1_WORKERS=4 / TIER1_INFERENCE_WORKERS=8 /
TIER1_INFERENCE_CAPACITY=256 / TIER1_THREADS=4` 属于这一类。每个 `.env` 只迁移一次
（写 `TIER1_LEGACY_DEFAULTS_MIGRATED=<日期>`），否则 small 档上等于旧默认值的档位值会被
反复注释。`ENGINE_RESOURCE_PROFILE=manual` 完全不迁移。

**U2 拓扑**：`tier1-scale.sh <cpu|gpu> <N> --apply` 把 `TIER1_REPLICAS=<N>` 与
`TIER1_SCALE_MODE=<cpu|gpu>` 写回 `.env`；`upgrade.sh` / `upgrade-bundle.sh` /
`deploy-offline.sh`（含回滚路径）按这两个键叠加 `-f tier1-<mode>.override.yml` 并加
`--scale tier1-classifier=<N>`。`gpu` 模式在升级前跑与扩容相同的预检，失败即中止，
不会悄悄退回 CPU 镜像。两个键为空 = 基础 compose、单副本，行为与旧版本一致。

供需两侧现在共用 `deploy/docker-compose/tier1-topology.sh` 一个公式：

```
supply = TIER1_REPLICAS x TIER1_WORKERS x TIER1_INFERENCE_CAPACITY
demand = SECURITY_ENGINE_REPLICAS x WEB_CONCURRENCY x SECURITY_TIER1_MAX_INFLIGHT
```

因此 `tier1-scale.sh --check` 与 autotune 的 `ENGINE_RESOURCE_TIER1_CONCURRENCY_STATUS`
逐字一致，不会一边 within_limit 一边 over_limit。

回到单副本：`./tier1-scale.sh reset --apply`。

**升级后的自查**（三条都能在 10 秒内看完）：

```bash
cd deploy/docker-compose
grep -n 'migrated-by-autotune' .env                      # 迁移了什么
ls -l .env.bak-tier1-migrate-*                           # 备份在哪（600）
grep -E '^TIER1_(REPLICAS|SCALE_MODE)=' .env             # 扩容拓扑是否还在
./tier1-scale.sh cpu 1 --check                           # 供需是否仍匹配
docker ps --filter name=tier1-classifier --format '{{.Names}}' | wc -l   # 实测副本数
```

> 副本数口径：`/health.runtime.resource_profile.tier1_replicas` 与 `tier1_scale_mode`
> 是**配置值**（读 `.env`），不是实测副本数。`tier1_runtime` 的探针经 Compose DNS 解析，
> 多副本时只会命中其中一个副本，报的是**单副本**的池子；真实副本数用 `docker ps` 数，
> 或用 `capacity_matches_profile` 判断"这一个副本的池子是否等于档位"。
