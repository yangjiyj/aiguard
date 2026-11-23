# 2.6.7 语义预算与 Tier1 恢复调查（B，有界结果）

本分支只改 security-engine，并使用合成 loopback HTTP 上游做实验。未向生产模型发负载，未修改 Tier1 服务、现网配置、超时或防护模式。

## 当前只读证据及口径

主任务提供的现场读数：

- 已鉴权 security-engine /ready 返回 200 ready=true；该结果主要覆盖文件能力，不能代替 Judge/Tier1 端到端 readiness。
- Tier1 /health model_loaded=true；/stats scored_count=31，p50=75.71ms、p95=130.86ms。
- 过去三小时有六条 semantic incomplete，reason=tier1_timeout；容器无重启。
- 当前有效配置：semantic total 9s、Judge operation 8s、Tier1 operation 1s；输入/Agent语义开，输出关，sample1，阈值0.30/0.70。Tier1 THREADS=2、WORKERS=1。其余参数用代码默认。
- 六条历史事件没有可用 windows_attempted/scanned_chars/total_chars 数字，不能重建当次队列、分窗或上游调用耗时。近期缺少旧 Judge timeout/unavailable 日志不证明历史问题已经解决。

Tier1 /stats 的计时从等待服务侧推理池之前开始，包含 Tier1 自身排队及评分；但仅成功返回的评分写入统计。它不覆盖 security-engine 客户端池排队、DNS/连接阶段和失败请求。不能用31条成功结果的p95否定六条超时。

## 代码上可区分的机制

1. semantic.detect 的 9 秒预算跨所有窗口、Tier1、主 Judge 与复核共享；窗口1200字符、重叠200、默认最多32窗。每个窗口开始和每个阶段都用剩余预算。
2. 引擎输入端默认8 worker/32容量、30秒请求预算，包含输入队列与前置工作；semantic阶段期限再与该请求期限取较早值。正常前置工作不会直接扣掉新建的9秒语义预算，但接近30秒父期限时会压缩它。
3. Tier1客户端池默认4 worker/32容量。等待线程池的时间包含在语义总预算内；已过期排队任务取消且不再调用模型。未完成的运行调用保留容量，避免超时风暴绕过限制。
4. Tier1 HTTP socket/HTTP/解析失败一般返回 None，形成 tier1_unavailable；tier1_timeout 表示外层等待共享期限到期，不等价于模型评分超过1秒。请求临界点存在两条返回路径竞争，因此实验不把 unavailable 与 timeout 的细微先后解释为两个独立故障。
5. 来源逐组调用在网关侧串行，并尊重外层HTTP context；当前没有显式把前一来源已用时作为数字预算传给下一次engine调用。不能未经证据把“多来源串行”直接当作同一个engine 9秒预算被消耗。
6. DNS/连接阶段可能迟迟未进入模型服务，成功评分统计对此没有覆盖。本轮只通过受控客户端池阻塞实验验证等效排队机制，没有对生产DNS做故障注入。

## 已确认并修复的恢复错误

Tier1Client 原来把所有失败计入按URL共享的熔断器。调用方剩余时间比Tier1正常operation budget短时，健康上游无法在这个人为缩短的期限内完成，连续五次会被错误计为上游故障并熔断30秒，随后充足预算请求也被短路。

真实HTTP复现：上游稳定80ms返回成功，正常Tier1预算500ms；连续五次15ms调用方预算：

- 修前：五次请求均未完成，breaker错误打开，后续充足预算请求被跳过。
- 修后：五次请求仍未完成，不伪造安全/成功；不把这种已耗尽的缩短预算作为上游健康失败。后续500ms预算请求可正常完成。
- 原operation timeout足额耗尽仍计失败并正常熔断；短预算中的即时HTTP503仍计失败，不能用“预算短”豁免真实快速服务错误。冷却后成功仍清零breaker。
- 没有延长任何timeout，没有更改final action、故障模式或关闭规则。

该错误是隔离实验确认的代码缺陷。没有证据证明它就是现场六条历史事件的唯一或实际根因。

## 新增可解释证据

每个Tier1运行失败finding.triage携带仅数字/布尔字段：

- tier1_budget_ms：该次Tier1开始前剩余的有效总预算。
- tier1_client_call_started：是否已从客户端队列进入实际调用。
- tier1_client_queue_ms：等待调用开始的时间。
- tier1_client_call_elapsed_ms：进入调用后截至返回失败的已用时间。

每次调用独立采样，用锁保护跨线程快照；不保存URL、token或客户正文。原有window_start/end、windows_attempted、scanned_chars、total_chars继续保留。顶层仍是原有 semantic_status/reason。是否贯穿Go留证与数据库嵌套triage，交总集成检查；不能凭新字段倒填历史数字。

## 隔离实验与回执

tests/test_tier1_budget_recovery_267.py 六个实验：

- 健康上游 + 短调用方预算，不污染breaker。
- 原operation预算真实超时，正常熔断与冷却恢复。
- 短预算但即时503，仍触发健康失败。
- 客户端线程池阻塞：零次模型HTTP调用也可发生tier1_timeout；释放后下一请求恢复。
- 父请求期限短于语义预算：父期限正确约束，未完成不变成攻击。
- 单个窗口仅25ms，但多个窗口共享60ms总预算：明确返回覆盖未完成。

首次：1 failed、5 passed，失败即健康上游breaker污染；修后6 passed。
目标 Python 3.11.15 专项加原Tier1/deadline/预算传播回归：31 passed，2.57s。

真实FastAPI引擎HTTP又用两种可控故障验证：

- Tier1上游HTTP503 → 引擎HTTP200 semantic=incomplete / tier1_unavailable。
- Tier1实际socket超时 → 引擎HTTP200 semantic=incomplete / tier1_timeout。
- 普通请求无伪攻击finding；绑定真实github_token能力的合成凭据请求保持block。
- 独立wrapper：tests/run_quality_http_267.py --semantic-fixture unavailable|timeout|completed，供Go入口测试同容器loopback接入。completed仅代表受控Tier1低风险返回完成，不是实际模型就绪证据。

compileall app 成功。最新目标3.11全模块：1770 passed、3 failed、1 skipped，73.59s。三项失败仍为已在2.6.6基线确认的bench numpy缺失；skip仍是本地Qwen8091未运行。本轮未安装依赖、未将失败改成跳过。

## 剩余边界

- 无法重建历史六条timeout的实际等待位置，也未证明历史Judge失败已经消失。
- 未实测生产Judge的任务完成质量、长上下文排队、峰值并发或CPU容量；不能据文件ready、模型loaded或这些合成请求宣布恢复完整语义可靠性。
- Judge熔断同样位于HTTP失败路径；它当前只收到调用的有效timeout，缺少正常operation budget与剩余总预算的独立归因。本轮没有将Tier1修复直接套到Judge，没有声明Judge恢复缺陷已解决。
- 语义输出配置当前关闭，样本/计数不包含该阶段。
- 本分支不负责修改网关failuremode契约或告警故障聚合；Go实际观察/fail-open/fail-close及确定性secret保护由B/C总集成回执提供。
