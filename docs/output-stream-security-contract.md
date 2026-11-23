# 输出安全的流式缓冲与严格模式契约

修复基线：d5839091（2026-09-05）。本项改变 gateway-core 的 Chat / 原生 Responses / 原生 Messages 输出检查和传输，不限制客户 QPS，也不调整客户租户的 audit_only / failure_mode。

## 模式

- stream_enforce：按 choice 和 content / reasoning 字段分别维护检查上下文及待发尾部；相邻同一协议身份的小 delta 合并扫描。检查通过后，只发送该字段扣留尾部之前的 UTF-8 完整前缀。统一队列保持文本、reasoning 和 usage 事件的顺序；切换字段/choice 不强制释放旧字段尾部。上游大 delta 分块扫描，不再因为单个 delta 大于扫描窗而静默只查前缀。工具参数仍扣留至最终工具决策，标准化为工具开始、参数、finish 事件。
- strict_buffered：支持 StreamAdapter 的三个入口在有界读取器中累计，完整输出检查结束前不向客户端发送任何 SSE 事件，包含 role/usage。累计输出预算、解析/工具/选择数上限不足时，发送明确失败，不释放待发正文。完整响应通过后才发 SSE。无 StreamAdapter 的兼容调用路径仍在完整返回后、发送前校验字节预算；其上游累计内存保护由供应商适配器负责。
- stream_audit 或 SECURITY_AUDIT_ONLY：保留原有审计放行行为，不把已输出风险报告成阻断。

strict_buffered 的预算限制独立于检测器故障时的 GUARDRAIL_FAILURE_MODE。要验收“检查成功后才发送”，必须使用 enforce + fail-close，不能启用 audit_only 或 fail-open。输出检测没有完成会记录 output_scan_incomplete；检查完成也只说明实际启用的检测链路执行结束，不能证明所有未知语义风险都可识别。

## 可配置参数

| 环境变量 | 默认 | 接受范围（字节） | 含义 |
| --- | ---: | ---: | --- |
| GATEWAY_OUTPUT_STREAM_HOLDBACK_BYTES | 256 | 4–16384 | 每个字段保留的未发送尾部 |
| GATEWAY_OUTPUT_STREAM_SCAN_BATCH_BYTES | 1024 | 4–49152 | 合并多少新增字节后检查一次，UTF-8 边界可稍提前 |
| GATEWAY_OUTPUT_STREAM_PENDING_BYTES | 4194304 | 65536–67108864 | 单请求待发队列的正文总字节上限 |
| GATEWAY_OUTPUT_STRICT_MAX_BYTES | 4194304 | 1024–67108864 | 严格模式完整响应 JSON 字节预算；流式读取期间也检查累计输出字节 |

配置非法会启动失败，避免无意设置成零保护。每个扫描请求最大 64 KiB（历史上下文最多 16 KiB + 新增最多 48 KiB）。仍有原有防御上限：每个 content / reasoning 字段累计 4 MiB、工具参数 1 MiB、32 choices、每 choice 64 tools、终结原始事件 1 MiB。这些上限触发时必须明确未完成；提高 strict 总预算不会绕过单字段上限。

队列额外限制 8192 个未合并事件，通道状态不超过 64 个。前面字段停止增长时，它的保留尾部可能使后续字段一起延后到完整复核；这是顺序与有限尾部保留同时成立的代价。队列上限耗尽按现有 failure_mode：close 阻断并记未完成，open 可以发送未完成检查的数据并留痕。硬资源上限仍可中止流，不能用 fail-open 导致内存无限增长。单机或多实例均使用同一契约，容量测量应包括排队内存和客户端首字延迟。

## 掩码与工具数据

增量扫描若要求 mask，该字段保留到全文复核后再对齐替换。最终复核不能改写已发送的前缀；跨交织字段无法安全定位替换时失败，不乱序重写。整段短响应的 mask 可在首次正文发送前完成。取消后不会刷新待发尾部，写入阻塞会阻止继续消费上游。

结构化 tool arguments 现在独立经过输出 DLP，再进入 AgentGuard 动作风险检查；分段参数在完成后检查。mask 结果必须仍是合法 JSON，否则阻断；audit_only 保持原始参数和审计记录。修复了 tool start 同时携带 arguments 时累计两遍的问题。

## 能力边界

有限尾部能防止被覆盖跨度内的跨 delta 手机号、密钥等前缀过早发送，但不能保证任意长标记、无限跨段上下文或复杂语义机密零泄漏。末尾全文复核可以发现后续风险，但无法撤回前面已经发送的内容。需要整个响应发送前决策时选择 strict_buffered，并使用真实客户样本评估识别能力。

本次修复覆盖 /v1/chat/completions、/v1/responses 和 /v1/messages 的生产 Handler。原生模式保留 delta 的 item/content/block 标识和事件次序；Responses 在输出分片合并后重新生成单调序号。非空 start 内容快照若未规范化为可检查正文，会明确报告未完成；不直接穿透。Responses 的原始终结快照必须单独通过结构化工具检查和全部字符串字段检查（含 reasoning / metadata）后才可保留原生形状；无法定位的原生快照 mask 明确阻断。重复的 output_text.done / content_part.done / output_item.done 快照不提前透传，最终 response.completed 承载已检查的完整结果。Messages 的 usage/stop 在最终检查后发送。

## 验证

真实 HTTP 上游 + 真实 HTTP 客户端覆盖跨 delta API key / 手机号的前缀、reasoning/content 交织、72 KiB UTF-8 单 delta、末尾 flush、DONE 与 usage、全文 mask、strict 超预算 / 检出阻断。严格模式检查器被测试闸门阻塞期间客户端连响应头都收不到，放行后正常完成。

补充测试覆盖 choice 交织、工具分段参数 DLP 与 audit_only、预算耗尽、取消不刷新、同步背压、配置范围；既有 handler/config/relay 包回归通过。吞吐、召回与客户业务误报仍需在最终集成配置中独立测试，本项不声称达到任何特定 QPS。



复核补充：fail-open 不能覆盖已经得到的 mask 决策。已知待脱敏字段遇到队列超限、最终检查失败或最终结果未兑现脱敏时，不得原文刷新；记录失败并终止。流式发现证据最多保留 1024 条及 1 MiB 去重键，超出记录 output_findings_truncated / output_findings_dropped，安全 block / mask 判断仍完整执行。

构建验证：本 worktree 中 Go 默认 VCS 探测误入 /home/dev，标准 go build 报 git status exit 128；使用 -buildvcs=false 构建验证通过，没有修改全局 Git 设置。


原生补充验收：两个生产 HTTP 入口均验证跨分片密钥前缀、严格模式阻断、取消不刷新、正常末尾 UTF-8 内容及身份/序号。专门验证 terminal-only metadata 敏感值，以及 delta.logprobs / delta 扩展字段 / start 扩展字段；实际保留到客户端的非 delta Raw 字符串、属性和数字均检查，固定元数据采用每请求最多 256 项缓存。原生不同 item/content/block 的掩码无法可靠定位时阻断，避免把一个 item 的替换文本写到另一个 item。已知 mask 不因 fail-open 超预算或最终检测故障而失效的两条回归均通过。

最终集成复核还覆盖了 Responses 终结事件包络：扫描完整保留事件的属性名、字符串和数值，仅排除编码器重建的 sequence_number；不能仅检查 response 子对象。两种模式共 6 个真实 HTTP 子例先复现泄漏再修复。
