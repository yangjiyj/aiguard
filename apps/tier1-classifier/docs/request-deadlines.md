# Tier-1 排队、时限和可用性

本节描述组件合同，不代表吞吐、容量或模型正确率验收。

- 分类器默认单推理 worker。security-engine 的 SECURITY_TIER1_MAX_INFLIGHT 默认 1，限制本进程对固定 sidecar 的同时调用数；它与执行线程池/排队容量是不同的限制。更大的值只用于已核实具有相应并行能力的 sidecar。
- 调用侧排队计入调用者传入的剩余总预算。获准发送后，网络调用仍受配置的 tier1_timeout 和剩余总预算共同限制，不延长上层 deadline。
- 客户端发送 X-JJDGuard-Inference-Budget-Ms，为返回结果保留少量传输余量。sidecar 取该值与 TIER1_INFERENCE_TIMEOUT_SECONDS 的较小者；请求不能扩大服务端上限。缺省兼容旧调用者；非正整数或重复 header 被拒绝。
- 实际开始推理前再次检查预算。排队耗尽返回 inference_queue_timeout；已开始后超时返回 inference_timeout；超出容量返回 inference_capacity_overflow。都明确 coverage_complete=false。
- 已经进入 ONNX 的调用不能保证立即中断；运行任务继续持有容量槽，直到真正结束，不能因 HTTP 超时释放出虚假容量。

## 健康熔断与负载反馈

已知的容量/工作预算耗尽不等于后端损坏，不累计健康熔断失败。网络故障、普通 HTTP 错误、模型未就绪、无效响应等仍受熔断保护。调用者主动缩短预算导致的到期也不作为后端健康失败。

没有自动重试、阈值调整或失败转良性。classify 继续返回预测 tuple 或 None；内部 classify_detailed 另外返回不含原文的 Tier1Failure。语义引擎保留其具体原因，并继续标记检测未完成。

## 只读诊断

/health 与 /stats 保留兼容行为。/stats 仍仅统计成功打分的延迟，不应据此计算全部请求的完成率。

新增 /diagnostics 使用既有内部 token 鉴权，包含经过鉴权和请求体 schema 校验的 classify 调用计数、完成/失败分类、当前池状态及服务端时限，不包含请求文本、模型输入或凭据。它不统计被中间件或 schema 校验提前拒绝的所有 HTTP 请求。

/classify 的 timing 区分 queue_ms、inference_ms、total_ms，并说明 inference_started。时间均为经过时间，不是 CPU 时间；超时响应中的 inference_ms 只描述响应时已经观察到的时长。
