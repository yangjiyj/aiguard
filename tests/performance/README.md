# 客户 POC 性能压测脚本

这组脚本用于 POC 阶段证明智能体安全网关在开启审计/AgentGuard 后仍能稳定转发公网大模型请求。脚本只依赖 Python 标准库，方便在客户临时虚拟机上直接运行。

## 文件

- `gateway_load.py`：并发压测 OpenAI 兼容 `/v1/chat/completions` 接口，输出 RPS、错误率、P50/P95/P99。
- `mock_llm_provider.py`：本地模拟公网大模型供应商，支持普通响应和工具调用红队响应。

## 快速自检

```bash
cd /home/dev/jjdguard-src
python3 tests/performance/gateway_load.py --scenario tool-redteam --print-sample
```

连接真实网关：

```bash
python3 tests/performance/gateway_load.py \
  --url http://127.0.0.1:8080/v1/chat/completions \
  --api-key "$POC_API_KEY" \
  --requests 200 \
  --concurrency 20 \
  --scenario mixed \
  --max-error-rate 0.01 \
  --max-p95-ms 3000
```

## POC 建议压测阶梯

| 阶段 | 请求数 | 并发 | 场景 | 目标 |
|---|---:|---:|---|---|
| 冒烟 | 100 | 10 | normal | 接口稳定、审计入库 |
| 安全混合 | 500 | 30 | mixed | 正常流量不误拦，高风险工具调用可审计/阻断 |
| POC 峰值 | 3000 | 80 | mixed | P95 < 3s，错误率 < 1%，资源无持续打满 |
| 扩容评估 | 10000+ | 按现场资源 | mixed | 用于估算 12000 人规模所需节点数 |

## 容量换算

不要把“12000 名员工”直接等同于 12000 并发。现场容量按以下公式估算：

```text
业务 QPS = 峰值活跃用户数 × 单活跃用户每分钟请求数 / 60
建议网关容量 = 业务 QPS × 1.3 以上余量
```

POC 阶段建议先测出单 gateway 节点在开启 AgentGuard 后的稳定 QPS，再按客户峰值活跃比例和余量横向扩容。
