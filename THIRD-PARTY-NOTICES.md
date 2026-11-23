# 第三方组件与模型声明（THIRD-PARTY NOTICES）

本文件列出 JJDGuard 离线安装包中随附的第三方模型与第三方运行组件，以及各自的来源和许可，供客户做软件成分审计。自研代码以 AGPL-3.0 开源，见仓库根目录 LICENSE。

最后核对：2026-09-30。

## 随附模型

| 组件 | 用途 | 来源 | 许可 | 说明 |
|---|---|---|---|---|
| JJDGuard bundled judge 4B v1（Q4_K_M 量化，`jjdguard-bundled-judge-4b-v1-Q4_K_M.gguf`） | 语义复核 judge（CPU） | 基座 Qwen/Qwen3-4B-Instruct-2507（revision `cdbee75f17c01a7cc42f958dc650907174af0554`）；JJDGuard 用自有判定数据做 LoRA 微调后合并进基座，再用 llama.cpp 量化 | Apache-2.0（基座许可；微调部分为 JJDGuard 自有） | 修改说明：权重经 JJDGuard 微调，已不同于上游发布；基座版本、适配器与成品哈希记录在 `deploy/docker-compose/owned-judge-model.lock.json` |
| Tier-1 攻击初筛分类器（`models/prompt-guard-2/model.onnx`，目录名为历史沿用） | 输入攻击概率初筛 | JJDGuard 自训：冻结的 intfloat/multilingual-e5-small 编码器 + 自训 LR 分类头，融合为单个 ONNX | 编码器 MIT；分类头为 JJDGuard 自有 | 不包含 Meta Prompt-Guard 权重，与 Llama 许可无关；哈希记录在 `owned-tier1-model.lock.json` |

GPU 附加包（`gpu-judge-7b-lora-addon`）是单独交付的：模型为 JJDGuard 自训的 judge-v4（基座 Qwen2.5-7B-Instruct，Apache-2.0；微调后合并为完整模型，Q4_K_M 量化，`judge-v4-Q4_K_M.gguf`），不含任何 LoRA 适配器；文件哈希记录在 `deploy/docker-compose/owned-judge-7b-lora.lock.json`（文件名为历史沿用）。附加包名中的 `lora` 同为历史沿用。它不包含在标准离线包中。

## 随附第三方运行组件（容器镜像）

| 组件 | 版本 | 许可 | 说明 |
|---|---|---|---|
| PostgreSQL（`postgres:16-alpine`） | 16 | PostgreSQL License | |
| Valkey（`valkey/valkey:8.1.10-alpine`） | 8.1.10 | BSD-3-Clause | Replaces Redis 7.4 (RSALv2/SSPLv1); compose service name stays `redis` |
| Keycloak（`keycloak/keycloak:26.3`） | 26.3 | Apache-2.0 | 企业 AI 门户的身份服务 |
| Caddy（`caddy:2-alpine`） | 2 | Apache-2.0 | 企业 AI 门户的入口 |
| llama.cpp（judge 推理引擎，编译进 llm-judge 镜像） | b10326（commit 3653e6d6d547） | MIT | |
| ONNX Runtime（Tier-1 推理，CPU） | 以镜像内依赖清单为准 | MIT | |
| github.com/emmansun/gmsm | v0.43.0 | MIT | SM4 / SM3 国密算法（纯 Go），编译进 control-plane、gateway-core、proxy-server、worker；来源 https://github.com/emmansun/gmsm |
| Tongsuo（铜锁） | 8.4.0 | Apache-2.0 | TLCP/NTLS 协议栈，静态链接进可选的 guomi-tls 镜像；来源 https://github.com/Tongsuo-Project/Tongsuo；许可全文随镜像 `/opt/guomi-tls/licenses/Tongsuo-LICENSE.txt` |
| Tengine | 3.1.0 | BSD-2-Clause | 可选 guomi-tls 国密 HTTPS 入口（含 ngx_tongsuo_ntls 模块）；来源 https://github.com/alibaba/tengine；许可全文随镜像 `/opt/guomi-tls/licenses/Tengine-LICENSE` |

完整的依赖清单（SBOM，SPDX 2.3）随安装包提供，位于 `sbom/bundle.spdx.json`。

## 已知事项

- **Valkey (Redis replacement)**: The bundled cache is Valkey 8.1.10 under BSD-3-Clause; Redis 7.4 (RSALv2/SSPLv1) is no longer shipped. Valkey stores data in the new `valkey-data` volume. Redis 7.4 writes RDB version 12, which Valkey 7.2/8 cannot read (verified 2026-09-27); the upgrade copies the must-keep keys at command level, and the old `redis-data` volume is left untouched as a rollback anchor and is not mounted.

## License texts: Tier-1 encoder (intfloat/multilingual-e5-small)

Upstream: `intfloat/multilingual-e5-small`, revision `614241f622f53c4eeff9890bdc4f31cfecc418b3`. The model card of that revision declares `license: mit`; the upstream snapshot ships no LICENSE file, so the text below is the SPDX `MIT` license text, copied verbatim (sha256 `b85dcd3e453d05982552c52b5fc9e0bdd6d23c6f8e844b984a88af32570b0cc0`). Copyright holder as published upstream: intfloat (the model authors); the upstream publishes no year.

```text
MIT License

Copyright (c) <year> <copyright holders>

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
```
