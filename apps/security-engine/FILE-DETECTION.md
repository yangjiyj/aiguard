# 文件 DLP 与 OCR 部署和验收

本次修复保留现有 `file_content_dlp_enabled` 全局托管配置和审计/阻断策略；不自动修改运行环境或客户策略。单机线程参数是每实例预算，与网关 QPS 上限无关。

## 已实现

- 正文截断、页数/图像数/压缩层数超预算、跳过成员、空正文和解析失败都显式报告；可读前缀仍送现有检测器。
- ZIP/TAR/GZIP 按真实格式处理内部文本、DOCX/PPTX/XLSX、PDF、图像及受限递归压缩包；共用成员和展开字节预算。
- PDF 使用 pypdf 字体映射提取中文；PDF 内图像、PNG/JPEG/GIF/BMP/WEBP/TIFF 使用本地 Tesseract 中文+英文识别。多帧/像素/字节/并发均有预算。
- 解析在独立子进程内执行；排队与执行共用截止时间，限制地址空间，超时终止整个子进程组。普通文本不进入文件/OCR容量池。
- `/health` 保持进程存活语义；受内部令牌保护的 `/ready` 返回能力是否启用、是否可用和缺失项。缺失依赖时启用的 DLP readiness 为 503。
- 旧 API OCR 钩子仍可在 DLP 关闭时工作；启用时由 engine 的附件桥接统一检查，避免重复 OCR 和丢失未完成状态。

## 离线依赖闭环

`requirements.offline.lock` 固定 pypdf 6.17.0、Pillow 12.1.1、tesserocr 2.11.0 和兼容 Python 3.11 的 cysignals 1.12.5。官方 tesserocr manylinux wheel 携带本地运行库；中文/英文语言文件和许可证在 `ocr-resources.lock.json` 按上游 Git revision、文件 SHA256、字节数固定。

构建依赖种子镜像可使用 `Dockerfile.file-deps`（只在准备公开依赖时联网），或在批准的依赖来源镜像中安装同样的锁定 wheel 并用 `deploy/docker-compose/prepare-security-ocr-resources.py --download --output /usr/local/lib/python3.11/site-packages/jjdguard_ocr_data` 放入语言资源。最终服务镜像不执行网络安装，继续通过既有 `prepare-security-engine-python-deps-input.sh` 导出并验证来源镜像的 `site-packages`。来源请用已审阅镜像 SHA256，正式离线包仍必须从 main 通过项目既有打包入口与门禁产生。

缺失、替换或截断语言资源会被依赖快照校验拒绝；最终 Dockerfile 会在构建时验证实际 Python/native 依赖可加载与语言哈希。旧的无 OCR 来源镜像无法通过新锁定要求，需要重新准备依赖来源，不能仅更新 requirements 文件就宣称交付完成。

## 就绪后启用

1. 在候选镜像或隔离验收实例执行 `SECURITY_FILE_CONTENT_DLP_ENABLED=true python -m app.file_readiness --require-enabled`。要求 `ready=true`、`missing=[]`、中文/英文 OCR 均可用。
2. 执行 `SECURITY_FILE_CONTENT_DLP_ENABLED=true python -m app.file_selftest`。镜像自带三份合成文件，分别验证中文 PDF、中文图像、扫描 PDF 的敏感手机号检测，输入/输出各审计和阻断两种模式共 12 例，并要求没有正文检测覆盖缺口。命令仅影响子进程，不修改正在运行的服务策略。
3. 通过控制台“安全策略”的文件策略设置启用文件内容 DLP（对应 `/system/settings` 的 `file_content_dlp_enabled=true`），等待节点配置投影确认。托管设置为真源，已存在的数据库设置可能覆盖环境变量，不能仅改 `.env`。
4. 使用内部令牌读取运行服务 `/ready`，确认 enabled/available 均为 true；再用合成测试文件经过实际网关检查命中和审计记录。保持客户原有审计/阻断模式，策略变更单独按交付要求执行。

离线包 `acceptance-gate.sh` 已内置第 2 步，失败即包验收失败。开发回归：安装锁定运行依赖、pytest、pytest-asyncio、numpy；执行 `python -m pytest`。固定三份二进制测试样本已经入库，正常测试无需字体或 reportlab；只有重建样本才需要 reportlab 4.4.10 与 Noto CJK 字体。

## 参数与边界

- `SECURITY_FILE_MAX_CONCURRENT_PARSE` 默认 4；`SECURITY_OCR_MAX_CONCURRENT_PARSE` 默认 2。PDF/压缩包也可能进入 OCR，保守计入 OCR 任务预算。
- `SECURITY_FILE_PARSE_MEMORY_MB` 默认每解析进程 768 MB；`SECURITY_OCR_TIMEOUT_SEC` 默认 15 秒。并发与容器内存预算应一起配置。
- PDF 默认最多 100 页、100 个图像；OCR 默认单图 8 MiB、2500 万像素、10 帧；压缩包默认最多 3 层。超限会报告未完成，不静默通过。
- Office 内嵌图片/OLE、旧 DOC/XLS/PPT、RAR/7z 等仍以明确未完成状态交由策略处置；没有把它们宣传为完整检测。
- OCR 完成表示运行了识别，不保证任意拍照、手写、低分辨率或遮挡文本的识别率。使用独立业务样本评估漏检与误报。

## 官方依据

- pypdf 文本提取及图像扫描边界：https://pypdf.readthedocs.io/en/stable/user/extract-text.html
- tesserocr API、语言资源和版本：https://github.com/sirfz/tesserocr
- Tesseract fast 中文/英文模型：https://github.com/tesseract-ocr/tessdata_fast
