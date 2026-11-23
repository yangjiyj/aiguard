# POC 漏洞扫描入口

`poc_vuln_scan.sh` 是客户 POC 交付前的统一安全自检脚本。它不会替代专业渗透测试，但能把代码侧常见风险先扫一遍，并生成可归档报告。

## 运行

```bash
cd /home/dev/jjdguard-src
bash scripts/security/poc_vuln_scan.sh
```

报告目录：`reports/security/poc-*/summary.md`

严格门禁模式：

```bash
POC_SCAN_STRICT=1 bash scripts/security/poc_vuln_scan.sh
```

## 推荐安装工具

- `gitleaks`：硬编码密钥扫描。
- `govulncheck`：Go 依赖和调用路径漏洞扫描。
- `gosec`：Go 静态安全扫描。
- `semgrep`：跨语言 SAST。
- `trivy`：文件系统、依赖、镜像和配置扫描。
- `pip-audit`：Python 依赖漏洞扫描。

如果工具没有安装，脚本会记录 `WARN` 并跳过对应项；`gitleaks` 缺失时会启用脱敏的高置信 grep 兜底扫描。

## 验收口径

- 正式演示前，至少保证 secrets 扫描无 `FAIL`。
- 正式交付前，建议严格模式无 `FAIL`，`WARN` 有书面解释。
- 所有报告必须脱敏归档，不能把密钥明文写入审计或交付材料。
