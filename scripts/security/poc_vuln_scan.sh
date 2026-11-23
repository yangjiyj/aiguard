#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
REPORT_ROOT="${REPORT_ROOT:-$ROOT_DIR/reports/security}"
RUN_ID="${RUN_ID:-poc-$(date -u +%Y%m%dT%H%M%SZ)}"
OUT_DIR="$REPORT_ROOT/$RUN_ID"
STRICT="${POC_SCAN_STRICT:-0}"
SUMMARY="$OUT_DIR/summary.md"

mkdir -p "$OUT_DIR"
pass_count=0
warn_count=0
fail_count=0

record() {
  local status="$1" name="$2" detail="$3"
  case "$status" in
    PASS) pass_count=$((pass_count + 1)) ;;
    WARN) warn_count=$((warn_count + 1)) ;;
    FAIL) fail_count=$((fail_count + 1)) ;;
  esac
  printf -- '- **%s** `%s`: %s\n' "$status" "$name" "$detail" >> "$SUMMARY"
}

mask_secret_lines() {
  sed -E \
    -e 's/(sk-[A-Za-z0-9_-]{6})[A-Za-z0-9_-]{8,}/\1***MASKED***/g' \
    -e 's/(AKIA[0-9A-Z]{4})[0-9A-Z]{12}/\1***MASKED***/g' \
    -e 's/(gh[pousr]_[A-Za-z0-9_]{6})[A-Za-z0-9_]{20,}/\1***MASKED***/g' \
    -e 's/(eyJ[A-Za-z0-9_-]{6})[A-Za-z0-9_.-]{20,}/\1***MASKED***/g'
}

run_cmd() {
  local name="$1" outfile="$2"
  shift 2
  echo "==> $name"
  if "$@" > "$outfile" 2>&1; then
    record PASS "$name" "完成，报告 $outfile"
  else
    record FAIL "$name" "失败或发现风险，报告 $outfile"
  fi
}

go_module_dirs() {
  find "$ROOT_DIR" \
    -path "$ROOT_DIR/reports" -prune -o \
    -path "$ROOT_DIR/apps/web-console/node_modules" -prune -o \
    -name go.mod -print | sort | while read -r modfile; do
      local module_dir
      module_dir="$(dirname "$modfile")"
      if find "$module_dir" -name '*.go' -not -path '*/vendor/*' -print -quit | grep -q .; then
        printf '%s\n' "$module_dir"
      fi
    done
}

write_header() {
  cat > "$SUMMARY" <<EOF
# POC 漏洞扫描摘要

- 运行时间：$(date -u +%Y-%m-%dT%H:%M:%SZ)
- 仓库：$ROOT_DIR
- 报告目录：$OUT_DIR
- 严格模式：$STRICT

## 检查项

EOF
}

scan_git_state() {
  local outfile="$OUT_DIR/git-status.txt"
  git -C "$ROOT_DIR" status --short > "$outfile"
  if [[ -s "$outfile" ]]; then
    record WARN git-status "工作区存在未提交变更，报告 $outfile"
  else
    record PASS git-status "工作区干净"
  fi
}

scan_secrets() {
  local outfile="$OUT_DIR/secrets.txt"
  if command -v gitleaks >/dev/null 2>&1; then
    if gitleaks detect --source "$ROOT_DIR" --no-git --redact --no-banner --report-format json --report-path "$OUT_DIR/gitleaks.json" > "$outfile" 2>&1; then
      record PASS gitleaks "未发现硬编码密钥，报告 $OUT_DIR/gitleaks.json"
    else
      record FAIL gitleaks "发现疑似密钥或扫描失败，报告 $OUT_DIR/gitleaks.json / $outfile"
    fi
    return
  fi

  local raw="$OUT_DIR/fallback-secret-grep.raw"
  local pattern='(sk-[A-Za-z0-9_-]{20,}|AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9_]{30,}|eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}|-----BEGIN (RSA |OPENSSH |EC |DSA )?PRIVATE KEY-----)'
  if git -C "$ROOT_DIR" grep -n -I -E "$pattern" -- . \
      ':!reports' ':!docs' ':!tests' ':!*_test.go' ':!**/testdata/**' \
      ':!apps/security-engine/tests' ':!apps/control-plane/internal/repository/rules.go' \
      ':!scripts/security/poc_vuln_scan.sh' > "$raw" 2>/dev/null; then
    mask_secret_lines < "$raw" > "$outfile"
    record FAIL fallback-secret-scan "gitleaks 未安装，脱敏 grep 发现疑似密钥，报告 $outfile"
  else
    : > "$outfile"
    record PASS fallback-secret-scan "gitleaks 未安装，使用脱敏 grep 兜底，未发现高置信密钥"
  fi
}

scan_go_vulns() {
  if command -v govulncheck >/dev/null 2>&1; then
    local outfile="$OUT_DIR/govulncheck.txt"
    echo "==> govulncheck"
    : > "$outfile"
    local failed=0
    local affected=0
    while read -r module_dir; do
      [[ -z "$module_dir" ]] && continue
      {
        printf '\n## %s\n' "${module_dir#$ROOT_DIR/}"
        (cd "$module_dir" && GOWORK=off govulncheck ./...)
      } >> "$outfile" 2>&1 || failed=1
    done < <(go_module_dirs)
    if grep -Eq 'Your code is affected by [1-9]|Vulnerability #[0-9]+' "$outfile"; then
      affected=1
    fi
    if [[ "$failed" == "1" ]]; then
      record FAIL govulncheck "扫描失败，报告 $outfile"
    elif [[ "$affected" == "1" ]]; then
      record FAIL govulncheck "发现代码可达漏洞，报告 $outfile"
    else
      record PASS govulncheck "未发现代码可达漏洞，报告 $outfile"
    fi
  else
    record WARN govulncheck "未安装，跳过 Go 漏洞库扫描"
  fi
}

scan_gosec() {
  if command -v gosec >/dev/null 2>&1; then
    local outfile="$OUT_DIR/gosec.txt"
    local jsonfile="$OUT_DIR/gosec.jsonl"
    echo "==> gosec"
    : > "$outfile"
    : > "$jsonfile"
    local failed=0
    while read -r module_dir; do
      [[ -z "$module_dir" ]] && continue
      local module_name="${module_dir#$ROOT_DIR/}"
      local module_json="$OUT_DIR/gosec-${module_name//\//_}.json"
      local status=0
      {
        printf '\n## %s\n' "$module_name"
        (cd "$module_dir" && GOWORK=off gosec -fmt=json -out="$module_json" ./...) || status=$?
        cat "$module_json" >> "$jsonfile" 2>/dev/null || true
      } >> "$outfile" 2>&1
      if [[ "$status" != "0" ]]; then
        failed=1
      fi
    done < <(go_module_dirs)
    local counts
    counts="$(python3 - "$OUT_DIR" <<'PY'
import json
import pathlib
import sys

total = 0
high_high = 0
for path in pathlib.Path(sys.argv[1]).glob("gosec-*.json"):
    try:
        data = json.loads(path.read_text() or "{}")
    except Exception:
        continue
    for issue in data.get("Issues", []):
        total += 1
        if issue.get("severity") == "HIGH" and issue.get("confidence") == "HIGH":
            high_high += 1
print(total, high_high)
PY
)"
    local issue_count="${counts%% *}"
    local high_high_count="${counts##* }"
    if [[ "$failed" == "1" && "$issue_count" == "0" ]]; then
      record FAIL gosec "扫描失败，报告 $outfile"
    elif [[ "$high_high_count" != "0" ]]; then
      record FAIL gosec "发现 $high_high_count 个高置信高危 SAST 阻断项，报告 $outfile / $jsonfile"
    elif [[ "$issue_count" != "0" ]]; then
      record WARN gosec "发现 $issue_count 个待确认 SAST 项，无高置信高危阻断项；报告 $outfile / $jsonfile"
    else
      record PASS gosec "未发现 SAST 风险项，报告 $outfile / $jsonfile"
    fi
  else
    record WARN gosec "未安装，跳过 Go SAST 扫描"
  fi
}

scan_semgrep() {
  if command -v semgrep >/dev/null 2>&1; then
    run_cmd semgrep "$OUT_DIR/semgrep.txt" bash -lc "cd '$ROOT_DIR' && semgrep --config auto --error --exclude reports ."
  else
    record WARN semgrep "未安装，跳过通用 SAST 扫描"
  fi
}

scan_npm_audit() {
  if [[ ! -f "$ROOT_DIR/apps/web-console/package-lock.json" ]]; then
    record WARN npm-audit "apps/web-console/package-lock.json 不存在，跳过"
    return
  fi
  if ! command -v npm >/dev/null 2>&1; then
    record WARN npm-audit "npm 未安装，跳过前端依赖审计"
    return
  fi
  echo "==> npm-audit-web-console"
  if (cd "$ROOT_DIR/apps/web-console" && npm audit --json --audit-level=high --registry=https://registry.npmjs.org) > "$OUT_DIR/npm-audit-web-console.json" 2>&1; then
    record PASS npm-audit-web-console "未发现高危及以上 npm audit 阻断项，报告 $OUT_DIR/npm-audit-web-console.json"
  else
    if grep -Eq 'NOT_IMPLEMENTED|audit endpoint returned an error|404 Not Found' "$OUT_DIR/npm-audit-web-console.json"; then
      record WARN npm-audit-web-console "当前 npm registry 不支持 audit 接口，请切到 https://registry.npmjs.org 后复跑；报告 $OUT_DIR/npm-audit-web-console.json"
    else
      record FAIL npm-audit-web-console "发现 npm audit 风险或命令失败，报告 $OUT_DIR/npm-audit-web-console.json"
    fi
  fi
}

scan_python_audit() {
  if command -v pip-audit >/dev/null 2>&1; then
    run_cmd pip-audit-security-engine "$OUT_DIR/pip-audit-security-engine.txt" bash -lc "cd '$ROOT_DIR/apps/security-engine' && pip-audit -r requirements.txt"
  else
    record WARN pip-audit "未安装，跳过 Python 依赖漏洞扫描"
  fi
}

scan_trivy_fs() {
  if command -v trivy >/dev/null 2>&1; then
    run_cmd trivy-fs "$OUT_DIR/trivy-fs.txt" trivy fs --scanners vuln,secret,misconfig --skip-dirs "$ROOT_DIR/reports" "$ROOT_DIR"
  else
    record WARN trivy "未安装，跳过文件系统/依赖综合扫描"
  fi
}

write_footer() {
  cat >> "$SUMMARY" <<EOF

## 汇总

- PASS：$pass_count
- WARN：$warn_count
- FAIL：$fail_count

## POC 说明

- WARN 多为本机未安装扫描工具，不等于代码无风险；正式交付前建议安装 gitleaks、govulncheck、gosec、semgrep、trivy、pip-audit 后复跑。
- FAIL 需要逐项确认；如果是样例数据或测试夹具，应在报告中说明并保留脱敏证据。
- 设置 POC_SCAN_STRICT=1 时，任何 FAIL 或 WARN 都会导致脚本非零退出，适合交付前门禁。
EOF
}

main() {
  write_header
  scan_git_state
  scan_secrets
  scan_go_vulns
  scan_gosec
  scan_semgrep
  scan_npm_audit
  scan_python_audit
  scan_trivy_fs
  write_footer
  echo "summary: $SUMMARY"

  if [[ "$STRICT" == "1" ]]; then
    (( fail_count == 0 && warn_count == 0 ))
  else
    (( fail_count == 0 ))
  fi
}

main "$@"
