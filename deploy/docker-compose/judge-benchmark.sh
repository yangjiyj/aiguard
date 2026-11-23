#!/bin/sh
# 语义裁判性能自适应：部署后实测 3B judge 单次推理延迟，按档位调整执行超时，检测阈值保持不变。
#
# CPU 性能决定排队/执行预算，不决定攻击检测阈值。检测阈值必须由效果评估确定。
# 低阈值意味着更多请求进入裁判；高分也不能由分类器直接给出攻击结论。
# 本脚本实测后选档，只替换尚未改动的出厂默认值；升级重跑时保留客户明确选择。
#
# 调用：sh judge-benchmark.sh（在 deploy-offline.sh 末尾自动调用，也可独立运行）
# 依赖：llm-judge 容器已起且健康；postgres 容器可用（写 system_settings）。
set -eu

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"
COMPOSE_WRAPPER="$SCRIPT_DIR/compose-wrapper.sh"

# 最多等待 llm-judge 健康（秒）。冷启动含 GGUF 加载，给足时间。
WAIT_TIMEOUT=180

echo "[step] judge-benchmark: 等待 llm-judge 健康（最多 ${WAIT_TIMEOUT}s）"
elapsed=0
while [ "$elapsed" -lt "$WAIT_TIMEOUT" ]; do
  if sh "$COMPOSE_WRAPPER" exec -T llm-judge /bin/bash -c 'exec 3<>/dev/tcp/127.0.0.1/8080' >/dev/null 2>&1; then
    break
  fi
  sleep 5
  elapsed=$((elapsed + 5))
  printf "."
done
echo

if [ "$elapsed" -ge "$WAIT_TIMEOUT" ]; then
  echo "[warn] llm-judge ${WAIT_TIMEOUT}s 内未健康，跳过自适应（保持默认配置）"
  return 0 2>/dev/null || exit 0
fi
echo "[ok] llm-judge 已健康（等待 ${elapsed}s）"

# 连发 3 次真实语义裁判调用。直接复用 security-engine 的生产提示词、JSON schema、
# max_tokens 与出站校验，避免用过短的合成请求把慢 CPU 错分成 fast 档。
epoch_millis() {
  value="$(date +%s%3N 2>/dev/null || true)"
  case "$value" in
    ''|*[!0-9]*)
      seconds="$(date +%s 2>/dev/null || true)"
      case "$seconds" in
        ''|*[!0-9]*) printf '0\n' ;;
        *) printf '%s000\n' "$seconds" ;;
      esac
      ;;
    *) printf '%s\n' "$value" ;;
  esac
}

# 取中位数，避免首次冷启动（KV cache miss）拉高均值。
echo "[step] judge-benchmark: 实测裁判延迟（3 次，取中位数）"
latencies=""
for i in 1 2 3; do
  t0="$(epoch_millis)"
  if sh "$COMPOSE_WRAPPER" exec -T security-engine python -c '
from app.detectors.llm_judge import judge_semantic
opinion = judge_semantic(
    "JJDGuard semantic runtime health check. Treat this sentence as benign.",
    url="http://llm-judge:8080/v1/chat/completions", model="bundled-judge",
    api_key="bundled-judge", timeout=30.0, judge_backend="bundled",
    allow_private_egress=False)
raise SystemExit(0 if opinion is not None else 1)
' >/dev/null 2>&1; then
    t1="$(epoch_millis)"
    if [ "$t0" != "0" ] && [ "$t1" != "0" ]; then
      ms=$(( t1 - t0 ))
      latencies="$latencies $ms"
      printf "  第 %s 次: %sms\n" "$i" "$ms"
    else
      echo "[warn] 第 $i 次: 计时失败（date 不支持 %N），跳过该次"
    fi
  else
    echo "[warn] 第 $i 次裁判请求失败，跳过"
  fi
done

# 解析中位数（POSIX sh：排序后取中间值）
median=$(echo "$latencies" | tr " " "\n" | grep -E "^[0-9]+$" | sort -n | \
  awk '{a[NR]=$1} END { if (NR==0) {print ""} else if (NR%2==1) {print a[(NR+1)/2]} else {print int((a[NR/2]+a[NR/2+1])/2)}}')

if [ -z "$median" ]; then
  echo "[warn] 3 次裁判请求全部失败，跳过自适应（保持默认配置）"
  return 0 2>/dev/null || exit 0
fi

echo "[info] 裁判延迟中位数: ${median}ms"

# Performance profiles adjust time budgets only; preserve every customer detection threshold.
if [ "$median" -lt 3000 ]; then
  JUDGE_TIMEOUT=8; TOTAL_TIMEOUT=9; TIER="fast"
  ADVICE="已按实测设置执行预算，检测阈值保持不变"
elif [ "$median" -lt 8000 ]; then
  JUDGE_TIMEOUT=14; TOTAL_TIMEOUT=15; TIER="medium"
  ADVICE="延长执行预算，检测阈值保持不变；容量需单独压测"
else
  JUDGE_TIMEOUT=24; TOTAL_TIMEOUT=25; TIER="slow"
  ADVICE="裁判延迟较高，延长预算并建议增加推理资源；检测标准不降级"
fi

echo "[info] 自适应档位: $TIER（${ADVICE}）"

# 写入 system_settings：仅出厂值可被性能档位替换，客户后续手配不会被升级覆盖。
# 这些键经 control-plane 的 semantic-config 接口透传给 security-engine，热生效（无需重启）。
echo "[step] judge-benchmark: 写入自适应配置到 system_settings"
sh "$COMPOSE_WRAPPER" exec -T postgres psql -U "${POSTGRES_USER:-jjdguard}" -d "${POSTGRES_DB:-jjdguard}" <<SQL
-- Only timeout factory defaults may be adapted; never rewrite detection thresholds.
INSERT INTO system_settings (key, value, updated_at) VALUES
  ('judge_timeout', '${JUDGE_TIMEOUT}', NOW())
ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = NOW()
WHERE system_settings.value = '8';
INSERT INTO system_settings (key, value, updated_at) VALUES
  ('semantic_total_timeout', '${TOTAL_TIMEOUT}', NOW())
ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = NOW()
WHERE system_settings.value = '9';
SQL

echo "[ok] judge-benchmark 完成: 检测阈值保持不变, judge_timeout=${JUDGE_TIMEOUT}s, total_timeout=${TOTAL_TIMEOUT}s"
if [ "$TIER" = "slow" ]; then
  echo "[警告] 当前裁判延迟 ${median}ms；执行预算 ${TOTAL_TIMEOUT}s 不代表容量保证。"
  echo "  - 检测阈值与租户审计/阻断策略保持不变。"
  echo "  - 按实际工作量验证排队和检测完成率；必要时增加独立推理实例或算力。"
fi
