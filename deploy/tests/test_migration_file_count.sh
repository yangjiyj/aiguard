#!/usr/bin/env bash
# 迁移文件统计按 deploy/lib/migration-version.sh 的规则（三位以上数字编号，去掉 002_seed_data.sql 和
# *_verify.sql），与 migration-runner 实际执行的文件一一对应。打包自检、交付验收闸、中性基线迁移器都用它，
# 出现 1010_ 这类四位编号时数量和账本才对得上。
set -Eeuo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
LIB="$ROOT/deploy/lib/migration-version.sh"
source "$LIB"

fixture="$(mktemp -d)"
trap 'rm -rf "$fixture"' EXIT
mig="$fixture/migrations"
mkdir -p "$mig/1011_directory_not_file.sql" "$fixture/bin"
for name in 001_init_schema.sql 002_seed_data.sql 099_check_verify.sql 998_scrub.sql 999_protection_settings.sql \
  1010_alert_evidence_identity_raw.sql 12_too_short.sql notes_1.sql readme.md 'abc_1010.sql'; do
  printf 'SELECT 1;\n' >"$mig/$name"
done

count="$(migration_versioned_count "$mig")"
[[ "$count" == 4 ]] || { echo "[migration-count] want 4 got $count" >&2; exit 1; }

names=()
while IFS= read -r -d '' file; do names+=("${file##*/}"); done < <(migration_versioned_files "$mig")
listed="$(printf '%s\n' "${names[@]}" | sort | tr '\n' ' ')"
[[ "$listed" == "001_init_schema.sql 1010_alert_evidence_identity_raw.sql 998_scrub.sql 999_protection_settings.sql " ]] ||
  { echo "[migration-count] unexpected files: $listed" >&2; exit 1; }

# 与 migration-runner 的发现规则一致：dry-run 列出的迁移就是统计到的这些。
cat >"$fixture/bin/psql" <<'SH'
#!/usr/bin/env bash
set -Eeuo pipefail
if [[ "$*" == *MIGRATION_RUNNER_LOCK_HOLDER=1* ]]; then
  while IFS= read -r line; do
    [[ "$line" == *pg_try_advisory_lock* ]] && printf '%s\n' __MIGRATION_RUNNER_LOCK_ACQUIRED__
    [[ "$line" == '\q' ]] && exit 0
  done
fi
exit 0
SH
chmod +x "$fixture/bin/psql"
dry="$(MIGRATION_PSQL="$fixture/bin/psql" bash "$ROOT/deploy/lib/migration-runner.sh" --dry-run --migrations-dir "$mig" | grep -c '^\[dry-run\] ' || true)"
[[ "$dry" == "$count" ]] || { echo "[migration-count] runner would apply $dry, counted $count" >&2; exit 1; }

# 三个统计点都改用同一规则，不再写死三位数字。打包脚本和验收闸是 POSIX sh，经 bash 调用库函数。
for script in deploy/docker-compose/package-offline-bundle.sh deploy/lib/acceptance-gate.sh deploy/migrations/prepare-jjdguard-neutral-baseline.sh; do
  if grep -Fq "'[0-9][0-9][0-9]_*.sql'" "$ROOT/$script"; then
    echo "[migration-count] $script still counts only three-digit migrations" >&2
    exit 1
  fi
  grep -Eq 'migration_versioned_(count|files)' "$ROOT/$script" ||
    { echo "[migration-count] $script does not use migration-version.sh rules" >&2; exit 1; }
done
via_sh="$(sh -c 'bash -c ". \"\$1\" && migration_versioned_count \"\$2\"" migration-count "$1" "$2"' sh "$LIB" "$mig")"
[[ "$via_sh" == "$count" ]] || { echo "[migration-count] sh caller got $via_sh" >&2; exit 1; }

printf 'migration_file_count=ok four_digit_counted=%s\n' "$count"
