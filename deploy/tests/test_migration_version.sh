#!/usr/bin/env bash
set -Eeuo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
source "$ROOT/deploy/lib/migration-version.sh"

migration_name_valid 999_last_three_digit.sql
migration_name_valid 1000_first_four_digit.sql
! migration_name_valid 99_too_short.sql
migration_version_lt 999_last_three_digit.sql 1000_first_four_digit.sql
! migration_version_lt 1000_first_four_digit.sql 999_last_three_digit.sql

fixture="$(mktemp -d)"
trap 'rm -rf "$fixture"' EXIT
mkdir -p "$fixture/migrations" "$fixture/bin" "$fixture/db"
printf 'SELECT 999;\n' >"$fixture/migrations/999_last_three_digit.sql"
printf 'SELECT 1000;\n' >"$fixture/migrations/1000_first_four_digit.sql"

cat >"$fixture/bin/psql" <<'SH'
#!/usr/bin/env bash
set -Eeuo pipefail
if [[ "$*" == *MIGRATION_RUNNER_LOCK_HOLDER=1* ]]; then
  while IFS= read -r line; do
    [[ "$line" == *pg_try_advisory_lock* ]] && printf '%s\n' __MIGRATION_RUNNER_LOCK_ACQUIRED__
    [[ "$line" == '\q' ]] && exit 0
  done
fi
sql="$*"
[[ "$sql" == *to_regclass* ]] && exit 0
[[ "$sql" == *information_schema.columns* ]] && exit 0
exit 0
SH
chmod +x "$fixture/bin/psql"
output="$(MIGRATION_PSQL="$fixture/bin/psql" bash "$ROOT/deploy/lib/migration-runner.sh" --dry-run --migrations-dir "$fixture/migrations")"
line999="$(printf '%s\n' "$output" | rg -n '999_last' | cut -d: -f1)"
line1000="$(printf '%s\n' "$output" | rg -n '1000_first' | cut -d: -f1)"
[[ "$line999" -lt "$line1000" ]]
printf 'migration_version=ok 999_before_1000\n'
