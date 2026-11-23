#!/usr/bin/env bash

migration_name_valid() {
  [[ "${1:-}" =~ ^[0-9]{3,}_[A-Za-z0-9_.-]+\.sql$ ]]
}

migration_number() {
  local name="${1##*/}" prefix
  migration_name_valid "$name" || return 1
  prefix="${name%%_*}"
  printf '%s\n' "$((10#$prefix))"
}

migration_version_lt() {
  local left="${1##*/}" right="${2##*/}" left_number right_number
  left_number="$(migration_number "$left")" || return 2
  right_number="$(migration_number "$right")" || return 2
  if (( left_number != right_number )); then
    (( left_number < right_number ))
    return
  fi
  [[ "$left" < "$right" ]]
}

migration_latest_sql() {
  cat <<'SQL'
SELECT COALESCE((
  SELECT version
  FROM schema_migrations
  WHERE version ~ '^[0-9]{3,}_[A-Za-z0-9_.-]+[.]sql$'
  ORDER BY split_part(version, '_', 1)::bigint DESC, version DESC
  LIMIT 1
), '')
SQL
}

# migration_versioned_files 列出 DIR 下会被 migration-runner 执行的迁移文件：文件名符合 migration_name_valid
# （三位以上数字编号），去掉 runner 默认排除的 002_seed_data.sql 和 *_verify.sql。路径以 NUL 分隔、按 sort -z 排列。
# 打包自检、交付验收闸、中性基线迁移器统计或比对迁移文件都用它，不要再写死三位数字的通配。
migration_versioned_files() {
  local dir="$1" file name
  while IFS= read -r -d '' file; do
    name="${file##*/}"
    migration_name_valid "$name" || continue
    case "$name" in
      002_seed_data.sql|*_verify.sql) continue ;;
    esac
    printf '%s\0' "$file"
  done < <(find "$dir" -maxdepth 1 -type f -name '*_*.sql' -print0 | sort -z)
}

# migration_versioned_count 输出 migration_versioned_files 的文件数。
migration_versioned_count() {
  local count=0 file
  while IFS= read -r -d '' file; do
    count=$((count + 1))
  done < <(migration_versioned_files "$1")
  printf '%s\n' "$count"
}
