#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
[[ "$#" == 3 ]] || { echo 'usage: apply-customer-environment-scope-repair.sh CONTAINER PGUSER PGDATABASE' >&2; exit 2; }
container="$1"
pguser="$2"
pgdatabase="$3"
sql="$SCRIPT_DIR/customer-environment-scope-repair.sql"

[[ "$container" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$ ]] || { echo 'invalid postgres container identity' >&2; exit 2; }
[[ "$pguser" =~ ^[A-Za-z_][A-Za-z0-9_.-]{0,62}$ ]] || { echo 'invalid postgres user identity' >&2; exit 2; }
[[ "$pgdatabase" =~ ^[A-Za-z_][A-Za-z0-9_.-]{0,62}$ ]] || { echo 'invalid postgres database identity' >&2; exit 2; }
[[ -f "$sql" && ! -L "$sql" ]] || { echo 'customer scope repair SQL is missing or unsafe' >&2; exit 2; }

docker exec -i "$container" psql -U "$pguser" -d "$pgdatabase" -v ON_ERROR_STOP=1 <"$sql"
