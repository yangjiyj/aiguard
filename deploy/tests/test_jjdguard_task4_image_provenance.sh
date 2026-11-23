#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BASE_IMAGE_PARSER="$ROOT_DIR/deploy/docker-compose/dockerfile-base-images.py"
readonly OWNED_TIER1_MODEL_LOCK_PATH='deploy/docker-compose/owned-tier1-model.lock.json'
PRISMA_ENGINE_LOCK_PATH='deploy/docker-compose/release-prisma-engines.lock.json'
readonly PRISMA_ENGINE_ARM64_LOCK_PATH='deploy/docker-compose/release-prisma-engines.arm64.lock.json'
PRISMA_ENGINE_PLATFORM=linux-musl-openssl-3.0.x
PRISMA_QUERY_ENGINE=libquery_engine-linux-musl-openssl-3.0.x.so.node
PRISMA_SCHEMA_ENGINE=schema-engine-linux-musl-openssl-3.0.x

die() {
  printf '[task4-provenance] %s\n' "$*" >&2
  exit 1
}

sha256_file() {
  sha256sum "$1" | awk '{print $1}'
}

canonical_receipt_sha() {
  jq -cS 'del(.revision)' "$1" | sha256sum | awk '{print $1}'
}

readonly -a OWNED_MODEL_REQUIRED_FILES=(
  model.onnx
  config.json
  tokenizer.json
  tokenizer_config.json
  special_tokens_map.json
)

archive_sha() {
  local repo=$1 revision=$2 out=$3
  git -C "$repo" archive --format=tar --prefix=source/ "$revision" >"$out"
  sha256_file "$out"
}

blob_oid() {
  git -C "$VERIFY_REPO" rev-parse "$VERIFY_TREE:$1"
}

assert_json() {
  local file=$1 filter=$2
  jq -e "$filter" "$file" >/dev/null || die "receipt assertion failed: $file :: $filter"
}

approved_model_manifest_from_tree() {
  local repo=$1 tree=$2 lock_json
  lock_json=$(git -C "$repo" show "$tree:$OWNED_TIER1_MODEL_LOCK_PATH") ||
    die 'approved owned Tier-1 model lock is absent from the candidate tree'
  jq -e '
      (keys | sort) == ["license","manifest","model_id","origin","schema","upstream"] and
      .schema == "jjdguard-owned-tier1-model-lock/v1" and
      .model_id == "jjdguard-tier1-e5small-lr" and
      .license == "MIT" and
      .upstream == {"repo":"intfloat/multilingual-e5-small","revision":"614241f622f53c4eeff9890bdc4f31cfecc418b3"} and
      .origin == "user-trained" and
      (.manifest | type == "array" and length == 5) and
      ([.manifest[].path] | sort) == [
        "config.json",
        "model.onnx",
        "special_tokens_map.json",
        "tokenizer.json",
        "tokenizer_config.json"
      ] and
      all(.manifest[];
        (keys | sort) == ["path","sha256","size"] and
        (.path | type == "string" and test("^[A-Za-z0-9._-]+$")) and
        (.size | type == "number" and . > 0 and . == floor) and
        (.sha256 | type == "string" and test("^[0-9a-f]{64}$")))
    ' <<<"$lock_json" >/dev/null ||
    die 'approved owned Tier-1 model lock is invalid'
  jq -cS '.manifest | sort_by(.path)' <<<"$lock_json"
}

approved_model_lock_sha256_from_tree() {
  local repo=$1 tree=$2
  git -C "$repo" show "$tree:$OWNED_TIER1_MODEL_LOCK_PATH" |
    sha256sum | awk '{print $1}'
}

assert_owned_model_receipt() {
  local receipt=$1 expected_locked_manifest=$2 expected_lock_sha=$3
  local count unique_count path expected_digest actual_digest actual_locked_manifest
  jq -e '
      (.owned_model | keys) == ["approved_lock_sha256","content_sha256","manifest","origin","schema"] and
      .owned_model.schema == "jjdguard-owned-tier1-model/v1" and
      .owned_model.origin == "user-trained-locked-input" and
      (.owned_model.approved_lock_sha256 | type == "string" and test("^[0-9a-f]{64}$")) and
      (.owned_model.content_sha256 | type == "string" and test("^[0-9a-f]{64}$")) and
      (.owned_model.manifest | type == "array" and length > 0) and
      all(.owned_model.manifest[];
        (.path | type == "string") and
        (.path | (test("[\u0000-\u001f\u007f]") | not)) and
        (.mode | type == "string") and
        (.mode | test("^[0-7]{3,4}$")) and
        (.size | (type == "number") and (. > 0) and (. == floor)) and
        (.sha256 | type == "string") and
        (.sha256 | test("^[0-9a-f]{64}$")))
    ' "$receipt" >/dev/null || die 'owned Tier-1 model receipt shape is invalid'
  expected_digest=$(jq -cS '.owned_model.manifest' "$receipt" | sha256sum | awk '{print $1}')
  actual_digest=$(jq -er '.owned_model.content_sha256' "$receipt")
  [[ "$actual_digest" == "$expected_digest" ]] || die 'owned Tier-1 model manifest digest mismatch'
  [[ "$(jq -er '.owned_model.approved_lock_sha256' "$receipt")" == "$expected_lock_sha" ]] ||
    die 'owned Tier-1 model approval lock digest mismatch'
  actual_locked_manifest=$(jq -cS '[.owned_model.manifest[] | {path,size,sha256}] | sort_by(.path)' "$receipt")
  [[ "$actual_locked_manifest" == "$expected_locked_manifest" ]] ||
    die 'owned Tier-1 model does not match the approved source lock'
  count=$(jq '.owned_model.manifest | length' "$receipt")
  unique_count=$(jq '[.owned_model.manifest[].path] | unique | length' "$receipt")
  [[ "$count" == "$unique_count" ]] || die 'owned Tier-1 model manifest has duplicate paths'
  while IFS= read -r path; do
    case "$path" in
      ''|/*|.|..|./*|../*|*//*|*/./*|*/../*|*/.|*/..) die "unsafe owned Tier-1 model manifest path: $path" ;;
    esac
  done < <(jq -r '.owned_model.manifest[].path' "$receipt")
  for path in "${OWNED_MODEL_REQUIRED_FILES[@]}"; do
    jq -e --arg path "$path" \
      'any(.owned_model.manifest[]; .path == $path)' "$receipt" >/dev/null ||
      die "required owned Tier-1 model manifest path missing: $path"
  done
}

assert_tier1_python_dependencies_receipt() {
  local receipt=$1 expected_lock_sha actual_packages
  jq -e '
      (.python_dependencies | type == "object") and
      (.python_dependencies | keys | sort) == [
        "content_sha256","file_count","origin","packages",
        "requirements_lock_sha256","schema","source_image","source_image_id"
      ] and
      .python_dependencies.schema == "jjdguard-tier1-python-deps/v1" and
      (.python_dependencies.origin == "home-existing-tier1-image" or
       (.python_dependencies.origin == "home-arm64-python-dependency-image" and
        .python_dependencies.source_image == "jjdguard-tier1-python-deps:arm64")) and
      (.python_dependencies.source_image | type == "string" and length > 0) and
      (.python_dependencies.source_image_id | type == "string" and
        test("^sha256:[0-9a-f]{64}$")) and
      (.python_dependencies.requirements_lock_sha256 | type == "string" and
        test("^[0-9a-f]{64}$")) and
      (.python_dependencies.content_sha256 | type == "string" and
        test("^[0-9a-f]{64}$")) and
      (.python_dependencies.file_count | type == "number" and . > 0 and . == floor) and
      (.python_dependencies.packages | type == "array" and length > 0) and
      all(.python_dependencies.packages[];
        (keys | sort) == ["name","version"] and
        (.name | type == "string" and length > 0) and
        (.version | type == "string" and length > 0))
    ' "$receipt" >/dev/null || die 'Tier1 local Python dependency receipt is invalid'
  expected_lock_sha=$(git -C "$VERIFY_REPO" cat-file blob \
    "$VERIFY_TREE:apps/tier1-classifier/requirements.lock" | sha256sum | awk '{print $1}')
  [[ "$(jq -er '.python_dependencies.requirements_lock_sha256' "$receipt")" == "$expected_lock_sha" ]] ||
    die 'Tier1 Python dependency requirements lock digest mismatch'
  actual_packages=$(jq -cS '.python_dependencies.packages | map(.name) | unique | length' "$receipt")
  [[ "$actual_packages" == "$(jq '.python_dependencies.packages | length' "$receipt")" ]] ||
    die 'Tier1 Python dependency receipt has duplicate package names'
}

assert_source_blobs() {
  local receipt=$1
  shift
  local path oid actual expected
  expected=$(printf '%s\n' "$@" | LC_ALL=C sort | jq -R . | jq -s .)
  actual=$(jq -cS '.source_blobs | keys | sort' "$receipt")
  [[ "$actual" == "$(jq -cS . <<<"$expected")" ]] ||
    die "source blob path set mismatch: $receipt"
  for path in "$@"; do
    oid=$(blob_oid "$path")
    [[ "$(jq -er --arg path "$path" '.source_blobs[$path]' "$receipt")" == "$oid" ]] ||
      die "source blob drift: $path"
  done
}

assert_portal_prisma_receipt() {
  local receipt=$1 lock_json expected_lock_sha expected_manifest expected_content_sha
  local actual_manifest actual_content_sha field
  lock_json=$(git -C "$VERIFY_REPO" show "$VERIFY_TREE:$PRISMA_ENGINE_LOCK_PATH") ||
    die 'Portal Prisma engine lock is absent from the candidate tree'
  jq -e --arg platform "$PRISMA_ENGINE_PLATFORM" --arg query "$PRISMA_QUERY_ENGINE" --arg schema_engine "$PRISMA_SCHEMA_ENGINE" '
      (keys | sort) == ["manifest","origin","platform","prisma_version","schema","source_image","source_image_id"] and
      .schema == "jjdguard-release-prisma-engines-lock/v1" and
      .prisma_version == "6.19.3" and
      .platform == $platform and
      (.manifest | type == "array" and length == 2) and
      ([.manifest[].path] | sort) == ([$query,$schema_engine] | sort) and
      all(.manifest[];
        (keys | sort) == ["path","sha256","size"] and
        (.path | type == "string") and
        (.size | type == "number" and . > 0 and . == floor) and
        (.sha256 | type == "string" and test("^[0-9a-f]{64}$")))
    ' <<<"$lock_json" >/dev/null || die 'Portal Prisma engine lock is invalid'
  jq -e '
      (.prisma_engines | type == "object") and
      (.prisma_engines | keys | sort) == [
        "approved_lock_sha256","content_sha256","manifest","origin","schema",
        "source_image","source_image_id"
      ] and
      .prisma_engines.schema == "jjdguard-release-prisma-engines/v1" and
      (.prisma_engines.approved_lock_sha256 | type == "string" and test("^[0-9a-f]{64}$")) and
      (.prisma_engines.content_sha256 | type == "string" and test("^[0-9a-f]{64}$")) and
      (.prisma_engines.manifest | type == "array" and length == 2)
    ' "$receipt" >/dev/null || die 'Portal Prisma engine receipt is invalid'
  expected_lock_sha=$(git -C "$VERIFY_REPO" cat-file blob \
    "$VERIFY_TREE:$PRISMA_ENGINE_LOCK_PATH" | sha256sum | awk '{print $1}')
  expected_manifest=$(jq -cS '.manifest | sort_by(.path)' <<<"$lock_json")
  expected_content_sha=$(printf '%s' "$expected_manifest" | sha256sum | awk '{print $1}')
  [[ "$(jq -er '.prisma_engines.approved_lock_sha256' "$receipt")" == "$expected_lock_sha" ]] ||
    die 'Portal Prisma engine approval lock digest mismatch'
  for field in origin source_image source_image_id; do
    [[ "$(jq -er ".prisma_engines.$field" "$receipt")" == "$(jq -er ".$field" <<<"$lock_json")" ]] ||
      die "Portal Prisma engine $field drift"
  done
  actual_manifest=$(jq -cS '.prisma_engines.manifest | sort_by(.path)' "$receipt")
  [[ "$actual_manifest" == "$expected_manifest" ]] ||
    die 'Portal Prisma engine manifest does not match the candidate lock'
  actual_content_sha=$(printf '%s' "$actual_manifest" | sha256sum | awk '{print $1}')
  [[ "$(jq -er '.prisma_engines.content_sha256' "$receipt")" == "$actual_content_sha" &&
     "$actual_content_sha" == "$expected_content_sha" ]] ||
    die 'Portal Prisma engine manifest digest mismatch'
}

base_images_from_tree() {
  local path=$1
  git -C "$VERIFY_REPO" show "$VERIFY_TREE:$path" |
    python3 "$BASE_IMAGE_PARSER" --dockerfile - ||
    die "unable to parse pinned base images: $path"
}

model_manifest_json() {
  local root=$1 tsv=$2 path mode size
  : >"$tsv"
  find "$root" -type f -printf '%P\t%m\t%s\n' | LC_ALL=C sort |
  while IFS=$'\t' read -r path mode size; do
    printf '%s\t%s\t%s\t%s\n' "$path" "$mode" "$size"       "$(sha256_file "$root/$path")"
  done >"$tsv"
  jq -cS -Rn '[inputs | split("\t") |
    {path:.[0],mode:.[1],size:(.[2]|tonumber),sha256:.[3]}]' <"$tsv"
}

verify_receipts() {
  local repo=$1 tree=$2 receipt_dir=$3 docker_cmd=$4 revision=${5:-}
  local expected_components=${6:-}
  local portal tier1 buildset tmp archive1 archive2 sha1 sha2 path expected archive_revision
  local portal_id tier1_id cid actual_models expected_models approved_models approved_model_lock_sha report_path
  local portal_selected=0 tier1_selected=0 expected_components_json actual
  local -a receipt_paths
  VERIFY_REPO=$repo
  VERIFY_TREE=$tree

  case "$expected_components" in
    portal)
      portal_selected=1
      expected_components_json='["portal"]'
      ;;
    tier1)
      tier1_selected=1
      expected_components_json='["tier1"]'
      ;;
    portal,tier1)
      portal_selected=1
      tier1_selected=1
      expected_components_json='["portal","tier1"]'
      ;;
    *) die 'expected components must be portal, tier1, or portal,tier1' ;;
  esac
  [[ "$tree" =~ ^[0-9a-f]{40}$ ]] || die 'invalid candidate tree'
  git -C "$repo" cat-file -e "$tree^{tree}"
  if [[ -n "$revision" ]]; then
    [[ "$revision" =~ ^[0-9a-f]{40}$ ]] || die 'invalid candidate revision'
    [[ "$(git -C "$repo" rev-parse "$revision^{commit}")" == "$revision" ]] ||
      die 'candidate revision is unavailable'
    [[ "$(git -C "$repo" rev-parse "$revision^{tree}")" == "$tree" ]] ||
      die 'candidate revision/tree mismatch'
  fi
  [[ "$(git -C "$repo" write-tree)" == "$tree" ]] ||
    die 'candidate tree differs from reviewed index'
  git -C "$repo" diff --quiet || die 'tracked dirty source is forbidden'
  [[ -z "$(git -C "$repo" ls-files --others --exclude-standard --     enterprise-ai-portal apps/tier1-classifier apps/security-engine/bench)" ]] ||
    die 'included untracked source is forbidden'

  portal="$receipt_dir/portal-image-receipt.json"
  tier1="$receipt_dir/tier1-image-receipt.json"
  buildset="$receipt_dir/build-set-receipt.json"
  receipt_paths=("$buildset")
  if [[ "$portal_selected" == 1 ]]; then
    receipt_paths+=("$portal")
  else
    [[ ! -e "$portal" && ! -L "$portal" ]] ||
      die 'unexpected Portal receipt for selected components'
  fi
  if [[ "$tier1_selected" == 1 ]]; then
    receipt_paths+=("$tier1")
  else
    [[ ! -e "$tier1" && ! -L "$tier1" &&
       ! -e "$receipt_dir/tier1-bench-gate-report.json" &&
       ! -L "$receipt_dir/tier1-bench-gate-report.json" ]] ||
      die 'unexpected Tier-1 receipt for selected components'
  fi
  for path in "${receipt_paths[@]}"; do
    [[ -f "$path" && ! -L "$path" ]] || die "receipt missing: $path"
    [[ "$(stat -c %a "$path")" == 600 ]] || die "receipt mode must be 0600: $path"
    jq -e . "$path" >/dev/null || die "invalid receipt JSON: $path"
  done
  if [[ -n "$revision" ]]; then
    for path in "${receipt_paths[@]}"; do
      [[ "$(jq -er '.revision' "$path")" == "$revision" ]] ||
        die "candidate revision receipt drift: $path"
    done
  fi

  assert_json "$buildset" '
    .schema=="jjdguard-task4-build-set-receipt/v2" and
    (. | keys)==["archive_sha256","candidate_tree","components","receipts","revision","schema"] and
    (.components | type)=="array" and
    (.receipts | type)=="object"'
  actual=$(jq -cS '.components' "$buildset")
  [[ "$actual" == "$expected_components_json" ]] ||
    die 'build-set component selection mismatch'
  actual=$(jq -cS '.receipts | keys' "$buildset")
  [[ "$actual" == "$expected_components_json" ]] ||
    die 'build-set receipt key selection mismatch'
  if [[ "$portal_selected" == 1 ]]; then
    assert_json "$portal" '
      .schema=="jjdguard-task4-image-receipt/v1" and
      .component=="portal" and
      (.build_args | keys)==["NEXT_PUBLIC_BILLING_ENABLED"] and
      (.build_engine | keys)==["docker_client_version","docker_server_version","kind"] and
      .build_engine.kind=="docker-daemon" and
      (.build_args.NEXT_PUBLIC_BILLING_ENABLED=="true" or
       .build_args.NEXT_PUBLIC_BILLING_ENABLED=="false")'
  fi
  if [[ "$tier1_selected" == 1 ]]; then
    assert_json "$tier1" '
      .schema=="jjdguard-task4-image-receipt/v1" and
      .component=="tier1" and
      (. | keys)==["archive_sha256","base_images","bench","build_engine","candidate_tree","component","image","image_id","model_manifest","oci_config_digest","owned_model","python_dependencies","revision","schema","source_blobs"] and
      (.build_engine | keys)==["docker_client_version","docker_server_version","kind"] and
      .build_engine.kind=="docker-daemon"'
  fi
  archive_revision=$(jq -er '.revision' "$buildset")
  [[ "$archive_revision" =~ ^[0-9a-f]{40}$ ]] || die 'receipt source revision is invalid'
  for path in "${receipt_paths[@]:1}"; do
    [[ "$(jq -er '.revision' "$path")" == "$archive_revision" ]] ||
      die "candidate revision receipt drift: $path"
  done
  [[ "$(git -C "$repo" rev-parse "$archive_revision^{commit}")" == "$archive_revision" &&
     "$(git -C "$repo" rev-parse "$archive_revision^{tree}")" == "$tree" ]] ||
    die 'receipt revision/tree mismatch'
  for path in "${receipt_paths[@]}"; do
    [[ "$(jq -er '.candidate_tree' "$path")" == "$tree" ]] ||
      die "candidate tree receipt drift: $path"
  done
  if [[ "$portal_selected" == 1 ]]; then
    [[ "$(jq -er '.receipts.portal' "$buildset")" == "$(canonical_receipt_sha "$portal")" ]] ||
      die 'Portal receipt chain mismatch'
  fi
  if [[ "$tier1_selected" == 1 ]]; then
    [[ "$(jq -er '.receipts.tier1' "$buildset")" == "$(canonical_receipt_sha "$tier1")" ]] ||
      die 'Tier-1 receipt chain mismatch'
  fi

  tmp=$(mktemp -d)
  chmod 0700 "$tmp"
  archive1="$tmp/a.tar"; archive2="$tmp/b.tar"
  sha1=$(archive_sha "$repo" "$archive_revision" "$archive1")
  sha2=$(archive_sha "$repo" "$archive_revision" "$archive2")
  [[ "$sha1" == "$sha2" ]] || die 'same candidate tree produced different archives'
  for path in "${receipt_paths[@]}"; do
    [[ "$(jq -er '.archive_sha256' "$path")" == "$sha1" ]] ||
      die "archive digest drift: $path"
  done

  if [[ "$portal_selected" == 1 ]]; then
    assert_source_blobs "$portal" \
      enterprise-ai-portal/Dockerfile \
      enterprise-ai-portal/package-lock.json \
      "$PRISMA_ENGINE_LOCK_PATH" \
      deploy/docker-compose/verify-release-prisma-engines.py
    assert_portal_prisma_receipt "$portal"
    expected=$(base_images_from_tree enterprise-ai-portal/Dockerfile)
    [[ "$(jq -cS '.base_images' "$portal")" == "$(jq -cS . <<<"$expected")" ]] ||
      die 'Portal base images drift'
    portal_id=$(jq -er '.image_id' "$portal")
    [[ "$(jq -er '.oci_config_digest' "$portal")" == "$portal_id" ]] ||
      die 'Portal OCI config digest mismatch'
    [[ "$("$docker_cmd" image inspect "$(jq -er '.image' "$portal")" --format '{{.Id}}')" == "$portal_id" ]] ||
      die 'Portal tag retag detected'
  fi

  if [[ "$tier1_selected" == 1 ]]; then
    tier1_paths=(
      apps/tier1-classifier/Dockerfile
      deploy/docker-compose/owned-tier1-model.lock.json
      apps/tier1-classifier/requirements.lock
      apps/tier1-classifier/entrypoint.sh
      apps/tier1-classifier/app/__init__.py
      apps/tier1-classifier/app/classifier.py
      apps/tier1-classifier/app/header_compat.py
      apps/tier1-classifier/app/latency_stats.py
      apps/tier1-classifier/app/main.py
      apps/tier1-classifier/app/model.py
      apps/security-engine/bench/__init__.py
      apps/security-engine/bench/run_bench.py
      apps/security-engine/bench/scorers.py
      apps/security-engine/bench/metrics.py
      apps/security-engine/bench/gate_artifact.py
      apps/security-engine/bench/data/zh_jailbreak.jsonl
      apps/security-engine/bench/data/zh_benign.jsonl
      deploy/docker-compose/verify-tier1-python-deps.py
    )
    assert_source_blobs "$tier1" "${tier1_paths[@]}"
    expected=$(base_images_from_tree apps/tier1-classifier/Dockerfile)
    [[ "$(jq -cS '.base_images' "$tier1")" == "$(jq -cS . <<<"$expected")" ]] ||
      die 'Tier-1 base images drift'

    approved_models=$(approved_model_manifest_from_tree "$repo" "$tree")
    approved_model_lock_sha=$(approved_model_lock_sha256_from_tree "$repo" "$tree")
    assert_owned_model_receipt "$tier1" "$approved_models" "$approved_model_lock_sha"
    assert_tier1_python_dependencies_receipt "$tier1"
    [[ "$(jq -cS '.model_manifest' "$tier1")" == "$(jq -cS '.owned_model.manifest' "$tier1")" ]] ||
      die 'Tier-1 image model manifest differs from the owned local input'

    report_path=$(jq -er '.bench.path' "$tier1")
    [[ "$report_path" == tier1-bench-gate-report.json ]] || die 'unexpected bench report path'
    [[ "$(jq -er '.bench.passed' "$tier1")" == true ]] || die 'bench gate did not pass'
    [[ "$(sha256_file "$receipt_dir/$report_path")" == "$(jq -er '.bench.sha256' "$tier1")" ]] ||
      die 'bench report replacement detected'

    tier1_id=$(jq -er '.image_id' "$tier1")
    [[ "$(jq -er '.oci_config_digest' "$tier1")" == "$tier1_id" ]] ||
      die 'Tier-1 OCI config digest mismatch'
    [[ "$("$docker_cmd" image inspect "$(jq -er '.image' "$tier1")" --format '{{.Id}}')" == "$tier1_id" ]] ||
      die 'Tier-1 tag retag detected'

    install -d -m 0700 "$tmp/model"
    cid=$("$docker_cmd" create "$tier1_id")
    trap '"$docker_cmd" rm -f -v "$cid" >/dev/null 2>&1 || true; rm -rf "$tmp"' RETURN
    "$docker_cmd" cp "$cid:/models/prompt-guard-2/." "$tmp/model"
    "$docker_cmd" rm -f -v "$cid" >/dev/null
    cid=
    actual_models=$(model_manifest_json "$tmp/model" "$tmp/model.tsv")
    expected_models=$(jq -cS '.model_manifest' "$tier1")
    [[ "$actual_models" == "$expected_models" ]] ||
      die 'Tier-1 model extra/missing/tamper detected'
    [[ "$(jq -er '.model_manifest | length' "$tier1")" -gt 0 ]] ||
      die 'Tier-1 model manifest is empty'
  fi
  rm -rf "$tmp"
  trap - RETURN
  printf '[task4-provenance] verified %s\n' "$tree"
}

refresh_buildset() {
  local dir=$1 portal_sha tier1_sha tmp
  portal_sha=$(canonical_receipt_sha "$dir/portal-image-receipt.json")
  tier1_sha=$(canonical_receipt_sha "$dir/tier1-image-receipt.json")
  tmp="$dir/build-set-receipt.json.tmp"
  jq --arg p "$portal_sha" --arg t "$tier1_sha" \
    '.receipts.portal=$p | .receipts.tier1=$t' \
    "$dir/build-set-receipt.json" | jq -cS . >"$tmp"
  chmod 0600 "$tmp"; mv -f "$tmp" "$dir/build-set-receipt.json"
}

expect_reject() {
  local label=$1
  shift
  ( "$@" ) >/dev/null 2>&1 && die "self-test expected rejection: $label"
  return 0
}

expect_reject_contains() {
  local label=$1 needle=$2 output
  shift 2
  if output=$("$@" 2>&1); then
    die "self-test expected rejection: $label"
  fi
  [[ "$output" == *"$needle"* ]] ||
    die "self-test rejection mismatch: $label :: $output"
}

make_mock_docker() {
  local path=$1
  printf '%s\n'     '#!/usr/bin/env bash' 'set -Eeuo pipefail'     'state=${MOCK_DOCKER_STATE:?}'     'case "$1 $2" in'     '  "image inspect")'     '    ref=$3'     '    case "$ref" in portal:test) cat "$state/portal.id" ;; tier1:test) cat "$state/tier1.id" ;; sha256:*) printf "%s\n" "$ref" ;; *) exit 1 ;; esac ;;'     '  *) case "$1" in'     '    create) printf "fixture-container\n" ;;'     '    cp) cp -a "$state/model/." "$3/" ;;'     '    rm) exit 0 ;;'     '    *) exit 64 ;; esac ;;'     'esac' >"$path"
  chmod 0500 "$path"
}

fixture_write_receipts() {
  local repo=$1 tree=$2 dir=$3 state=$4 archive portal_blobs tier1_blobs owned_model engine_json approved_lock_sha
  local prisma_lock_sha prisma_manifest prisma_content_sha prisma_engines
  local source_tsv path ref model_json model_digest revision tier1_python_deps requirements_lock_sha
  revision=$(git -C "$repo" rev-parse HEAD)
  archive=$(archive_sha "$repo" "$revision" "$dir/candidate.tar")
  prisma_lock_sha=$(git -C "$repo" cat-file blob \
    "$tree:$PRISMA_ENGINE_LOCK_PATH" | sha256sum | awk '{print $1}')
  prisma_manifest=$(git -C "$repo" show \
    "$tree:$PRISMA_ENGINE_LOCK_PATH" | jq -cS '.manifest | sort_by(.path)')
  prisma_content_sha=$(printf '%s' "$prisma_manifest" | sha256sum | awk '{print $1}')
  prisma_engines=$(git -C "$repo" show \
    "$tree:$PRISMA_ENGINE_LOCK_PATH" | jq -cS \
    --arg approved_lock_sha256 "$prisma_lock_sha" \
    --arg content_sha256 "$prisma_content_sha" \
    '{schema:"jjdguard-release-prisma-engines/v1",origin,source_image,source_image_id,
      approved_lock_sha256:$approved_lock_sha256,content_sha256:$content_sha256,
      manifest:(.manifest | sort_by(.path))}')
  portal_blobs=$(jq -n \
    --arg dockerfile "$(git -C "$repo" rev-parse "$tree:enterprise-ai-portal/Dockerfile")" \
    --arg package_lock "$(git -C "$repo" rev-parse "$tree:enterprise-ai-portal/package-lock.json")" \
    --arg prisma_lock "$(git -C "$repo" rev-parse "$tree:$PRISMA_ENGINE_LOCK_PATH")" \
    --arg prisma_lock_path "$PRISMA_ENGINE_LOCK_PATH" \
    --arg prisma_verifier "$(git -C "$repo" rev-parse "$tree:deploy/docker-compose/verify-release-prisma-engines.py")" \
    '{("enterprise-ai-portal/Dockerfile"):$dockerfile,
      ("enterprise-ai-portal/package-lock.json"):$package_lock,
      ($prisma_lock_path):$prisma_lock,
      ("deploy/docker-compose/verify-release-prisma-engines.py"):$prisma_verifier}')
  source_tsv="$dir/source.tsv"; : >"$source_tsv"
  for path in "${FIXTURE_TIER1_PATHS[@]}"; do
    printf '%s\t%s\n' "$path" "$(git -C "$repo" rev-parse "$tree:$path")" >>"$source_tsv"
  done
  tier1_blobs=$(jq -Rn '[inputs|split("\t")|{(.[0]):.[1]}]|add' <"$source_tsv")
  model_json=$(model_manifest_json "$state/model" "$dir/model.tsv")
  model_digest=$(jq -cS . <<<"$model_json" | sha256sum | awk '{print $1}')
  approved_lock_sha=$(git -C "$repo" show "$tree:$OWNED_TIER1_MODEL_LOCK_PATH" |
    sha256sum | awk '{print $1}')
  owned_model=$(jq -cn --arg digest "$model_digest" --arg lock_sha "$approved_lock_sha" --argjson manifest "$model_json" \
    '{schema:"jjdguard-owned-tier1-model/v1",origin:"user-trained-locked-input",
      approved_lock_sha256:$lock_sha,content_sha256:$digest,manifest:$manifest}')
  requirements_lock_sha=$(git -C "$repo" cat-file blob \
    "$tree:apps/tier1-classifier/requirements.lock" | sha256sum | awk '{print $1}')
  tier1_python_deps=$(jq -cn --arg requirements_lock_sha "$requirements_lock_sha" \
    '{schema:"jjdguard-tier1-python-deps/v1",origin:"home-existing-tier1-image",
      source_image:"docker-compose-tier1-classifier:latest",
      source_image_id:"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      requirements_lock_sha256:$requirements_lock_sha,
      content_sha256:"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
      file_count:1,packages:[{name:"fixture-pkg",version:"1.0"}]}')
  engine_json='{"kind":"docker-daemon","docker_client_version":"fixture-client","docker_server_version":"fixture-server"}'
  ref=node:22-alpine@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
  jq -cn --arg revision "$revision" --arg tree "$tree" --arg archive "$archive" --arg base "$ref"     --arg id "$(cat "$state/portal.id")" --argjson blobs "$portal_blobs" --argjson engine "$engine_json" --argjson prisma_engines "$prisma_engines"     '{schema:"jjdguard-task4-image-receipt/v1",component:"portal",revision:$revision,
      candidate_tree:$tree,archive_sha256:$archive,image:"portal:test",
      image_id:$id,oci_config_digest:$id,
      base_images:[{from_index:0,stage:null,reference:$base,
        digest:"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}],
      source_blobs:$blobs,build_engine:$engine,
      prisma_engines:$prisma_engines,
      build_args:{NEXT_PUBLIC_BILLING_ENABLED:"false"}}' >"$dir/portal-image-receipt.json"
  ref=python:3.11-slim@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
  jq -cn --arg revision "$revision" --arg tree "$tree" --arg archive "$archive" --arg base "$ref"     --arg id "$(cat "$state/tier1.id")" --argjson blobs "$tier1_blobs" --argjson engine "$engine_json"     --argjson models "$model_json" --argjson owned "$owned_model" --argjson python_deps "$tier1_python_deps"     '{schema:"jjdguard-task4-image-receipt/v1",component:"tier1",revision:$revision,
      candidate_tree:$tree,archive_sha256:$archive,image:"tier1:test",
      image_id:$id,oci_config_digest:$id,
      base_images:[{from_index:0,stage:null,reference:$base,
        digest:"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}],
      source_blobs:$blobs,build_engine:$engine,owned_model:$owned,
      model_manifest:$models,python_dependencies:$python_deps,
      bench:{path:"tier1-bench-gate-report.json",sha256:"",passed:true}}'     >"$dir/tier1-image-receipt.json"
  printf '{"gate":{"status":"PASS"}}\n' >"$dir/tier1-bench-gate-report.json"
  jq --arg sha "$(sha256_file "$dir/tier1-bench-gate-report.json")"     '.bench.sha256=$sha' "$dir/tier1-image-receipt.json" | jq -cS .     >"$dir/tier1.tmp"
  mv "$dir/tier1.tmp" "$dir/tier1-image-receipt.json"
  jq -cn --arg revision "$revision" --arg tree "$tree" --arg archive "$archive" \
    '{schema:"jjdguard-task4-build-set-receipt/v2",revision:$revision,
      candidate_tree:$tree,archive_sha256:$archive,
      components:["portal","tier1"],receipts:{portal:"",tier1:""}}' \
    >"$dir/build-set-receipt.json"
  chmod 0600 "$dir/"*.json
  refresh_buildset "$dir"
}

self_test_fixture() {
  local tmp repo dir state mock revision tree pristine path portal_only tier1_only output model_lock
  local -a verify_cli
  tmp=$(mktemp -d); chmod 0700 "$tmp"; trap "rm -rf -- '$tmp'" EXIT
  repo="$tmp/repo"; dir="$tmp/receipts"; state="$tmp/docker-state"
  git init -q "$repo"; git -C "$repo" config user.name fixture
  git -C "$repo" config user.email fixture@example.invalid
  install -d -m 0700 "$dir" "$state/model"
  FIXTURE_TIER1_PATHS=(
    apps/tier1-classifier/Dockerfile
    deploy/docker-compose/owned-tier1-model.lock.json
    apps/tier1-classifier/requirements.lock
    apps/tier1-classifier/entrypoint.sh
    apps/tier1-classifier/app/__init__.py
    apps/tier1-classifier/app/classifier.py
    apps/tier1-classifier/app/header_compat.py
    apps/tier1-classifier/app/latency_stats.py
    apps/tier1-classifier/app/main.py
    apps/tier1-classifier/app/model.py
    apps/security-engine/bench/__init__.py
    apps/security-engine/bench/run_bench.py
    apps/security-engine/bench/scorers.py
    apps/security-engine/bench/metrics.py
    apps/security-engine/bench/gate_artifact.py
      apps/security-engine/bench/data/zh_jailbreak.jsonl
      apps/security-engine/bench/data/zh_benign.jsonl
      deploy/docker-compose/verify-tier1-python-deps.py
  )
  mkdir -p "$repo/enterprise-ai-portal" "$repo/deploy/docker-compose"
  printf 'FROM node:22-alpine@sha256:%064d\n' 0 | tr 0 a >"$repo/enterprise-ai-portal/Dockerfile"
  printf '{}\n' >"$repo/enterprise-ai-portal/package-lock.json"
  jq -cn --arg platform "$PRISMA_ENGINE_PLATFORM" \
    --arg query "$PRISMA_QUERY_ENGINE" --arg schema_engine "$PRISMA_SCHEMA_ENGINE" \
    '{schema:"jjdguard-release-prisma-engines-lock/v1",prisma_version:"6.19.3",
      platform:$platform,origin:"home-local-portal-runtime",
      source_image:"enterprise-ai-portal:0.2.0-slim",
      source_image_id:"sha256:e28bd38e70cb8623542e8b37b24e14ccd9aecff610c903dcd86df3fd215433b5",
      manifest:[
        {path:$query,size:7,sha256:"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
        {path:$schema_engine,size:7,sha256:"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}
      ]}' >"$repo/$PRISMA_ENGINE_LOCK_PATH"
  printf 'fixture Prisma engine verifier\n' >"$repo/deploy/docker-compose/verify-release-prisma-engines.py"
  for path in "${FIXTURE_TIER1_PATHS[@]}"; do
    mkdir -p "$repo/$(dirname "$path")"
    printf 'fixture:%s\n' "$path" >"$repo/$path"
  done
  printf '%s\n' \
    'fixture-pkg==1.0 \\' \
    '    --hash=sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' \
    >"$repo/apps/tier1-classifier/requirements.lock"
  printf 'FROM python:3.11-slim@sha256:%064d\n' 0 | tr 0 b >"$repo/apps/tier1-classifier/Dockerfile"
  printf 'model\n' >"$state/model/model.onnx"
  printf '{}\n' >"$state/model/config.json"
  printf '{}\n' >"$state/model/tokenizer.json"
  printf '{}\n' >"$state/model/tokenizer_config.json"
  printf '{}\n' >"$state/model/special_tokens_map.json"
  model_lock=$(model_manifest_json "$state/model" "$tmp/model-lock.tsv")
  model_lock=$(jq -cS '[.[] | {path,size,sha256}] | sort_by(.path)' <<<"$model_lock")
  jq -cn --argjson manifest "$model_lock" \
    '{schema:"jjdguard-owned-tier1-model-lock/v1",model_id:"jjdguard-tier1-e5small-lr",license:"MIT",upstream:{repo:"intfloat/multilingual-e5-small",revision:"614241f622f53c4eeff9890bdc4f31cfecc418b3"},
      origin:"user-trained",manifest:$manifest}' \
    >"$repo/$OWNED_TIER1_MODEL_LOCK_PATH"
  printf 'sha256:%064d\n' 1 | tr 0 c >"$state/portal.id"
  printf 'sha256:%064d\n' 2 | tr 0 d >"$state/tier1.id"
  mock="$tmp/docker"; make_mock_docker "$mock"
  git -C "$repo" add -- .; git -C "$repo" commit -qm candidate
  revision=$(git -C "$repo" rev-parse HEAD)
  tree=$(git -C "$repo" rev-parse HEAD^{tree})
  fixture_write_receipts "$repo" "$tree" "$dir" "$state"
  pristine="$tmp/pristine"; cp -a "$dir" "$pristine"
  MOCK_DOCKER_STATE="$state" verify_receipts "$repo" "$tree" "$dir" "$mock" \
    "$revision" portal,tier1 >/dev/null

  portal_only="$tmp/portal-only"
  cp -a "$pristine" "$portal_only"
  rm "$portal_only/tier1-image-receipt.json" \
    "$portal_only/tier1-bench-gate-report.json"
  jq '.components=["portal"] | del(.receipts.tier1)' \
    "$portal_only/build-set-receipt.json" >"$portal_only/build-set.tmp"
  mv "$portal_only/build-set.tmp" "$portal_only/build-set-receipt.json"
  chmod 0600 "$portal_only/build-set-receipt.json"
  if ! output=$(JJD_TASK4_TESTING=1 MOCK_DOCKER_STATE="$state" "$0" \
    --target-arch "$target_arch" \
    --repo "$repo" --candidate-revision "$revision" \
    --candidate-tree "$tree" --receipt-dir "$portal_only" \
    --expected-components portal --docker-command "$mock" 2>&1); then
    die "Portal-only verifier failed: $output"
  fi

  tier1_only="$tmp/tier1-only"
  cp -a "$pristine" "$tier1_only"
  rm "$tier1_only/portal-image-receipt.json"
  jq '.components=["tier1"] | del(.receipts.portal)' \
    "$tier1_only/build-set-receipt.json" >"$tier1_only/build-set.tmp"
  mv "$tier1_only/build-set.tmp" "$tier1_only/build-set-receipt.json"
  chmod 0600 "$tier1_only/build-set-receipt.json"
  if ! output=$(JJD_TASK4_TESTING=1 MOCK_DOCKER_STATE="$state" "$0" \
    --target-arch "$target_arch" \
    --repo "$repo" --candidate-revision "$revision" \
    --candidate-tree "$tree" --receipt-dir "$tier1_only" \
    --expected-components tier1 --docker-command "$mock" 2>&1); then
    die "Tier1-only verifier failed: $output"
  fi
  expect_reject_contains 'extra Tier1 receipt' \
    'unexpected Tier-1 receipt for selected components' \
    env JJD_TASK4_TESTING=1 MOCK_DOCKER_STATE="$state" "$0" \
    --target-arch "$target_arch" \
    --repo "$repo" --candidate-tree "$tree" --receipt-dir "$pristine" \
    --expected-components portal --docker-command "$mock"
  expect_reject_contains 'missing Tier1 receipt' 'receipt missing:' \
    env JJD_TASK4_TESTING=1 MOCK_DOCKER_STATE="$state" "$0" \
    --target-arch "$target_arch" \
    --repo "$repo" --candidate-tree "$tree" --receipt-dir "$portal_only" \
    --expected-components portal,tier1 --docker-command "$mock"
  cp -a "$pristine" "$tmp/unknown-field"
  jq '.unknown=true' "$tmp/unknown-field/build-set-receipt.json" \
    >"$tmp/unknown-field/build-set.tmp"
  mv "$tmp/unknown-field/build-set.tmp" \
    "$tmp/unknown-field/build-set-receipt.json"
  chmod 0600 "$tmp/unknown-field/build-set-receipt.json"
  expect_reject_contains 'unknown build-set field' 'receipt assertion failed:' \
    env JJD_TASK4_TESTING=1 MOCK_DOCKER_STATE="$state" "$0" \
    --target-arch "$target_arch" \
    --repo "$repo" --candidate-tree "$tree" \
    --receipt-dir "$tmp/unknown-field" \
    --expected-components portal,tier1 --docker-command "$mock"
  verify_cli=(env JJD_TASK4_TESTING=1 MOCK_DOCKER_STATE="$state" "$0"
    --target-arch "$target_arch"
    --repo "$repo" --candidate-tree "$tree" --receipt-dir "$dir"
    --expected-components portal,tier1 --docker-command "$mock")

  cp -a "$pristine" "$tmp/missing-prisma-engines"
  jq 'del(.prisma_engines)' "$tmp/missing-prisma-engines/portal-image-receipt.json" \
    >"$tmp/missing-prisma-engines/portal-image-receipt.tmp"
  mv "$tmp/missing-prisma-engines/portal-image-receipt.tmp" \
    "$tmp/missing-prisma-engines/portal-image-receipt.json"
  chmod 0600 "$tmp/missing-prisma-engines/portal-image-receipt.json"
  refresh_buildset "$tmp/missing-prisma-engines"
  expect_reject_contains 'missing Portal Prisma receipt' \
    'Portal Prisma engine receipt is invalid' \
    env JJD_TASK4_TESTING=1 MOCK_DOCKER_STATE="$state" "$0" \
    --target-arch "$target_arch" \
    --repo "$repo" --candidate-tree "$tree" \
    --receipt-dir "$tmp/missing-prisma-engines" \
    --expected-components portal,tier1 --docker-command "$mock"

  for prisma_case in lock manifest digest; do
    cp -a "$pristine" "$tmp/prisma-$prisma_case"
    case "$prisma_case" in
      lock)
        jq '.prisma_engines.approved_lock_sha256="ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"' \
          "$tmp/prisma-$prisma_case/portal-image-receipt.json" ;;
      manifest)
        jq '.prisma_engines.manifest[0].sha256="ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"' \
          "$tmp/prisma-$prisma_case/portal-image-receipt.json" ;;
      digest)
        jq '.prisma_engines.content_sha256="ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"' \
          "$tmp/prisma-$prisma_case/portal-image-receipt.json" ;;
    esac >"$tmp/prisma-$prisma_case/portal-image-receipt.tmp"
    mv "$tmp/prisma-$prisma_case/portal-image-receipt.tmp" \
      "$tmp/prisma-$prisma_case/portal-image-receipt.json"
    chmod 0600 "$tmp/prisma-$prisma_case/portal-image-receipt.json"
    refresh_buildset "$tmp/prisma-$prisma_case"
    expect_reject "Portal Prisma $prisma_case tamper" \
      env JJD_TASK4_TESTING=1 MOCK_DOCKER_STATE="$state" "$0" \
      --target-arch "$target_arch" \
      --repo "$repo" --candidate-tree "$tree" \
      --receipt-dir "$tmp/prisma-$prisma_case" \
      --expected-components portal,tier1 --docker-command "$mock"
  done

  jq '.revision="0000000000000000000000000000000000000000"' \
    "$dir/portal-image-receipt.json" >"$dir/x"
  mv "$dir/x" "$dir/portal-image-receipt.json"
  chmod 0600 "$dir/portal-image-receipt.json"
  expect_reject 'candidate revision receipt drift' "${verify_cli[@]}" \
    --candidate-revision "$revision"
  cp -a "$pristine/." "$dir/"

  printf 'dirty\n' >>"$repo/enterprise-ai-portal/package-lock.json"
  expect_reject 'tracked dirty' "${verify_cli[@]}"
  git -C "$repo" restore --worktree enterprise-ai-portal/package-lock.json

  printf 'extra\n' >"$repo/apps/tier1-classifier/untracked.txt"
  expect_reject 'included untracked' "${verify_cli[@]}"
  rm "$repo/apps/tier1-classifier/untracked.txt"

  printf 'changed\n' >>"$repo/enterprise-ai-portal/package-lock.json"
  git -C "$repo" add -- enterprise-ai-portal/package-lock.json
  expect_reject 'candidate tree/source change' "${verify_cli[@]}"
  git -C "$repo" restore --staged --worktree enterprise-ai-portal/package-lock.json

  printf 'outside\n' >"$repo/outside.txt"; git -C "$repo" add -- outside.txt
  expect_reject 'task-external staged' "${verify_cli[@]}"
  git -C "$repo" restore --staged outside.txt; rm "$repo/outside.txt"

  cp -a "$pristine/." "$dir/"
  printf 'sha256:%064d\n' 9 | tr 0 e >"$state/portal.id"
  expect_reject 'retag' "${verify_cli[@]}"
  printf 'sha256:%064d\n' 1 | tr 0 c >"$state/portal.id"

  cp -a "$pristine/." "$dir/"
  jq '.build_args={}' "$dir/portal-image-receipt.json" >"$dir/x"
  mv "$dir/x" "$dir/portal-image-receipt.json"
  chmod 0600 "$dir/portal-image-receipt.json"
  refresh_buildset "$dir"
  expect_reject 'Portal billing receipt tamper' "${verify_cli[@]}"

  for path in base_images source_blobs model_manifest owned_model owned_model_digest owned_model_duplicate owned_model_unsafe python_dependencies; do
    cp -a "$pristine/." "$dir/"
    case "$path" in
      base_images) jq '.base_images[0].reference="python:3.11-slim@sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff" |
        .base_images[0].digest="sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"' "$dir/tier1-image-receipt.json" >"$dir/x" ;;
      source_blobs) jq '.source_blobs["apps/tier1-classifier/requirements.lock"]="0000000000000000000000000000000000000000"' "$dir/tier1-image-receipt.json" >"$dir/x" ;;
      model_manifest) jq '.model_manifest[0].sha256="ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"' "$dir/tier1-image-receipt.json" >"$dir/x" ;;
      owned_model) jq '.owned_model.manifest[0].sha256="ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"' "$dir/tier1-image-receipt.json" >"$dir/x" ;;
      owned_model_digest) jq '.owned_model.content_sha256="ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"' "$dir/tier1-image-receipt.json" >"$dir/x" ;;
      owned_model_duplicate) jq '.owned_model.manifest += [.owned_model.manifest[0]]' "$dir/tier1-image-receipt.json" >"$dir/x" ;;
      owned_model_unsafe) jq '.owned_model.manifest[0].path="../model.onnx"' "$dir/tier1-image-receipt.json" >"$dir/x" ;;
      python_dependencies) jq '.python_dependencies.requirements_lock_sha256="ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"' "$dir/tier1-image-receipt.json" >"$dir/x" ;;
    esac
    mv "$dir/x" "$dir/tier1-image-receipt.json"; chmod 0600 "$dir/tier1-image-receipt.json"; refresh_buildset "$dir"
    expect_reject "$path tamper" "${verify_cli[@]}"
  done

  cp -a "$pristine/." "$dir/"
  printf '{"gate":{"status":"FAIL"}}\n' >"$dir/tier1-bench-gate-report.json"
  expect_reject 'bench report replacement' "${verify_cli[@]}"

  cp -a "$pristine/." "$dir/"
  printf 'extra\n' >"$state/model/extra.bin"
  expect_reject 'model extra' "${verify_cli[@]}"
  rm "$state/model/extra.bin"
  mv "$state/model/model.onnx" "$state/model/model.missing"
  expect_reject 'model missing' "${verify_cli[@]}"
  mv "$state/model/model.missing" "$state/model/model.onnx"
  printf 'tamper\n' >>"$state/model/model.onnx"
  expect_reject 'model tamper' "${verify_cli[@]}"
  printf 'model\n' >"$state/model/model.onnx"

  MOCK_DOCKER_STATE="$state" verify_receipts "$repo" "$tree" "$pristine" "$mock" \
    "$revision" portal,tier1 >/dev/null
  printf '[task4-provenance] fixture PASS\n'
}

assert_tier1_build_context() {
  local script=$1
  awk '
    index($0, "\"$docker_cmd\" buildx build --load --platform \"linux/$target_arch\" --no-cache --pull=false") &&
      index($0, "\"${source_labels[@]}\"") &&
      index($0, "--tag \"$tier1_image\"") {
        context_line = NR + 1
        next
      }
    NR == context_line && $0 == "  \"$tier1_context\"" {
      found = 1
    }
    END { exit !found }
  ' "$script"
}

assert_task4_override_gate() {
  local build=$1 tmp repo wrapper marker revision tree archive_sha output owned_model_input unapproved_model_input tier1_python_deps_input npm_cache_context npm_cache_sha256 prisma_engine_input
  local docker_log portal_id prisma_schema_sha prisma_query_sha
  local -a fixture_tier1_paths
  tmp=$(mktemp -d)
  chmod 0700 "$tmp"
  npm_cache_context="$tmp/npm-cache-context"
  install -d -m 0700 "$npm_cache_context"
  : >"$npm_cache_context/npm-cache.tar"
  chmod 0400 "$npm_cache_context/npm-cache.tar"
  npm_cache_sha256=$(sha256_file "$npm_cache_context/npm-cache.tar")
  prisma_engine_input="$tmp/prisma-engines"
  install -d -m 0700 "$prisma_engine_input"
  printf 'schema engine fixture\n' >"$prisma_engine_input/schema-engine-linux-musl-openssl-3.0.x"
  printf 'query engine fixture\n' >"$prisma_engine_input/libquery_engine-linux-musl-openssl-3.0.x.so.node"
  chmod 0500 "$prisma_engine_input"/*
  repo="$tmp/repo"
  wrapper="$tmp/docker-wrapper"
  marker="$tmp/docker-called"
  install -d -m 0700 "$repo" "$repo/enterprise-ai-portal"
  git init -q "$repo"
  git -C "$repo" config user.name fixture
  git -C "$repo" config user.email fixture@example.invalid
  git -C "$repo" remote add origin git@example.invalid:fixture/repo.git
  printf 'FROM node:22-alpine@sha256:%064d\n' 0 | tr 0 a \
    >"$repo/enterprise-ai-portal/Dockerfile"
  printf '{}\n' >"$repo/enterprise-ai-portal/package-lock.json"
  install -d -m 0700 "$repo/deploy/docker-compose"
  cp "$ROOT_DIR/deploy/docker-compose/verify-release-prisma-engines.py" \
    "$repo/deploy/docker-compose/verify-release-prisma-engines.py"
  chmod 0500 "$repo/deploy/docker-compose/verify-release-prisma-engines.py"
  prisma_schema_sha="$(sha256_file "$prisma_engine_input/schema-engine-linux-musl-openssl-3.0.x")"
  prisma_query_sha="$(sha256_file "$prisma_engine_input/libquery_engine-linux-musl-openssl-3.0.x.so.node")"
  jq -n \
    --arg schema_sha "$prisma_schema_sha" \
    --arg query_sha "$prisma_query_sha" \
    --argjson schema_size "$(stat -c %s "$prisma_engine_input/schema-engine-linux-musl-openssl-3.0.x")" \
    --argjson query_size "$(stat -c %s "$prisma_engine_input/libquery_engine-linux-musl-openssl-3.0.x.so.node")" \
    '{schema:"jjdguard-release-prisma-engines-lock/v1",prisma_version:"6.19.3",
      platform:"linux-musl-openssl-3.0.x",origin:"home-local-portal-runtime",
      source_image:"enterprise-ai-portal:0.2.0-slim",
      source_image_id:"sha256:e28bd38e70cb8623542e8b37b24e14ccd9aecff610c903dcd86df3fd215433b5",manifest:[
        {path:"libquery_engine-linux-musl-openssl-3.0.x.so.node",size:$query_size,sha256:$query_sha},
        {path:"schema-engine-linux-musl-openssl-3.0.x",size:$schema_size,sha256:$schema_sha}
      ]}' >"$repo/deploy/docker-compose/release-prisma-engines.lock.json"
  git -C "$repo" add -- .
  git -C "$repo" commit -qm candidate
  revision=$(git -C "$repo" rev-parse HEAD)
  tree=$(git -C "$repo" rev-parse HEAD^{tree})
  archive_sha=$(git -C "$repo" archive --format=tar "$revision" |
    sha256sum | awk '{print $1}')
  printf '%s\n' \
    '#!/usr/bin/env bash' \
    'set -Eeuo pipefail' \
    ': >"${TASK4_OVERRIDE_MARKER:?}"' \
    'exit 91' >"$wrapper"
  chmod 0500 "$wrapper"

  if output=$(JJD_TASK4_DOCKER="$wrapper" TASK4_OVERRIDE_MARKER="$marker" \
    "$build" --candidate-revision "$revision" --candidate-tree "$tree" \
    --receipt-dir "$tmp/receipts-env" --portal-image portal:test \
    --tier1-image tier1:test --source-root "$repo" \
    --source-archive-sha256 "$archive_sha" --repo "$repo" 2>&1); then
    rm -rf -- "$tmp"
    die 'JJD_TASK4_DOCKER must be rejected outside testing mode'
  fi
  [[ "$output" == *'JJD_TASK4_TESTING=1'* ]] || {
    rm -rf -- "$tmp"
    die 'JJD_TASK4_DOCKER rejection must name the testing gate'
  }
  [[ ! -e "$marker" ]] || {
    rm -rf -- "$tmp"
    die 'JJD_TASK4_DOCKER executed before the testing gate'
  }

  if output=$(TASK4_OVERRIDE_MARKER="$marker" "$build" \
    --candidate-revision "$revision" --candidate-tree "$tree" \
    --receipt-dir "$tmp/receipts-cli" --portal-image portal:test \
    --tier1-image tier1:test --source-root "$repo" \
    --source-archive-sha256 "$archive_sha" --repo "$repo" \
    --docker-command "$wrapper" 2>&1); then
    rm -rf -- "$tmp"
    die '--docker-command must be rejected outside testing mode'
  fi
  [[ "$output" == *'JJD_TASK4_TESTING=1'* ]] || {
    rm -rf -- "$tmp"
    die '--docker-command rejection must name the testing gate'
  }
  [[ ! -e "$marker" ]] || {
    rm -rf -- "$tmp"
    die '--docker-command executed before the testing gate'
  }

  if output=$(JJD_TASK4_TESTING=1 JJD_TASK4_DOCKER="$wrapper" \
    TASK4_OVERRIDE_MARKER="$marker" BILLING_ENABLED=invalid \
    "$build" --candidate-revision "$revision" --candidate-tree "$tree" \
    --receipt-dir "$tmp/receipts-billing" --portal-image portal:test \
    --tier1-image tier1:test --source-root "$repo" \
    --source-archive-sha256 "$archive_sha" --repo "$repo" 2>&1); then
    rm -rf -- "$tmp"
    die 'invalid BILLING_ENABLED must be rejected'
  fi
  [[ "$output" == *'BILLING_ENABLED must be true or false'* ]] || {
    rm -rf -- "$tmp"
    die 'invalid BILLING_ENABLED rejection is missing'
  }
  [[ ! -e "$marker" ]] || {
    rm -rf -- "$tmp"
    die 'invalid BILLING_ENABLED reached Docker'
  }

  docker_log="$tmp/docker.log"
  portal_id=$(printf 'sha256:%064d\n' 3 | tr 0 e)
  chmod 0700 "$wrapper"
  printf '%s\n' \
    '#!/usr/bin/env bash' \
    'set -Eeuo pipefail' \
    'case "$1 $2" in' \
    '  "version --format")' \
    '    case "$3" in "{{.Client.Version}}") printf "fixture-client\\n" ;; "{{.Server.Version}}") printf "fixture-server\\n" ;; *) exit 46 ;; esac ;;' \
    '  "image inspect")' \
    '    case "$3" in' \
    '      chat-portal/portal-proxy:0.1.0) printf "%s\n" "${TASK4_OPAQUE_ID:?}" ;;' \
    '      portal:test) printf "%s\n" "${TASK4_PORTAL_ID:?}" ;;' \
    '      *) printf "%s\n" "$*" >>"${TASK4_DOCKER_LOG:?}"; exit 44 ;;' \
    '    esac ;;' \
    '  *)' \
    '    if [[ "$1" == build || "$1" == buildx ]]; then' \
    '      printf "%s\n" "$*" >>"${TASK4_DOCKER_LOG:?}"' \
    '    else' \
    '      printf "%s\n" "$*" >>"${TASK4_DOCKER_LOG:?}"' \
    '      exit 45' \
    '    fi ;;' \
    'esac' >"$wrapper"
  chmod 0500 "$wrapper"
  if ! output=$(JJD_TASK4_TESTING=1 JJD_TASK4_DOCKER="$wrapper" \
    TASK4_DOCKER_LOG="$docker_log" TASK4_PORTAL_ID="$portal_id" \
    TASK4_OPAQUE_ID="$(printf 'sha256:%064d\n' 4 | tr 0 f)" \
    BILLING_ENABLED=false "$build" --candidate-revision "$revision" \
    --candidate-tree "$tree" --receipt-dir "$tmp/receipts-portal" \
    --portal-image portal:test --npm-cache-context "$npm_cache_context" \
    --npm-cache-sha256 "$npm_cache_sha256" \
    --prisma-engine-input "$prisma_engine_input" --source-root "$repo" \
    --source-archive-sha256 "$archive_sha" --repo "$repo" 2>&1); then
    rm -rf -- "$tmp"
    die "Portal-only Task4 build failed: $output"
  fi
  [[ -f "$tmp/receipts-portal/portal-image-receipt.json" &&
     ! -e "$tmp/receipts-portal/tier1-image-receipt.json" &&
     ! -e "$tmp/receipts-portal/tier1-bench-gate-report.json" ]] || {
    rm -rf -- "$tmp"
    die 'Portal-only Task4 receipt set is not exact'
  }
  jq -e '
    .schema=="jjdguard-task4-build-set-receipt/v2" and
    .components==["portal"] and
    (.receipts | keys)==["portal"]' \
    "$tmp/receipts-portal/build-set-receipt.json" >/dev/null || {
    rm -rf -- "$tmp"
    die 'Portal-only build-set v2 selection is invalid'
  }
  jq -e '.build_args=={NEXT_PUBLIC_BILLING_ENABLED:"false"}' \
    "$tmp/receipts-portal/portal-image-receipt.json" >/dev/null || {
    rm -rf -- "$tmp"
    die 'Portal false billing receipt is invalid'
  }
  jq -e '.base_images==[{
      from_index:0,
      stage:null,
      reference:"node:22-alpine@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      digest:"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    }]' "$tmp/receipts-portal/portal-image-receipt.json" >/dev/null || {
    rm -rf -- "$tmp"
    die 'Portal base_images receipt is invalid'
  }
  jq -e '(has("base_image") | not) and (has("base_digest") | not)' \
    "$tmp/receipts-portal/portal-image-receipt.json" >/dev/null || {
    rm -rf -- "$tmp"
    die 'legacy single-base receipt fields are forbidden'
  }
  grep -Fq -- '--build-arg NEXT_PUBLIC_BILLING_ENABLED=false' "$docker_log" || {
    rm -rf -- "$tmp"
    die 'Portal false billing build argument is missing'
  }
  grep -Fq -- "--build-context release-npm-cache=$npm_cache_context" "$docker_log" || {
    rm -rf -- "$tmp"
    die 'Portal local NPM cache context is missing'
  }
  ! grep -Fq -- "--build-context release-prisma-engine=$prisma_engine_input" "$docker_log" || {
    rm -rf -- "$tmp"
    die 'Portal build used the mutable Prisma engine input directly'
  }
  grep -Fq -- '--build-context release-prisma-engine=' "$docker_log" || {
    rm -rf -- "$tmp"
    die 'Portal local Prisma engine snapshot context is missing'
  }
  ! grep -Fq 'tier1:test' "$docker_log" || {
    rm -rf -- "$tmp"
    die 'Portal-only Task4 touched the Tier1 tag'
  }

  fixture_tier1_paths=(
    apps/tier1-classifier/Dockerfile
    apps/tier1-classifier/requirements.lock
    apps/tier1-classifier/entrypoint.sh
    apps/tier1-classifier/app/__init__.py
    apps/tier1-classifier/app/classifier.py
    apps/tier1-classifier/app/header_compat.py
    apps/tier1-classifier/app/latency_stats.py
    apps/tier1-classifier/app/main.py
    apps/tier1-classifier/app/model.py
    apps/security-engine/bench/__init__.py
    apps/security-engine/bench/run_bench.py
    apps/security-engine/bench/scorers.py
    apps/security-engine/bench/metrics.py
    apps/security-engine/bench/gate_artifact.py
    apps/security-engine/bench/data/zh_jailbreak.jsonl
    apps/security-engine/bench/data/zh_benign.jsonl
    deploy/docker-compose/verify-tier1-python-deps.py
  )
  for path in "${fixture_tier1_paths[@]}"; do
    mkdir -p "$repo/$(dirname "$path")"
    printf 'fixture:%s\n' "$path" >"$repo/$path"
  done
  cp "$ROOT_DIR/deploy/docker-compose/verify-tier1-python-deps.py" \
    "$repo/deploy/docker-compose/verify-tier1-python-deps.py"
  chmod 0500 "$repo/deploy/docker-compose/verify-tier1-python-deps.py"
  printf '%s\n' \
    'fixture-pkg==1.0 \\' \
    '    --hash=sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' \
    >"$repo/apps/tier1-classifier/requirements.lock"
  printf 'FROM python:3.11-slim@sha256:%064d\n' 0 | tr 0 b \
    >"$repo/apps/tier1-classifier/Dockerfile"
  owned_model_input="$tmp/owned-tier1"
  tier1_python_deps_input="$tmp/tier1-python-deps"
  install -d -m 0700 "$owned_model_input"
  install -d -m 0700 "$tier1_python_deps_input/site-packages/fixture_pkg-1.0.dist-info"
  printf '%s\n' \
    '{"schema":"jjdguard-tier1-python-deps-source/v1","origin":"home-existing-tier1-image","source_image":"docker-compose-tier1-classifier:latest","source_image_id":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}' \
    >"$tier1_python_deps_input/source.json"
  printf '%s\n' \
    'Metadata-Version: 2.1' \
    'Name: fixture-pkg' \
    'Version: 1.0' \
    >"$tier1_python_deps_input/site-packages/fixture_pkg-1.0.dist-info/METADATA"
  printf '%s\n' 'VALUE = "fixture"' >"$tier1_python_deps_input/site-packages/fixture_pkg.py"
  printf 'model\n' >"$owned_model_input/model.onnx"
  printf '{}\n' >"$owned_model_input/config.json"
  printf '{}\n' >"$owned_model_input/tokenizer.json"
  printf '{}\n' >"$owned_model_input/tokenizer_config.json"
  printf '{}\n' >"$owned_model_input/special_tokens_map.json"
  install -d -m 0700 "$repo/deploy/docker-compose"
  jq -n \
    --arg model_onnx_sha "$(sha256_file "$owned_model_input/model.onnx")" \
    --argjson model_onnx_size "$(wc -c <"$owned_model_input/model.onnx")" \
    --arg config_sha "$(sha256_file "$owned_model_input/config.json")" \
    --argjson config_size "$(wc -c <"$owned_model_input/config.json")" \
    --arg tokenizer_sha "$(sha256_file "$owned_model_input/tokenizer.json")" \
    --argjson tokenizer_size "$(wc -c <"$owned_model_input/tokenizer.json")" \
    --arg tokenizer_config_sha "$(sha256_file "$owned_model_input/tokenizer_config.json")" \
    --argjson tokenizer_config_size "$(wc -c <"$owned_model_input/tokenizer_config.json")" \
    --arg special_tokens_sha "$(sha256_file "$owned_model_input/special_tokens_map.json")" \
    --argjson special_tokens_size "$(wc -c <"$owned_model_input/special_tokens_map.json")" \
    '{schema:"jjdguard-owned-tier1-model-lock/v1",model_id:"jjdguard-tier1-e5small-lr",license:"MIT",upstream:{repo:"intfloat/multilingual-e5-small",revision:"614241f622f53c4eeff9890bdc4f31cfecc418b3"},origin:"user-trained",manifest:[
      {path:"config.json",size:$config_size,sha256:$config_sha},
      {path:"model.onnx",size:$model_onnx_size,sha256:$model_onnx_sha},
      {path:"special_tokens_map.json",size:$special_tokens_size,sha256:$special_tokens_sha},
      {path:"tokenizer.json",size:$tokenizer_size,sha256:$tokenizer_sha},
      {path:"tokenizer_config.json",size:$tokenizer_config_size,sha256:$tokenizer_config_sha}
    ]}' >"$repo/deploy/docker-compose/owned-tier1-model.lock.json"
  git -C "$repo" add -- .
  git -C "$repo" commit -qm tier1-candidate
  revision=$(git -C "$repo" rev-parse HEAD)
  tree=$(git -C "$repo" rev-parse HEAD^{tree})
  archive_sha=$(git -C "$repo" archive --format=tar "$revision" |
    sha256sum | awk '{print $1}')
  : >"$docker_log"
  chmod 0700 "$wrapper"
  printf '%s\n' \
    '#!/usr/bin/env bash' \
    'set -Eeuo pipefail' \
    'if [[ "$1 $2" == "version --format" ]]; then' \
    '  case "$3" in "{{.Client.Version}}") printf "fixture-client\\n" ;; "{{.Server.Version}}") printf "fixture-server\\n" ;; *) exit 92 ;; esac' \
    '  exit 0' \
    'fi' \
    'printf "%s\n" "$*" >>"${TASK4_DOCKER_LOG:?}"' \
    'exit 91' >"$wrapper"
  chmod 0500 "$wrapper"
  unapproved_model_input="$tmp/unapproved-tier1"
  cp -a "$owned_model_input" "$unapproved_model_input"
  printf 'unapproved-model\n' >"$unapproved_model_input/model.onnx"
  : >"$docker_log"
  if output=$(JJD_TASK4_TESTING=1 JJD_TASK4_DOCKER="$wrapper" \
    TASK4_DOCKER_LOG="$docker_log" "$build" \
    --candidate-revision "$revision" --candidate-tree "$tree" \
    --receipt-dir "$tmp/receipts-unapproved-tier1" --tier1-image tier1:test \
    --tier1-model-input "$unapproved_model_input" \
    --tier1-python-deps-input "$tier1_python_deps_input" \
    --source-root "$repo" --source-archive-sha256 "$archive_sha" \
    --repo "$repo" 2>&1); then
    rm -rf -- "$tmp"
    die 'unapproved Tier1 input must be rejected before Docker'
  fi
  [[ "$output" == *'owned Tier-1 model input does not match approved user-trained model lock'* ]] || {
    rm -rf -- "$tmp"
    die "unapproved Tier1 input rejection is missing: $output"
  }
  [[ ! -s "$docker_log" ]] || {
    rm -rf -- "$tmp"
    die 'unapproved Tier1 input reached Docker'
  }
  : >"$docker_log"
  if output=$(JJD_TASK4_TESTING=1 JJD_TASK4_DOCKER="$wrapper" \
    TASK4_DOCKER_LOG="$docker_log" "$build" \
    --candidate-revision "$revision" --candidate-tree "$tree" \
    --receipt-dir "$tmp/receipts-tier1" --tier1-image tier1:test \
    --tier1-model-input "$owned_model_input" \
    --tier1-python-deps-input "$tier1_python_deps_input" \
    --source-root "$repo" --source-archive-sha256 "$archive_sha" \
    --repo "$repo" 2>&1); then
    rm -rf -- "$tmp"
    die 'Tier1-only fixture must stop at the fake build Docker'
  fi
  grep -Fq 'buildx build --load --platform linux/amd64 --no-cache --pull=false' "$docker_log" || {
    rm -rf -- "$tmp"
    die "Tier1-only Task4 did not reach build Docker: $output"
  }
  ! grep -Eq 'portal:test|chat-portal/portal-proxy' "$docker_log" || {
    rm -rf -- "$tmp"
    die 'Tier1-only Task4 touched a Portal tag'
  }
  [[ ! -e "$tmp/receipts-tier1/portal-image-receipt.json" ]] || {
    rm -rf -- "$tmp"
    die 'Tier1-only Task4 generated a Portal receipt'
  }
  rm -rf -- "$tmp"
}

assert_task4_daemon_identity_drift_gate() {
  local root=$1 tmp docker baseline
  tmp=$(mktemp -d)
  docker="$tmp/docker"
  printf '%s\n' \
    '#!/usr/bin/env bash' \
    'set -Eeuo pipefail' \
    '[[ "$1 $2" == "version --format" ]] || exit 64' \
    'case "$3" in' \
    '  "{{.Client.Version}}") printf "fixture-client\\n" ;;' \
    '  "{{.Server.Version}}") printf "%s\\n" "${TASK4_IDENTITY_SERVER:-fixture-server}" ;;' \
    '  *) exit 65 ;;' \
    'esac' >"$docker"
  chmod 0500 "$docker"
  # shellcheck disable=SC1091
  source "$root/deploy/docker-compose/lib-build-identity.sh"
  baseline=$(docker_daemon_engine_json "$docker") || die 'cannot capture Task4 daemon fixture identity'
  if TASK4_IDENTITY_SERVER=drifted-server \
    assert_docker_daemon_identity_unchanged "$baseline" "$docker" >/dev/null 2>&1; then
    rm -rf -- "$tmp"
    die 'Task4 daemon identity drift was accepted'
  fi
  rm -rf -- "$tmp"
}

assert_task4_explicit_repo_from_non_git_cwd() {
  local root=$1 build=$2 tmp revision tree output
  tmp=$(mktemp -d)
  install -d -m 0700 "$tmp/outside"
  revision=$(git -C "$root" rev-parse HEAD)
  tree=$(git -C "$root" rev-parse HEAD^{tree})
  if output=$(cd "$tmp/outside" && "$build" \
    --candidate-revision "$revision" --candidate-tree "$tree" \
    --repo "$root" 2>&1); then
    rm -rf -- "$tmp"
    die 'Task4 builder must reject missing build inputs'
  fi
  [[ "$output" == *'--receipt-dir and at least one Task4 image are required'* ]] || {
    rm -rf -- "$tmp"
    die "Task4 builder ignored explicit --repo outside a Git worktree: $output"
  }
  [[ "$output" != *'fatal: not a git repository'* ]] || {
    rm -rf -- "$tmp"
    die "Task4 builder resolved Git before parsing explicit --repo: $output"
  }
  rm -rf -- "$tmp"
}

self_test() {
  local root build offline_builder mutated_build
  root=$(git rev-parse --show-toplevel)
  [[ -x "$root/deploy/tests/stage_jjdguard_task4_candidate.sh" ]] ||
    die 'stage script missing'
  build="$root/deploy/tests/build_jjdguard_task4_images.sh"
  offline_builder="$root/deploy/docker-compose/build-offline-images-for-arch.sh"
  [[ -x "$build" ]] ||
    die 'build script missing'
  assert_task4_daemon_identity_drift_gate "$root"
  assert_task4_explicit_repo_from_non_git_cwd "$root" "$build"
  assert_task4_override_gate "$build"
  grep -Fq -- '--build-arg "NEXT_PUBLIC_BILLING_ENABLED=$billing_enabled"' "$build" ||
    die 'Portal build must receive NEXT_PUBLIC_BILLING_ENABLED'
  grep -Fq 'build_args:{NEXT_PUBLIC_BILLING_ENABLED:$billing}' "$build" ||
    die 'Portal receipt must record NEXT_PUBLIC_BILLING_ENABLED'
  ! grep -q 'git -C "$repo" archive' "$build" ||
    die 'Task4 helper must not create a second Git archive'
  grep -Fq -- '--source-root)' "$build" ||
    die 'Task4 helper must require the unified source root'
  grep -Fq -- '--source-archive-sha256)' "$build" ||
    die 'Task4 helper must require the unified source archive digest'
  grep -Fq -- '--source-root "$SOURCE_ROOT"' "$offline_builder" ||
    die 'offline builder must pass the unified source root to Task4'
  grep -Fq -- '--source-archive-sha256 "$SOURCE_ARCHIVE_SHA256"' "$offline_builder" ||
    die 'offline builder must pass the unified source archive digest to Task4'
  grep -Fq 'env -u JJD_TASK4_DOCKER -u JJD_TASK4_TESTING' "$offline_builder" ||
    die 'offline builder must clear Task4 test overrides'
  grep -Fq 'task4_components_csv=' "$offline_builder" ||
    die 'offline builder must derive the exact Task4 selection'
  grep -Fq -- '--expected-components "$task4_components_csv"' "$offline_builder" ||
    die 'offline builder must pass the exact Task4 selection to verification'
  grep -Fq 'NEXT_PUBLIC_BILLING_ENABLED' "$offline_builder" ||
    die 'offline builder must record Portal billing provenance'
  grep -Fq '"$source_root/enterprise-ai-portal"' "$build" ||
    die 'Portal image must build directly from the unified source root'
  grep -Fq 'cp -a "$source_root/apps/tier1-classifier/." "$tier1_context/"' "$build" ||
    die 'Tier-1 temporary context must originate from the unified source root'
  grep -Fq -- '--tier1-model-input)' "$build" ||
    die 'Task4 must require an explicit local Tier-1 model input'
  grep -Fq -- '--tier1-python-deps-input)' "$build" ||
    die 'Task4 must require an explicit local Tier-1 Python dependency input'
  grep -Fq 'python_dependencies' "$build" ||
    die 'Tier-1 receipt must identify the local Python dependency snapshot'
  grep -Fq -- '--prisma-engine-input)' "$build" ||
    die 'Task4 must require an explicit local Prisma engine input'
  grep -Fq -- '--prisma-engine-input "$PRISMA_ENGINE_INPUT"' "$offline_builder" ||
    die 'offline builder must pass the local Prisma engine input to Task4'
  grep -Fq -- 'release-prisma-engine=$prisma_engine_context' "$build" ||
    die 'Portal build must receive the local Prisma engine snapshot context'
  grep -Fq 'prisma_engines' "$build" ||
    die 'Portal receipt must identify the local Prisma engine input'
  grep -Fq -- '--network-mode)' "$build" ||
    die 'Task4 must expose an explicit build network mode'
  grep -Fq -- '--tier1-model-input "$TIER1_OWNED_MODEL_INPUT"' "$offline_builder" ||
    die 'offline builder must pass the owned Tier-1 model input to Task4'
  grep -Fq -- '--tier1-python-deps-input "$TIER1_PYTHON_DEPS_INPUT"' "$offline_builder" ||
    die 'offline builder must pass the local Tier-1 Python dependency input to Task4'
  grep -Fq -- 'TASK4_BUILD_NETWORK_MODE=none' "$offline_builder" ||
    die 'offline builder must force Task4 image construction offline'
  grep -Fq -- '--network-mode "$TASK4_BUILD_NETWORK_MODE"' "$offline_builder" ||
    die 'offline builder must pass the fixed offline network mode to Task4'
  grep -Fq '"$docker_cmd" buildx build --load --platform "linux/$target_arch" --no-cache --pull=false --network "$build_network_mode"' "$build" ||
    die 'Task4 image construction must use its explicit network mode'
  grep -Fq 'owned_model' "$build" ||
    die 'Tier-1 receipt must identify the owned local model input'
  for forbidden in snapshot_download HF_ENDPOINT TIER1_EMBEDDER_ \
    build-baseline-model.sh requirements-train.lock training/tests/test_retrain.py; do
    if grep -Fq -- "$forbidden" "$build"; then
      die "formal Tier-1 construction must not contain $forbidden"
    fi
  done
  assert_tier1_build_context "$build" ||
    die 'Tier-1 image must build from the derived temporary context'
  mutated_build=$(mktemp)
  sed 's|^  "\$tier1_context"$|  "$tmp/wrong-context"|' \
    "$build" >"$mutated_build"
  printf '%s\n' ': "$tier1_context"' >>"$mutated_build"
  if assert_tier1_build_context "$mutated_build"; then
    rm -f "$mutated_build"
    die 'Tier-1 context assertion accepts an unrelated string'
  fi
  rm -f "$mutated_build"
  grep -Fq 'org.opencontainers.image.revision=$candidate_revision' "$build" ||
    die 'candidate images must carry the full source revision label'
  grep -Fq 'org.opencontainers.image.source=$source_remote' "$build" ||
    die 'candidate images must carry the source remote label'
  grep -Fq 'com.jjdguard.source.tree=$candidate_tree' "$build" ||
    die 'candidate images must carry the source tree label'
  grep -Fq 'docker_daemon_engine_json' "$build" ||
    die 'Task4 must record its Docker daemon build engine'
  grep -Fq 'assert_docker_daemon_identity_unchanged' "$build" ||
    die 'Task4 must reject Docker daemon identity drift during construction'
  ! grep -Eq '(build|tag).*chat-portal/portal-proxy' "$build" ||
    die 'opaque Portal Proxy build/retag is forbidden'
  bash "$root/deploy/tests/stage_jjdguard_task4_candidate.sh" --self-test
  self_test_fixture
  printf '[task4-provenance] self-test PASS\n'
}

candidate_revision= candidate_tree= receipt_dir= repo= expected_components=
target_arch=amd64
docker_cmd=docker
if [[ ${JJD_TASK4_DOCKER+x} ]]; then
  [[ "${JJD_TASK4_TESTING:-0}" == 1 ]] ||
    die 'JJD_TASK4_DOCKER requires JJD_TASK4_TESTING=1'
  docker_cmd=$JJD_TASK4_DOCKER
fi
mode=verify
while (($#)); do
  case "$1" in
    --self-test) mode=selftest; shift ;;
    --candidate-revision) candidate_revision=$2; shift 2 ;;
    --candidate-tree) candidate_tree=$2; shift 2 ;;
    --receipt-dir) receipt_dir=$2; shift 2 ;;
    --repo) repo=$2; shift 2 ;;
    --expected-components) expected_components=$2; shift 2 ;;
    --target-arch) target_arch=$2; shift 2 ;;
    --docker-command)
      [[ "${JJD_TASK4_TESTING:-0}" == 1 ]] ||
        die '--docker-command requires JJD_TASK4_TESTING=1'
      docker_cmd=$2
      shift 2
      ;;
    --self-test-fixture) mode=fixture; shift ;;
    *) die "unknown argument: $1" ;;
  esac
done
case "$target_arch" in
  amd64) ;;
  arm64)
    PRISMA_ENGINE_LOCK_PATH=$PRISMA_ENGINE_ARM64_LOCK_PATH
    PRISMA_ENGINE_PLATFORM=linux-musl-arm64-openssl-3.0.x
    PRISMA_QUERY_ENGINE=libquery_engine-linux-musl-arm64-openssl-3.0.x.so.node
    PRISMA_SCHEMA_ENGINE=schema-engine-linux-musl-arm64-openssl-3.0.x
    ;;
  *) die '--target-arch must be amd64 or arm64' ;;
esac
if [[ "$mode" == fixture ]]; then self_test_fixture; exit 0; fi
if [[ "$mode" == selftest ]]; then self_test; exit 0; fi
if [[ -z "$candidate_tree" && -z "$receipt_dir" ]]; then self_test; exit 0; fi
repo=${repo:-$(git rev-parse --show-toplevel)}
[[ -n "$candidate_tree" && -n "$receipt_dir" && -n "$expected_components" ]] ||
  die '--candidate-tree, --receipt-dir and --expected-components are required together'
verify_receipts "$repo" "$candidate_tree" "$receipt_dir" "$docker_cmd" \
  "$candidate_revision" "$expected_components"
