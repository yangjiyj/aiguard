#!/bin/sh

image_catalog_path() {
  _lst="${IMAGES_LST:-}"
  if [ -z "$_lst" ]; then
    _here="$(CDPATH= cd -- "$(dirname -- "$0")" 2>/dev/null && pwd || echo .)"
    _lst="$_here/images.lst"
  fi
  printf '%s\n' "$_lst"
}

validate_image_catalog() {
  _lst="$(image_catalog_path)"
  [ -f "$_lst" ] || {
    echo "[error] images.lst not found: $_lst" >&2
    return 1
  }
  awk '
    function fail(message) {
      printf "[error] invalid image catalog at line %d: %s\n", NR, message > "/dev/stderr"
      invalid=1
    }
    function relative_path(path) {
      return path != "-" && path !~ /^\// && path !~ /(^|\/)\.\.(\/|$)/
    }
    /^[[:space:]]*#/ || /^[[:space:]]*$/ { next }
    {
      rows++
      if (NF != 7) {
        fail("expected exactly seven fields")
        next
      }
      image=$1; profile=$2; kind=$3; component=$4
      digest=$5; dockerfile=$6; context=$7
      if (image ~ /@sha256:/) fail("runtime tag contains a digest")
      if (profile != "common" && profile != "full" && profile != "chat") fail("unknown profile")
      if (kind != "first-party" && kind != "upstream-source" && kind != "home-runtime" && kind != "third-party") fail("unknown source kind")
      if (component !~ /^[a-z0-9][a-z0-9.-]*$/) fail("invalid component name")
      if (seen_image[image]++) fail("duplicate runtime tag")
      if (seen_component[component]++) fail("duplicate component")
      if (kind == "third-party") {
        if (length(digest) != 71 || digest !~ /^sha256:[0-9a-f]+$/) fail("invalid third-party digest")
        if (dockerfile != "-" || context != "-") fail("third-party source paths must be -")
      } else {
        if (digest != "-") fail("source-built image digest must be -")
        if (!relative_path(dockerfile) || !relative_path(context)) fail("source paths must be repository-relative")
      }
    }
    END {
      if (rows == 0) {
        print "[error] image catalog is empty" > "/dev/stderr"
        invalid=1
      }
      exit invalid
    }
  ' "$_lst"
}

validate_requested_profile() {
  case "$1" in
    lite|full) ;;
    *)
      echo "[error] unsupported bundle profile: $1" >&2
      return 1
      ;;
  esac
}

# 按 profile 输出完整目录行。chat 与 lite/full 正交。
read_image_catalog_for_profile() {
  _profile="${1:-lite}"
  validate_requested_profile "$_profile" || return 1
  validate_image_catalog || return 1
  _lst="$(image_catalog_path)"
  awk -v prof="$_profile" -v inc="${INCLUDE_CHAT:-0}" '
    /^[[:space:]]*#/ || /^[[:space:]]*$/ { next }
    $2 == "common" || (prof == "full" && $2 == "full") || (inc == "1" && $2 == "chat") {
      print
    }
  ' "$_lst"
}

# 按 profile 输出 runtime_tag（每行一个）。
read_images_for_profile() {
  _catalog_rows="$(read_image_catalog_for_profile "${1:-lite}")" || return 1
  printf '%s\n' "$_catalog_rows" | awk 'NF { print $1 }'
}

# 输出选中镜像中的 third-party runtime_tag 与 expected_digest。
read_image_digests_for_profile() {
  _profile="${1:-lite}"
  _catalog_rows="$(read_image_catalog_for_profile "$_profile")" || return 1
  printf '%s\n' "$_catalog_rows" |
    awk 'NF && $3 == "third-party" { print $1, $5 }'
}
