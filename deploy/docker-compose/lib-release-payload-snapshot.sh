#!/bin/sh

# Materialize the exact revision approved by release-source-gate before any
# version-controlled deployment files are copied into a customer artifact.
create_release_payload_snapshot() {
  [ "$#" -eq 3 ] || {
    echo '[error] release payload snapshot expects repository, revision, and destination' >&2
    return 1
  }

  repository="$1"
  revision="$2"
  destination="$3"

  [ -d "$repository" ] && [ ! -L "$repository" ] || {
    echo '[error] release payload source repository is not a real directory' >&2
    return 1
  }
  [ -d "$destination" ] && [ ! -L "$destination" ] || {
    echo '[error] release payload snapshot destination is not a real directory' >&2
    return 1
  }
  [ -z "$(find "$destination" -mindepth 1 -maxdepth 1 -print -quit)" ] || {
    echo '[error] release payload snapshot destination must be empty' >&2
    return 1
  }
  git -C "$repository" cat-file -e "$revision^{tree}" 2>/dev/null || {
    echo '[error] release payload revision does not resolve to a Git tree' >&2
    return 1
  }

  if ! (
    umask 077
    git -C "$repository" archive --format=tar "$revision" |
      tar -x -C "$destination"
  ); then
    echo '[error] unable to materialize release payload Git snapshot' >&2
    return 1
  fi
}
