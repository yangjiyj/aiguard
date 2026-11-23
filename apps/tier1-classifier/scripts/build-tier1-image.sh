#!/bin/sh
# Historical release entrypoint. It cannot construct a formal image because
# formal release provenance requires the reviewed Git archive and owned input.
set -eu

echo '[error] build-tier1-image.sh is retired for formal releases.' >&2
echo '[error] Use deploy/docker-compose/build-offline-images-for-arch.sh with TIER1_OWNED_MODEL_INPUT.' >&2
exit 78
