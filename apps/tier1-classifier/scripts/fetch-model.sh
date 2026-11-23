#!/bin/sh
# Historical release entrypoint. Formal releases accept only the reviewed local
# model input and never download a replacement model.
set -eu

echo '[error] fetch-model.sh is retired for formal releases.' >&2
echo '[error] Use deploy/docker-compose/build-offline-images-for-arch.sh with TIER1_OWNED_MODEL_INPUT.' >&2
exit 78
