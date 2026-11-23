#!/bin/sh
# Historical release entrypoint. Formal releases must package the reviewed
# user-trained model instead of training a replacement on the build host.
set -eu

echo '[error] build-baseline-model.sh is retired for formal releases.' >&2
echo '[error] Use deploy/docker-compose/build-offline-images-for-arch.sh with TIER1_OWNED_MODEL_INPUT.' >&2
exit 78
