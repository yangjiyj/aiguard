#!/bin/sh
set -eu

invalid_payload() {
  echo '[error] invalid built-in identity mount payload' >&2
  exit 1
}

[ "$#" -eq 1 ] && [ -n "$1" ] || invalid_payload
bundle_root="$1"

for directory in \
  "$bundle_root" \
  "$bundle_root/chat" \
  "$bundle_root/chat/keycloak-realm" \
  "$bundle_root/chat/keycloak-themes" \
  "$bundle_root/chat/keycloak-themes/jjdguard" \
  "$bundle_root/directory-truststore"; do
  [ -d "$directory" ] && [ ! -L "$directory" ] || invalid_payload
done

set -- \
  "$bundle_root/chat/keycloak-realm" \
  "$bundle_root/chat/keycloak-themes/jjdguard" \
  "$bundle_root/directory-truststore"

# Validate every mount tree before changing any mode.
for identity_root in "$@"; do
  invalid_member="$(find "$identity_root" ! -type d ! -type f -print -quit)" ||
    invalid_payload
  [ -z "$invalid_member" ] || invalid_payload
done

for identity_root in "$@"; do
  find "$identity_root" -type d -exec chmod 0755 {} +
  find "$identity_root" -type f -exec chmod 0644 {} +
done
