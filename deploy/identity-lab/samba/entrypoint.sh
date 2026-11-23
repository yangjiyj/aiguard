#!/usr/bin/env bash
# Start the upstream Samba image, then seed the lab identities only after AD is ready.
set -euo pipefail

# Docker rootless volume ownership is mapped to the host UID. Samba refuses a TLS
# key not owned by root (CVE-2013-4476), so fix the ownership inside its namespace.
chown 0:0 /var/lib/samba/private/tls/cert.pem \
  /var/lib/samba/private/tls/key.pem \
  /var/lib/samba/private/tls/ca.pem
chmod 600 /var/lib/samba/private/tls/key.pem

/init.sh &
init_pid=$!

cleanup() {
  kill "$init_pid" 2>/dev/null || true
  wait "$init_pid" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

# /init.sh enables the lab's no-complexity policy after domain provision. Do
# not seed against the partially-created SAM database before that setting lands.
until test -f /etc/samba/external/smb.conf && \
  samba-tool domain passwordsettings show 2>/dev/null | grep -Fqx 'Password complexity: off'; do
  if ! kill -0 "$init_pid" 2>/dev/null; then
    wait "$init_pid"
    exit 1
  fi
  sleep 1
done

# The image's initial provision resets the key ownership after the early chown.
chown 0:0 /var/lib/samba/private/tls/cert.pem \
  /var/lib/samba/private/tls/key.pem \
  /var/lib/samba/private/tls/ca.pem
chmod 600 /var/lib/samba/private/tls/key.pem
/bin/bash /provision.sh
wait "$init_pid"
