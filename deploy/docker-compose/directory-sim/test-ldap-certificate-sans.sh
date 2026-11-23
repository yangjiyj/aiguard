#!/usr/bin/env sh
set -eu

compose_file=${1:-directory-sim/docker-compose.yml}
bootstrap_file=${2:-directory-sim/bootstrap-home-identity-test.sh}

grep -Fq 'subjectAltName=DNS:ldap-sim.jjdguard.test' "$compose_file"
grep -Fq 'LDAP_TLS_VERIFY_CLIENT: never' "$compose_file"
grep -Fq 'subjectAltName=DNS:dc-sim.ad.jjdguard.test,DNS:dc-sim' "$bootstrap_file"
grep -Fq -- '-checkhost dc-sim.ad.jjdguard.test' "$bootstrap_file"
grep -Fq 'install -m 0600 lab-ca.key.new lab-ca.key' "$bootstrap_file"
! grep -Eq 'docker (cp|exec.*cat).*lab-ca.key' "$bootstrap_file"
