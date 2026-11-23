#!/usr/bin/env bash
# Shared, normalized build-host identity capture.  The release builder uses the
# active Buildx identity; Task4's legacy daemon builds use the daemon subset.

build_identity_fail() {
  printf '[error] build identity verification failed: %s\n' "$1" >&2
  return 1
}

build_identity_json() {
  local docker_cmd=${1:-docker}
  local client server buildx inspect
  client="$("$docker_cmd" version --format '{{.Client.Version}}')" || {
    build_identity_fail 'unable to identify Docker client'; return 1;
  }
  server="$("$docker_cmd" version --format '{{.Server.Version}}')" || {
    build_identity_fail 'unable to identify Docker server'; return 1;
  }
  buildx="$("$docker_cmd" buildx version | tr '\n' ' ' | sed 's/[[:space:]]*$//')" || {
    build_identity_fail 'unable to identify Docker Buildx'; return 1;
  }
  inspect="$("$docker_cmd" buildx inspect)" || {
    build_identity_fail 'unable to identify active Buildx nodes'; return 1;
  }
  python3 - "$client" "$server" "$buildx" "$inspect" <<'PY'
import json
import re
import sys

client, server, buildx, inspect = sys.argv[1:]
for name, value in (("Docker client", client), ("Docker server", server),
                    ("Buildx", buildx)):
    if not value or any(ch in value for ch in "\r\n\x00"):
        raise SystemExit(f"invalid {name} identity")
builder = None
nodes = []
in_nodes = False
current = None
for raw in inspect.splitlines():
    line = raw.strip()
    if line == "Nodes:":
        in_nodes = True
        continue
    # Node sub-sections (Labels:, Devices:, GC Policy ...) list their entries
    # indented, e.g. CDI devices print " Name: nvidia.com/gpu=0".  Only an
    # unindented Name: line identifies the builder or a Buildx node.
    if raw[:1].isspace():
        continue
    match = re.fullmatch(r"Name:\s*(.+)", line)
    if not in_nodes and match and builder is None:
        builder = match.group(1)
        continue
    if not in_nodes:
        continue
    if match:
        if current is not None:
            nodes.append(current)
        current = {"name": match.group(1)}
        continue
    if current is None:
        continue
    for prefix, key in (("Endpoint:", "endpoint"), ("Status:", "status"),
                        ("BuildKit version:", "buildkit_version")):
        if line.startswith(prefix):
            current[key] = line[len(prefix):].strip()
            break
if current is not None:
    nodes.append(current)
if builder is None:
    raise SystemExit("Buildx builder identity is incomplete")
for node in nodes:
    if set(node) != {"name", "endpoint", "status", "buildkit_version"}:
        raise SystemExit("Buildx node identity is incomplete")
    if any(not value or any(ch in value for ch in "\r\n\x00") for value in node.values()):
        raise SystemExit("Buildx node identity is invalid")
if not nodes or len({node["name"] for node in nodes}) != len(nodes):
    raise SystemExit("Buildx node identity is incomplete or duplicated")
print(json.dumps({
    "docker_client_version": client,
    "docker_server_version": server,
    "buildx_version": buildx,
    "buildx_builder": builder,
    "buildx_nodes": nodes,
}, sort_keys=True, separators=(",", ":")))
PY
}

buildx_engine_json() {
  local identity=$1
  python3 - "$identity" <<'PY'
import json
import sys

identity = json.loads(sys.argv[1])
required = {"docker_client_version", "docker_server_version", "buildx_version",
            "buildx_builder", "buildx_nodes"}
if not isinstance(identity, dict) or set(identity) != required:
    raise SystemExit("build identity schema is invalid")
print(json.dumps({"kind": "buildx", "builder": identity["buildx_builder"],
                  "nodes": identity["buildx_nodes"]},
                 sort_keys=True, separators=(",", ":")))
PY
}

docker_daemon_engine_json() {
  local docker_cmd=${1:-docker}
  local client server
  client="$("$docker_cmd" version --format '{{.Client.Version}}')" || {
    build_identity_fail 'unable to identify Docker client'; return 1;
  }
  server="$("$docker_cmd" version --format '{{.Server.Version}}')" || {
    build_identity_fail 'unable to identify Docker server'; return 1;
  }
  python3 - "$client" "$server" <<'PY'
import json
import sys

client, server = sys.argv[1:]
if not client or not server or any(ch in client + server for ch in "\r\n\x00"):
    raise SystemExit("Docker daemon identity is invalid")
print(json.dumps({"kind": "docker-daemon", "docker_client_version": client,
                  "docker_server_version": server},
                 sort_keys=True, separators=(",", ":")))
PY
}

assert_build_identity_unchanged() {
  local expected=$1 docker_cmd=${2:-docker} observed
  observed="$(build_identity_json "$docker_cmd")" || return 1
  [[ "$observed" == "$expected" ]] || {
    build_identity_fail 'Buildx identity drifted during or after image construction'
    return 1
  }
}

assert_docker_daemon_identity_unchanged() {
  local expected=$1 docker_cmd=${2:-docker} observed
  observed="$(docker_daemon_engine_json "$docker_cmd")" || return 1
  [[ "$observed" == "$expected" ]] || {
    build_identity_fail 'Docker daemon identity drifted during or after Task4 construction'
    return 1
  }
}
