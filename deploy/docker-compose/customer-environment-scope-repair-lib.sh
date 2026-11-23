#!/usr/bin/env bash

# Historical scope repair is intentionally gated by an exact deployment-owned
# value. Never infer this from request metadata or from a missing variable: the
# same upgrade tooling is also used by home, Claude and Codex deployments.
customer_environment_scope_repair_enabled() {
  [[ "${GATEWAY_ENVIRONMENT_SCOPE-}" == customer ]]
}
