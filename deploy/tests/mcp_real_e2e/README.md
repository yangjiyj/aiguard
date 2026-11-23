# MCP real closed-loop acceptance

This harness proves the MCP gateway against real JJDGuard processes and a real
PostgreSQL database. Handler mocks do not count as acceptance.

## Run

From the repository root on the development host:

```bash
bash deploy/tests/mcp_real_e2e/run.sh
```

The harness creates an isolated Compose project, dedicated PostgreSQL and Redis
volumes, real control-plane/security-engine/gateway images, and three controlled
Streamable HTTP upstreams. It uses random credentials and loopback-only host
ports.

The default run removes all test containers, networks, volumes, images,
credentials, Claude Code test configuration, and database data. It retains only
the sanitized evidence JSON and migration log under:

```text
.artifacts/mcp-real-e2e/<run-id>/
```

Set `MCP_E2E_KEEP=1` only for local diagnosis. Never use that option on a shared
customer deployment.

## Coverage

The acceptance client verifies:

- Streamable HTTP negotiation for MCP `2025-11-25`, session propagation, and
  rejection of JSON-RPC batches;
- explicit private-egress opt-in, DNS/IP target validation, stored upstream
  credential injection, and removal of caller credentials;
- clean asset synchronization using approved immutable snapshots;
- strict `allow`, `audit`, `block`, deterministic admission protection, and confirmation
  decisions;
- identical client retries mapping to one pending confirmation and exactly one
  upstream execution after approval;
- the original MCP session retrieving the exact cached `CallToolResult` with
  the same JSON-RPC id after approval, including stable repeated retrieval with
  no second upstream execution;
- repeated administrator approval causing no replay;
- approval-context drift failing closed without forwarding the encrypted old
  request to a changed route or credential, proven by upstream counters and
  PostgreSQL execution facts;
- tenant isolation at the public `/mcp/{serverID}` boundary;
- description-poison, divergent shadow-tool, and rug-pull quarantine;
- deterministic admission description scanning even when runtime AgentGuard is
  disabled;
- non-streaming response capacity limits;
- decision, result, admission, confirmation, and encrypted replay evidence in
  PostgreSQL;
- Claude Code remote HTTP MCP capability and a temporary connection smoke when
  the installed CLI supports it.

## Controlled upstream

`mock_mcp_server.py` is an intentionally small protocol server. It supports
`initialize`, `notifications/initialized`, `tools/list`, `tools/call`, session
deletion, and a bounded SSE ping. Test-only control modes are:

- `clean`
- `poison`
- `rug_pull`
- `shadow`
- `huge`
- `delay`

The state endpoint stores only counters and SHA-256 argument digests. It never
returns raw authorization values or raw tool arguments.

Run its dependency-free contract tests with:

```bash
python3 deploy/tests/mcp_real_e2e/test_mock_mcp_server.py
bash deploy/tests/mcp_real_e2e/test_claude_output.sh
```
bash deploy/tests/mcp_real_e2e/test_log_sanitize.sh
