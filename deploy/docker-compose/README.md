# Private Deployment Guide

This compose bundle is for private/customer environments.

## What changed for production use

- Web console runs the **production nginx image**, not Vite dev mode.
- `gateway-core`, `control-plane`, `security-engine`, and `web-console` all expose health checks.
- Provider secret encryption key is **required** through `JJD_PROVIDER_SECRET_KEY`.
- Bootstrap admin credentials are **required** through `BOOTSTRAP_ADMIN_*`.
- PostgreSQL init no longer loads `002_seed_data.sql` demo data.
- Bootstrap creates only the private deployment defaults:
  - tenant: `tenant_default`
  - admin user: value of `BOOTSTRAP_ADMIN_USERNAME`

Change the bootstrap admin password immediately after first login.

## One-click deployment

```bash
cd deploy/docker-compose
sh deploy-oneclick.sh
```

This script will:

- auto-generate `.env` when it does not exist
- auto-pick available ports when defaults are occupied
- auto-generate provider, internal API, audit-chain, PostgreSQL, Redis, and admin secrets
- bind external entry points to the detected host IP and keep internal services on `127.0.0.1`
- auto-generate the bootstrap admin password
- start the whole stack
- apply private migrations
- initialize runtime defaults
- run a smoke test
- print the final access URLs and admin password

It also writes the final result to:

```bash
deploy/docker-compose/.deploy-result
```

## Offline deployment

### JJDGuard 2.6.7 customer contract

The customer package is a self-contained Linux x86_64/amd64 installer. It does not require
Python, pip, pypdf, OCR packages, OpenSSL, a pre-installed verifier, a public key, or any
manual signature operation on the customer host.

The same package works on amd64 Hygon hosts and distribution families such as Kylin, UOS,
and openEuler when the host provides a normal Linux shell, tar/gzip, SHA-256 utility, and
root or sudo. The package includes the Docker Engine/Compose fallback for amd64 hosts and
selects a safe init integration. ARM and loongarch64 are outside the 2.6.7 delivery matrix.

The installer detects a fresh host or an existing JJDGuard release, validates the package
contents before changing the host, preserves data/configuration, and writes rollback state
before an in-place upgrade. If an upgrade fails, it stops the new stack and restores the
previous fixed release and its database backup.

For customer delivery, keep the `.run` and its checksum together without renaming them:

```bash
JJDGuard-offline-<version>-<shortsha>-amd64.run
JJDGuard-offline-<version>-<shortsha>-amd64.run.sha256
```

Verify the checksum, mark the file executable, then install or repair with one command:

```bash
sha256sum -c JJDGuard-offline-<version>-<shortsha>-amd64.run.sha256
chmod +x JJDGuard-offline-<version>-<shortsha>-amd64.run
sudo ./JJDGuard-offline-<version>-<shortsha>-amd64.run
```

The sealed installer verifies its embedded payload before extracting it. Do not manually extract
the archive or invoke internal install scripts.

The installer will auto-generate local secrets, ports, bootstrap admin password,
load Docker images, start services, apply migrations, and run a smoke test.

For a source checkout or engineering investigation, build commands remain under `deploy/docker-compose`, but those raw artifacts are not a customer installation path.

## Optional local AI triage

The security engine can attach an AI triage explanation to deterministic rule findings.
This is optional and disabled by default:

```env
SECURITY_LLM_JUDGE_MODE=off
SECURITY_LLM_JUDGE_URL=http://127.0.0.1:8091/v1/chat/completions
SECURITY_LLM_JUDGE_MODEL=qwen2.5-7b-instruct-local
SECURITY_LLM_JUDGE_TIMEOUT=8
SECURITY_LLM_JUDGE_API_KEY=local-test-key
```

For offline customers, keep `SECURITY_LLM_JUDGE_MODE=off` unless they already have an
intranet OpenAI-compatible model endpoint. When available, set the mode to `shadow` and
point `SECURITY_LLM_JUDGE_URL` to that local endpoint.

Shadow mode only writes review explanations, suggested actions, and customer-facing report
text into alert evidence. It does not automatically allow, block, mask, or downgrade requests.
Deterministic rules still make the gateway decision. Redline findings such as private keys,
real tokens, cloud metadata, malicious scripts, and high-risk internal endpoints cannot be
downgraded by the model; actual enforcement still follows the global audit/strict runtime mode.

## Manual deployment

```bash
cd deploy/docker-compose
cp .env.example .env
vi .env
docker compose up -d --build
```

Then run:

```bash
sh smoke-test.sh
```

If you want the environment to become immediately usable after the stack is up, fill in
`DEFAULT_PROVIDER_*` in `.env` and run:

```bash
sh bootstrap-runtime.sh
```

That script will:

- enable content audit and tool audit
- initialize default detector rules
- create the configured upstream provider
- sync models from that provider
- create an internal API key for `project_default`

For an existing private deployment, take a backup first and then run the explicit migration script:

```bash
sh backup-db.sh
sh migrate-private.sh
```

## One-command upgrades

Use `upgrade.sh` for repeatable single-instance upgrades. It performs preflight checks,
creates a database backup, switches service images by immutable digest, runs the shared
migration runner, validates PostgreSQL state, runs the existing smoke test, and then performs
a real forwarding probe through the gateway/proxy. If image switch, migration, smoke, or the
real forwarding probe fails, the script switches images back to the previous known-good
digests recorded in `UPGRADE_STATE_FILE`.

Example:

```bash
cd deploy/docker-compose
UPGRADE_MIN_DATA_VERSION=077_request_logs_proxy_access_type_resolved.sql \
UPGRADE_FORWARD_PROBE_URL=http://127.0.0.1:8082/v1/models \
bash upgrade.sh \
  --customer-deployment \
  --from-version 2026.06.21 \
  --to-version 2026.06.22 \
  --gateway-core docker-compose-gateway-core@sha256:<64-hex-digest> \
  --control-plane docker-compose-control-plane@sha256:<64-hex-digest> \
  --security-engine docker-compose-security-engine@sha256:<64-hex-digest> \
  --proxy-server docker-compose-proxy-server@sha256:<64-hex-digest> \
  --web-console docker-compose-web-console@sha256:<64-hex-digest>
```

Operational notes:

- Do not pass `:latest`; every upgraded service image must use `IMAGE@sha256:<digest>`.
- For a customer one-click installation created before deployment scope was persisted, pass
  `--customer-deployment`. It adds `customer` only when the scope is absent, preserves an
  existing valid home/Claude/Codex/customer scope, and fails on an invalid value.
- `UPGRADE_MIN_DATA_VERSION` is required. The upgrade stops during preflight when the target
  version's minimum data version is not provided or the live database is below it.
- Set `UPGRADE_FORWARD_PROBE_URL` to a real or near-real upstream path that proves traffic
  traverses the gateway/proxy to an upstream service. The older smoke test is still run, but
  it is not the only upgrade health check.
- `upgrade.sh` calls `migrate-private.sh`, then queries the live Postgres container to verify
  baseline tables and `schema_migrations`. This covers existing databases created by `initdb`
  before `schema_migrations` existed, because the shared migration runner records the initdb
  baseline before applying later migrations.
- Logs are written under `upgrade-logs/` by default. Database backups are written under
  `backups/`. Each upgrade step logs its result and duration. The last known-good digest state
  is stored at `.upgrade/current-digests.env`; if that file is missing, preflight attempts to
  capture current service digests from the compose host before changing images. If a complete
  rollback anchor cannot be built for the services being upgraded, the script stops before
  backup, override generation, or `docker compose up`.
- On failure after migrations have started, image rollback is attempted automatically, but
  database changes are not reverted automatically. The script prints the backup path so the
  operator can make an explicit restore decision.
- The script is intended for the customer/test compose host. It does not phone home and does
  not push, merge, deploy to any remote environment, or restore databases automatically.

### Air-gapped (offline) upgrades

`upgrade.sh` is self-contained on air-gapped hosts and no longer requires a manual
`docker load` before the upgrade:

- After preflight and backup, and before switching images, the script runs an idempotent
  image-import step. If an `offline-artifacts/jjdguard-offline-images-*.tar.gz`
  archive is present (the same archive produced by `export-offline-images.sh` and shipped in
  the offline bundle), it verifies the `.sha256` checksum and runs `docker load` automatically.
  If no archive is present the step is skipped, so environments that pre-stage images via CI
  keep working unchanged. Point `OFFLINE_IMAGE_ARCHIVE=/path/to/archive.tar.gz` at a specific
  archive to override discovery.
- The offline bundle ships only `docker-compose.offline.yml`. When `COMPOSE_FILE` is not set
  explicitly and `docker-compose.yml` is absent, `upgrade.sh` auto-selects
  `docker-compose.offline.yml`. Set `COMPOSE_FILE=docker-compose.offline.yml` to force it.

### Offline bundle in-place upgrade (customer one-command)

When a new offline `.run` is delivered, verify its checksum and run it directly. The installer
detects an existing JJDGuard installation and performs the in-place upgrade or repair:

```bash
sha256sum -c JJDGuard-offline-<version>-<shortsha>-amd64.run.sha256
sudo ./JJDGuard-offline-<version>-<shortsha>-amd64.run
```

Do not manually extract raw archives or invoke internal installation scripts.

Keep the previous installation directory, old images, data volumes, and backups through the
suggested observation window. For a failed upgrade, retain the installer output before making an
explicit rollback decision.

## Ports

- Web Console: `https://<host>:${WEB_HTTPS_PORT}` (default `443`, self-signed certificate)
- Gateway API: `http://<host>:${GATEWAY_PORT}` (default `8080`)
- Control Plane API: `http://<host>:${CONTROL_PORT}` (default `8081`)
- Security Engine: `http://<host>:${SECURITY_PORT}` (default `8000`)
- Forward Proxy: `http://<host>:${FORWARD_PROXY_PORT}` (default `3128`)

Database and Redis host port exposure are also configurable through:

- `POSTGRES_PORT` (default `5432`)
- `REDIS_PORT` (default `6379`)

## Bind addresses

The compose files expose only the customer-facing entry points on all interfaces by default. Internal control, detection, database, and cache ports still fall back to `127.0.0.1`.

The one-click and offline installers generate customer-local `.env` values:

- `WEB_BIND`, `WEB_HTTPS_BIND`, `GATEWAY_BIND`, `PROXY_BIND`, and `FORWARD_PROXY_BIND` default to `0.0.0.0` so multi-NIC hosts can be reached through every configured address. Set `JJD_EXTERNAL_BIND=<customer reachable IP>` before first install when the delivery requires a single restricted bind address.
- `CONTROL_BIND`, `SECURITY_BIND`, `POSTGRES_BIND`, and `REDIS_BIND` default to `127.0.0.1`.

For customer delivery, do not hard-code an internal lab IP in the repository. The generated `.deploy-result` lists the detected access URLs, and the generated TLS certificate includes all detected non-loopback IPv4 addresses.

When the optional `vm-proxy` profile is enabled, set `FORWARD_PROXY_VM_BIND` and `FORWARD_PROXY_VM_PORT` only if the VM needs a dedicated proxy address. The default VM profile bind is `127.0.0.1:3129` so it cannot conflict with the main multi-NIC proxy listener.

## Health checks

```bash
curl http://127.0.0.1:8080/health
curl http://127.0.0.1:8081/health
curl http://127.0.0.1:8000/health
curl -k https://127.0.0.1:${WEB_HTTPS_PORT:-443}/health
```

Expected result: HTTP 200.

## Important operational notes

1. The PostgreSQL init scripts run only on the **first** database initialization.
2. If `postgres-data` already exists, changing init SQL files will not re-apply automatically.
3. For upgrades on an existing environment, run `backup-db.sh` and `migrate-private.sh` instead of deleting the data volume.
4. Provider API keys configured in the admin console or `bootstrap-runtime.sh` are encrypted using `JJD_PROVIDER_SECRET_KEY`.
5. The bootstrap admin is forced to change the configured initial password before accessing other administrative functions.
