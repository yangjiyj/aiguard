# Audit query budget benchmark

This harness measures the control-plane HTTP handlers together with PostgreSQL. It does not include network transfer, browser parsing, or browser rendering.

## Requirements

- Linux host with `bash`, Docker, `psql`, Go, and `sha256sum`
- Local `postgres:16-alpine` image; the runner never pulls an image
- At least 5 GB free for 100k, or 25 GB for 1M
- A clean output directory below the repository root

The runner creates an isolated PostgreSQL container, applies the real migrations, seeds deterministic synthetic data, compiles the handler test harness, and removes the container on exit. Set `JJD_QUERY_BENCHMARK_KEEP=1` only when manual database inspection is required.

## Run

```bash
bash tools/performance/audit-query-budget/run.sh \
  100000 \
  work/audit-query-budget-optimized-100k
```

An optional comma-separated third argument restricts every phase to named cases:

```bash
bash tools/performance/audit-query-budget/run.sh \
  100000 \
  work/audit-query-budget-runs-100k \
  access_runs,access_runs_exact_count
```

The only supported scales are `100000` and `1000000`. Results under `work/` are raw local evidence and must not be committed. A report should record their paths and SHA256 hashes.

## Fixed environment

- PostgreSQL 16 Alpine
- 2 CPUs, 2 GiB memory, 256 MiB shared memory
- `shared_buffers=256MB`, `effective_cache_size=1GB`, `work_mem=16MB`
- `random_page_cost=1.1`, JIT disabled, 40 maximum connections
- Target tenant plus 10% cross-tenant noise
- Customer environment scope and a fixed 2026-08-01 through 2026-10-01 query window

At 100k the target tenant contains 100k request logs, 140k content logs, 80k access content logs, 10k security events, 100k tool-call logs, and 100k evidence-run index rows. The seed also includes ACL-only, content-only, old-tail, and common Chinese keyword matches so an empty result cannot pass as fast.

## Phases

- `pg-restart-cold`: one request after restarting PostgreSQL. This clears PostgreSQL shared buffers but does not clear the host page cache, so it is not a cold-disk measurement.
- `hot`: one warm-up followed by five sequential samples.
- `concurrent`: one warm-up followed by ten simultaneous requests.
- `explain`: one request per case with `auto_explain`, `ANALYZE`, and buffers enabled. HTTP and application-level failures are recorded and do not stop later plan collection.
- `cancelled`: an already-cancelled context probe for the expensive access keyword path.

Every JSONL result records latency, response-body bytes, HTTP status distribution, application error codes, successful request count, and completeness. Keyword concurrency should be read as two admitted requests plus busy rejections, not as ten successful searches. The access records/runs cases use the real console contract (`skip_total=true` and `limit+1`); matching `*_exact_count` cases retain the legacy exact-count path as a control.

## Outputs

- `environment.txt`: revision, host, container, PostgreSQL, cache boundary, and measurement layer
- `table-counts.tsv`: seeded row counts by tenant
- `pg-restart-cold.jsonl`, `hot.jsonl`, `concurrent.jsonl`: timed samples
- `explain.jsonl`: explain-phase handler results
- `auto-explain.log`: exact SQL plans with actual buffers
- `migrations.log`, `seed.log`: setup evidence

Useful summaries:

```bash
jq -r '[.case,.phase,.p95_ms,.response_body_bytes,.goal_met,.completeness_met,.successes,(.status_counts|tojson),([.samples[].error_code // empty]|unique|join(","))]|@tsv' \
  work/audit-query-budget-optimized-100k/hot.jsonl

sha256sum work/audit-query-budget-optimized-100k/{environment.txt,hot.jsonl,concurrent.jsonl,pg-restart-cold.jsonl,explain.jsonl,auto-explain.log,table-counts.tsv}
```

Do not publish migration logs or connection strings. The runner uses an ephemeral local benchmark password and does not include the DSN in `environment.txt`.
