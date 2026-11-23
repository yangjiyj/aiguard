# Judge coverage and bounded admission

Inputs of at most 1200 characters retain the Tier-1 fast path. Longer inputs
are sent to the judge in 1200-character windows with 200-character overlap.
Every window, including the short final window, bypasses Tier-1 gating:
a low score on text containing unrelated context must not exclude its tail.
This intentionally increases judge demand for long input; it is not a model
throughput improvement. Evaluate long-text completion as well as latency.

The existing shared request deadline and SECURITY_SEMANTIC_MAX_WINDOWS limit
remain authoritative. Exhausted budgets return semantic_telemetry with
incomplete coverage; they must never be counted as inspected benign content.
Semantic findings retain their window locations and counting state during
deduplication, so an earlier observation cannot erase a later confirmed attack.

Completed model opinions for long windows have a per-configuration in-memory
LRU cache: SECURITY_JUDGE_WINDOW_CACHE_SIZE defaults to 512 (maximum 4096),
SECURITY_JUDGE_WINDOW_CACHE_TTL to 60 seconds (maximum 300). Keys hash the exact
judge input, content source and task context; no original content is kept as a
cache key. Errors and incomplete calls are never cached. Policy processing and
review are still evaluated per request, and a managed configuration replacement
creates a new cache. When changing weights behind an unchanged endpoint and model
alias, restart the engine too so old opinions cannot survive that change.
Performance reports must distinguish repeated history from fresh text.

Regular judge calls may recover a briefly occupied inference slot. They wait
at most SECURITY_JUDGE_REGULAR_QUEUE_WAIT (default 3 seconds), also limited by
SECURITY_JUDGE_QUEUE_WAIT and the request budget after reserving
SECURITY_JUDGE_QUEUE_CALL_RESERVE (default 1 second, capped by the operation
timeout). The operation timeout is an upper bound, not a duration estimate;
reserving all of it can reject a short call behind a briefly busy slot.
SECURITY_JUDGE_QUEUE_CAPACITY (default 8) bounds regular
waiters. It does not exclude the existing high-priority wait path. Actual
execution remains bounded by SECURITY_JUDGE_CAPACITY and SECURITY_JUDGE_WORKERS.
Socket timeout is recomputed after admission, parent cancellation is observed,
and running work holds capacity until it actually finishes.

Unconfirmed suspicious opinions remain observations with
counts_as_security_finding=false. Only a valid malicious review can promote
them; its category and evidence reason come from the reviewer. An invalid
review category produces incomplete telemetry instead of a counting attack.

Evaluate three separate outcomes: counting security findings, non-counting
observations, and incomplete inspection. Do not count severity alone as an alert.

Long-window evaluation uses a separately configured orchestration pool (default
four workers), shared across requests. Each request uses at most that configured
number of windows in flight. Exhausted
orchestration capacity falls back to synchronous work; it does not create an
unbounded queue. The inference worker/capacity limits and original deadline
remain authoritative. Window results are consumed in source order, and a gap
still produces incomplete telemetry. Completed slots immediately accept the next window while result delivery stays
in source order. Exact duplicates wait for their cache-producing window.

The gateway can recover transient semantic timeout/capacity results even when
HTTP inspection itself completed. At most two single-item recovery attempts
share the original request deadline. A successful HTTP call is not sufficient
for semantic completion. No page action or global failure policy changes.

Development releases may explicitly set --semantic-max-windows (any positive integer). The
manifest records this capacity change, only the security-engine environment is
changed, and rollback retains the previous value. Ordinary defaults stay at 32.
The 2026-09-20 alert UI/runtime release selects 128 because retained tool output
requires more than 32 windows; request and inference timeouts are unchanged.


Unchanged authenticated configuration heartbeats retain the current detector
and its caches. Both the held revision and effective override values must match;
a real change (including changed values with a reused revision) rebuilds the
snapshot. Validation, attestation, health checks and reporting still run.

SECURITY_SEMANTIC_WINDOW_PARALLELISM defaults to four and accepts any positive integer.
The explicit development release flag --semantic-window-parallelism sets this
limit together with SECURITY_JUDGE_WORKERS and SECURITY_JUDGE_CAPACITY. It is
recorded in the manifest and supported for a full or security-engine-only
release; rollback keeps all original values. The 7B service already has eight
slots. Selecting eight engine slots does not change the model service or weights.


Deployment capacity and cluster endpoint examples: `docs/deployment-capacity.md`
at the repository root. Standard and offline Compose propagate customer values;
no upper clamp is applied to window concurrency or maximum window count. Judge
workers inherit window concurrency when unset, and judge capacity inherits the
worker count. Explicit overrides still take precedence. Large window plans also
observe the parent deadline during planning, before any inference is submitted.


### Batch deadline and request fairness (2026-09-23)

`SECURITY_SEMANTIC_REQUEST_PARALLELISM` bounds each request independently of
the shared window/inference pool. Unset inherits shared window parallelism;
it accepts any positive integer and cannot consume more shared slots than exist.
This changes scheduling only: every planned window remains subject to the
original coverage and deadline checks, and uninspected tails stay incomplete.

The batch deadline defaults to at most 18 seconds (or a shorter input envelope),
leaving transport headroom under the default 20-second gateway client. Explicit
operator settings remain authoritative. Existing deployments with an explicit
8-second value must be updated deliberately; the candidate release supports
`--security-batch-budget-seconds` and `--semantic-request-parallelism`, records
both in its manifest, and restores old values on rollback. Select the batch
deadline above the managed semantic budget and below the outer caller deadline;
the home candidate uses 18 / 15 / 14 seconds (batch / semantic / judge), an
16-slot shared pool, and at most 4 windows per request. This is a candidate
capacity setting, not a throughput promise.

The engine now reports non-operational when a five-minute window has at least
five attempts and fewer than 95% succeeded. A successful probe cannot erase
real traffic timeouts. Old failures expire normally; the circuit breaker and
incomplete-detection policy are unchanged. The control plane consumes this
degraded receipt even when its legacy independent success floor is lower.

Concurrent requests for the same exact long window and context share one pending
inference. Waiting callers retain their own deadline and cancellation; they do
not extend or cancel the owner. Failed/cancelled owners never populate the cache
and always release waiters. Different content, source or task context remains
independent. The in-flight map is bounded by the existing worker/admission pools.
