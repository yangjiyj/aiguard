# T22 controlled acceptance runner

## Scope

This artifact is a separate acceptance-tool candidate based on the frozen T22 source follow-up cc6f820b0f3422f55bd6fcc6511e898f395e1cb7. It does not modify the frozen T22 source candidate.

The runner implements a plan-only default and a gated HTTP apply path for the official T22/T13 API:

- POST /admin/v1/agent/delegations
- POST /admin/v1/agent/authorize
- POST /admin/v1/agent/delegations/{id}/revoke
- GET /admin/v1/agent/delegations/{id}/calls?limit=200

The apply path tests a parent-created child, a nested grandchild, an out-of-scope grant attempt by the child, cross-project denial, one-use quota exhaustion, exact run/instance/tool-call investigation, parent revoke propagation, and a short-TTL denial. The out-of-scope case requires both the exact `delegation exceeds its parent scope` API error and a successful `agents.delegate` call row keyed by that request's idempotency key. Created-grant responses must preserve exact quota maximum/window/expiry. The quota case requires one successful target authorization followed by `reason=quota_exceeded`, and the parent and child investigation views must each return exactly one row per expected tuple with exact action/resource/decision fields. It never calls the T17 ticket mutation API and never claims that an authorization decision is a business effect.

## Current acceptance blockers

Read-only canonical state for 2026-09-26 shows T22.accept, T13.accept, T15.accept, and T17.accept as PLANNED. The T22 acceptance graph requires all three dependency acceptances.

T15 source attempt 824f31b9f01263705ede6cb50aa10a07739f574f carries run_id, instance_id, and tool_call_id through both request and claim reauthorization and has source-scope review only. Canonical T15 state still records SERVER_FEATURE_REVIEWED_BUT_T14_CALLBACK_NOT_INTEGRATED, so this is not yet an accepted or deployed T14/T15 execution path.

Migration 868 is source-only. The T22 source checkout has migration 868; the T15 context-preserve source checkout has migration 866. The required ordered application and a full target database ledger have not been verified by this work. No API, database, migration, service, or business action was executed.

The runner deliberately does not test T15 approval/claim, T17 real effects, or offline outages. A successful runner report therefore remains CONTROL_PLANE_AUTHORIZATION_PASS_EFFECT_AND_OFFLINE_NOT_RUN; it is not a T22.accept verdict. The controller still needs the real child effect receipt and explicit offline-limit evidence.

## Safe invocation

No arguments prints the static plan and performs no network or filesystem writes:

    python3 tools/t22_acceptance/t22_acceptance_runner.py

The apply invocation is for the root runtime owner only, after an explicit apply decision and every gate below passes:

    python3 tools/t22_acceptance/t22_acceptance_runner.py --apply \
      --gate /absolute/private/runtime-gate.json \
      --private-input /absolute/private/fixture-input.json \
      --out-dir /absolute/private/new-run-directory

The two input JSON files must be owned by the invoking user and mode 0600. The parent bearer must be a separate absolute-path file, mode 0600 (or stricter), containing only the 64-hex bearer. The output path must not exist; the runner creates it mode 0700 and creates mode-0600 journal.json and run-report.json before its first HTTP mutation.

Bearer values are held in process memory only and are never written to either output file or printed. Redirects and environment proxies are disabled. The API URL must use HTTPS unless it is loopback. POST calls have no automatic retries. Each request intent and idempotency key is fsynced before the call. A transport/server failure with uncertain mutation outcome stops the run and preserves an unknown-outcome record for root-only reconciliation.

The runner itself does not apply migration files, build or deploy a service, change tenant/project configuration, create a parent principal, or cause a downstream ticket effect.

## Runtime gate contract

runtime-gate.json uses schema t22.runtime-gate.v1. It must contain:

- apply_authorized: true, scope_policy: dedicated_test_environment, is_production: false.
- Exact api_base_url, tenant_id, project_id, and parent_principal_id pins matching the private fixture.
- t22_source_review with status PASS or PASS_SOURCE_DELTA_ONLY, candidate commit `cc6f820b0f3422f55bd6fcc6511e898f395e1cb7`, exact tree `889647de1ccf9332a7269a8f282e9c2ef9308dbf`, and a hash-bound receipt whose embedded candidate commit/tree match both pins.
- Hash-bound controller acceptance receipts for T13.accept, T15.accept, and T17.accept, each marked ACCEPTED. Each receipt must be schema `agent-platform.controller-acceptance-record.v1` and its `node_id`, `candidate_digest`, `status`, and `review_verdict` must bind to the gate entry and the same canonical accepted node.
- server with source commit/tree, binary SHA-256, included_commits containing the exact cc6f820 commit, and process identity fields pid, exact string start_ticks, and executable SHA-256 equal to the expected binary SHA-256.
- t15_context_contract marked ACCEPTED, with exact request and claim context fields run_id, instance_id, tool_call_id, and same_context_reauthorization: true.
- migration marked VERIFIED_APPLIED, with full_ledger_verified: true, a hashed root ledger receipt, a nonsecret SHA-256 database identity, and applied rows for versions 861 through 866 plus 868 in order. The runner pins exact source hashes: 861 `c59fc56888427f9db17dfd97fbc031c678cce8ac14ca1a6f655e17865e9da862`; 862 `1e897afea24bba263e93bebc9e3d903f6286756cf14552b76db8e3c7c8db0d2b`; 863 `36b8991bce3f35e4d296c48bbd930d61959bdaf36023b73eb4a392be87e96fe0`; 864 `26c2ddd010466ba8b4f8adf5b40b6b649752cd740d93a43837eff47fe9bb5975`; 865 `a36b255223027f1b5ad0a761bd5e8cb11e1156089e5cc0860e720b2aea89d3f4`; 866 `2ccd162e4181d6199fcf84cfbf04e88b990ed15d6ab69a8f250548161067de36`; and 868 `8dc50945f3828b6384be3a79bff61efa529a09f537aa2b29e39d39927b70b89c`. Version 867 is not part of the T22 source prerequisite; root still verifies the complete target ledger and the final integrated migration bytes before any apply.
- feature_license marked ACTIVE, with a hash-bound root status receipt.
- clock.offset_verified: true and max_offset_seconds no greater than three.
- offline_policy.no_offline_grant_cache: true, pending_effects_fail_closed: true, and instant_revocation_promised: false.

The runner never obtains the ledger, runtime identity, license, or dependency receipts itself. Root supplies the hash-bound receipts after its authorized read-only checks and migration/deployment procedures. The canonical acceptance record must carry the same accepted node ID and candidate digest as its gate entry; the T22 source-review receipt must carry the exact cc6f820 commit and tree.

## Private input and parent fixture

fixture-input.json uses schema t22.acceptance-private-input.v1 and supplies the API URL, expected tenant/project IDs, a distinct other_project_id, target action/resource, parent bearer file path, bounded TTL/SLO values, and authorize_context.

parent_fixture_receipt is a path+SHA reference to schema t22.parent-fixture.v1. It must be VERIFIED, dedicated_test_environment, and contain the tenant/project, parent principal ID, parent principal expiry, and sanitized parent grant snapshots. The parent needs:

1. agents.delegate on exactly project/{project_id}, conditioned on that project, with quota for at least two creates.
2. The exact target action/resource conditioned on that project with quota for at least two allowed attempts.
3. The child receives an agents.delegate grant with quota for at least two create attempts; the first is the out-of-scope negative case and the second creates the valid grandchild.
4. Parent grant expiries beyond the entire TTL wait.

authorize_context supplies only the nonsensitive scalar conditions required by that target grant; the runner adds the project and generates fresh run/instance/tool-call correlation IDs and a harmless marker. It rejects sensitive-looking context keys and never accepts caller-supplied correlation IDs.

## Durable side effects and cleanup

There is no delete/unlink API for delegation records. A complete apply run leaves:

- One main child relation and its grandchild subtree, revoked through the parent's exact relation ID. The revoke endpoint synchronously revokes descendants.
- One short-TTL child relation and its child principal/call history, retained as expired.
- T13 authorization request/usage rows and investigation rows for the permitted/denied probes.
- The expected child agents.delegate quota use for a failed out-of-scope creation attempt; the handler authorizes the delegation request before the repository rejects its wider resource grant.

The run report names exact created IDs and marks the expired residue. Revocation is recorded as a tombstone, not cleanup or deletion. If the process stops after a mutation whose result is unknown, the durable journal preserves the idempotency key; do not retry automatically or claim cleanup. Root must reconcile the exact outcome read-only before any follow-up.

The API-only runner measures denial timing using the local UTC clock after the root-pinned maximum host clock offset. It records revoke-to-first-probe timing and expiry-to-first-probe timing. Root must choose and approve the target SLOs before apply.

## Evidence boundaries

- A T13 allowed=true response proves only an authorization decision. It does not prove a T17 call, a ticket change, or a downstream effect.
- A denied HTTP response from the T22 API is platform authorization evidence; it is not a model refusal.
- Investigation checks compare exact run/instance/tool-call tuples and check that raw marker values and bearer values do not appear in returned call rows.
- This runner does not test cross-tenant reads; its scope test is the original T22 cross-project denial. A separate tenant-isolation case needs a second root-pinned tenant principal.
- Offline limits are stated from the T22 source contract but are not outage/runtime evidence until root runs and records the separate controlled outage case.
