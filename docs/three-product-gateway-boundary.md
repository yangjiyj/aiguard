# Independent JJDGuard gateway boundary

Source: fa5f7f2a. This patch is not deployed and creates no runtime identity.

The gateway console now always identifies as JJDGuard, ignoring stale PRODUCT_PROFILE inputs. Endpoint enrollment, platform assets and native timelines move to the independently deployed platform. Gateway AgentGuard, MCP protection, model traffic detection, routing, gateway sessions and tool audit remain intact. Existing platform tables/history remain for migration/rollback; they are not deleted by this patch.

## Dedicated connector capability

Provision a new gateway-native identity named `agent-platform-jjdguard`, role `platform_connector`, active, one explicit tenant, after separate runtime authorization. Never reuse a human administrator. The dedicated `POST /admin/v1/service-login` validates username/password and issues the gateway's own opaque session token. It rejects all other roles and credentials requiring rotation. Redis applies 10 attempts/account/minute and 60/IP/minute, temporary lock 60s, fail closed without Redis. Logs contain account/IP hashes and success/failure audit IDs, never password/token.

Closed route contract (including RBAC dry-run and administrative grants):
- GET /admin/v1/me
- GET, POST /admin/v1/security/policies
- PATCH /admin/v1/security/policies/{id}
- GET /admin/v1/security/policy-assets
- PUT /admin/v1/security/policy-assets/{id}
- GET, POST /admin/v1/agentguard/policies
- PUT /admin/v1/agentguard/policies/{id}
- GET, POST /admin/v1/mcp-policies
- PUT /admin/v1/mcp-policies/{id}

Every handler uses the authenticated gateway tenant; body-supplied foreign tenant fields are rejected or overwritten by server authority. Grants do not widen this role. No DELETE, user/admin/provider/key/upgrade/internal platform endpoint access. Security events are readable only as the same-tenant minimal risk metadata projection (GET /admin/v1/audit/events via connectorRiskMetadata: IDs, type, severity, rule, action, principal key, timestamps; never matched_summary, evidence pointers or bodies). Audit operations, content audit, exports and risk dispositions remain explicitly denied. The role seed uses gateway_security_policies and AgentGuard/MCP policy read/write, with no audit resource. The dedicated role is enforced by role + closed routes, not broader legacy security_events permission aliases.

Risk metadata projection is prepared for a future separately authorized read contract, but currently unreachable by this role. It includes only id, request_id, tenant_id, project_id, user_id, event_type, severity, rule_id, action_taken, principal_key, created_at. No matched_summary, evidence_ref, rule_name, bodies, provider credentials or unknown future fields.

## Deployment and rollback

No running JJDGuard or LSE service is modified. Existing home production upgrades must use deploy/release/home-service-release.sh from clean live-main and its controlled immutable archive build; this feature branch must pass review/integration before that release gate. Do not hand-build or override an existing compose service.

Proposed independent validation instance, pending explicit runtime authorization: /home/dev/jjdguard-connector-validation-20261001, separate compose project/service names, ports API 18881/gateway 18880/web 15881/DB 55465 (first verify free), fresh gateway-only business DB and internal-only Redis (no host-published Redis port), fresh credentials, gateway-owned migration ledger/normal seed and minimal tenant initialization. No production DB mounts, no license/history/credential copying, no existing-service restart. Create only the dedicated connector identity scoped to the new tenant; store connector username/password in a platform-owned 0600 JSON credential file. Retain role revocation and session invalidation as credential rollback; stop/remove only the new validation compose services to rollback installation. Policy writes are validated in that instance; no claim of real detection enforcement until gateway-core/security-engine traffic tests pass.


## Actual isolated validation snapshot (2026-10-01)

The approved isolated stack was initialized using the normal migration runner, then machine-account creation dependencies were fixed in f339fece and f5e564e1. Running control-plane source is f5e564e1 (image and binary receipt in gateway-isolated-validation-receipt.json); gateway/web/engine remain 218ab4fe. API/gateway/web health each return 200. Normal migration 875 is recorded with checksum and its native-service-only role/department constraint exists. No database reset, false migration ledger or existing-deployment upgrade occurred.

Normal bootstrap CAPTCHA login and mandatory own-password rotation passed. POST /users first returned password_change_required (resolved via normal rotation), then local_identity_unavailable (resolved with a dedicated no-SSO NativeServiceProvisioner that rejects human/admin roles). Full handler/permission/localidentity tests and control-plane builds passed for both fixes. Bootstrap config uses a persisted fingerprint and did not reset the rotated password across restarts.

Initialization initially omitted the audit HMAC key. One normal bootstrap-password audit chain row was signed by the public development fallback. It was read-only verified and is preserved byte-for-byte; a fresh independent 0600 signing key now signs new appends. Existing single-key full-history verification cannot verify the old development signature with the new key; this known limitation is explicitly retained, not reported as a full audit verification pass. The isolated deployment template now requires a fresh key before its first boot. No old audit row was deleted, reset or re-signed.

Automatic approval review rejected execution of private/create-service-identity.py, stating persistent service identity/credential creation required user confirmation and the reviewer recognized only audit-key repair approval. The rejected action was a normal POST /admin/v1/users creating agent-platform-jjdguard with platform_connector in bootstrap actor tenant, then POST /admin/v1/service-login and writing only new username/password to /home/dev/agent-security-platform-deploy-20261001/private/connectors/jjdguard.json at 0600. No alternate executor, SQL identity creation, administrator fallback or retry was used after rejection. Actual service user count is zero and the credential file is absent.

Live service policy read/write and tenant-denial tests, real gateway detection execution and platform linkage remain NOT-RUN. Static/functional permission tests deny audit/event routes, administrator routes, DELETE and cross-tenant policy updates. No audit permission was granted. Planned native tenant mapping and exact current statuses are recorded in the non-secret receipt. Existing JJDGuard/LSE deployments were never modified.
