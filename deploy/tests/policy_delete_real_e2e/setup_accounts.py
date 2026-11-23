"""Seeds the freshly started isolated stack: admin password, a department with full model access, the
users the tests log in as (alice = chat key owner, auditor1, officer1), a mock OpenAI provider/model and
alice's gateway key. Idempotent enough for a fresh stack; run once by run.sh."""
import json
import sys

sys.path.insert(0, ".")
from e2e_lib import *  # noqa: E402,F401,F403

token = admin_token()


def api(method, path, body=None):
    return req(method, CP + "/admin/v1" + path, body, token=token)


def must(label, result, ok=(200, 201)):
    status, body = result
    if status not in ok:
        raise SystemExit(f"{label} failed: {status} {json.dumps(body, ensure_ascii=False)[:300]}")
    print(f"ok  {label}")
    return body


team = must("department", api("POST", "/teams", {"name": "e2e-dept"}))["team"]
psql(f"UPDATE teams SET model_access_mode='all_active' WHERE id='{team['id']}'")

alice = must("user alice", api("POST", "/users", {
    "username": "alice", "password": "Zx#E2e-Pass-20261109", "email": "alice@e2e.local", "role": "developer", "department_id": team["id"]}))
must("user auditor1", api("POST", "/users", {
    "username": "auditor1", "password": "Auditor#E2e-20261109", "email": "auditor1@e2e.local", "role": "auditor", "department_id": team["id"]}))
must("user officer1", api("POST", "/users", {
    "username": "officer1", "password": "Offi#E2e-Pass-20261109", "email": "officer1@e2e.local", "role": "security_officer", "department_id": team["id"]}))

provider = must("provider", api("POST", "/providers", {
    "name": "mock-openai", "provider_type": "openai", "base_url": "http://upstream:9000/v1", "api_key": "sk-mock-upstream"}))
must("model", api("POST", "/models", {
    "provider_id": provider["id"], "model_name": "mock-model", "upstream_model_id": "mock-model",
    "protocols": ["chat_completions"], "status": "active"}))
key = must("key", api("POST", "/keys", {"project_id": "project_default", "user_id": alice["id"], "name": "alice-e2e"}))
set_env("API_KEY", key["full_key"])
print("seeded")
